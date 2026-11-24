"""Complaint store plus the intelligence graph that links complaints sharing infrastructure."""
import json
import sqlite3
import threading
import time

import networkx as nx

# Platforms and shorteners shared by millions of people; linking on them would merge unrelated cases.
IGNORED_DOMAINS = {
    "bit.ly", "tinyurl.com", "t.ly", "cutt.ly", "rb.gy", "is.gd", "google.com", "forms.gle",
    "wa.me", "whatsapp.com", "facebook.com", "youtube.com", "t.me", "instagram.com", "telegram.org",
}
NODE_TYPES = {"domains": "domain", "upi_ids": "upi", "phones": "phone", "ips": "ip", "bots": "bot", "apk_sha256": "apk",
              "apk_certs": "cert", "packages": "pkg"}


class Store:
    def __init__(self, path: str = ":memory:"):
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.lock = threading.Lock()
        self.db.execute(
            "create table if not exists complaints(id integer primary key autoincrement,"
            " created_at text, kind text, label text, score integer, verdict text, result text)"
        )
        self.db.commit()

    # ---- storage -------------------------------------------------------
    def add(self, label: str, result: dict) -> int:
        with self.lock:
            cur = self.db.execute(
                "insert into complaints(created_at, kind, label, score, verdict, result) values(?,?,?,?,?,?)",
                (time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()), result["kind"], label,
                 result["score"], result["verdict"], json.dumps(result)),
            )
            self.db.commit()
            return cur.lastrowid

    def _row(self, r) -> dict:
        return {"id": r["id"], "created_at": r["created_at"], "kind": r["kind"], "label": r["label"],
                "score": r["score"], "verdict": r["verdict"], "result": json.loads(r["result"])}

    def get(self, cid: int):
        with self.lock:
            r = self.db.execute("select * from complaints where id=?", (cid,)).fetchone()
        return self._row(r) if r else None

    def list(self) -> list:
        with self.lock:
            rows = self.db.execute("select * from complaints order by id desc").fetchall()
        return [{k: v for k, v in self._row(r).items() if k != "result"} for r in rows]

    def reset(self):
        with self.lock:
            self.db.execute("delete from complaints")
            self.db.execute("delete from sqlite_sequence where name='complaints'")
            self.db.commit()

    # ---- graph ---------------------------------------------------------
    def _graph(self) -> nx.Graph:
        g = nx.Graph()
        with self.lock:
            rows = self.db.execute("select * from complaints").fetchall()
        for r in rows:
            row = self._row(r)
            c = f"c:{row['id']}"
            g.add_node(c, type="complaint", cid=row["id"], label=row["label"], score=row["score"], verdict=row["verdict"])
            for key, ntype in NODE_TYPES.items():
                for value in row["result"].get("identifiers", {}).get(key, []):
                    if ntype == "domain" and value in IGNORED_DOMAINS:
                        continue
                    n = f"{ntype}:{value}"
                    g.add_node(n, type=ntype, label=value)
                    g.add_edge(c, n)
        return g

    @staticmethod
    def _components(g: nx.Graph):
        for comp in nx.connected_components(g):
            cids = sorted(g.nodes[n]["cid"] for n in comp if g.nodes[n]["type"] == "complaint")
            if len(cids) >= 2:
                yield comp, cids

    def _describe(self, g, comp, cids) -> dict:
        shared = sorted(
            ({"type": g.nodes[n]["type"], "value": g.nodes[n]["label"], "complaints": g.degree(n)}
             for n in comp if g.nodes[n]["type"] != "complaint" and g.degree(n) >= 2),
            key=lambda s: (-s["complaints"], s["type"], s["value"]),
        )
        scores = [g.nodes[n]["score"] for n in comp if g.nodes[n]["type"] == "complaint"]
        return {"cluster_id": f"CL-{cids[0]:04d}", "complaint_ids": cids, "size": len(cids),
                "max_score": max(scores), "shared_identifiers": shared, "priority_targets": shared[:5]}

    def clusters(self) -> list:
        g = self._graph()
        out = [self._describe(g, comp, cids) for comp, cids in self._components(g)]
        return sorted(out, key=lambda c: (-c["size"], c["cluster_id"]))

    def cluster_of(self, cid: int):
        g = self._graph()
        for comp, cids in self._components(g):
            if cid in cids:
                return self._describe(g, comp, cids)
        return None

    def graph_json(self, cluster_id: str | None = None) -> dict:
        g = self._graph()
        keep = set()
        for comp, cids in self._components(g):
            if cluster_id is None or f"CL-{cids[0]:04d}" == cluster_id:
                keep |= comp
        sub = g.subgraph(keep)
        nodes = [{"id": n, **{k: v for k, v in d.items()}} for n, d in sub.nodes(data=True)]
        edges = [{"source": a, "target": b} for a, b in sub.edges()]
        return {"nodes": nodes, "edges": edges}
