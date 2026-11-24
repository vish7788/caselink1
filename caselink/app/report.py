"""One-page investigator report in HTML and PDF."""
import html
import io

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

TYPE_LABEL = {"domain": "Domain", "upi": "UPI ID", "phone": "Phone", "ip": "IP address", "bot": "Telegram bot", "apk": "APK hash",
              "cert": "APK signing certificate", "pkg": "App package"}


def recommended_actions(identifiers: dict) -> list:
    acts = []
    for d in identifiers.get("domains", []):
        acts.append(f"Request suspension of {d} through the registrar and hosting abuse contacts; consider reporting to CERT-In.")
    for u in identifiers.get("upi_ids", []):
        acts.append(f"Ask the bank or payment provider's nodal officer to flag or freeze {u} and trace the linked account.")
    for p in identifiers.get("phones", []):
        acts.append(f"Ask the telecom operator to trace and block {p}; the number can also be reported on Sanchar Saathi.")
    for b in identifiers.get("bots", []):
        acts.append(f"Preserve evidence and request takedown of Telegram bot {b} through Telegram's abuse channel.")
    for h in identifiers.get("apk_sha256", []):
        acts.append(f"Share APK hash {h[:16]}... with CERT-In and device security teams; advise the victim to uninstall and change credentials.")
    for ip in identifiers.get("ips", []):
        acts.append(f"Request hosting details and logs for {ip} from the network provider.")
    return acts


def report_data(store, cid: int):
    row = store.get(cid)
    if not row:
        return None
    res = row["result"]
    ids = res.get("identifiers", {})
    return {"id": cid, "created_at": row["created_at"], "label": row["label"], "kind": row["kind"],
            "score": row["score"], "verdict": row["verdict"], "reasons": res.get("reasons", []),
            "identifiers": ids, "urls": [u["url"] for u in res.get("urls", [])],
            "permissions": res.get("permissions", []), "cluster": store.cluster_of(cid),
            "actions": recommended_actions(ids)}


def _ioc_rows(d):
    rows = []
    for key, label in [("domains", "Domain"), ("upi_ids", "UPI ID"), ("phones", "Phone"), ("ips", "IP address"),
                       ("bots", "Telegram bot"), ("apk_sha256", "APK SHA-256"), ("apk_certs", "Signing cert SHA-256"),
                       ("packages", "App package")]:
        for v in d["identifiers"].get(key, []):
            rows.append((label, v))
    return rows


def render_html(d: dict) -> str:
    e = html.escape
    li = lambda items: "".join(f"<li>{e(i)}</li>" for i in items) or "<li>None found</li>"
    ioc = "".join(f"<tr><td>{e(a)}</td><td>{e(b)}</td></tr>" for a, b in _ioc_rows(d)) or "<tr><td colspan=2>None found</td></tr>"
    cl = d["cluster"]
    if cl:
        targets = "".join(f"<tr><td>{e(TYPE_LABEL.get(t['type'], t['type']))}</td><td>{e(t['value'])}</td><td>{t['complaints']}</td></tr>" for t in cl["priority_targets"])
        cluster = (f"<p>Linked with <b>{cl['size'] - 1}</b> other complaint(s) in cluster <b>{e(cl['cluster_id'])}</b> "
                   f"(complaints {', '.join('#' + str(i) for i in cl['complaint_ids'])}). Identifiers shared across the most complaints:</p>"
                   f"<table><tr><th>Type</th><th>Value</th><th>Complaints</th></tr>{targets}</table>")
    else:
        cluster = "<p>No other complaint shares infrastructure with this one yet.</p>"
    return f"""<!doctype html><html><head><meta charset="utf-8"><title>CaseLink report #{d['id']}</title>
<style>body{{font:15px/1.5 system-ui,sans-serif;max-width:820px;margin:32px auto;padding:0 16px;color:#14213D}}
h1{{margin-bottom:0}}h2{{margin-top:28px;border-bottom:2px solid #2EC4B6;padding-bottom:4px}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:6px 10px;text-align:left}}
.v{{display:inline-block;padding:4px 12px;border-radius:12px;color:#fff;font-weight:600;background:{'#C0392B' if d['verdict']=='malicious' else '#D68910' if d['verdict']=='suspicious' else '#1E8449'}}}</style></head><body>
<h1>CaseLink investigator report</h1><p>Complaint #{d['id']} · {e(d['label'])} · {e(d['created_at'])} UTC</p>
<p><span class="v">{e(d['verdict'].replace('_', ' ').upper())}</span> &nbsp; Risk score <b>{d['score']}/100</b></p>
<h2>Why it was flagged</h2><ul>{li(r['text'] + f" (+{r['points']})" for r in d['reasons'])}</ul>
<h2>Indicators of compromise</h2><table><tr><th>Type</th><th>Value</th></tr>{ioc}</table>
<h2>Linked complaints</h2>{cluster}
<h2>Suggested next steps</h2><ul>{li(d['actions'])}</ul>
<p style="color:#666;font-size:13px">Automated triage to support an investigation. Verify findings before acting.</p></body></html>"""


def render_pdf(d: dict) -> bytes:
    ss = getSampleStyleSheet()
    body = ParagraphStyle("b", parent=ss["BodyText"], fontSize=9.5, leading=13)
    h2 = ParagraphStyle("h2", parent=ss["Heading2"], textColor=colors.HexColor("#0B7A70"), spaceBefore=10, spaceAfter=4)
    e = html.escape
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm, topMargin=16 * mm, bottomMargin=16 * mm)
    s = [Paragraph("CaseLink investigator report", ss["Title"]),
         Paragraph(f"Complaint #{d['id']} · {e(d['label'])} · {e(d['created_at'])} UTC", body),
         Paragraph(f"<b>Verdict: {e(d['verdict'].replace('_', ' ').upper())}</b> · Risk score {d['score']}/100", body),
         Paragraph("Why it was flagged", h2)]
    s += [Paragraph(f"• {e(r['text'])} (+{r['points']})", body) for r in d["reasons"]] or [Paragraph("• No risk signals found", body)]
    s.append(Paragraph("Indicators of compromise", h2))
    rows = [["Type", "Value"]] + [[a, Paragraph(e(b), body)] for a, b in _ioc_rows(d)] if _ioc_rows(d) else [["Type", "Value"], ["-", "None found"]]
    t = Table(rows, colWidths=[35 * mm, 130 * mm])
    t.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, colors.grey), ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#E8F6F4")),
                           ("FONTSIZE", (0, 0), (-1, -1), 9), ("VALIGN", (0, 0), (-1, -1), "TOP")]))
    s.append(t)
    s.append(Paragraph("Linked complaints", h2))
    cl = d["cluster"]
    if cl:
        s.append(Paragraph(f"Cluster {e(cl['cluster_id'])}: {cl['size']} complaints share infrastructure "
                           f"({', '.join('#' + str(i) for i in cl['complaint_ids'])}). Highest-impact identifiers:", body))
        for tgt in cl["priority_targets"]:
            s.append(Paragraph(f"• {e(TYPE_LABEL.get(tgt['type'], tgt['type']))}: {e(tgt['value'])} ({tgt['complaints']} complaints)", body))
    else:
        s.append(Paragraph("No other complaint shares infrastructure with this one yet.", body))
    s.append(Paragraph("Suggested next steps", h2))
    s += [Paragraph(f"• {e(a)}", body) for a in d["actions"]] or [Paragraph("• None", body)]
    s += [Spacer(1, 8), Paragraph("Automated triage to support an investigation. Verify findings before acting.", ParagraphStyle("f", parent=body, textColor=colors.grey, fontSize=8))]
    doc.build(s)
    return buf.getvalue()
