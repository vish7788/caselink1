"""Opt-in live checks: domain age (RDAP) and a look at what the page actually asks for.

This server fetches addresses supplied by strangers, so it is hardened against SSRF:
- only http/https on ports 80 and 443;
- every hostname (and every redirect hop) must resolve to public IP addresses only;
- the connection is pinned to the validated IP, so DNS cannot change between check and fetch;
- redirects are followed by hand (max 4), the body is capped at 300 KB, no JavaScript is run.
Enable with CASELINK_LIVE=1. Nothing here runs unless a request asks for it.
"""
import ipaddress
import re
import socket
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

import httpx

from .extract import IP_RE, host_of, registered_domain

ALLOWED_PORTS = {80, 443}
MAX_BYTES = 300_000
MAX_HOPS = 4
TIMEOUT = 6.0
UA = "Mozilla/5.0 (compatible; CaseLinkTriage/0.1)"
SENSITIVE_FIELD = re.compile(r"otp|cvv|card|pin|mpin|upi|expiry|aadhaar|pan\b", re.I)


class Blocked(Exception):
    """The address is not allowed to be fetched."""


class Unresolvable(Blocked):
    """The hostname does not resolve."""


def resolve_public(host: str) -> list:
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        raise Unresolvable("hostname does not resolve")
    ips = []
    for info in infos:
        ip = info[4][0].split("%")[0]
        if not ipaddress.ip_address(ip).is_global:
            raise Blocked(f"resolves to a non-public address ({ip})")
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise Unresolvable("hostname does not resolve")
    return ips


def _fetch_once(client: httpx.Client, url: str, ip: str):
    p = urlparse(url)
    port = p.port or (443 if p.scheme == "https" else 80)
    ip_host = f"[{ip}]" if ":" in ip else ip
    target = f"{p.scheme}://{ip_host}:{port}{p.path or '/'}" + (f"?{p.query}" if p.query else "")
    headers = {"Host": p.netloc.rsplit("@", 1)[-1], "User-Agent": UA}
    with client.stream("GET", target, headers=headers, extensions={"sni_hostname": p.hostname}) as r:
        body = b""
        for chunk in r.iter_bytes():
            body += chunk
            if len(body) > MAX_BYTES:
                break
        return r.status_code, r.headers.get("location"), body[:MAX_BYTES]


def fetch_page(url: str) -> dict:
    redirects, current = [], url
    with httpx.Client(timeout=TIMEOUT, follow_redirects=False, verify=False) as client:
        for _ in range(MAX_HOPS + 1):
            p = urlparse(current)
            if p.scheme not in ("http", "https") or not p.hostname:
                raise Blocked("only http and https addresses are fetched")
            if (p.port or (443 if p.scheme == "https" else 80)) not in ALLOWED_PORTS:
                raise Blocked("port not allowed")
            ip = resolve_public(p.hostname)[0]
            status, location, body = _fetch_once(client, current, ip)
            if status in (301, 302, 303, 307, 308) and location:
                current = urljoin(current, location)
                redirects.append(current)
                continue
            return {"final_url": current, "status": status, "redirects": redirects, "body": body.decode("utf-8", "ignore")}
    raise Blocked("too many redirects")


def domain_age_days(domain: str):
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,251}[a-z0-9]", domain):
        return None
    try:
        r = httpx.get(f"https://rdap.org/domain/{domain}", timeout=TIMEOUT, follow_redirects=True,
                      headers={"Accept": "application/rdap+json"})
        if r.status_code != 200:
            return None
        for ev in r.json().get("events", []):
            if ev.get("eventAction") == "registration":
                registered = datetime.fromisoformat(ev["eventDate"].replace("Z", "+00:00"))
                return max(0, (datetime.now(timezone.utc) - registered).days)
    except Exception:
        return None
    return None


class _Page(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.title, self._in_title = "", False
        self.inputs, self.forms, self.text = [], [], []

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "input":
            self.inputs.append((a.get("type", "text").lower(), f"{a.get('name', '')} {a.get('placeholder', '')} {a.get('id', '')}"))
        elif tag == "form":
            self.forms.append(a.get("action", ""))

    def handle_endtag(self, tag):
        if tag == "title":
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data
        elif len(self.text) < 3000:
            self.text.append(data)


def check(url: str) -> dict:
    from .url_analyzer import OFFICIAL, is_official  # imported here to avoid a circular import

    out = {"reasons": [], "domain_age_days": None, "final_url": None, "redirects": [], "title": None, "page": "not fetched"}
    reasons = out["reasons"]
    host = host_of(url)
    reg = registered_domain(host)

    if not IP_RE.fullmatch(host):
        age = domain_age_days(reg)
        out["domain_age_days"] = age
        if age is not None:
            pts = 30 if age < 7 else 25 if age < 30 else 12 if age < 90 else 0
            if pts:
                reasons.append({"points": pts, "text": f"Domain was registered only {age} day(s) ago (RDAP)", "source": "live"})

    try:
        page = fetch_page(url)
    except Unresolvable:
        out["page"] = "unresolvable"
        reasons.append({"points": 0, "text": "Domain no longer resolves; the site may already be taken down. Preserve evidence.", "source": "live"})
        return out
    except Blocked as e:
        out["page"] = f"not fetched: {e}"
        return out
    except Exception:
        out["page"] = "unreachable"
        return out

    out.update(final_url=page["final_url"], redirects=page["redirects"], page=f"fetched (HTTP {page['status']})")
    parser = _Page()
    parser.feed(page["body"])
    out["title"] = parser.title.strip()[:200] or None
    final_reg = registered_domain(host_of(page["final_url"]))
    text = (parser.title + " " + " ".join(parser.text)).lower()

    if len(page["redirects"]) >= 3:
        reasons.append({"points": 5, "text": f"Passes through {len(page['redirects'])} redirects before the final page", "source": "live"})
    if final_reg != reg:
        reasons.append({"points": 5, "text": f"Redirects to a different domain ({final_reg})", "source": "live"})

    brand = next((b for b in OFFICIAL if b in text and not is_official(final_reg)), None)
    has_password = any(t == "password" for t, _ in parser.inputs)
    sensitive = [n for t, n in parser.inputs if SENSITIVE_FIELD.search(n)]
    if brand and has_password:
        reasons.append({"points": 20, "text": f"Page asks for a password while presenting itself as {brand.upper()}", "source": "live"})
    elif brand:
        reasons.append({"points": 15, "text": f"Page presents itself as {brand.upper()} but is hosted on {final_reg}", "source": "live"})
    elif has_password and not is_official(final_reg):
        reasons.append({"points": 5, "text": "Page contains a password field", "source": "live"})
    if sensitive:
        reasons.append({"points": 15, "text": "Page asks for OTP, card or PIN details", "source": "live"})
    for action in parser.forms:
        if action.lower().startswith(("http://", "https://")) and registered_domain(host_of(action)) != final_reg:
            reasons.append({"points": 10, "text": f"Form sends the data to a different domain ({registered_domain(host_of(action))})", "source": "live"})
            break
    return out
