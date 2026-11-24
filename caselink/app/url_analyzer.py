"""Heuristic phishing-link analysis. Offline by default; each finding carries its reason."""
import re

from . import ml
from .extract import IP_RE, host_of, registered_domain

SUSPICIOUS_TLDS = {"xyz", "top", "click", "icu", "shop", "live", "vip", "cc", "buzz", "cfd", "sbs", "work", "loan", "rest", "monster"}
SHORTENERS = {"bit.ly", "tinyurl.com", "t.ly", "cutt.ly", "rb.gy", "is.gd"}
LURE_WORDS = ("login", "verify", "kyc", "update", "secure", "otp", "reward", "refund", "claim", "unblock", "bonus")

# brand token -> domains that really belong to it
OFFICIAL = {
    "sbi": {"sbi.co.in", "onlinesbi.sbi", "onlinesbi.com", "sbi.bank.in"},
    "hdfc": {"hdfcbank.com", "hdfc.com"},
    "icici": {"icicibank.com", "icici.com"},
    "axis": {"axisbank.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "npci": {"npci.org.in"},
    "amazon": {"amazon.in", "amazon.com"},
    "flipkart": {"flipkart.com"},
    "irctc": {"irctc.co.in"},
    "incometax": {"incometax.gov.in"},
    "uidai": {"uidai.gov.in"},
    "epfo": {"epfindia.gov.in"},
    "indiapost": {"indiapost.gov.in"},
}
SHORT_BRANDS = {"sbi", "hdfc", "axis"}  # too short for substring matching; match whole tokens only


def _lev(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _normalise(token: str) -> str:
    return token.replace("rn", "m").replace("vv", "w").replace("0", "o").replace("1", "l")


def is_official(reg: str) -> bool:
    return any(reg == o or reg.endswith("." + o) for domains in OFFICIAL.values() for o in domains)


def verdict_for(score: int) -> str:
    return "malicious" if score >= 60 else "suspicious" if score >= 30 else "low_risk"


def analyze_url(url: str) -> dict:
    host = host_of(url)
    reg = registered_domain(host) if host else ""
    tld = host.rsplit(".", 1)[-1] if "." in host else ""
    reasons = []

    def add(points, text):
        reasons.append({"points": points, "text": text})

    if IP_RE.fullmatch(host):
        add(25, "Link uses a raw IP address instead of a domain name")
    if "xn--" in host:
        add(20, "Domain uses punycode, which can hide look-alike characters")
    if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
        add(15, "URL contains '@', which can disguise the real destination")
    if host.count(".") >= 4:
        add(10, "Unusually deep subdomain chain")
    if reg.split(".")[0].count("-") >= 2:
        add(10, "Domain name stuffed with hyphens")
    if tld in SUSPICIOUS_TLDS:
        add(15, f"Domain ends in .{tld}, a TLD heavily used in throwaway scam sites")
    if reg in SHORTENERS:
        add(10, "Shortened link hides the final destination")
    if url.lower().startswith("http://"):
        add(10, "Page is served over plain HTTP")
    if len(url) > 75:
        add(5, "Very long URL")

    tokens = [t for t in re.split(r"[^a-z0-9]+", host) if t]
    reg_label = reg.split(".")[0] if reg else ""
    for brand, official in OFFICIAL.items():
        if reg in official or any(reg.endswith("." + o) or reg == o for o in official):
            continue
        hit = brand in tokens if brand in SHORT_BRANDS else brand in host
        if hit:
            add(30, f"Impersonates {brand.upper()}: brand name in a domain that is not official")
            break
        if brand not in SHORT_BRANDS and len(brand) >= 5:
            if any(0 <= _lev(_normalise(t), brand) <= 1 and t != brand for t in tokens + [reg_label]):
                add(30, f"Look-alike spelling of {brand.upper()}")
                break

    path = url.split("//", 1)[-1].partition("/")[2].lower()
    lures = [w for w in LURE_WORDS if w in path or w in host]
    if lures:
        add(min(15, 5 * len(lures)), "Lure words in the address: " + ", ".join(lures[:4]))

    ml_prob = None
    if reg and not IP_RE.fullmatch(host) and not is_official(reg):
        ml_prob = ml.phishing_probability(reg)
        if ml_prob is not None and ml_prob >= 0.5:
            add(round(30 * ml_prob), f"Trained model: the domain name pattern is {ml_prob:.0%} likely to be phishing")

    score = min(100, sum(r["points"] for r in reasons))
    return {"url": url, "host": host, "registered_domain": reg, "score": score,
            "verdict": verdict_for(score), "reasons": reasons,
            "ml_probability": None if ml_prob is None else round(ml_prob, 3)}


def enrich_live(result: dict) -> dict:
    """Add live evidence (domain age, page inspection) to a static result. Opt-in, see live.py."""
    from . import live
    info = live.check(result["url"])
    result["reasons"].extend(info["reasons"])
    result["score"] = min(100, result["score"] + sum(r["points"] for r in info["reasons"]))
    result["verdict"] = verdict_for(result["score"])
    result["live"] = {k: v for k, v in info.items() if k != "reasons"}
    return result
