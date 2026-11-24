"""Turns raw complaint input into a scored, explained result with extracted identifiers."""
import re

from .apk_analyzer import analyze_apk  # re-exported for the API layer
from .extract import extract_identifiers
from .url_analyzer import analyze_url, enrich_live, verdict_for

PHRASES = [
    (r"\bkyc\b", 8, "Message pushes a KYC update"),
    (r"(account|card|sim).{0,30}(blocked|suspended|closed|expire)", 10, "Threatens to block or close an account"),
    (r"\b(urgent|immediately|today|within 24 hours|tonight)\b", 5, "Creates artificial urgency"),
    (r"\b(refund|cashback|reward|lottery|prize|gift voucher)\b", 8, "Dangles a refund or reward"),
    (r"\b(otp|cvv|pin|password)\b", 8, "Asks for OTP, PIN or password"),
    (r"(install|download).{0,40}(apk|app)|\.apk\b", 12, "Pushes an app or APK install outside the Play Store"),
    (r"(customs|delivery|parcel).{0,40}(fee|charge|pay)", 8, "Parcel or customs fee pretext"),
    (r"electricity.{0,30}(disconnect|cut)", 10, "Electricity-disconnection pretext"),
]
PHRASE_CAP = 25
KEEP = ("domains", "upi_ids", "phones", "ips", "bots")


LIVE_URL_LIMIT = 3  # live checks are slow, so only the most suspicious links get them


def analyze_text(text: str, live: bool = False) -> dict:
    ids = extract_identifiers(text)
    urls = [analyze_url(u) for u in ids["urls"]]
    if live:
        for r in sorted(urls, key=lambda r: -r["score"])[:LIVE_URL_LIMIT]:
            enrich_live(r)
    top = max(urls, key=lambda r: r["score"], default=None)
    reasons = [{"points": r["points"], "text": r["text"], "source": top["host"]} for r in (top["reasons"] if top else [])]
    base = top["score"] if top else 0

    used = 0
    for pattern, pts, why in PHRASES:
        if used >= PHRASE_CAP:
            break
        if re.search(pattern, text, re.I):
            pts = min(pts, PHRASE_CAP - used)
            used += pts
            reasons.append({"points": pts, "text": why, "source": "message text"})

    score = min(100, base + used)
    return {
        "kind": "text",
        "score": score,
        "verdict": verdict_for(score),
        "reasons": reasons,
        "urls": urls,
        "identifiers": {k: ids[k] for k in KEEP},
    }


__all__ = ["analyze_text", "analyze_apk"]
