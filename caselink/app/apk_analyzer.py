"""Static APK triage: permissions, risky capabilities and hardcoded indicators. Never executes the app."""
import hashlib
import io
import re
import zipfile

from .extract import extract_identifiers
from .url_analyzer import OFFICIAL, verdict_for

RISKY_PERMISSIONS = {
    "READ_SMS": (15, "Can read SMS, which lets an app capture OTPs"),
    "RECEIVE_SMS": (15, "Can intercept incoming SMS"),
    "SEND_SMS": (15, "Can send SMS silently"),
    "BIND_ACCESSIBILITY_SERVICE": (25, "Accessibility service can read the screen and tap on the user's behalf"),
    "SYSTEM_ALERT_WINDOW": (15, "Can draw overlays on top of other apps (fake login screens)"),
    "BIND_DEVICE_ADMIN": (20, "Requests device-admin rights, which makes it hard to uninstall"),
    "REQUEST_INSTALL_PACKAGES": (10, "Can install further APKs"),
    "READ_CONTACTS": (10, "Can read the contact list"),
    "READ_CALL_LOG": (10, "Can read call history"),
    "BIND_NOTIFICATION_LISTENER_SERVICE": (10, "Can read notifications, including OTPs"),
    "RECORD_AUDIO": (5, "Can record audio"),
    "READ_PHONE_STATE": (5, "Can read phone identity"),
}
CODE_MARKERS = [
    (rb"DexClassLoader", 10, "Loads additional code at runtime"),
    (rb"api\.telegram\.org/bot", 20, "Sends data to a Telegram bot"),
    (rb"AccessibilityService", 5, "References the accessibility API"),
    (rb"SmsManager", 5, "References the SMS API"),
]
PERM_RE = re.compile(rb"android\.permission\.([A-Z_]+)")
ASCII_RE = re.compile(rb"[\x20-\x7e]{6,}")
SCAN_SUFFIXES = (".dex", ".xml", ".js", ".html", ".json", ".txt", ".properties", ".arsc")


def _strings(data: bytes) -> bytes:
    """ASCII runs from raw bytes plus a UTF-16LE view (binary manifests store text that way)."""
    utf16 = data.replace(b"\x00", b"")
    return b"\n".join(ASCII_RE.findall(data) + ASCII_RE.findall(utf16))


def analyze_apk(filename: str, data: bytes) -> dict:
    sha256 = hashlib.sha256(data).hexdigest()
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        return {"kind": "apk", "filename": filename, "sha256": sha256, "score": 0, "verdict": "low_risk",
                "reasons": [{"points": 0, "text": "File is not a valid APK (not a ZIP archive)"}],
                "permissions": [], "identifiers": {"apk_sha256": [sha256]}}

    names = zf.namelist()
    reasons, permissions, blob = [], set(), b""
    for n in names:
        if n.endswith("AndroidManifest.xml") or n.lower().endswith(SCAN_SUFFIXES):
            try:
                raw = zf.read(n)[:8_000_000]
            except Exception:
                continue
            if n == "AndroidManifest.xml":
                permissions |= {p.decode() for p in PERM_RE.findall(_strings(raw))}
            blob += _strings(raw) + b"\n"

    # Proper parsing of real, binary-manifest APKs (optional dependency: androguard). Falls back to the string scan above.
    package = app_name = None
    certs, debug_signed = [], False
    try:
        from loguru import logger
        logger.disable("androguard")
        from androguard.core.apk import APK
        apk = APK(data, raw=True)
        permissions |= {p.rsplit(".", 1)[-1] for p in apk.get_permissions()}
        package, app_name = apk.get_package(), apk.get_app_name()
        for c in apk.get_certificates():
            if "Android Debug" in c.subject.human_friendly:
                debug_signed = True
            else:
                certs.append(c.sha256_fingerprint.replace(" ", "").lower())
    except Exception:
        pass
    if debug_signed:
        reasons.append({"points": 5, "text": "Signed with the public Android debug certificate, which store apps never use"})
    label_tokens = re.split(r"[^a-z0-9]+", f"{app_name or ''} {filename}".lower())
    brand = next((b for b in OFFICIAL if b in label_tokens or (len(b) >= 5 and b in "".join(label_tokens))), None)
    if brand:
        reasons.append({"points": 15, "text": f"App presents itself as {brand.upper()}; banks and brands distribute through official stores, not sideloaded APKs"})

    for perm, (pts, why) in RISKY_PERMISSIONS.items():
        if perm in permissions:
            reasons.append({"points": pts, "text": f"{perm}: {why}"})
    if {"READ_SMS", "RECEIVE_SMS"} & permissions and "BIND_ACCESSIBILITY_SERVICE" in permissions:
        reasons.append({"points": 15, "text": "OTP interception combined with screen control is a classic banking-trojan pattern"})
    for pattern, pts, why in CODE_MARKERS:
        if re.search(pattern, blob):
            reasons.append({"points": pts, "text": why})
    if not any(n.endswith(".dex") for n in names):
        reasons.append({"points": 5, "text": "No classes.dex found; archive may be malformed or packed"})

    text = blob.decode("latin-1")
    ids = extract_identifiers(text)
    ids = {k: v[:25] for k, v in ids.items()}
    ids["apk_sha256"] = [sha256]
    if certs:
        ids["apk_certs"] = certs
    if package:
        ids["packages"] = [package]
    if ids.get("upi_ids"):
        reasons.append({"points": 10, "text": f"{len(ids['upi_ids'])} hardcoded UPI ID(s) found inside the app"})

    score = min(100, sum(r["points"] for r in reasons))
    return {"kind": "apk", "filename": filename, "sha256": sha256, "score": score,
            "verdict": verdict_for(score), "reasons": reasons, "package": package, "app_name": app_name,
            "permissions": sorted(permissions), "identifiers": ids}
