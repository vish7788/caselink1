import io
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from PIL import Image, ImageDraw, ImageFont

from app import live, ml
from app.apk_analyzer import analyze_apk
from app.graph import Store
from app.main import create_app
from app.pipeline import analyze_text
from app.url_analyzer import analyze_url

DATA = Path(__file__).parent / "data"


# ---------- trained model ----------
def test_model_is_shipped_with_honest_metrics():
    metrics = json.loads((ml.MODEL_DIR / "metrics.json").read_text())
    assert metrics["holdout_auc"] > 0.85 and metrics["holdout_size"] >= 5000
    assert "caveat" in metrics


def test_model_separates_scam_style_from_known_domains():
    assert ml.phishing_probability("sbi-kyc-update.top") > 0.8
    assert ml.phishing_probability("hdfc-secure-login.top") > 0.8
    assert ml.phishing_probability("wikipedia.org") < 0.3


def test_model_adds_a_reason_but_never_flags_official_domains():
    bad = analyze_url("http://sbi-rewards-claim.xyz/")
    assert bad["ml_probability"] > 0.5 and any("Trained model" in r["text"] for r in bad["reasons"])
    good = analyze_url("https://www.irctc.co.in/")
    assert good["ml_probability"] is None and good["verdict"] == "low_risk"


# ---------- real APK ----------
def test_real_apk_is_parsed_with_its_binary_manifest():
    r = analyze_apk("TestActivity.apk", (DATA / "TestActivity.apk").read_bytes())
    assert r["package"] == "tests.androguard"
    assert r["verdict"] == "low_risk"
    assert any("debug certificate" in x["text"] for x in r["reasons"])
    assert "apk_certs" not in r["identifiers"]  # the public debug cert must never link unrelated cases
    assert r["identifiers"]["packages"] == ["tests.androguard"]


def test_shared_signing_certificate_links_apks():
    s = Store(":memory:")
    for name in ("a.apk", "b.apk"):
        s.add(name, {"kind": "apk", "score": 80, "verdict": "malicious", "reasons": [],
                     "identifiers": {"apk_sha256": [name], "apk_certs": ["ab12" * 16]}})
    c = s.clusters()
    assert len(c) == 1 and c[0]["shared_identifiers"][0]["type"] == "cert"


# ---------- live checks ----------
@pytest.mark.parametrize("host", ["localhost", "127.0.0.1", "10.0.0.5", "192.168.1.1", "169.254.169.254", "100.64.0.1", "::1"])
def test_ssrf_guard_blocks_non_public_addresses(host):
    with pytest.raises(live.Blocked):
        live.resolve_public(host)


@pytest.mark.parametrize("url", ["http://127.0.0.1/", "http://169.254.169.254/latest/meta-data/", "file:///etc/passwd",
                                 "http://example.com:8080/", "ftp://example.com/"])
def test_fetch_refuses_dangerous_urls(url):
    with pytest.raises(live.Blocked):
        live.fetch_page(url)


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/start":
            self.send_response(302)
            self.send_header("Location", "/login")
            self.end_headers()
            return
        body = (b"<html><head><title>SBI Net Banking Login</title></head><body>"
                b"<form action='http://collector.example.net/post'><input type=password name=pw>"
                b"<input name='otp_code' placeholder='Enter OTP'></form></body></html>")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def local_site(monkeypatch):
    srv = HTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    # The test server is on loopback, which the real guard refuses, so the resolver and port list are overridden here only.
    monkeypatch.setattr(live, "resolve_public", lambda host: ["127.0.0.1"])
    monkeypatch.setattr(live, "ALLOWED_PORTS", {port})
    monkeypatch.setattr(live, "domain_age_days", lambda d: 3)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    yield port
    srv.shutdown()


def test_live_check_reads_the_page_and_domain_age(local_site):
    info = live.check(f"http://sbi-secure-login.test:{local_site}/start")
    texts = " | ".join(r["text"] for r in info["reasons"])
    assert info["title"] == "SBI Net Banking Login" and len(info["redirects"]) == 1
    assert "registered only 3 day" in texts
    assert "asks for a password while presenting itself as SBI" in texts
    assert "OTP, card or PIN" in texts
    assert "different domain (example.net)" in texts


def test_live_results_feed_the_complaint_score(local_site):
    text = f"Please check http://sbi-secure-login.test:{local_site}/start"
    static, live_res = analyze_text(text), analyze_text(text, live=True)
    assert live_res["score"] > static["score"]
    assert live_res["urls"][0]["live"]["domain_age_days"] == 3


def test_live_is_off_unless_enabled(tmp_path, monkeypatch):
    monkeypatch.delenv("CASELINK_LIVE", raising=False)
    c = TestClient(create_app(str(tmp_path / "t.db")))
    r = c.post("/api/analyze/text", json={"text": "http://x.top", "live": True})
    assert r.status_code == 400 and "CASELINK_LIVE=1" in r.json()["detail"]
    assert c.get("/api/health").json()["features"]["live_checks"] is False


# ---------- OCR ----------
def _screenshot(lines):
    try:
        font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf", 30)
    except OSError:
        font = ImageFont.load_default(size=30)
    im = Image.new("RGB", (1000, 60 * len(lines) + 40), "white")
    d = ImageDraw.Draw(im)
    for i, line in enumerate(lines):
        d.text((20, 20 + 60 * i), line, fill="black", font=font)
    buf = io.BytesIO()
    im.save(buf, "PNG")
    return buf.getvalue()


def test_screenshot_ocr_feeds_the_pipeline(tmp_path):
    c = TestClient(create_app(str(tmp_path / "t.db")))
    if not c.get("/api/health").json()["features"]["screenshot_ocr"]:
        pytest.skip("tesseract not installed")
    png = _screenshot(["Your SBI account will be blocked today.", "Update KYC at http://sbi-kyc-update.top/login",
                       "Pay Rs 10 to refund.desk77@ybl", "Call 9000011122"])
    r = c.post("/api/analyze/image", files={"file": ("chat.png", png, "image/png")}).json()
    assert r["identifiers"]["domains"] == ["sbi-kyc-update.top"]
    assert r["identifiers"]["upi_ids"] == ["refund.desk77@ybl"]
    assert r["identifiers"]["phones"] == ["9000011122"]
    assert r["verdict"] == "malicious"


def test_image_endpoint_rejects_garbage(tmp_path):
    c = TestClient(create_app(str(tmp_path / "t.db")))
    if not c.get("/api/health").json()["features"]["screenshot_ocr"]:
        pytest.skip("tesseract not installed")
    assert c.post("/api/analyze/image", files={"file": ("x.png", b"not an image")}).status_code == 400


# ---------- bulk CSV ----------
def test_csv_import_clusters_and_validates(tmp_path):
    c = TestClient(create_app(str(tmp_path / "t.db")))
    csv_data = ("text,label\n"
                '"Pay to scam.one@ybl, link http://kyc-bank-update.top/x",case A\n'
                '"They asked for money to scam.one@ybl",case B\n'
                ",empty row\n"
                '"Unrelated: lottery prize at http://win-big.click",case C\n')
    r = c.post("/api/import/csv", files={"file": ("in.csv", csv_data.encode())}).json()
    assert r["imported"] == 3 and r["skipped"] == 1 and r["clusters"] == 1
    assert c.post("/api/import/csv", files={"file": ("bad.csv", b"a,b\n1,2\n")}).status_code == 400
