from fastapi.testclient import TestClient

from app.apk_analyzer import analyze_apk
from app.extract import extract_identifiers, registered_domain
from app.main import create_app
from app.seed import DEMO_APKS, make_demo_apk
from app.url_analyzer import analyze_url


def test_extracts_identifiers():
    ids = extract_identifiers("Pay refund.desk77@ybl, call +91 90000 11122? no: 9000011122. Visit http://sbi-kyc-update.top/login. and 10.1.2.3")
    assert ids["upi_ids"] == ["refund.desk77@ybl"]
    assert ids["phones"] == ["9000011122"]
    assert ids["domains"] == ["sbi-kyc-update.top"]
    assert ids["ips"] == ["10.1.2.3"]


def test_registered_domain_two_part_suffix():
    assert registered_domain("www.sbi.co.in") == "sbi.co.in"
    assert registered_domain("a.b.evil.xyz") == "evil.xyz"


def test_phishing_url_flagged_and_official_clean():
    bad = analyze_url("http://sbi-kyc-update.top/login")
    assert bad["verdict"] == "malicious"
    assert any("Impersonates SBI" in r["text"] for r in bad["reasons"])
    assert analyze_url("https://www.sbi.co.in/")["verdict"] == "low_risk"


def test_typosquat_detected():
    r = analyze_url("https://paytrn-support.shop/verify")
    assert any("Look-alike" in x["text"] for x in r["reasons"])


def test_apk_flags_trojan_pattern():
    name, data = DEMO_APKS[0]
    r = analyze_apk(name, data)
    assert r["verdict"] == "malicious"
    assert "BIND_ACCESSIBILITY_SERVICE" in r["permissions"]
    assert r["identifiers"]["bots"] == ["123456789"]
    assert r["identifiers"]["upi_ids"] == ["refund.desk77@ybl"]


def test_non_apk_rejected_gracefully():
    r = analyze_apk("x.apk", b"not a zip")
    assert r["score"] == 0 and "not a valid APK" in r["reasons"][0]["text"]


def test_end_to_end_clustering_and_reports(tmp_path):
    c = TestClient(create_app(str(tmp_path / "t.db")))
    assert c.post("/api/demo/load").json()["loaded"] == 11
    clusters = c.get("/api/clusters").json()
    big, small = clusters[0], clusters[1]
    # SBI gang: 5 text complaints + 2 APKs linked through UPI, domains, IP, phone and Telegram bot
    assert big["size"] == 7
    assert big["priority_targets"][0]["value"] == "refund.desk77@ybl"
    assert small["size"] == 2 and "customs.help21@paytm" in [t["value"] for t in small["shared_identifiers"]]
    # the lone Amazon lookalike and the legitimate SBI notice stay unlinked
    linked = {i for cl in clusters for i in cl["complaint_ids"]}
    assert 8 not in linked and 9 not in linked
    pdf = c.get("/api/complaints/1/report.pdf")
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    assert "CL-0001" in c.get("/api/complaints/1/report.html").text
    assert c.get("/api/complaints/999").status_code == 404


def test_new_complaint_joins_existing_cluster(tmp_path):
    c = TestClient(create_app(str(tmp_path / "t.db")))
    c.post("/api/demo/load")
    r = c.post("/api/analyze/text", json={"text": "Sent money to customs.help21@paytm after a parcel message"}).json()
    assert r["cluster"]["size"] == 3


def test_apk_upload_endpoint(tmp_path):
    c = TestClient(create_app(str(tmp_path / "t.db")))
    data = make_demo_apk(["READ_SMS"], ["http://evil-login.top/x"])
    r = c.post("/api/analyze/apk", files={"file": ("a.apk", data)}).json()
    assert r["kind"] == "apk" and "READ_SMS" in r["permissions"]
