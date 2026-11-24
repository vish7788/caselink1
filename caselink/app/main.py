import csv
import io
import os
from pathlib import Path

from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from starlette.concurrency import run_in_threadpool

from .graph import Store
from .ml import load_model
from .ocr import OCRUnavailable, available as ocr_available, ocr_image
from .pipeline import analyze_apk, analyze_text
from .report import render_html, render_pdf, report_data
from .seed import load_demo

BASE = Path(__file__).parent
MAX_UPLOAD = 25 * 1024 * 1024
MAX_CSV_BYTES = 5 * 1024 * 1024
MAX_CSV_ROWS = 5000


class TextIn(BaseModel):
    text: str
    label: str | None = None
    live: bool = False  # domain age and page inspection; needs CASELINK_LIVE=1 on the server


def create_app(db_path: str | None = None) -> FastAPI:
    db_path = db_path or os.environ.get("CASELINK_DB", str(BASE.parent / "data" / "caselink.db"))
    store = Store(db_path)
    live_enabled = os.environ.get("CASELINK_LIVE") == "1"
    app = FastAPI(title="CaseLink", description="Complaint-to-case fraud intelligence (prototype)")
    app.mount("/static", StaticFiles(directory=BASE / "static"), name="static")

    def finish(label: str, result: dict) -> dict:
        cid = store.add(label, result)
        return {"id": cid, "label": label, **result, "cluster": store.cluster_of(cid)}

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(BASE / "static" / "index.html")

    @app.get("/api/health")
    def health():
        return {"status": "ok", "complaints": len(store.list()), "features": {
            "trained_model": load_model() is not None, "live_checks": live_enabled, "screenshot_ocr": ocr_available()}}

    @app.post("/api/analyze/text")
    def analyze_text_endpoint(body: TextIn):
        if not body.text.strip():
            raise HTTPException(400, "text is empty")
        if body.live and not live_enabled:
            raise HTTPException(400, "Live checks are disabled. Start the server with CASELINK_LIVE=1 to enable them.")
        return finish(body.label or body.text.strip()[:40], analyze_text(body.text, live=body.live))

    @app.post("/api/analyze/apk")
    async def analyze_apk_endpoint(file: UploadFile = File(...)):
        data = await file.read(MAX_UPLOAD + 1)
        if len(data) > MAX_UPLOAD:
            raise HTTPException(413, "file larger than 25 MB")
        name = Path(file.filename or "upload.apk").name
        return finish(name, analyze_apk(name, data))

    @app.post("/api/analyze/image")
    async def analyze_image_endpoint(file: UploadFile = File(...)):
        data = await file.read(MAX_UPLOAD + 1)
        if len(data) > MAX_UPLOAD:
            raise HTTPException(413, "file larger than 25 MB")
        try:
            text = await run_in_threadpool(ocr_image, data)
        except OCRUnavailable as e:
            raise HTTPException(501, f"Screenshot OCR is unavailable: {e}")
        except ValueError as e:
            raise HTTPException(400, str(e))
        if not text:
            raise HTTPException(422, "No text could be read from the image")
        name = Path(file.filename or "screenshot").name
        return {"ocr_text": text, **finish(name, analyze_text(text))}

    @app.post("/api/import/csv")
    async def import_csv(file: UploadFile = File(...)):
        """Bulk intake: a CSV with a 'text' column (the complaint) and an optional 'label' column."""
        raw = await file.read(MAX_CSV_BYTES + 1)
        if len(raw) > MAX_CSV_BYTES:
            raise HTTPException(413, "CSV larger than 5 MB")
        reader = csv.DictReader(io.StringIO(raw.decode("utf-8-sig", "ignore")))
        if "text" not in [(f or "").strip().lower() for f in (reader.fieldnames or [])]:
            raise HTTPException(400, "CSV needs a 'text' column (and optionally a 'label' column)")
        imported = skipped = 0
        for i, row in enumerate(reader):
            if i >= MAX_CSV_ROWS:
                break
            row = {(k or "").strip().lower(): (v or "") for k, v in row.items() if k}
            text = row.get("text", "").strip()
            if not text:
                skipped += 1
                continue
            store.add((row.get("label") or text[:40]).strip(), analyze_text(text))
            imported += 1
        return {"imported": imported, "skipped": skipped, "row_limit": MAX_CSV_ROWS, "clusters": len(store.clusters())}

    @app.get("/api/complaints")
    def complaints():
        return store.list()

    @app.get("/api/complaints/{cid}")
    def complaint(cid: int):
        row = store.get(cid)
        if not row:
            raise HTTPException(404, "complaint not found")
        return {**row, "cluster": store.cluster_of(cid)}

    @app.get("/api/complaints/{cid}/report.pdf")
    def report_pdf(cid: int):
        d = report_data(store, cid)
        if not d:
            raise HTTPException(404, "complaint not found")
        return Response(render_pdf(d), media_type="application/pdf",
                        headers={"Content-Disposition": f"inline; filename=caselink-{cid}.pdf"})

    @app.get("/api/complaints/{cid}/report.html", response_class=HTMLResponse)
    def report_html(cid: int):
        d = report_data(store, cid)
        if not d:
            raise HTTPException(404, "complaint not found")
        return render_html(d)

    @app.get("/api/clusters")
    def clusters():
        return store.clusters()

    @app.get("/api/graph")
    def graph(cluster_id: str | None = None):
        return store.graph_json(cluster_id)

    @app.post("/api/demo/load")
    def demo_load():
        return {"loaded": load_demo(store)}

    return app


app = create_app()
