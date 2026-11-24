"""Screenshot OCR via Tesseract (English plus Hindi when the language pack is installed)."""
import io


class OCRUnavailable(Exception):
    pass


def available() -> bool:
    try:
        import pytesseract
        return bool(pytesseract.get_languages())
    except Exception:
        return False


def ocr_image(data: bytes) -> str:
    try:
        import pytesseract
        from PIL import Image, ImageOps
    except ImportError:
        raise OCRUnavailable("install pytesseract and pillow")
    Image.MAX_IMAGE_PIXELS = 40_000_000  # refuse decompression bombs
    try:
        img = ImageOps.exif_transpose(Image.open(io.BytesIO(data))).convert("L")
    except Exception as e:
        raise ValueError(f"not a readable image ({type(e).__name__})")
    if img.width < 1200:  # small phone screenshots OCR far better when enlarged
        scale = 2 if img.width >= 600 else 3
        img = img.resize((img.width * scale, img.height * scale))
    try:
        installed = set(pytesseract.get_languages())
    except Exception:
        raise OCRUnavailable("the tesseract program is not installed")
    langs = "+".join(l for l in ("eng", "hin") if l in installed)
    if not langs:
        raise OCRUnavailable("tesseract has no English language data")
    return pytesseract.image_to_string(img, lang=langs).strip()
