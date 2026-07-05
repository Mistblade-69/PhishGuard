"""
ocr_scanner.py
Extracts visible text from a screenshot (e.g. a phishing email screenshot
with no raw headers available) using Tesseract OCR. Also pulls out any URLs
found in that OCR'd text so they can go through the normal url_analyzer checks.

100% normal code -- no AI. The AI vision judgment happens separately in
llm_agent.get_verdict_from_screenshot(), which sees the raw image itself.
"""

import re
import pytesseract
from PIL import Image
import io

URL_REGEX = re.compile(r"https?://[^\s\"'<>\)]+")


def extract_text_from_image(image_bytes: bytes) -> str:
    """Runs OCR on a screenshot and returns the extracted text."""
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        return pytesseract.image_to_string(img)
    except Exception as e:
        return f"[OCR failed: {e}]"


def extract_urls_from_text(text: str) -> list:
    return list(dict.fromkeys(URL_REGEX.findall(text)))