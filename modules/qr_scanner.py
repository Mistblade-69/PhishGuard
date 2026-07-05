"""
qr_scanner.py
Decodes QR codes from images attached/embedded in an email ("quishing" attacks).
Uses OpenCV's built-in QR detector -- no extra system dependencies needed
(unlike pyzbar, which requires libzbar to be installed).

100% normal code -- pure image processing, no AI.
"""

import io
import numpy as np
import cv2
from PIL import Image


def decode_qr_from_bytes(image_bytes: bytes) -> list:
    """
    Given raw image bytes, returns a list of decoded string payloads
    (usually URLs) found in any QR codes in the image. Empty list if none found.
    """
    try:
        pil_img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
    except Exception:
        return []

    cv_img = cv2.cvtColor(np.array(pil_img), cv2.COLOR_RGB2BGR)

    detector = cv2.QRCodeDetector()
    try:
        retval, decoded_info, points, _ = detector.detectAndDecodeMulti(cv_img)
    except Exception:
        return []

    if not retval:
        return []

    return [text for text in decoded_info if text]


def scan_email_images(images: list) -> list:
    """
    images: list of (filename, bytes) tuples, as produced by email_parser.
    Returns list of dicts: {"filename": ..., "decoded_payloads": [...]}
    only for images where a QR code was actually found.
    """
    results = []
    for filename, img_bytes in images:
        if not img_bytes:
            continue
        payloads = decode_qr_from_bytes(img_bytes)
        if payloads:
            results.append({"filename": filename, "decoded_payloads": payloads})
    return results