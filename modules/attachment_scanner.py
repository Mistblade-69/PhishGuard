"""
attachment_scanner.py
Deterministic risk scoring for email attachments based on file extensions,
double extensions, macro-enabled Office formats, and magic-byte / extension
mismatches. This is NOT malware detonation/sandboxing -- it's fast pattern-based
triage, same first-pass approach real email security gateways use.

100% normal code -- no AI.
"""

import re

try:
    import magic  # python-magic; needs libmagic installed on the system
    HAS_MAGIC = True
except Exception:
    HAS_MAGIC = False

EXECUTABLE_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse",
    "ws", "wsf", "msi", "msc", "ps1", "jar", "reg", "hta"
}

MACRO_ENABLED_EXTENSIONS = {"docm", "xlsm", "pptm", "dotm", "xltm", "potm"}

ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "tar", "gz", "iso"}


def _get_extension(filename: str) -> str:
    if "." not in filename:
        return ""
    return filename.rsplit(".", 1)[-1].lower()


def _has_double_extension(filename: str) -> bool:
    parts = filename.split(".")
    if len(parts) < 3:
        return False
    # e.g. invoice.pdf.exe -> second-to-last part looks like a normal doc extension
    suspicious_first_ext = parts[-2].lower()
    return suspicious_first_ext in {"pdf", "doc", "docx", "xls", "xlsx", "jpg", "png", "txt", "ppt", "pptx"}


def check_attachment(filename: str, file_bytes: bytes, declared_content_type: str = "") -> dict:
    ext = _get_extension(filename)
    flags = []

    if _has_double_extension(filename):
        flags.append(f"double extension detected ('{filename}') -- classic disguise technique")

    if ext in EXECUTABLE_EXTENSIONS:
        flags.append(f"executable/script file type (.{ext})")

    if ext in MACRO_ENABLED_EXTENSIONS:
        flags.append(f"macro-enabled Office file (.{ext}) -- verify sender before enabling macros")

    if ext in ARCHIVE_EXTENSIONS:
        flags.append(f"archive file (.{ext}) -- contents cannot be inspected without extraction")

    # Magic-byte check: does the real file type match what the extension claims?
    if HAS_MAGIC and file_bytes:
        try:
            detected_type = magic.from_buffer(file_bytes, mime=True)
            if _mismatch(detected_type, ext):
                flags.append(f"file signature ({detected_type}) does not match extension (.{ext}) -- possible disguise")
        except Exception:
            pass

    risk = "high" if any("executable" in f or "double extension" in f or "does not match" in f for f in flags) \
        else "medium" if flags else "low"

    return {
        "filename": filename,
        "extension": ext,
        "declared_content_type": declared_content_type,
        "flags": flags,
        "risk": risk,
    }


def _mismatch(detected_mime: str, claimed_ext: str) -> bool:
    """Very small sanity map -- flags only clear, high-confidence mismatches."""
    expectations = {
        "pdf": "application/pdf",
        "docx": "application/vnd.openxmlformats",
        "xlsx": "application/vnd.openxmlformats",
        "png": "image/png",
        "jpg": "image/jpeg",
        "jpeg": "image/jpeg",
        "gif": "image/gif",
        "txt": "text/plain",
    }
    expected_prefix = expectations.get(claimed_ext)
    if not expected_prefix:
        return False
    return not detected_mime.startswith(expected_prefix.split(";")[0].split("application/vnd")[0]) and expected_prefix not in detected_mime


def scan_attachments(attachments: list) -> list:
    """attachments: list of (filename, bytes, content_type) from email_parser."""
    return [check_attachment(fn, data, ct) for fn, data, ct in attachments]