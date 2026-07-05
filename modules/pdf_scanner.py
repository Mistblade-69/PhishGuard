"""
pdf_scanner.py
Extracts evidence from PDF attachments for phishing/malware triage:
- visible text (for LLM reasoning + URL extraction)
- clickable link annotations (often invisible in the rendered text --
  a classic trick: display text says "DocuSign" but the actual link
  annotation points somewhere else entirely)
- risk flags: embedded JavaScript, embedded files, encryption
- a rendered image of the first page, so the vision-capable LLM can also
  judge visual mimicry (fake DocuSign/invoice branding, etc.)

100% normal code -- no AI. Uses PyMuPDF (fitz), which is pure Python and
needs no external system binary (unlike poppler-based tools).
"""

import re
import fitz  # PyMuPDF

URL_REGEX = re.compile(r"https?://[^\s\"'<>\)]+")


def _open(pdf_bytes: bytes):
    return fitz.open(stream=pdf_bytes, filetype="pdf")


def extract_text(pdf_bytes: bytes) -> str:
    """Visible text across all pages (capped to avoid huge LLM payloads)."""
    try:
        doc = _open(pdf_bytes)
        text_parts = [page.get_text() for page in doc]
        doc.close()
        return "\n".join(text_parts)[:8000]
    except Exception as e:
        return f"[PDF text extraction failed: {e}]"


def extract_link_annotations(pdf_bytes: bytes) -> list:
    """
    Pulls clickable link URIs directly from the PDF's link annotations --
    NOT the same as URLs visible in the text. A malicious PDF can show the
    text "Click here to verify" while the actual link annotation points to
    a completely different phishing domain. This catches that mismatch.
    """
    links = []
    try:
        doc = _open(pdf_bytes)
        for page_num, page in enumerate(doc):
            for link in page.get_links():
                uri = link.get("uri")
                if uri:
                    links.append({"page": page_num + 1, "uri": uri})
        doc.close()
    except Exception:
        pass
    return links


def extract_urls_from_text(text: str) -> list:
    return list(dict.fromkeys(URL_REGEX.findall(text)))


def check_pdf_risk_flags(pdf_bytes: bytes) -> dict:
    """
    Structural risk flags: embedded JavaScript (a common malicious-PDF
    vector), embedded files (can smuggle an executable inside a PDF),
    and encryption (sometimes used to evade automated scanners).
    """
    flags = []
    info = {"page_count": 0, "encrypted": False, "has_javascript": False, "embedded_file_count": 0}

    try:
        doc = _open(pdf_bytes)
        info["page_count"] = doc.page_count
        info["encrypted"] = doc.is_encrypted

        try:
            js_count = 0
            for xref in range(1, doc.xref_length()):
                obj = doc.xref_object(xref, compressed=False)
                if obj and ("/JS" in obj or "/JavaScript" in obj):
                    js_count += 1
            info["has_javascript"] = js_count > 0
        except Exception:
            pass

        try:
            info["embedded_file_count"] = doc.embfile_count()
        except Exception:
            pass

        doc.close()
    except Exception as e:
        flags.append(f"could not fully inspect PDF structure: {e}")

    if info["has_javascript"]:
        flags.append("PDF contains embedded JavaScript -- can execute code when opened, high risk")
    if info["embedded_file_count"] > 0:
        flags.append(f"PDF has {info['embedded_file_count']} embedded file(s) -- can smuggle executables")
    if info["encrypted"]:
        flags.append("PDF is encrypted/password-protected -- can be used to evade automated scanners")

    info["flags"] = flags
    info["risk"] = "high" if info["has_javascript"] or info["embedded_file_count"] > 0 else \
        "medium" if info["encrypted"] else "low"
    return info


def render_first_page_image(pdf_bytes: bytes, zoom: float = 2.0) -> bytes:
    """
    Renders page 1 as a PNG so the vision-capable LLM can judge visual
    mimicry (fake letterhead, spoofed e-signature branding, etc.), the same
    way it inspects an uploaded screenshot.
    """
    doc = _open(pdf_bytes)
    page = doc[0]
    mat = fitz.Matrix(zoom, zoom)
    pix = page.get_pixmap(matrix=mat)
    png_bytes = pix.tobytes("png")
    doc.close()
    return png_bytes