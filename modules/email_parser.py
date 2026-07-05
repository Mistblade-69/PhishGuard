"""
email_parser.py
Parses raw .eml files into a structured dict: headers, body text, URLs,
inline/attached images, and file attachments.

100% deterministic code -- no AI involved here.
"""

import re
from email import policy
from email.parser import BytesParser
from dataclasses import dataclass, field


URL_REGEX = re.compile(r"https?://[^\s\"'<>\)]+")


@dataclass
class ParsedEmail:
    subject: str = ""
    sender: str = ""
    sender_domain: str = ""
    reply_to: str = ""
    date: str = ""
    body_text: str = ""
    urls: list = field(default_factory=list)
    images: list = field(default_factory=list)          # list of (filename, bytes)
    attachments: list = field(default_factory=list)     # list of (filename, bytes, content_type)
    auth_headers: dict = field(default_factory=dict)    # raw SPF/DKIM/DMARC header strings


def _extract_domain(from_header: str) -> str:
    match = re.search(r"@([\w\.-]+)", from_header or "")
    return match.group(1).lower() if match else ""


def parse_eml_file(path: str) -> ParsedEmail:
    with open(path, "rb") as f:
        msg = BytesParser(policy=policy.default).parse(f)
    return _parse_message(msg)


def parse_eml_bytes(raw_bytes: bytes) -> ParsedEmail:
    msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
    return _parse_message(msg)


def _parse_message(msg) -> ParsedEmail:
    parsed = ParsedEmail()

    parsed.subject = msg.get("Subject", "")
    parsed.sender = msg.get("From", "")
    parsed.sender_domain = _extract_domain(parsed.sender)
    parsed.reply_to = msg.get("Reply-To", "")
    parsed.date = msg.get("Date", "")

    # Common auth-related headers (may or may not be present depending on mail server)
    for header in ("Received-SPF", "Authentication-Results", "DKIM-Signature"):
        value = msg.get(header)
        if value:
            parsed.auth_headers[header] = value

    body_parts = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = part.get_content_disposition()
            filename = part.get_filename()

            if content_type in ("text/plain", "text/html") and content_disposition != "attachment":
                try:
                    body_parts.append(part.get_content())
                except Exception:
                    pass

            elif filename and content_type.startswith("image/"):
                try:
                    parsed.images.append((filename, part.get_payload(decode=True)))
                except Exception:
                    pass

            elif content_disposition == "attachment" or (filename and not content_type.startswith("text/")):
                try:
                    parsed.attachments.append((filename or "unnamed", part.get_payload(decode=True), content_type))
                except Exception:
                    pass
    else:
        try:
            body_parts.append(msg.get_content())
        except Exception:
            pass

    parsed.body_text = "\n".join(body_parts)
    parsed.urls = list(dict.fromkeys(URL_REGEX.findall(parsed.body_text)))  # dedupe, preserve order

    return parsed