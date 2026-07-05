"""
header_check.py
Deterministic parsing of SPF / DKIM / DMARC results from email headers.

Real mail servers stamp an 'Authentication-Results' header with these results
already computed -- we are just reading and structuring that, not re-verifying
cryptographic signatures ourselves. That's normal for a triage tool.

100% normal code -- no AI.
"""

import re


def analyze_auth_headers(auth_headers: dict) -> dict:
    """
    Returns a structured summary:
    {
        "spf": "pass" | "fail" | "softfail" | "none" | "unknown",
        "dkim": "pass" | "fail" | "none" | "unknown",
        "dmarc": "pass" | "fail" | "none" | "unknown",
        "raw": {...original headers...}
    }
    """
    result = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown", "raw": auth_headers}

    spf_header = auth_headers.get("Received-SPF", "")
    if spf_header:
        result["spf"] = _extract_result(spf_header, default="none")

    auth_results = auth_headers.get("Authentication-Results", "")
    if auth_results:
        spf_match = re.search(r"spf=(\w+)", auth_results, re.IGNORECASE)
        dkim_match = re.search(r"dkim=(\w+)", auth_results, re.IGNORECASE)
        dmarc_match = re.search(r"dmarc=(\w+)", auth_results, re.IGNORECASE)

        if spf_match and result["spf"] == "unknown":
            result["spf"] = spf_match.group(1).lower()
        if dkim_match:
            result["dkim"] = dkim_match.group(1).lower()
        if dmarc_match:
            result["dmarc"] = dmarc_match.group(1).lower()

    if auth_headers.get("DKIM-Signature") and result["dkim"] == "unknown":
        result["dkim"] = "present_unverified"

    return result


def _extract_result(header_value: str, default: str) -> str:
    match = re.match(r"\s*(\w+)", header_value)
    return match.group(1).lower() if match else default


def risk_flags_from_auth(auth_summary: dict) -> list:
    """Turns the auth summary into plain-language risk flags for the report."""
    flags = []
    if auth_summary["spf"] in ("fail", "softfail"):
        flags.append(f"SPF check {auth_summary['spf']} -- sender may be spoofed")
    if auth_summary["dkim"] in ("fail",):
        flags.append("DKIM signature failed -- message may have been altered or forged")
    if auth_summary["dmarc"] in ("fail",):
        flags.append("DMARC check failed -- sending domain policy was not satisfied")
    if auth_summary["spf"] == "none" and auth_summary["dkim"] == "unknown":
        flags.append("No SPF or DKIM data found -- authenticity cannot be verified")
    return flags