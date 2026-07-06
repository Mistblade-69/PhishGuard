"""
main.py
CLI entry point that runs the full phishing detection pipeline on a single
.eml file (or a whole folder of them in --batch mode).

Pipeline order:
  1. Parse email                     [normal code]
  2. Check auth headers (SPF/DKIM)   [normal code]
  3. Analyze URLs + typosquats       [normal code]
  4. Check brand impersonation       [normal code]
  5. Decode any QR codes in images   [normal code]
  6. Scan attachments                [normal code]
  7. Feed all evidence to the LLM    [AI-powered]  <-- verdict + explanation
  8. Print report / optionally log a correction
"""

import argparse
import json
import os
import sys

from modules.email_parser import parse_eml_file
from modules.header_check import analyze_auth_headers, risk_flags_from_auth
from modules.url_analyzer import analyze_urls, check_brand_impersonation
from modules.qr_scanner import scan_email_images
from modules.attachment_scanner import scan_attachments
from modules.llm_agent import get_verdict
from modules.feedback import log_correction
from modules.malware_scanner import full_malware_scan
from modules.history import save_analysis

load_dotenv()


def run_pipeline(eml_path: str) -> dict:
    parsed = parse_eml_file(eml_path)

    auth_summary = analyze_auth_headers(parsed.auth_headers)
    auth_flags = risk_flags_from_auth(auth_summary)

    url_analysis = analyze_urls(parsed.urls)
    brand_check = check_brand_impersonation(parsed.body_text, parsed.sender_domain)
    qr_findings = scan_email_images(parsed.images)

    # Also run URL analysis on any URLs decoded from QR codes
    qr_urls = [payload for finding in qr_findings for payload in finding["decoded_payloads"]
               if payload.startswith("http")]
    if qr_urls:
        url_analysis += analyze_urls(qr_urls)

    attachment_scan = scan_attachments(parsed.attachments)

    malware_results = []
    for filename, file_bytes, content_type in parsed.attachments:
        scan_result = full_malware_scan(file_bytes)
        if scan_result["yara_matches"] or scan_result["virustotal"].get("found"):
            malware_results.append({"filename": filename, **scan_result})

    email_summary = {
        "subject": parsed.subject,
        "sender": parsed.sender,
        "sender_domain": parsed.sender_domain,
        "reply_to": parsed.reply_to,
        "body_text": parsed.body_text,
        "auth_summary": auth_summary,
        "auth_flags": auth_flags,
        "url_analysis": url_analysis,
        "brand_check": brand_check,
        "qr_findings": qr_findings,
        "attachment_scan": attachment_scan,
    }

    verdict = get_verdict(email_summary)

    save_analysis(
        source_type="eml",
        identifier=parsed.subject or os.path.basename(eml_path),
        verdict=verdict,
        evidence={
            "auth_flags": auth_flags, "url_analysis": url_analysis,
            "brand_check": brand_check, "qr_findings": qr_findings,
            "attachment_scan": attachment_scan, "malware_scan": malware_results,
        },
        malware_flags=malware_results,
    )

    return {
        "file": os.path.basename(eml_path),
        "subject": parsed.subject,
        "sender": parsed.sender,
        "evidence": {
            "auth_flags": auth_flags,
            "url_analysis": url_analysis,
            "brand_check": brand_check,
            "qr_findings": qr_findings,
            "attachment_scan": attachment_scan,
        },
        "verdict": verdict,
    }


def print_report(result: dict):
    print("=" * 70)
    print(f"FILE:    {result['file']}")
    print(f"SUBJECT: {result['subject']}")
    print(f"FROM:    {result['sender']}")
    print("-" * 70)

    v = result["verdict"]
    verdict_label = v.get("verdict", "unknown").upper()
    print(f"VERDICT:    {verdict_label}   (confidence: {v.get('confidence', 0)}%)")

    techniques = v.get("techniques_detected", [])
    if techniques:
        print(f"TECHNIQUES: {', '.join(techniques)}")

    print("\nREASONING:")
    for point in v.get("reasoning", []):
        print(f"  - {point}")

    ev = result["evidence"]
    if ev["auth_flags"]:
        print("\nAUTH FLAGS:")
        for f in ev["auth_flags"]:
            print(f"  - {f}")

    risky_urls = [u for u in ev["url_analysis"] if u["flags"]]
    if risky_urls:
        print("\nSUSPICIOUS URLS:")
        for u in risky_urls:
            print(f"  - {u['url']}")
            for flag in u["flags"]:
                print(f"      -> {flag}")

    if ev["brand_check"]["impersonation_detected"]:
        print("\nBRAND IMPERSONATION DETECTED:")
        print(f"  {ev['brand_check']['details']}")

    if ev["qr_findings"]:
        print("\nQR CODES FOUND:")
        for finding in ev["qr_findings"]:
            print(f"  - {finding['filename']}: {finding['decoded_payloads']}")

    risky_attachments = [a for a in ev["attachment_scan"] if a["flags"]]
    if risky_attachments:
        print("\nRISKY ATTACHMENTS:")
        for a in risky_attachments:
            print(f"  - {a['filename']} (risk: {a['risk']})")
            for flag in a["flags"]:
                print(f"      -> {flag}")

    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(description="AI-powered phishing email triage tool")
    parser.add_argument("path", help="Path to a .eml file, or a folder if --batch is set")
    parser.add_argument("--batch", action="store_true", help="Treat path as a folder of .eml files")
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of formatted report")
    parser.add_argument("--correct", metavar="ACTUAL_VERDICT", choices=["phishing", "suspicious", "legitimate"],
                         help="Log a correction if the verdict was wrong (single-file mode only)")
    args = parser.parse_args()

    if not os.environ.get("GEMINI_API_KEY"):
        print("ERROR: GEMINI_API_KEY not set. Copy .env.example to .env and add your key.", file=sys.stderr)
        sys.exit(1)

    if args.batch:
        results = []
        files = sorted(f for f in os.listdir(args.path) if f.endswith(".eml"))
        for fname in files:
            result = run_pipeline(os.path.join(args.path, fname))
            results.append(result)
            if args.json:
                print(json.dumps(result, indent=2))
            else:
                print_report(result)
        if not args.json:
            print(f"\nProcessed {len(results)} emails.")
    else:
        result = run_pipeline(args.path)
        if args.json:
            print(json.dumps(result, indent=2))
        else:
            print_report(result)

        if args.correct:
            log_correction(
                email_subject=result["subject"],
                predicted_verdict=result["verdict"].get("verdict", "unknown"),
                actual_verdict=args.correct,
            )
            print(f"\nLogged correction: predicted='{result['verdict'].get('verdict')}' actual='{args.correct}'")


if __name__ == "__main__":
    main()
