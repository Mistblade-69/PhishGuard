"""
url_analyzer.py
Analyzes URLs for typosquatting, suspicious patterns, and known-brand domain
mismatches. All deterministic string/pattern matching -- no AI.
"""

import re
import tldextract
from rapidfuzz.distance import Levenshtein

# Use tldextract's bundled snapshot instead of fetching the live public suffix
# list over the network -- keeps this tool working offline / in sandboxed envs
# and avoids noisy warnings when network access is restricted.
tldextract.extract = tldextract.TLDExtract(suffix_list_urls=()).__call__

# A small reference list of commonly-impersonated brands and their real domains.
# Extend this list freely -- it's just data.
KNOWN_BRANDS = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "office365": "office.com",
    "google": "google.com",
    "amazon": "amazon.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "chase": "chase.com",
    "bankofamerica": "bankofamerica.com",
    "wellsfargo": "wellsfargo.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "linkedin": "linkedin.com",
    "dropbox": "dropbox.com",
    "adobe": "adobe.com",
    "irs": "irs.gov",
    "usps": "usps.com",
    "docusign": "docusign.com",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"
}

SUSPICIOUS_TLDS = {"zip", "top", "xyz", "click", "gq", "tk", "ml", "cf", "work", "loan"}


def _registered_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}".lower()


def _domain_tokens(domain: str) -> list:
    """
    Splits a domain into meaningful segments to compare against brand names,
    e.g. 'paypa1-alerts.com' -> ['paypa1', 'alerts'] so we catch the
    brand-like token even when it's combined with extra words.
    """
    ext = tldextract.extract(domain)
    main = ext.domain.lower()
    tokens = re.split(r"[-_.]", main)
    tokens = [t for t in tokens if t]
    return tokens or [main]


def check_typosquat(domain: str, brand_domains: dict = KNOWN_BRANDS) -> dict:
    """
    Compares a domain (and its individual hyphen/dot-separated segments)
    against known brand domains using edit distance. Checking segments
    catches cases like 'paypa1-alerts.com', where the full domain differs a
    lot from 'paypal.com' but the first segment 'paypa1' is a near-exact
    typosquat of 'paypal'.
    """
    domain = domain.lower().strip()
    ext = tldextract.extract(domain)
    tokens = _domain_tokens(domain)

    best_match = None
    best_distance = None
    best_token = None

    for brand, real_domain in brand_domains.items():
        if domain == real_domain:
            return {"is_typosquat": False, "matched_brand": brand, "distance": 0, "note": "exact legitimate match"}

        brand_core = tldextract.extract(real_domain).domain  # e.g. "paypal"

        # Compare against each token in the domain (catches 'paypa1' inside 'paypa1-alerts.com')
        for token in tokens:
            distance = Levenshtein.distance(token, brand_core)
            if best_distance is None or distance < best_distance:
                best_distance = distance
                best_match = brand
                best_token = token

        # Also compare the full registered domain, in case it's a simple whole-domain typo
        full_distance = Levenshtein.distance(f"{ext.domain}.{ext.suffix}", real_domain)
        if full_distance < best_distance:
            best_distance = full_distance
            best_match = brand
            best_token = f"{ext.domain}.{ext.suffix}"

    if best_match is None:
        return {"is_typosquat": False, "matched_brand": None, "distance": None, "note": "no brand reference matched"}

    # Distance <= 1 on a short brand-name token is a strong typosquat signal
    # (short strings need a tighter threshold than full domains to avoid false positives).
    is_typosquat = best_distance is not None and 0 < best_distance <= 1
    return {
        "is_typosquat": is_typosquat,
        "matched_brand": best_match,
        "distance": best_distance,
        "matched_token": best_token,
        "note": f"segment '{best_token}' is close to brand '{best_match}' (edit distance {best_distance})" if is_typosquat else "no close brand match",
    }


def analyze_url(url: str) -> dict:
    """Full analysis of a single URL: domain, typosquat check, shortener/suspicious-TLD flags."""
    domain = _registered_domain(url)
    ext = tldextract.extract(url)

    typosquat_result = check_typosquat(domain)

    flags = []
    if domain in URL_SHORTENERS:
        flags.append("URL shortener -- destination is hidden")
    if ext.suffix in SUSPICIOUS_TLDS:
        flags.append(f"suspicious top-level domain (.{ext.suffix})")
    if typosquat_result["is_typosquat"]:
        flags.append(f"possible typosquat of {typosquat_result['matched_brand']}")
    if re.search(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", url):
        flags.append("uses raw IP address instead of domain name")
    if url.count("@") > 0:
        flags.append("contains '@' -- may be used to obscure real destination")

    return {
        "url": url,
        "domain": domain,
        "typosquat": typosquat_result,
        "flags": flags,
        "risk": "high" if flags else "low",
    }


def analyze_urls(urls: list) -> list:
    return [analyze_url(u) for u in urls]


def check_brand_impersonation(body_text: str, sender_domain: str) -> dict:
    """
    Checks if the email body mentions a known brand by name while the sender
    domain doesn't match (or is a typosquat of) that brand's real domain.
    """
    body_lower = body_text.lower()
    mentioned_brands = [b for b in KNOWN_BRANDS if b in body_lower]

    if not mentioned_brands:
        return {"impersonation_detected": False, "details": "no known brand mentioned in body"}

    findings = []
    for brand in mentioned_brands:
        real_domain = KNOWN_BRANDS[brand]
        if sender_domain == real_domain:
            continue  # legitimate match, skip

        typosquat_result = check_typosquat(sender_domain, {brand: real_domain})
        # Mentioning a brand by name while sending from *any* domain that isn't
        # that brand's real domain is already suspicious; a close typosquat match
        # makes it near-certain.
        findings.append({
            "brand": brand,
            "real_domain": real_domain,
            "sender_domain": sender_domain,
            "typosquat_check": typosquat_result,
            "likely_impersonation": True,  # brand named in body + domain mismatch, always worth flagging
            "high_confidence": typosquat_result["is_typosquat"],
        })

    impersonation_detected = any(f["likely_impersonation"] for f in findings)
    return {"impersonation_detected": impersonation_detected, "details": findings}