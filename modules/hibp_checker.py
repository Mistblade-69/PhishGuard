"""
hibp_checker.py
Have I Been Pwned integration:

1. check_password() -- FREE, no API key needed. Uses the Pwned Passwords
   k-anonymity API: only the first 5 characters of the password's SHA-1 hash
   are sent to HIBP, never the actual password or full hash. This is the
   same privacy-preserving technique browsers/password managers use.

2. check_email_breaches() -- requires a paid HIBP API key (breach-by-email
   lookups stopped being free a while back, ~$3.50/month via haveibeenpwned.com/API/Key).
   Included for completeness; the tool clearly reports when no key is set
   rather than failing silently.

100% normal code -- no AI. Pure API calls + hashing.
"""

import hashlib
import os
import requests

HIBP_API_KEY = os.environ.get("HIBP_API_KEY")  # optional, paid key for email breach lookups

PWNED_PASSWORDS_URL = "https://api.pwnedpasswords.com/range/{prefix}"
HIBP_BREACH_URL = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"


def check_password(password: str) -> dict:
    """
    Checks a password against the Pwned Passwords database using k-anonymity.
    Only a 5-character hash prefix is ever sent -- the real password stays local.
    """
    if not password:
        return {"error": "no password provided"}

    sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]

    try:
        resp = requests.get(PWNED_PASSWORDS_URL.format(prefix=prefix), timeout=10)
    except requests.RequestException as e:
        return {"error": f"request failed: {e}"}

    if resp.status_code != 200:
        return {"error": f"unexpected status code {resp.status_code}"}

    # Response is a list of "SUFFIX:COUNT" lines for all hashes sharing this prefix
    for line in resp.text.splitlines():
        line_suffix, count = line.split(":")
        if line_suffix == suffix:
            return {"pwned": True, "times_seen": int(count)}

    return {"pwned": False, "times_seen": 0}


def check_email_breaches(email: str) -> dict:
    """
    Checks if an email address has appeared in known data breaches.
    Requires HIBP_API_KEY (paid) set in your environment/.env.
    """
    if not HIBP_API_KEY:
        return {
            "available": False,
            "note": "No HIBP_API_KEY set -- this endpoint requires a paid HIBP key "
                    "(~$3.50/month at haveibeenpwned.com/API/Key). Skipping.",
        }

    try:
        resp = requests.get(
            HIBP_BREACH_URL.format(account=email),
            headers={"hibp-api-key": HIBP_API_KEY, "user-agent": "phishing-detector-training-project"},
            params={"truncateResponse": "false"},
            timeout=10,
        )
    except requests.RequestException as e:
        return {"available": False, "note": f"request failed: {e}"}

    if resp.status_code == 404:
        return {"available": True, "breached": False, "breaches": []}

    if resp.status_code == 429:
        return {"available": False, "note": "rate limited -- wait a moment and try again"}

    if resp.status_code != 200:
        return {"available": False, "note": f"unexpected status code {resp.status_code}"}

    breaches = resp.json()
    return {
        "available": True,
        "breached": True,
        "breach_count": len(breaches),
        "breaches": [
            {
                "name": b.get("Name"),
                "date": b.get("BreachDate"),
                "data_classes": b.get("DataClasses", []),
            }
            for b in breaches
        ],
    }