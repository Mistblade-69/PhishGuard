"""
feedback.py
Simple feedback loop: lets a user mark a verdict as wrong, logs it to a JSON
file, and provides basic aggregation stats. No AI here -- just logging and
counting. Demonstrates the *mechanism* you'd use to later improve the prompt
or fine-tune a classifier; no actual retraining happens in this project.
"""

import json
import os
from datetime import datetime, timezone

LOG_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "logs", "feedback_log.json")


def _load_log() -> list:
    if not os.path.exists(LOG_PATH):
        return []
    with open(LOG_PATH, "r") as f:
        try:
            return json.load(f)
        except json.JSONDecodeError:
            return []


def _save_log(entries: list):
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    with open(LOG_PATH, "w") as f:
        json.dump(entries, f, indent=2)


def log_correction(email_subject: str, predicted_verdict: str, actual_verdict: str, notes: str = ""):
    entries = _load_log()
    entries.append({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "email_subject": email_subject,
        "predicted_verdict": predicted_verdict,
        "actual_verdict": actual_verdict,
        "notes": notes,
    })
    _save_log(entries)


def get_stats() -> dict:
    entries = _load_log()
    if not entries:
        return {"total_corrections": 0, "by_predicted_verdict": {}}

    by_predicted = {}
    for e in entries:
        key = e["predicted_verdict"]
        by_predicted[key] = by_predicted.get(key, 0) + 1

    return {
        "total_corrections": len(entries),
        "by_predicted_verdict": by_predicted,
        "most_recent": entries[-5:],
    }