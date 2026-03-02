"""Compute an overall threat score from individual analysis results."""
from __future__ import annotations

from typing import Any, Dict, List


def compute_threat_score(
    auth_details: Dict[str, Any],
    blacklist_hits: List[str],
    attachments: List[Dict[str, Any]],
    links_risky_count: int,
) -> tuple[int, Dict[str, Any]]:
    """Calculate a 0-100 score along with a human-readable breakdown."""
    score = 0
    details: Dict[str, Any] = {}

    # authentication
    if auth_details:
        if auth_details.get("spf") == "fail":
            score += 20
        elif auth_details.get("spf") == "softfail":
            score += 10
        if auth_details.get("dkim") == "fail":
            score += 20
        if auth_details.get("dmarc") == "fail":
            score += 20
        details.update(auth_details)
    # blacklists
    if blacklist_hits:
        score += 30
        details["blacklist_hits"] = blacklist_hits
    # attachments
    risky_attachments = [a for a in attachments if a.get("risky")]
    if risky_attachments:
        score += 25
        details["risky_attachments"] = [a.get("filename") for a in risky_attachments]
    # links
    if links_risky_count > 0:
        score += min(25, links_risky_count * 8)
        details["risky_links"] = links_risky_count

    score = min(100, score)
    return score, details
