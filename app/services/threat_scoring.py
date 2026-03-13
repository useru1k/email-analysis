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
    details: Dict[str, Any] = {"score_breakdown": {}}

    # authentication
    auth_points = 0
    if auth_details:
        spf = auth_details.get("spf")
        if spf in ("fail", "missing"):
            auth_points += 20
        elif spf == "softfail":
            auth_points += 10
        dkim = auth_details.get("dkim")
        if dkim in ("fail", "missing"):
            auth_points += 20
        dmarc = auth_details.get("dmarc")
        if dmarc in ("fail", "missing"):
            auth_points += 20
        details.update(auth_details)
    if auth_points > 0:
        score += auth_points
        details["score_breakdown"]["auth"] = auth_points

    # blacklists
    if blacklist_hits:
        score += 30
        details["score_breakdown"]["blacklists"] = 30
        details["blacklist_hits"] = blacklist_hits

    # attachments
    risky_attachments = [a for a in attachments if a.get("risky")]
    if risky_attachments:
        score += 25
        details["score_breakdown"]["attachments"] = 25
        details["risky_attachments"] = [a.get("filename") for a in risky_attachments]

    # attachments flagged by VirusTotal
    vt_malicious: list[str] = []
    for a in attachments:
        vt = a.get("vt")
        if vt and isinstance(vt, dict):
            stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            # count any positive or suspicious hits as a red flag
            if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
                vt_malicious.append(a.get("filename"))
    if vt_malicious:
        # significant penalty for attachments that VT has detected
        score += 30
        details["score_breakdown"]["vt"] = 30
        details["vt_attachments"] = vt_malicious

    # links
    if links_risky_count > 0:
        link_points = min(25, links_risky_count * 8)
        score += link_points
        details["score_breakdown"]["links"] = link_points
        details["risky_links"] = links_risky_count

    score = min(100, score)
    return score, details
