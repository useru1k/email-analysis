"""Compute an overall threat score from individual analysis results."""
from __future__ import annotations

from typing import Any, Dict, List


def compute_threat_score(
    auth_details: Dict[str, Any],
    blacklist_hits: List[str],
    attachments: List[Dict[str, Any]],
    links_risky_count: int,
    headers: Dict[str, Any] | None = None,
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

    # Reply-To vs From check
    reply_points = 0
    try:
        if headers:
            from_hdr = headers.get("From", "")
            reply_hdr = headers.get("Reply-To", "")
            if from_hdr and reply_hdr:
                import email.utils

                from_addr = email.utils.parseaddr(from_hdr)[1].lower()
                reply_to_addr = email.utils.parseaddr(reply_hdr)[1].lower()

                def _domain(addr: str) -> str:
                    parts = addr.split("@")
                    return parts[-1].lower() if len(parts) == 2 else ""

                if from_addr and reply_to_addr and from_addr != reply_to_addr:
                    # heavier penalty if reply-to routes to a different domain
                    if _domain(from_addr) and _domain(reply_to_addr) and _domain(from_addr) != _domain(reply_to_addr):
                        reply_points = 20
                    else:
                        reply_points = 10
                    score += reply_points
                    details["score_breakdown"]["reply_to_mismatch"] = reply_points
                    details["reply_to_mismatch"] = {"from": from_addr, "reply_to": reply_to_addr}
    except Exception:
        # defensive: scoring should not crash on odd headers
        pass

    score = min(100, score)
    return score, details
