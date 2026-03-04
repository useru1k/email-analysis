"""Attachment scanning utilities."""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger(__name__)


@dataclass
class AttachmentRisk:
    filename: str
    content_type: str
    extension: str
    size: int
    sha256: str
    risky: bool


def compute_sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


async def virustotal_file_check(sha256: str, settings: Any) -> Optional[Dict[str, Any]]:
    """Query VirusTotal for a file report by SHA256 hash.

    Returns the parsed JSON response or ``None`` on failure.  The caller should
    only invoke this when an API key is available (``settings.virustotal_api_key``).
    """
    if not getattr(settings, "virustotal_api_key", None):
        return None
    headers = {"x-apikey": settings.virustotal_api_key}
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                return resp.json()
            logger.debug("VirusTotal file check returned %s for %s", resp.status_code, sha256)
    except Exception as exc:
        logger.debug("VirusTotal file check exception for %s: %s", sha256, exc)
    return None


def flag_attachment_risky(ext: str, content_type: str) -> bool:
    """Simple heuristics indicating potentially dangerous attachments.

    ``ext`` may be provided with or without a leading dot.  Normalize to avoid
    mistakes between the two forms.
    """
    ext = ext.lower().lstrip(".")
    exec_ext = {"exe", "scr", "bat", "cmd", "msi", "vbs", "js", "ps1"}
    doc_like = {"doc", "docx", "xls", "xlsx", "rtf", "pdf"}
    if ext in exec_ext:
        return True
    if ext in doc_like and content_type in ("application/x-msdownload",):
        return True
    return False
