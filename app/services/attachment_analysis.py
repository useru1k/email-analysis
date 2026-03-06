"""Attachment scanning utilities."""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx

from .cache import get_cached_hash, set_cached_hash

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
    """Query VirusTotal for a file report by SHA256 hash, using a local cache.

    If a cache file is configured (`settings.hash_cache_path`) the cache is
    consulted first.  A cached record is returned immediately and the network
    is not contacted.  On a cache miss the function performs the HTTP request
    and stores any successful response in the cache for future lookups.

    Returns the parsed JSON response or ``None`` on failure or when no API key is
    supplied.  Callers should only invoke this when an API key is available.
    """
    if not getattr(settings, "virustotal_api_key", None):
        return None

    cache_path = getattr(settings, "hash_cache_path", "hash_cache.json")
    cached = get_cached_hash(sha256, cache_path)
    if cached is not None:
        logger.debug("Cache hit for %s", sha256)
        return cached

    headers = {"x-apikey": settings.virustotal_api_key}
    url = f"https://www.virustotal.com/api/v3/files/{sha256}"
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                # store successful response
                set_cached_hash(sha256, data, cache_path)
                return data
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
