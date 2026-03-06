"""Simple local cache for VirusTotal file hash lookups.

This module provides a JSON-backed store mapping SHA256 hashes to the
responses previously returned by VirusTotal.  The cache path is configured
via ``Settings.hash_cache_path`` so the caller (usually
``attachment_analysis.virustotal_file_check``) can consult and update it.

A lock is used to avoid races when multiple threads/processes may write at the
same time; the cache is loaded on first access and updated in-memory before
being flushed to disk on each write.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from threading import Lock
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)

_lock = Lock()
_cache: Dict[str, Any] = {}
_cache_loaded = False


def _load_cache(path: str) -> None:
    global _cache, _cache_loaded
    if _cache_loaded:
        return
    try:
        p = Path(path)
        if p.exists():
            with p.open("r", encoding="utf-8") as f:
                _cache = json.load(f)
        else:
            _cache = {}
    except Exception as exc:  # pragma: no cover - safety
        logger.warning("Failed to load cache from %s: %s", path, exc)
        _cache = {}
    _cache_loaded = True


def _save_cache(path: str) -> None:
    try:
        p = Path(path)
        # ensure parent directory exists
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("w", encoding="utf-8") as f:
            json.dump(_cache, f)
    except Exception as exc:  # pragma: no cover - safety
        logger.warning("Failed to write cache to %s: %s", path, exc)


def get_cached_hash(sha256: str, path: str) -> Optional[Dict[str, Any]]:
    """Return cached data for *sha256* if present, otherwise ``None``."""
    with _lock:
        _load_cache(path)
        return _cache.get(sha256)


def set_cached_hash(sha256: str, data: Dict[str, Any], path: str) -> None:
    """Store *data* for *sha256* into the cache file located at *path*."""
    with _lock:
        _load_cache(path)
        _cache[sha256] = data
        _save_cache(path)
