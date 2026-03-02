"""Attachment scanning utilities."""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from typing import Dict

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


def flag_attachment_risky(ext: str, content_type: str) -> bool:
    exec_ext = {".exe", ".scr", ".bat", ".cmd", ".msi", ".vbs", ".js", ".ps1"}
    doc_like = {".doc", ".docx", ".xls", ".xlsx", ".rtf", ".pdf"}
    if ext in exec_ext:
        return True
    if ext in doc_like and content_type in ("application/x-msdownload",):
        return True
    return False
