"""Email parsing utilities.

These functions understand RFC822 messages and extract the pieces we care
about. They are intentionally synchronous since the Python email library is
blocking; network interactions are handled in other service modules.
"""
from __future__ import annotations

import re
import email
from email import policy
from email.parser import BytesParser, Parser
from typing import List, Dict


URL_REGEX = re.compile(r"https?://[^\s'\"<>]+")


def parse_email(raw: str | bytes) -> email.message.EmailMessage:
    """Parse raw EML text/bytes into an EmailMessage object."""
    if isinstance(raw, bytes):
        return BytesParser(policy=policy.default).parsebytes(raw)
    return Parser(policy=policy.default).parsestr(raw)


def extract_basic_headers(msg: email.message.EmailMessage) -> Dict[str, str]:
    return {
        "From": msg.get("From", ""),
        "To": msg.get("To", ""),
        "Subject": msg.get("Subject", ""),
        "Date": msg.get("Date", ""),
        "Authentication-Results": msg.get("Authentication-Results", ""),
    }


import ipaddress


def extract_received_ips(msg: email.message.EmailMessage) -> List[str]:
    """Return a list of unique valid IPs extracted from Received headers.

    The function uses the standard library ``ipaddress`` module to validate
    candidates, avoiding false positives (like single letters) and normalizing
    IPv6 addresses. Order is preserved and duplicates are removed.
    """
    received = msg.get_all("Received", []) or []
    ips: List[str] = []
    seen: set[str] = set()

    # look for any run of hex digits, dots or colons; we'll validate later
    token_re = re.compile(r"[0-9A-Fa-f:\.]+")

    for header in received:
        for cand in token_re.findall(header):
            try:
                ip_obj = ipaddress.ip_address(cand)
            except ValueError:
                continue
            ip_str = str(ip_obj)
            if ip_str not in seen:
                seen.add(ip_str)
                ips.append(ip_str)
    return ips


def extract_links_from_body(msg: email.message.EmailMessage) -> List[str]:
    """Collect http/https links from text/plain or text/html parts."""
    body_texts: List[str] = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype in ("text/plain", "text/html"):
                try:
                    body_texts.append(part.get_content())
                except Exception:
                    continue
    else:
        try:
            body_texts.append(msg.get_content())
        except Exception:
            pass
    text = "\n".join(t for t in body_texts if t)
    return URL_REGEX.findall(text)


from ..services.attachment_analysis import compute_sha256, flag_attachment_risky


def extract_attachments(msg: email.message.EmailMessage) -> List[Dict]:
    """Return metadata about attachments in the message.  

    Adds SHA-256 and a risk flag so callers don't need to do second passes.
    A ``vt`` key is included for later VirusTotal lookup results.
    """
    attachments: List[Dict] = []
    for part in msg.walk():
        disp = part.get("Content-Disposition", "")
        if disp and part.get_filename():
            fname = part.get_filename()
            payload = part.get_payload(decode=True) or b""
            ext = (fname and fname.rpartition(".")[2].lower()) or ""
            attachments.append({
                "filename": fname,
                "content_type": part.get_content_type(),
                "size": len(payload),
                "extension": ext,
                "sha256": compute_sha256(payload),
                "risky": flag_attachment_risky(ext, part.get_content_type()),
                # placeholder for VirusTotal result
                "vt": None,
            })
    return attachments

def check_header_issues(msg: email.message.EmailMessage) -> List[str]:
    """Apply simple heuristics for suspicious or missing headers.

    This returns a list of human-readable warning strings which may be displayed
    to the analyst. The heuristics are intentionally basic; more can be added
    later.
    """
    issues: List[str] = []

    # missing DKIM signature may indicate unauthenticated mail
    if not msg.get("DKIM-Signature"):
        issues.append("No DKIM-Signature header present")

    # missing Message-ID makes tracking/correlation harder and is often used in spam
    if not msg.get("Message-ID"):
        issues.append("No Message-ID header present")

    # common anti-spoofing: From domain vs Return-Path domain mismatch
    from_hdr = msg.get("From", "")
    return_path = msg.get("Return-Path", "")
    reply_to = msg.get("Reply-To", "")

    def _parse_addr(hdr: str) -> str:
        try:
            import email.utils
            _, addr = email.utils.parseaddr(hdr)
            return addr or ""
        except Exception:
            return ""

    from_addr = _parse_addr(from_hdr)
    return_addr = _parse_addr(return_path)
    reply_to_addr = _parse_addr(reply_to)

    def _domain(addr: str) -> str:
        parts = addr.split("@")
        return parts[-1].lower() if len(parts) == 2 else ""

    if from_addr and return_addr and _domain(from_addr) != _domain(return_addr):
        issues.append("From domain differs from Return-Path domain")

    if from_addr and reply_to_addr:
        if from_addr.lower() != reply_to_addr.lower():
            issues.append("Reply-To differs from From")
        if _domain(from_addr) and _domain(reply_to_addr) and _domain(from_addr) != _domain(reply_to_addr):
            issues.append("Reply-To domain differs from From domain")

    return issues
