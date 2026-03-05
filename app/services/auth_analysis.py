"""Authentication-related header parsing (SPF/DKIM/DMARC)."""
from __future__ import annotations

import logging
from typing import Dict
import email.utils
import dns.resolver

logger = logging.getLogger(__name__)


def parse_auth_results(msg: email.message.EmailMessage) -> Dict[str, str]:
    """Parse the Authentication-Results header and return a simple dict.

    If Authentication-Results is missing or incomplete, perform DNS lookups
    for SPF and DMARC records using built-in dns.resolver.

    Keys returned are ``spf``, ``dkim`` and ``dmarc`` when present.
    """
    details: Dict[str, str] = {}
    auth_results = msg.get("Authentication-Results", "").lower()
    
    # Parse from header if present
    if "spf=" in auth_results:
        if "spf=pass" in auth_results:
            details["spf"] = "pass"
        elif "spf=fail" in auth_results:
            details["spf"] = "fail"
        elif "spf=neutral" in auth_results or "spf=softfail" in auth_results:
            details["spf"] = "softfail"
    if "dkim=" in auth_results:
        if "dkim=pass" in auth_results:
            details["dkim"] = "pass"
        elif "dkim=fail" in auth_results:
            details["dkim"] = "fail"
    if "dmarc=" in auth_results:
        if "dmarc=pass" in auth_results:
            details["dmarc"] = "pass"
        elif "dmarc=fail" in auth_results:
            details["dmarc"] = "fail"
    
    # If missing, try DNS checks
    if "spf" not in details:
        domain = get_sender_domain(msg)
        if domain:
            if check_spf_record_exists(domain):
                details["spf"] = "configured"  # record exists, assume configured
            else:
                details["spf"] = "missing"
    
    if "dkim" not in details:
        # Simple check: if DKIM-Signature header exists, assume pass
        if msg.get("DKIM-Signature"):
            details["dkim"] = "present"
        else:
            details["dkim"] = "missing"
    
    if "dmarc" not in details:
        domain = get_sender_domain(msg)
        if domain:
            if check_dmarc_record_exists(domain):
                details["dmarc"] = "configured"
            else:
                details["dmarc"] = "missing"
    
    return details


def get_sender_domain(msg: email.message.EmailMessage) -> str | None:
    """Extract domain from From header."""
    from_hdr = msg.get("From", "")
    if from_hdr:
        _, addr = email.utils.parseaddr(from_hdr)
        if "@" in addr:
            return addr.split("@")[-1].lower()
    return None


def check_spf_record_exists(domain: str) -> bool:
    """Check if SPF TXT record exists for the domain."""
    try:
        answers = dns.resolver.resolve(domain, 'TXT')
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith('v=spf1'):
                return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    return False


def check_dmarc_record_exists(domain: str) -> bool:
    """Check if DMARC TXT record exists for _dmarc.domain."""
    try:
        answers = dns.resolver.resolve(f"_dmarc.{domain}", 'TXT')
        for rdata in answers:
            txt = str(rdata).strip('"')
            if txt.startswith('v=DMARC1'):
                return True
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
        pass
    return False
