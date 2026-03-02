"""Authentication-related header parsing (SPF/DKIM/DMARC)."""
from __future__ import annotations

import logging
from typing import Dict

logger = logging.getLogger(__name__)


def parse_auth_results(auth_results: str) -> Dict[str, str]:
    """Parse the Authentication-Results header and return a simple dict.

    Keys returned are ``spf``, ``dkim`` and ``dmarc`` when present.
    """
    details: Dict[str, str] = {}
    ar = auth_results.lower()
    if "spf=" in ar:
        if "spf=pass" in ar:
            details["spf"] = "pass"
        elif "spf=fail" in ar:
            details["spf"] = "fail"
        elif "spf=neutral" in ar or "spf=softfail" in ar:
            details["spf"] = "softfail"
    if "dkim=" in ar:
        if "dkim=pass" in ar:
            details["dkim"] = "pass"
        elif "dkim=fail" in ar:
            details["dkim"] = "fail"
    if "dmarc=" in ar:
        if "dmarc=pass" in ar:
            details["dmarc"] = "pass"
        elif "dmarc=fail" in ar:
            details["dmarc"] = "fail"
    return details
