"""URL and link related utilities and external service wrappers."""
from __future__ import annotations

import logging
import re
from typing import Any, Dict, List, Optional

import httpx
import tldextract

from ..config import Settings

logger = logging.getLogger(__name__)

SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}

URL_REGEX = re.compile(r"https?://[^\s'\"<>]+")


def extract_urls_from_text(text: str) -> List[str]:
    return URL_REGEX.findall(text)


def is_shortened(url: str) -> bool:
    try:
        parsed = tldextract.extract(url)
        dom = f"{parsed.domain}.{parsed.suffix}" if parsed.suffix else parsed.domain
        return dom.lower() in SHORTENER_DOMAINS
    except Exception:
        return False


async def expand_short_url(url: str, timeout: float = 8.0) -> str:
    """Follow redirects to obtain the final URL.

    A simple HEAD is attempted first then GET. If anything fails we return the
    original URL. Intended for use in online mode only.
    """
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.head(url)
            if resp.url:
                return str(resp.url)
    except Exception:
        pass
    try:
        async with httpx.AsyncClient(timeout=timeout, follow_redirects=True) as client:
            resp = await client.get(url)
            return str(resp.url or url)
    except Exception as exc:
        logger.debug("expand_short_url failed for %s: %s", url, exc)
        return url


async def virustotal_url_check(url: str, settings: Settings) -> Optional[Dict[str, Any]]:
    """Submit a URL to VirusTotal (v3) and return the API response.

    The caller is responsible for skipping this function when ``settings.virustotal_api_key``
    is not configured or in offline mode.
    """
    if not settings.virustotal_api_key:
        return None
    headers = {"x-apikey": settings.virustotal_api_key}
    try:
        async with httpx.AsyncClient(timeout=12.0) as client:
            resp = await client.post(
                "https://www.virustotal.com/api/v3/urls",
                data={"url": url},
                headers=headers,
            )
            if resp.status_code in (200, 201):
                return resp.json()
            logger.debug("VirusTotal returned %s for %s", resp.status_code, url)
    except Exception as exc:
        logger.debug("VirusTotal call exception for %s: %s", url, exc)
    return None


async def domain_intelligence(url: str) -> Dict[str, Any]:
    """Gather simple domain intelligence (WHOIS, DNS records).

    This is kept lightweight: failures return empty dict, allowing offline
    or partial operation.
    """
    intel: Dict[str, Any] = {"domain": None, "whois": None, "dns": {}}
    try:
        # extract domain
        parsed = tldextract.extract(url)
        domain = f"{parsed.domain}.{parsed.suffix}" if parsed.suffix else parsed.domain
        intel["domain"] = domain
        # WHOIS lookup (synchronous for simplicity)
        try:
            import whois
            w = whois.whois(domain)
            intel["whois"] = {
                "registrar": getattr(w, "registrar", None),
                "creation_date": getattr(w, "creation_date", None),
            }
        except Exception:
            pass
        # DNS records
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, "MX")
            intel["dns"]["mx"] = [str(r.exchange) for r in answers]
        except Exception:
            intel["dns"]["mx"] = []
        try:
            answers = dns.resolver.resolve(domain, "SOA")
            intel["dns"]["soa"] = [str(r) for r in answers]
        except Exception:
            intel["dns"]["soa"] = []
    except Exception:
        pass
    return intel
