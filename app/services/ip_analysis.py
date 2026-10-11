"""IP-related analysis such as geolocation and blacklist checks."""
from __future__ import annotations

import logging
import ipaddress
from typing import Any, Dict, List, Optional

import httpx

from ..config import Settings

logger = logging.getLogger(__name__)


def classify_ip(ip: str) -> Dict[str, Any]:
    """Validate and classify an IPv4 or IPv6 address.

    Public IP geolocation services cannot meaningfully locate loopback,
    private, link-local, multicast, reserved, or unspecified addresses.  Keep
    those addresses in the report, but classify them locally instead of
    sending them to an external service and displaying a misleading failure.
    """
    candidate = str(ip).strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1].strip()

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        return {
            "valid": False,
            "ip": candidate,
            "ip_family": "Unknown",
            "scope": "invalid",
            "is_global": False,
            "message": "Invalid IP address",
        }

    if address.is_loopback:
        scope = "loopback"
        message = "Loopback address; public geolocation is unavailable"
    elif address.is_unspecified:
        scope = "unspecified"
        message = "Unspecified address; public geolocation is unavailable"
    elif address.is_link_local:
        scope = "link-local"
        message = "Link-local address; public geolocation is unavailable"
    elif address.is_multicast:
        scope = "multicast"
        message = "Multicast address; public geolocation is unavailable"
    elif address.is_private:
        scope = "private"
        message = "Private address; public geolocation is unavailable"
    elif address.is_reserved:
        scope = "reserved"
        message = "Reserved address; public geolocation is unavailable"
    elif address.is_global:
        scope = "public"
        message = ""
    else:
        scope = "non-public"
        message = "Non-public address; public geolocation is unavailable"

    return {
        "valid": True,
        "ip": str(address),
        "ip_family": "IPv4" if address.version == 4 else "IPv6",
        "scope": scope,
        "is_global": address.is_global,
        "message": message,
    }


async def geolocate_ip(ip: str, settings: Settings) -> Dict[str, Any]:
    """Use the configured IP geolocation service to look up the address."""
    ip_info = classify_ip(ip)
    if not ip_info["valid"]:
        return {"status": "invalid", **ip_info}
    if not ip_info["is_global"]:
        return {"status": "local", **ip_info}

    normalized_ip = ip_info["ip"]
    url = f"{settings.ipapi_url}{normalized_ip}"
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, dict):
                    return {**ip_info, **data}
            logger.debug("geolocation failed for %s: status %s", normalized_ip, resp.status_code)
    except Exception as exc:  # broad on purpose; caller may still work in offline mode
        logger.debug("geolocation exception for %s: %s", normalized_ip, exc)
    return {"status": "fail", **ip_info}


async def abuseipdb_check(ip: str, settings: Settings) -> Optional[Dict[str, Any]]:
    """Query AbuseIPDB for an IP reputation report.

    Returns the JSON response or ``None`` if there was a problem or the API key
    is not configured.
    """
    ip_info = classify_ip(ip)
    if not ip_info["valid"] or not ip_info["is_global"]:
        return None
    if not settings.abuseipdb_api_key:
        return None
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": settings.abuseipdb_api_key, "Accept": "application/json"}
    params = {"ipAddress": ip_info["ip"]}
    try:
        async with httpx.AsyncClient(timeout=8.0) as client:
            resp = await client.get(url, headers=headers, params=params)
            if resp.status_code == 200:
                return resp.json()
            logger.debug("AbuseIPDB returned %s for %s", resp.status_code, ip)
    except Exception as exc:
        logger.debug("AbuseIPDB lookup exception for %s: %s", ip, exc)
    return None


async def check_ips(
    ips: List[str],
    settings: Settings,
    online: bool = True,
) -> List[Dict[str, Any]]:
    """Process a list of IPs: optionally geolocate and blacklist-check them.

    Returns a list of dicts with keys ``ip``, ``geo`` and optionally ``abuse``.
    The function automatically falls back to minimal data in offline mode.
    """
    results: List[Dict[str, Any]] = []
    if not ips:
        return results

    if not online:
        results = []
        for ip in ips:
            ip_info = classify_ip(ip)
            results.append({
                "ip": ip_info["ip"],
                "geo": {"status": "offline", **ip_info},
                "abuse": None,
            })
        return results

    # run lookups concurrently using asyncio.gather
    import asyncio

    tasks = []
    for ip in ips:
        tasks.append(geolocate_ip(ip, settings))
        tasks.append(abuseipdb_check(ip, settings))
    responses = await asyncio.gather(*tasks, return_exceptions=True)

    # responses will alternate geo, abuse
    for idx, ip in enumerate(ips):
        geo = responses[2 * idx] if 2 * idx < len(responses) else {"status": "fail"}
        abuse = responses[2 * idx + 1] if 2 * idx + 1 < len(responses) else None
        if isinstance(geo, Exception):
            logger.debug("IP geolocation task failed for %s: %s", ip, geo)
            geo = {"status": "fail"}
        if isinstance(abuse, Exception):
            logger.debug("AbuseIPDB task failed for %s: %s", ip, abuse)
            abuse = None
        results.append({"ip": ip, "geo": geo, "abuse": abuse})
    return results
