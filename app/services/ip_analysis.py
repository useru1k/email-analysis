"""IP-related analysis such as geolocation and blacklist checks."""
from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import httpx

from ..config import Settings

logger = logging.getLogger(__name__)


async def geolocate_ip(ip: str, settings: Settings) -> Dict[str, Any]:
    """Use the configured IP geolocation service to look up the address."""
    url = f"{settings.ipapi_url}{ip}"
    try:
        async with httpx.AsyncClient(timeout=6.0) as client:
            resp = await client.get(url)
            if resp.status_code == 200:
                return resp.json()
            logger.debug("geolocation failed for %s: status %s", ip, resp.status_code)
    except Exception as exc:  # broad on purpose; caller may still work in offline mode
        logger.debug("geolocation exception for %s: %s", ip, exc)
    return {"status": "fail"}


async def abuseipdb_check(ip: str, settings: Settings) -> Optional[Dict[str, Any]]:
    """Query AbuseIPDB for an IP reputation report.

    Returns the JSON response or ``None`` if there was a problem or the API key
    is not configured.
    """
    if not settings.abuseipdb_api_key:
        return None
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Key": settings.abuseipdb_api_key, "Accept": "application/json"}
    params = {"ipAddress": ip}
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
        return [{"ip": ip, "geo": {"status": "offline"}} for ip in ips]

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
        results.append({"ip": ip, "geo": geo, "abuse": abuse})
    return results
