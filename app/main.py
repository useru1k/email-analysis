# app/main.py
"""FastAPI application entrypoint.

Routes are intentionally thin; most of the business logic lives in the
``app.services`` package.  Dependency injection is used to supply the
configuration/settings object to handlers.
"""

from __future__ import annotations

import logging
import asyncio
from typing import List, Dict, Any

from fastapi import FastAPI, Request, Form, UploadFile, File, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from .config import get_settings, Settings
from .services import (
    parse_email,
    extract_basic_headers,
    extract_received_ips,
    extract_links_from_body,
    extract_attachments,
    check_header_issues,
    is_shortened,
    expand_short_url,
    virustotal_url_check,
    check_ips,
    parse_auth_results,
    compute_threat_score,
    domain_intelligence,
)

logger = logging.getLogger("app")


# configure logging output
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)


app = FastAPI()
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse("index.html", {"request": request})


@app.post("/analyze", response_class=HTMLResponse)
async def analyze(
    request: Request,
    mode: str = Form("online"),
    rawtext: str = Form(""),
    emlfile: UploadFile | None = File(None),
    settings: Settings = Depends(get_settings),
) -> HTMLResponse:
    # basic validation
    if not emlfile and not rawtext.strip():
        raise HTTPException(status_code=400, detail="Please upload a file or paste email content.")

    content = ""
    if emlfile:
        if not emlfile.filename.lower().endswith(".eml"):
            raise HTTPException(status_code=400, detail="Only .eml files are permitted.")
        data = await emlfile.read()
        if len(data) > settings.max_upload_size:
            raise HTTPException(status_code=413, detail="Uploaded file too large.")
        try:
            content = data.decode("utf-8", errors="replace")
        except Exception:
            content = data.decode("latin1", errors="replace")
    else:
        # raw text path
        if len(rawtext) > 1_000_000:
            raise HTTPException(status_code=413, detail="Raw text too long.")
        content = rawtext

    try:
        msg = parse_email(content)
    except Exception as exc:
        logger.error("Failed to parse email: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid email content.")

    headers = extract_basic_headers(msg)
    header_issues = check_header_issues(msg)
    ips = extract_received_ips(msg)
    links = extract_links_from_body(msg)
    attachments = extract_attachments(msg)

    # URL expansion and heuristics
    expanded_links: List[Dict[str, Any]] = []
    risky_link_count = 0
    link_tasks: List[Any] = []
    for u in links:
        shortened = is_shortened(u)
        final = u
        if mode == "online" and shortened:
            link_tasks.append(expand_short_url(u))
        else:
            link_tasks.append(asyncio.sleep(0, result=u))  # placeholder
        expanded_links.append({"original": u, "final": None, "shortened": shortened})
    # run expansion concurrently
    if link_tasks:
        results = await asyncio.gather(*link_tasks, return_exceptions=True)
        for idx, res in enumerate(results):
            final_url = res if isinstance(res, str) else links[idx]
            expanded_links[idx]["final"] = final_url
            # simple heuristic on final url
            low = final_url.lower()
            if any(word in low for word in ("login", "verify", "secure")):
                risky_link_count += 1
    
    # IP analysis
    ip_results = await check_ips(ips, settings, online=(mode == "online"))
    blacklist_hits: List[str] = []
    ip_geos: List[Dict[str, Any]] = []
    for entry in ip_results:
        ip_geos.append({"ip": entry.get("ip"), "geo": entry.get("geo")})
        abuse = entry.get("abuse")
        if abuse and abuse.get("data", {}).get("abuseConfidenceScore", 0) > 0:
            blacklist_hits.append(
                f"IP {entry.get('ip')} - AbuseIPDB score {abuse['data']['abuseConfidenceScore']}"
            )

    # VirusTotal link checks
    vt_results: List[Dict[str, Any]] = []
    link_intel: List[Dict[str, Any]] = []
    if mode == "online":
        # run VT if key present
        if settings.virustotal_api_key:
            vt_tasks = [virustotal_url_check(link["final"], settings) for link in expanded_links]
            vt_res = await asyncio.gather(*vt_tasks, return_exceptions=True)
            for idx, vt in enumerate(vt_res):
                vt_results.append({"url": expanded_links[idx]["final"], "vt": vt if not isinstance(vt, Exception) else None})
        # gather domain intelligence for each link as well
        intel_tasks = [domain_intelligence(link["final"]) for link in expanded_links]
        intel_res = await asyncio.gather(*intel_tasks, return_exceptions=True)
        for intel in intel_res:
            link_intel.append(intel if not isinstance(intel, Exception) else {})
    else:
        # offline leave empty
        link_intel = [{} for _ in expanded_links]

    # authentication parse
    auth_details = parse_auth_results(headers.get("Authentication-Results", ""))

    # compute threat score
    score, breakdown = compute_threat_score(auth_details, blacklist_hits, attachments, risky_link_count)

    result = {
        "headers": headers,
        "auth": auth_details,
        "header_issues": header_issues,
        "ips": ips,
        "ip_geos": ip_geos,
        "links": expanded_links,
        "link_intel": link_intel,
        "attachments": attachments,
        "vt_results": vt_results,
        "blacklist_hits": blacklist_hits,
        "threat_score": score,
        "breakdown": breakdown,
        "mode": mode,
    }

    logger.info("Analysis complete score=%s mode=%s ips=%s links=%s attachments=%s", score, mode, len(ips), len(links), len(attachments))

    # ensure JSON serializable for template (dates, objects)
    from fastapi.encoders import jsonable_encoder
    result_for_template = jsonable_encoder(result)

    try:
        return templates.TemplateResponse("result.html", {"request": request, "result": result_for_template})
    except Exception as e:
        logger.exception("Template rendering failed")
        return HTMLResponse(
            f"<html><body><h1>Error</h1><p>Template rendering failed: {e}</p></body></html>",
            status_code=500,
        )

