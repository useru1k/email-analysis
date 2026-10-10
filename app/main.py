# app/main.py

from __future__ import annotations

import logging
import asyncio
from pathlib import Path
from typing import List, Dict, Any

from fastapi import FastAPI, Request, Form, UploadFile, File, Depends, HTTPException
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles

from .config import get_settings, Settings
from .input_validator import get_input_source, InputMode
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
    virustotal_file_check,
    search_malware_reports,
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
_APP_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(_APP_DIR / "templates"))
app.mount("/static", StaticFiles(directory=str(_APP_DIR / "static")), name="static")


@app.exception_handler(Exception)
async def unhandled_exception_handler(request: Request, exc: Exception) -> HTMLResponse:
    """Return a safe response for unexpected application failures.

    The complete exception is logged for diagnosis, while the response avoids
    exposing stack traces, API keys, or third-party service details to users.
    FastAPI's built-in HTTPException handler continues to handle expected 4xx
    responses normally.
    """
    logger.exception("Unhandled error while processing %s %s", request.method, request.url.path)
    return HTMLResponse(
        "<html><body><h1>Analysis failed</h1>"
        "<p>The email could not be analyzed. Please try again or use offline mode.</p>"
        "</body></html>",
        status_code=500,
    )


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={"request": request},
    )


@app.post("/analyze", response_class=HTMLResponse)
async def analyze(
    request: Request,
    mode: str = Form("online"),
    rawtext: str = Form(""),
    emlfile: UploadFile | None = File(None),
    settings: Settings = Depends(get_settings),
) -> HTMLResponse:
    """
    Analyze email from either file upload or raw pasted content.

    Clean API design:
    - Input is strictly one of: file upload OR pasted raw content
    - Validation distinguishes between input sources
    - Backend handles both securely with appropriate validation

    Args:
        request: FastAPI request object
        mode: Analysis mode ('online' or 'offline')
        rawtext: Raw email content pasted by user
        emlfile: Uploaded .eml file
        settings: Application settings

    Returns:
        HTML response with analysis results

    Raises:
        HTTPException: For validation or processing errors
    """

    if mode not in {"online", "offline"}:
        raise HTTPException(status_code=400, detail="Mode must be either 'online' or 'offline'.")

    # Determine input source and validate.  Keep this a real bool; UploadFile's
    # filename is a string and otherwise leaks into the validator API.
    has_file = bool(emlfile is not None and emlfile.filename)

    # Read file data if provided
    file_data = None
    if has_file:
        # Read at most one byte beyond the configured limit so an oversized
        # upload cannot consume unbounded memory before validation.
        read_limit = max(1, settings.max_upload_size) + 1
        file_data = await emlfile.read(read_limit)

    # Use new validation logic to distinguish input source
    try:
        input_mode, content = get_input_source(
            has_file=has_file,
            filename=emlfile.filename if has_file and emlfile else None,
            file_data=file_data,
            raw_text=rawtext,
            max_file_size=settings.max_upload_size,
        )
        logger.info("Input validated: type=%s mode=%s content_size=%d bytes",
                   input_mode.value, mode, len(content))
    except HTTPException:
        raise  # Re-raise validation exceptions

    try:
        msg = parse_email(content)
    except Exception as exc:
        logger.error("Failed to parse email: %s", exc)
        raise HTTPException(status_code=400, detail="Invalid email content: could not parse as email.")

    try:
        headers = extract_basic_headers(msg)
        header_issues = check_header_issues(msg)
        ips = extract_received_ips(msg)
        links = extract_links_from_body(msg)
        attachments = extract_attachments(msg)
    except Exception as exc:
        logger.exception("Email content analysis failed after parsing: %s", exc)
        raise HTTPException(
            status_code=400,
            detail="Invalid email content: one or more message parts could not be analyzed.",
        ) from exc

    # run VirusTotal on attachments if we're online and have a key
    if mode == "online" and settings.virustotal_api_key and attachments:
        vt_file_tasks = [virustotal_file_check(att["sha256"], settings) for att in attachments]
        vt_file_res = await asyncio.gather(*vt_file_tasks, return_exceptions=True)
        for idx, vt in enumerate(vt_file_res):
            attachments[idx]["vt"] = vt if not isinstance(vt, Exception) else None

            # If VT flagged as malicious, search for additional reports
            if vt and not isinstance(vt, Exception) and isinstance(vt, dict):
                stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                if not isinstance(stats, dict):
                    stats = {}
                try:
                    attachments[idx]["vt_hits"] = sum(
                        int(stats.get(key, 0) or 0)
                        for key in ("malicious", "suspicious")
                    )
                except (TypeError, ValueError):
                    attachments[idx]["vt_hits"] = 0
                if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
                    reports = await search_malware_reports(attachments[idx]["sha256"], settings)
                    if reports:
                        attachments[idx]["malware_reports"] = reports

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
    # DNS checks are intentionally disabled in offline mode.  They are external
    # operations and previously caused offline requests to hang or fail.
    auth_details = parse_auth_results(msg, perform_dns_checks=(mode == "online"))

    # compute threat score
    score, breakdown = compute_threat_score(
        auth_details,
        blacklist_hits,
        attachments,
        risky_link_count,
        headers,
    )

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

    logger.info("Analysis complete: threat_score=%d mode=%s input_type=%s ips=%d links=%d attachments=%d",
                score, mode, input_mode.value, len(ips), len(links), len(attachments))

    # ensure JSON serializable for template (dates, objects)
    from fastapi.encoders import jsonable_encoder
    result_for_template = jsonable_encoder(result)

    try:
        return templates.TemplateResponse(
            request=request,
            name="result.html",
            context={"request": request, "result": result_for_template},
        )
    except Exception:
        logger.exception("Template rendering failed")
        return HTMLResponse(
            "<html><body><h1>Error</h1><p>Template rendering failed. Please try again.</p></body></html>",
            status_code=500,
        )

