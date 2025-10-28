# app/main.py
from fastapi import FastAPI, Request, Form, UploadFile, File
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from dotenv import load_dotenv
import os
from .utils import (
    parse_eml, extract_basic_headers, extract_received_ips,
    extract_links_from_body, expand_short_url, is_shortened,
    extract_attachments, compute_threat_score,
    virustotal_url_check, abuseipdb_check, geolocate_ip
)
import asyncio

load_dotenv()
VIRUSTOTAL = os.getenv("VIRUSTOTAL_API_KEY", "")
ABUSEIPDB = os.getenv("ABUSEIPDB_API_KEY", "")
IPAPI_URL = os.getenv("IPAPI_URL", "http://ip-api.com/json/")

app = FastAPI()
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")

@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.post("/analyze", response_class=HTMLResponse)
async def analyze(request: Request,
                  mode: str = Form("online"),
                  rawtext: str = Form(""),
                  emlfile: UploadFile = File(None)):
    # get raw data
    content = ""
    if emlfile:
        data = await emlfile.read()
        try:
            content = data.decode("utf-8", errors="replace")
        except:
            content = data.decode("latin1", errors="replace")
    else:
        content = rawtext

    msg = parse_eml(content)
    headers = extract_basic_headers(msg)
    ips = extract_received_ips(msg)
    links = extract_links_from_body(msg)
    attachments = extract_attachments(msg)

    # Expand shortened URLs (online only) and collect risky link count
    expanded = []
    risky_link_count = 0
    for u in links:
        final = u
        shortened = is_shortened(u)
        if mode == "online":
            if shortened:
                final = expand_short_url(u)
        expanded.append({"original": u, "final": final, "shortened": shortened})
        # simple heuristic: suspicious if final domain different from original shortener OR contains suspicious words
        try:
            if "login" in final.lower() or "verify" in final.lower() or "secure" in final.lower():
                risky_link_count += 1
        except:
            pass

    # Blacklist / OSINT checks (online)
    blacklist_hits = []
    ip_geos = []
    if mode == "online":
        # AbuseIPDB checks and geolocation - sequential for simplicity
        for ip in ips:
            geo = geolocate_ip(ip, ipapi_base=IPAPI_URL)
            ip_geos.append({"ip": ip, "geo": geo})
            # abuseipdb
            abuse = None
            if ABUSEIPDB:
                abuse = abuseipdb_check(ABUSEIPDB, ip)
                if abuse and abuse.get("data", {}).get("abuseConfidenceScore", 0) > 0:
                    blacklist_hits.append(f"IP {ip} - AbuseIPDB score {abuse['data']['abuseConfidenceScore']}")
    else:
        # offline: just populate ip_geos minimally
        for ip in ips:
            ip_geos.append({"ip": ip, "geo": {"status": "offline"}})

    # VirusTotal checks for links (online)
    vt_results = []
    if mode == "online" and VIRUSTOTAL:
        for item in expanded:
            try:
                vt = virustotal_url_check(VIRUSTOTAL, item["final"])
                vt_results.append({"url": item["final"], "vt": vt})
                # small heuristic: if vt present and indicates malicious, increment risky count
                if vt and isinstance(vt, dict):
                    # checking nested structure is v3-specific; we leave it as raw for demo
                    pass
            except Exception:
                pass

    # Threat Score
    score, breakdown = compute_threat_score(headers.get("Authentication-Results",""), blacklist_hits, attachments, risky_link_count)

    result = {
        "headers": headers,
        "ips": ips,
        "ip_geos": ip_geos,
        "links": expanded,
        "attachments": attachments,
        "vt_results": vt_results,
        "blacklist_hits": blacklist_hits,
        "threat_score": score,
        "breakdown": breakdown,
        "mode": mode
    }
    print(result)
    print("=== DEBUG INFO ===")
    print(f"Content length: {len(content)}")
    print(f"Headers: {headers}")
    print(f"IPs found: {ips}")
    print(f"Links found: {len(links)}")
    print(f"Attachments found: {len(attachments)}")
    print(f"Threat score: {score}")
    print(f"Mode: {mode}")
    print("==================")
    
    try:
        response = templates.TemplateResponse("result.html", {"request": request, "result": result})
        print("Template rendered successfully")
        return response
    except Exception as e:
        print(f"Template rendering error: {e}")
        # Return a simple error page
        from fastapi.responses import HTMLResponse
        return HTMLResponse(f"""
        <html>
        <body>
            <h1>Error</h1>
            <p>Template rendering failed: {e}</p>
            <p>Result data: {result}</p>
        </body>
        </html>
        """)
