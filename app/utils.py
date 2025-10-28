# app/utils.py
import re
import email
from email import policy
from email.parser import BytesParser, Parser
from typing import List, Dict, Tuple, Optional
import tldextract
import requests
import os
import mimetypes

SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly"}

URL_REGEX = re.compile(r"https?://[^\s'\"<>]+")

def parse_eml(raw: str) -> email.message.EmailMessage:
    """
    Accepts raw .eml as string and returns an EmailMessage
    """
    # If bytes required:
    if isinstance(raw, bytes):
        msg = BytesParser(policy=policy.default).parsebytes(raw)
    else:
        msg = Parser(policy=policy.default).parsestr(raw)
    return msg

def extract_basic_headers(msg: email.message.EmailMessage) -> Dict[str, str]:
    return {
        "From": msg.get("From", ""),
        "To": msg.get("To", ""),
        "Subject": msg.get("Subject", ""),
        "Date": msg.get("Date", ""),
        "Authentication-Results": msg.get("Authentication-Results", "")
    }

def extract_received_ips(msg: email.message.EmailMessage) -> List[str]:
    """
    Parse Received headers and extract IPv4/IPv6 addresses (in order)
    """
    received = msg.get_all("Received", []) or []
    ips = []
    ip_re = re.compile(r"\[?((?:\d{1,3}\.){3}\d{1,3}|[0-9a-fA-F:]+)\]?")
    for header in received:
        for m in ip_re.finditer(header):
            ip = m.group(1)
            # basic IPv4 sanity
            if "." in ip:
                parts = ip.split(".")
                if all(0 <= int(p) <= 255 for p in parts if p.isdigit()):
                    ips.append(ip)
            else:
                ips.append(ip)
    # return in order they appear (top-to-bottom)
    return ips

def extract_links_from_body(msg: email.message.EmailMessage) -> List[str]:
    body_texts = []
    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            if ctype == "text/plain":
                try:
                    body_texts.append(part.get_content())
                except:
                    pass
            elif ctype == "text/html":
                try:
                    body_texts.append(part.get_content())
                except:
                    pass
    else:
        try:
            body_texts.append(msg.get_content())
        except:
            pass
    text = "\n".join([t for t in body_texts if t])
    links = URL_REGEX.findall(text)
    return links

def expand_short_url(url: str, timeout=8) -> str:
    """
    Try HEAD first, fallback to GET. Returns final URL or original.
    Beware: this performs network calls (used in Online mode).
    """
    try:
        resp = requests.head(url, allow_redirects=True, timeout=timeout)
        final = resp.url
        if final:
            return final
    except Exception:
        pass
    try:
        resp = requests.get(url, allow_redirects=True, timeout=timeout)
        return resp.url or url
    except Exception:
        return url

def is_shortened(url: str) -> bool:
    try:
        parsed = tldextract.extract(url)
        dom = f"{parsed.domain}.{parsed.suffix}" if parsed.suffix else parsed.domain
        return dom.lower() in SHORTENER_DOMAINS
    except Exception:
        return False

def extract_attachments(msg: email.message.EmailMessage) -> List[Dict]:
    """
    Return list of attachments metadata: filename, content_type, size_bytes, extension
    """
    attachments = []
    for part in msg.walk():
        disp = part.get("Content-Disposition", "")
        if disp and part.get_filename():
            fname = part.get_filename()
            payload = part.get_payload(decode=True) or b""
            size = len(payload)
            ctype = part.get_content_type()
            ext = os.path.splitext(fname)[1].lower()
            attachments.append({
                "filename": fname,
                "content_type": ctype,
                "size": size,
                "extension": ext
            })
    return attachments

def flag_attachment_risky(ext: str, content_type: str) -> bool:
    """
    Flag extensions that are risky or executable disguised as docs.
    """
    exec_ext = {".exe", ".scr", ".bat", ".cmd", ".msi", ".vbs", ".js", ".ps1"}
    doc_like = {".doc", ".docx", ".xls", ".xlsx", ".rtf", ".pdf"}
    if ext in exec_ext:
        return True
    # quirks: .doc with content-type of exe would be suspicious (requires more complex checks)
    if ext in doc_like and content_type in ("application/x-msdownload",):
        return True
    return False

# Simple Threat Scoring
def compute_threat_score(auth_results: str, blacklists: List[str], attachments: List[Dict], links_risky_count: int) -> Tuple[int, Dict]:
    """
    Returns numeric score 0-100 plus breakdown.
    """
    score = 0
    details = {}
    # SPF/DKIM/DMARC in Authentication-Results
    if auth_results:
        ar = auth_results.lower()
        if "spf=pass" in ar:
            details['spf'] = "pass"
        elif "spf=fail" in ar:
            score += 20
            details['spf'] = "fail"
        elif "spf=neutral" in ar or "spf=softfail" in ar:
            score += 10
            details['spf'] = "softfail"
        if "dkim=pass" in ar:
            details['dkim'] = "pass"
        elif "dkim=fail" in ar:
            score += 20
            details['dkim'] = "fail"
        if "dmarc=pass" in ar:
            details['dmarc'] = "pass"
        elif "dmarc=fail" in ar:
            score += 20
            details['dmarc'] = "fail"
    # blacklists
    if blacklists:
        score += 30
        details['blacklist_hits'] = blacklists
    # attachments
    risky_attachments = [a for a in attachments if flag_attachment_risky(a.get("extension",""), a.get("content_type",""))]
    if risky_attachments:
        score += 25
        details['risky_attachments'] = [a['filename'] for a in risky_attachments]
    # links
    if links_risky_count > 0:
        score += min(25, links_risky_count * 8)
        details['risky_links'] = links_risky_count
    # clamp
    score = min(100, score)
    return score, details

# External integrations (VirusTotal, AbuseIPDB) - provide helper wrappers
def virustotal_url_check(api_key: str, url: str) -> Optional[Dict]:
    if not api_key:
        return None
    try:
        headers = {"x-apikey": api_key}
        # VirusTotal v3 URL analysis requires submitting URL or looking up by URL id
        resp = requests.post("https://www.virustotal.com/api/v3/urls", data={"url": url}, headers=headers, timeout=12)
        if resp.ok:
            data = resp.json()
            # return some summary
            return data
    except Exception:
        return None

def abuseipdb_check(api_key: str, ip: str) -> Optional[Dict]:
    if not api_key:
        return None
    try:
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip}
        resp = requests.get("https://api.abuseipdb.com/api/v2/check", headers=headers, params=params, timeout=8)
        if resp.ok:
            return resp.json()
    except Exception:
        return None

def geolocate_ip(ip: str, ipapi_base: str = "http://ip-api.com/json/"):
    """
    Uses ip-api (free) for geolocation: ipapi_base + ip
    """
    try:
        resp = requests.get(f"{ipapi_base}{ip}", timeout=6)
        if resp.ok:
            return resp.json()
    except Exception:
        return {"status":"fail"}
    return {"status":"fail"}

