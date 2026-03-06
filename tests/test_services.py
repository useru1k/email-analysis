"""Basic unit tests for service modules."""
import pytest
import hashlib
import asyncio
import email.message
from app.services import (
    parse_email,
    extract_basic_headers,
    extract_received_ips,
    extract_links_from_body,
    extract_attachments,
    check_header_issues,
    is_shortened,
    expand_short_url,
    compute_sha256,
    flag_attachment_risky,
    parse_auth_results,
    compute_threat_score,
    domain_intelligence,
    virustotal_file_check,
)

SAMPLE_EML = """From: test@example.com
To: victim@domain.com
Subject: Hello
Date: Thu, 1 Jan 2020 00:00:00 +0000

This is a test email. http://bit.ly/abc123
"""


def test_parse_and_headers():
    msg = parse_email(SAMPLE_EML)
    hdrs = extract_basic_headers(msg)
    assert hdrs["From"] == "test@example.com"
    assert "bit.ly" not in hdrs["Subject"]
    assert extract_received_ips(msg) == []
    assert extract_links_from_body(msg) == ["http://bit.ly/abc123"]


def test_shortened():
    assert is_shortened("http://bit.ly/abc")
    assert not is_shortened("https://example.com")


def test_attachments_and_hash():
    # craft a message with attachment
    from email.message import EmailMessage
    m = EmailMessage()
    m.set_content("body text")
    m.add_attachment(b"data", maintype="application", subtype="octet-stream", filename="test.exe")
    atts = extract_attachments(m)
    assert len(atts) == 1
    assert atts[0]["risky"]
    assert atts[0]["vt"] is None
    assert compute_sha256(b"data") == hashlib.sha256(b"data").hexdigest()


def test_flag_risky():
    assert flag_attachment_risky(".exe", "application/octet-stream")
    assert not flag_attachment_risky(".txt", "text/plain")


def test_auth_parse_and_score():
    auth = "spf=pass dkim=fail dmarc=none"
    msg = email.message.EmailMessage()
    msg["Authentication-Results"] = auth
    msg["From"] = "test@example.com"
    details = parse_auth_results(msg)
    assert details["spf"] == "pass"
    assert details["dkim"] == "fail"
    score, breakdown = compute_threat_score(details, ["hit"], [{"risky": True}], 2)
    assert score > 0
    assert "blacklist_hits" in breakdown


def test_threat_score_considers_vt():
    # attachments flagged by VT should increase the score
    vt_blob = {"data": {"attributes": {"last_analysis_stats": {"malicious": 1}}}}
    score, breakdown = compute_threat_score({}, [], [{"risky": False, "vt": vt_blob, "filename": "bad.exe"}], 0)
    assert score >= 30
    assert breakdown.get("vt_attachments") == ["bad.exe"]



@pytest.mark.asyncio
async def test_virustotal_file_check(monkeypatch):
    # simulate a successful VT response without hitting the network
    class DummyResp:
        status_code = 200
        def json(self):
            return {"fake": "data"}

    class DummyClient:
        def __init__(self, *args, **kwargs):
            pass
        async def get(self, url, headers=None):
            return DummyResp()
        async def __aenter__(self):
            return self
        async def __aexit__(self, exc_type, exc, tb):
            pass

    monkeypatch.setattr("app.services.attachment_analysis.httpx.AsyncClient", DummyClient)
    class DummySettings:
        virustotal_api_key = "key"

    res = await virustotal_file_check("abcd", DummySettings())
    assert res == {"fake": "data"}


def test_domain_intel():
    intel = asyncio.run(domain_intelligence("https://example.com"))
    assert intel.get("domain") == "example.com"


def test_header_issues():
    from email.message import EmailMessage
    m = EmailMessage()
    m["From"] = "user@example.com"
    m["Return-Path"] = "<other@evil.com>"
    issues = check_header_issues(m)
    assert any("Return-Path" in i for i in issues)


def test_ip_extraction():
    from email.message import EmailMessage
    # construct a message with Received headers containing valid and invalid
    m = EmailMessage()
    m.add_header("Received", "from [123.45.67.89] by mail;"
                 " from example.com (a) [::1] [123.45.67.89]")
    ips = extract_received_ips(m)
    # should include only the real IPv4 and IPv6 once
    assert "123.45.67.89" in ips
    assert "::1" in ips
    assert all(len(ip) > 1 for ip in ips)  # no single-letter tokens
    assert ips.count("123.45.67.89") == 1
