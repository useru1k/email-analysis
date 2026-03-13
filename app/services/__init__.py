"""Service layer package for the email analysis application.

Modules inside this package implement discrete areas of business logic such as
parsing, IP analysis, URL analysis, attachment handling, authentication
analysis and scoring. Using a service package keeps the FastAPI routes thin and
makes unit testing easier.
"""

from .parser import parse_email, extract_basic_headers, extract_received_ips, extract_links_from_body, extract_attachments, check_header_issues
from .ip_analysis import geolocate_ip, abuseipdb_check, check_ips
from .url_analysis import is_shortened, expand_short_url, virustotal_url_check, extract_urls_from_text, domain_intelligence
from .attachment_analysis import virustotal_file_check, search_malware_reports
from .attachment_analysis import flag_attachment_risky, AttachmentRisk, compute_sha256
from .auth_analysis import parse_auth_results
from .threat_scoring import compute_threat_score
from .cache import get_cached_hash, set_cached_hash

__all__ = [
    "parse_email",
    "extract_basic_headers",
    "extract_received_ips",
    "extract_links_from_body",
    "extract_attachments",
    "virustotal_file_check",
    "search_malware_reports",
    "geolocate_ip",
    "abuseipdb_check",
    "check_ips",
    "is_shortened",
    "expand_short_url",
    "virustotal_url_check",
    "extract_urls_from_text",
    "flag_attachment_risky",
    "AttachmentRisk",
    "compute_sha256",
    "parse_auth_results",
    "compute_threat_score",
    "get_cached_hash",
    "set_cached_hash",
]
