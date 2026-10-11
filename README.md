# Email Analysis System

Email Analysis System is a FastAPI web application for inspecting `.eml` messages and identifying indicators commonly associated with phishing, spoofing, malicious links, suspicious attachments, and risky sender infrastructure.

The application accepts either an uploaded email file or pasted raw email content. It parses the message locally, extracts headers and routing information, analyzes authentication results, checks links and attachments, and produces a threat score from 0 to 100. Online analysis can optionally enrich the report with third-party intelligence from VirusTotal, AbuseIPDB, IP geolocation, WHOIS, DNS, and Google Custom Search.

## Features

### Email parsing and validation

The application supports RFC 822 and MIME email messages. Input validation ensures that users submit exactly one source: an `.eml` file or pasted raw email content. Uploaded files and pasted messages are checked for empty content, supported format, size limits, and basic email headers before analysis begins.

### Header and authentication analysis

The analyzer extracts common headers such as `From`, `To`, `Subject`, `Date`, `Reply-To`, `Return-Path`, and `Authentication-Results`. It also checks for missing or inconsistent headers, including suspicious differences between the sender, return path, and reply address.

SPF, DKIM, and DMARC results are read from the `Authentication-Results` header when available. In online mode, DNS records may be checked when authentication information is missing. Offline mode does not perform DNS or other external lookups.

### IP address analysis

Received headers are scanned for valid IPv4 and IPv6 addresses. Addresses are normalized, deduplicated, and classified by family and scope. Public IP addresses can be enriched with geolocation and AbuseIPDB reputation data.

Loopback, private, link-local, multicast, reserved, and unspecified addresses are retained in the report but are not sent to public geolocation services. For example, `::1` is correctly reported as an IPv6 loopback address instead of being displayed as a failed lookup.

### URL and domain analysis

The analyzer extracts HTTP and HTTPS links from plain-text and HTML email parts. In online mode, supported shortened URLs can be expanded before further analysis. Links containing common phishing indicators such as `login`, `verify`, or `secure` are included in the local risk heuristics.

Online domain intelligence can include the extracted domain, WHOIS information, and MX and SOA DNS records. VirusTotal URL checks are available when a VirusTotal API key is configured.

### Attachment analysis

Email attachments are reported with their filename, content type, size, extension, and SHA-256 hash. Executable and potentially dangerous file types are marked as risky. VirusTotal file-hash lookups are available in online mode, and successful results are stored in a local JSON cache to avoid repeating the same lookup.

When configured, Google Custom Search can be used to find additional malware-analysis reports for attachments that receive suspicious or malicious VirusTotal results.

### Threat scoring

The application calculates a heuristic threat score between 0 and 100. The score considers authentication failures, blacklist or reputation findings, risky attachments, VirusTotal detections, suspicious links, and mismatches between `From` and `Reply-To` addresses.

The result page displays the score, its contributing factors, extracted evidence, and the external intelligence that was available during the analysis. The score is an indicator for investigation and should not be treated as a definitive malware verdict.

## Technology stack

- Python 3.10 or newer
- FastAPI and Uvicorn
- Jinja2 templates
- Python's standard email parsing library
- `httpx` for asynchronous HTTP requests
- `dnspython` for DNS lookups
- `tldextract` for domain parsing
- `python-whois` for WHOIS lookups
- Pydantic Settings for environment-based configuration
- Pytest for automated tests

## Project structure

```text
email-analysis/
├── app/
│   ├── main.py                    # FastAPI application and web routes
│   ├── config.py                  # Environment-based application settings
│   ├── input_validator.py         # File and raw-email validation
│   ├── requirement.txt            # Runtime dependency list
│   ├── services/
│   │   ├── parser.py              # Email, header, URL, and attachment parsing
│   │   ├── auth_analysis.py       # SPF, DKIM, and DMARC analysis
│   │   ├── ip_analysis.py         # IPv4/IPv6 validation and IP intelligence
│   │   ├── url_analysis.py        # URL expansion and domain intelligence
│   │   ├── attachment_analysis.py # Hashing and external attachment checks
│   │   ├── threat_scoring.py      # Threat score calculation
│   │   └── cache.py               # Local VirusTotal response cache
│   ├── templates/
│   │   ├── index.html             # Email submission page
│   │   └── result.html             # Analysis results page
│   └── static/
│       └── style.css               # Application styles
├── sample/                         # Example .eml messages
├── tests/                          # Service-level tests
├── pyproject.toml                  # Project metadata and dependencies
└── README.md
```

## Installation

### Prerequisites

Install the following before setting up the project:

- Python 3.10 or newer
- Git
- pip

### Windows

```powershell
git clone https://github.com/useru1k/email-analysis.git
cd email-analysis
python -m venv venv
.\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r app\requirement.txt
```

### Linux or macOS

```bash
git clone https://github.com/useru1k/email-analysis.git
cd email-analysis
python3 -m venv venv
source venv/bin/activate
python -m pip install --upgrade pip
pip install -r app/requirement.txt
```

The project also defines its dependencies in `pyproject.toml`. If you prefer an editable package installation, use:

```bash
pip install -e ".[dev]"
```

On Windows PowerShell, the same command is:

```powershell
pip install -e ".[dev]"
```

## Configuration

Online integrations are optional. The application can run in offline mode without API keys. To enable external intelligence, create a `.env` file in the project root:

```env
VIRUSTOTAL_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
GOOGLE_SEARCH_API_KEY=your_google_custom_search_api_key
GOOGLE_SEARCH_CX=your_google_custom_search_engine_id
IPAPI_URL=http://ip-api.com/json/
ENVIRONMENT=development
MAX_UPLOAD_SIZE=5242880
HASH_CACHE_PATH=hash_cache.json
```

| Variable | Description | Default |
|---|---|---|
| `VIRUSTOTAL_API_KEY` | Enables VirusTotal URL and attachment-hash lookups. | Empty |
| `ABUSEIPDB_API_KEY` | Enables AbuseIPDB reputation checks for public IP addresses. | Empty |
| `GOOGLE_SEARCH_API_KEY` | Enables searches for additional malware-analysis reports. | Empty |
| `GOOGLE_SEARCH_CX` | Google Custom Search Engine ID used with `GOOGLE_SEARCH_API_KEY`. | Empty |
| `IPAPI_URL` | IP geolocation service endpoint. | `http://ip-api.com/json/` |
| `ENVIRONMENT` | Application environment label. | `development` |
| `MAX_UPLOAD_SIZE` | Maximum upload size in bytes. | `5242880` |
| `HASH_CACHE_PATH` | JSON file used for cached VirusTotal file results. | `hash_cache.json` |

Keep `.env` out of source control. API keys should never be committed to the repository or included in screenshots, logs, or error responses.

## Running the application

Start the development server from the project root after activating the virtual environment:

```bash
uvicorn app.main:app --reload
```

On Windows, you can explicitly use the virtual environment's executable:

```powershell
.\venv\Scripts\python.exe -m uvicorn app.main:app --reload
```

The application is available at [http://127.0.0.1:8000](http://127.0.0.1:8000).

To expose the server on all network interfaces, use:

```bash
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Use `--reload` for local development only. For production deployments, run behind a reverse proxy and use an appropriate process manager and security configuration.

## Using the analyzer

### Uploading an email file

1. Open the application in a browser.
2. Select an `.eml` file from the upload area.
3. Choose Online or Offline analysis.
4. Select **Analyze Email**.
5. Review the threat score, headers, IP hops, links, attachments, and available intelligence.

### Pasting raw email content

1. Copy the complete raw message, including its headers and body.
2. Paste it into the raw email text area.
3. Choose an analysis mode.
4. Select **Analyze Email**.

The application accepts one input method at a time. If both a file and pasted content are supplied, the request is rejected with a validation error.

## Analysis modes

### Online mode

Online mode performs local analysis and attempts the configured external checks. Depending on the available API keys and network access, it can expand shortened URLs, query VirusTotal, check public IP addresses with AbuseIPDB, retrieve IP geolocation, and perform WHOIS and DNS lookups.

External service failures are handled as partial results. A failed or unavailable integration should not prevent the local email analysis from being displayed.

### Offline mode

Offline mode performs local parsing and heuristics only. It analyzes headers, authentication results already present in the message, links, attachments, hashes, and threat-score factors without making external DNS or API requests.

Offline mode is useful for privacy-sensitive analysis, development, testing, and environments without Internet access.

## Testing

Run the service tests from the project root:

```bash
pytest -q
```

The tests cover email parsing, header extraction, URL detection, attachment hashing, IP extraction and classification, authentication parsing, threat scoring, caching, and external-service response handling through mocks.

## Security and privacy considerations

Email messages may contain sensitive content, personal information, tokens, tracking links, and malicious attachments. Consider the following before using online mode:

- Do not upload confidential messages to third-party services unless you are authorized to do so.
- VirusTotal and other external providers may receive URLs or file hashes during online analysis.
- Do not open suspicious links or attachments directly from the result page.
- Treat the threat score as a triage signal rather than a final security decision.
- Run the application behind authentication and HTTPS before exposing it outside a trusted development environment.

## Contributing

Contributions are welcome. Before opening a pull request, keep changes focused, add or update tests for behavioral changes, and verify that the application compiles and the test suite passes.

## License and disclaimer

This project is intended for security analysis, research, and educational use. It does not guarantee that every malicious message will be detected, and it should not replace enterprise email security controls, incident-response procedures, or professional security review.
