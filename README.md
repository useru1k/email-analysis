# Email Analysis System for Detecting Phishing and Malicious Emails

An Email Analysis Tool with threat scoring, URL/attachment safety checks, and comprehensive security analysis for detecting phishing and malicious emails.

## Features

- **Threat Score Calculation**: Comprehensive 0-100 threat score based on multiple security factors
- **Email Authentication Analysis**: SPF, DKIM, and DMARC validation
- **IP Analysis**: 
  - Geolocation tracking
  - AbuseIPDB integration for blacklist checking
  - IP reputation scoring
- **URL Analysis**:
  - Shortened URL expansion
  - VirusTotal integration for URL scanning
  - Suspicious link detection
  - Domain intelligence (WHOIS, DNS records)
- **Attachment Analysis**:
  - Risky file type detection
  - MalwareBazaar integration for malware detection
  - SHA-256 hash calculation
- **Header Analysis**: Extraction and validation of email headers
- **Dual Mode Operation**: Online (with API integrations) and Offline modes

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package installer)
- Git (for cloning the repository)

### Step-by-Step Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/useru1k/email-analysis.git
   cd email-analysis
   ```

2. **Create a virtual environment** (recommended)
   
   On Windows:
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```
   
   On Linux/Mac:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. **Install dependencies**
   ```bash
   pip install -r app/requirement.txt
   ```

4. **Configure environment variables** (Optional, for online mode)
   
   Create a `.env` file in the root directory:
   ```env
   VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
   ABUSEIPDB_API_KEY=your_abuseipdb_api_key_here
   IPAPI_URL=http://ip-api.com/json/
   ```
   
   **Note**: 
   - VirusTotal API key is optional but recommended for URL scanning
   - AbuseIPDB API key is optional but recommended for IP reputation checking
   - You can use the application in offline mode without API keys

## Running the Application

### Start the Server

1. **Activate the virtual environment** (if not already activated)
   
   On Windows:
   ```bash
   venv\Scripts\activate
   ```
   
   On Linux/Mac:
   ```bash
   source venv/bin/activate
   ```

2. **Run the FastAPI server**
   ```bash
   uvicorn app.main:app --reload
   ```
   
   Or with specific host and port:
   ```bash
   uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
   ```

3. **Access the application**
   - Open your web browser
   - Navigate to: `http://localhost:8000`
   - You should see the Email Analysis interface

## Threat Score Calculation

The threat score is calculated on a scale of 0-100, where higher scores indicate greater threat levels. The scoring system evaluates multiple security factors:

## Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `VIRUSTOTAL_API_KEY` | VirusTotal API key for URL scanning | Yes | Empty |
| `ABUSEIPDB_API_KEY` | AbuseIPDB API key for IP reputation checking | No | Empty |
| `IPAPI_URL` | IP geolocation API endpoint | No | `http://ip-api.com/json/` |

### Analysis Modes

- **Online Mode**: 
  - Expands shortened URLs
  - Checks IPs against AbuseIPDB
  - Scans URLs with VirusTotal
  - Performs WHOIS and DNS lookups
  - Requires API keys for full functionality

- **Offline Mode**:
  - Analyzes email structure and headers
  - Detects risky attachments and links
  - Calculates threat score based on local analysis
  - No external API calls

## Project Structure

```
email-analysis/
├── app/
│   ├── __pycache__/
│   ├── main.py              # FastAPI application and routes
│   ├── utils.py             # Core analysis functions and threat scoring
│   ├── requirement.txt      # Python dependencies
│   ├── static/
│   │   └── style.css        # Application styles
│   ├── templates/
│   │   ├── index.html       # Main upload interface
│   │   └── result.html      # Analysis results page
│   └── venv/                # Virtual environment
├── sample/                  # Sample email files for testing
├── .env                     # Environment variables (create this)
└── README.md               # This file
```

## Technologies Used

- **FastAPI**: Modern web framework for building APIs
- **Jinja2**: Template engine for HTML rendering
- **dnspython**: DNS toolkit for domain lookups
- **requests/httpx**: HTTP client libraries for API integrations
- **tldextract**: Domain extraction from URLs
- **python-dotenv**: Environment variable management

## External Integrations

- **VirusTotal**: URL and domain reputation checking
- **AbuseIPDB**: IP address reputation and abuse reporting
- **MalwareBazaar**: Malware hash database lookup
- **ip-api.com**: IP geolocation service
- **whois.vu**: Domain WHOIS information

## Usage Examples

### Analyzing an Email File

1. Save an email as `.eml` format
2. Upload the file through the web interface
3. Select analysis mode
4. View comprehensive threat analysis and score

### Analyzing Raw Email Content

1. Copy raw email headers and body
2. Paste into the text area on the web interface
3. Select analysis mode
4. Get instant security analysis

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This tool is for security analysis and educational purposes only. Always verify results through multiple sources and exercise caution when handling potentially malicious emails.
