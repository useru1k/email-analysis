# Attachment Analysis with VirusTotal Integration

## Overview

Enhanced attachment analysis system that computes file hashes (SHA-256) and validates them against VirusTotal's malware database to generate a comprehensive threat score.

## Implementation Details

### 1. **Attachment Hash Extraction** (`app/services/parser.py`)
- **Function**: `extract_attachments()`
- Extracts all attachments from email messages
- Computes SHA-256 hash for each attachment using `compute_sha256()`
- Flags attachments with risky extensions (`.exe`, `.bat`, `.scr`, etc.)
- Includes `vt` field (initially `None`) for VirusTotal results
- **Output**: List of dicts with keys: `filename`, `content_type`, `size`, `extension`, `sha256`, `risky`, `vt`

### 2. **VirusTotal File Lookup** (`app/services/attachment_analysis.py`)
- **Function**: `virustotal_file_check(sha256: str, settings: Settings) -> Optional[Dict]`
- **Type**: Async function
- **API**: VirusTotal v3 `/files/{hash}` endpoint
- **Auth**: Uses `settings.virustotal_api_key` if available
- **Response**: Parsed JSON from VT containing analysis metadata
- **Error Handling**: Returns `None` gracefully on failures (network, missing key, etc.)
- **Logging**: Debug-level logs for all results

### 3. **Main Analysis Flow** (`app/main.py`)
```python
# After extracting attachments:
if mode == "online" and settings.virustotal_api_key and attachments:
    vt_file_tasks = [virustotal_file_check(att["sha256"], settings) for att in attachments]
    vt_file_res = await asyncio.gather(*vt_file_tasks, return_exceptions=True)
    for idx, vt in enumerate(vt_file_res):
        attachments[idx]["vt"] = vt if not isinstance(vt, Exception) else None
```
- Runs VT checks concurrently using `asyncio.gather()`
- Only executes in **online mode** with valid API key
- Gracefully handles exceptions (file availability, rate limits, etc.)
- Updates each attachment with VT response

### 4. **Threat Score Computation** (`app/services/threat_scoring.py`)

#### Scoring Penalties:
- **Authentication failures (SPF/DKIM/DMARC)**: +20 points each
- **IP blacklist hits**: +30 points
- **Risky attachment extensions**: +25 points
- **VirusTotal malicious flags**: +30 points (new)
- **Suspicious links**: +8 points per link (capped at +25)

#### VirusTotal Scoring Logic:
```python
vt_malicious: list[str] = []
for a in attachments:
    vt = a.get("vt")
    if vt and isinstance(vt, dict):
        stats = vt.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        # Count any positive or suspicious hits as a red flag
        if stats.get("malicious", 0) > 0 or stats.get("suspicious", 0) > 0:
            vt_malicious.append(a.get("filename"))
if vt_malicious:
    score += 30
    details["vt_attachments"] = vt_malicious
```

### 5. **Template Display** (`app/templates/result.html`)

Enhanced attachments table now shows:
| Column | Content |
|--------|---------|
| Filename | Attachment name |
| Type | MIME type |
| Size | Bytes (formatted) |
| SHA-256 | File hash (monospace) |
| Risk | Static heuristic flag (RISK/SAFE) |
| VT hits | Count of malicious + suspicious detections |

## Code Quality

### Senior Developer Practices Applied:
1. **Async/Concurrent Execution**: Uses `asyncio.gather()` for parallel VT queries
2. **Error Handling**: Exceptions caught and logged; graceful fallbacks
3. **Type Hints**: Full type annotations throughout
4. **Separation of Concerns**: 
   - Parsing → `parser.py`
   - API integration → `attachment_analysis.py`
   - Threat logic → `threat_scoring.py`
5. **Idempotency**: Optional VT key; offline mode still works
6. **Defensive Programming**: Nested `.get()` calls with defaults
7. **Logging**: Debug/info/error levels appropriately used
8. **Testing**: Comprehensive unit tests with async support

## Files Modified

- `app/main.py`: Made async VT calls; added import
- `app/services/parser.py`: Added `vt` field to attachment dicts
- `app/services/attachment_analysis.py`: Added `virustotal_file_check()` async function
- `app/services/threat_scoring.py`: Enhanced score computation for VT results
- `app/services/__init__.py`: Exported new functions
- `app/templates/result.html`: Updated UI for new attachment columns
- `tests/test_services.py`: Added comprehensive test coverage
- `README.md`: Updated documentation

## Testing

All tests pass with extensive coverage:

```bash
pytest tests/test_services.py::test_attachments_and_hash      # SHA-256 hashing
pytest tests/test_services.py::test_threat_score_considers_vt # Scoring logic
pytest tests/test_services.py::test_virustotal_file_check    # VT API integration
```

## Configuration

No new environment variables required. Uses existing `VIRUSTOTAL_API_KEY` setting.

### Behavior:
- **When API key present + online mode**: Full VT scanning
- **When API key missing or offline mode**: Graceful degradation (hash only)
