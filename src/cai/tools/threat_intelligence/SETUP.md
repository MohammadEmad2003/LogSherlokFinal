# Threat Intelligence Module - Setup & Usage Guide

> **Production-ready threat intelligence enrichment for the CAI Forensic Agent**

---

## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Prerequisites](#prerequisites)
4. [Installation](#installation)
5. [Configuration](#configuration)
6. [Downloading Threat Intel Databases](#downloading-threat-intel-databases)
7. [Usage Examples](#usage-examples)
8. [API Reference](#api-reference)
9. [Architecture](#architecture)
10. [Troubleshooting](#troubleshooting)

---

## Overview

The Threat Intelligence module provides automated IOC (Indicator of Compromise) enrichment for forensic investigations. It combines **offline databases** (for air-gapped environments) with **online APIs** (for real-time intelligence) to deliver comprehensive threat context.

### What It Does

- **Checks IOCs** (IPs, domains, URLs, file hashes) against known threat databases
- **Normalizes IOCs** (defangs `evil[.]com`, handles case, strips protocols)
- **Calculates threat scores** (0.0-1.0 with severity levels)
- **Maps to MITRE ATT&CK** (links malware families to techniques)
- **Generates STIX 2.1 bundles** (professional threat intelligence output)

---

## Features

| Feature                | Description                                                              |
| ---------------------- | ------------------------------------------------------------------------ |
| **IOC Normalization**  | Handles defanged IOCs (`evil[.]com`), URL extraction, case normalization |
| **Subdomain Matching** | `sub.evil.com` matches if `evil.com` is in the database                  |
| **Offline-First**      | Works without internet using local abuse.ch databases                    |
| **OTX Integration**    | AlienVault Open Threat Exchange (200k+ contributors)                     |
| **Caching**            | 1-hour TTL for OTX results to prevent API spam                           |
| **Thread-Safe**        | Safe for concurrent use in multi-threaded agents                         |
| **MITRE Mapping**      | 20+ malware families mapped to ATT&CK techniques                         |
| **STIX 2.1 Export**    | Professional threat intel format for SIEMs/TIPs                          |

---

## Prerequisites

### Required Python Packages

```bash
pip install stix2 OTXv2 typing_extensions
```

### Optional (Already Installed with CAI)

```bash
pip install requests
```

---

## Installation

The module is already installed as part of the CAI framework at:

```
src/cai/tools/threat_intelligence/
├── __init__.py
└── threat_intelligence.py
```

To verify installation:

```powershell
# Windows PowerShell
cd "C:\Users\Kareem H\Music\Track\Forensics-Agent\Challange-4-salamanca"
$env:PYTHONPATH = "src"
python -c "from cai.tools.threat_intelligence.threat_intelligence import enrich_ioc; print('OK')"
```

```bash
# Linux/macOS
cd /path/to/Challange-4-salamanca
PYTHONPATH=src python -c "from cai.tools.threat_intelligence.threat_intelligence import enrich_ioc; print('OK')"
```

---

## Configuration

### Environment Variables

| Variable       | Required | Description                    | Default       |
| -------------- | -------- | ------------------------------ | ------------- |
| `OTX_API_KEY`  | Optional | AlienVault OTX API key (free)  | None          |
| `TI_DATA_PATH` | Optional | Path to threat intel databases | `./knowledge` |

### Setting Environment Variables

**Windows PowerShell:**

```powershell
$env:OTX_API_KEY = "your-api-key-here"
$env:TI_DATA_PATH = "C:\path\to\knowledge"
```

**Windows Command Prompt:**

```cmd
set OTX_API_KEY=your-api-key-here
set TI_DATA_PATH=C:\path\to\knowledge
```

**Linux/macOS:**

```bash
export OTX_API_KEY="your-api-key-here"
export TI_DATA_PATH="/path/to/knowledge"
```

### Getting an OTX API Key (Free)

1. Go to [https://otx.alienvault.com](https://otx.alienvault.com)
2. Click **Sign Up** (free account)
3. After login, go to **Settings** → **API Integration**
4. Copy your **OTX API Key**

---

## Downloading Threat Intel Databases

The module uses three offline databases from [abuse.ch](https://abuse.ch):

### Windows PowerShell

```powershell
# Navigate to knowledge directory
cd "C:\Users\Kareem H\Music\Track\Forensics-Agent\Challange-4-salamanca\knowledge"

# 1. Feodo Tracker - Botnet C2 IPs (Emotet, TrickBot, QakBot)
Invoke-WebRequest -Uri "https://feodotracker.abuse.ch/downloads/ipblocklist.csv" -OutFile "feodo_c2.csv"

# 2. URLhaus - Malware distribution domains/URLs
Invoke-WebRequest -Uri "https://urlhaus.abuse.ch/downloads/text/" -OutFile "urlhaus_domains.txt"

# 3. MalwareBazaar - Malware file hashes (OPTIONAL - large file ~50MB)
Invoke-WebRequest -Uri "https://bazaar.abuse.ch/export/csv/recent/" -OutFile "malwarebazaar.csv"
```

### Linux/macOS

```bash
# Navigate to knowledge directory
cd /path/to/Challange-4-salamanca/knowledge

# 1. Feodo Tracker - Botnet C2 IPs
curl -o feodo_c2.csv "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"

# 2. URLhaus - Malware distribution domains/URLs
curl -o urlhaus_domains.txt "https://urlhaus.abuse.ch/downloads/text/"

# 3. MalwareBazaar - Malware file hashes (OPTIONAL - large file)
curl -o malwarebazaar.csv "https://bazaar.abuse.ch/export/csv/recent/"
```

### Database Descriptions

| Database          | File                  | Size  | Contents                          |
| ----------------- | --------------------- | ----- | --------------------------------- |
| **Feodo Tracker** | `feodo_c2.csv`        | ~50KB | Active botnet C2 IP addresses     |
| **URLhaus**       | `urlhaus_domains.txt` | ~2MB  | Malware distribution URLs/domains |
| **MalwareBazaar** | `malwarebazaar.csv`   | ~50MB | Recent malware sample hashes      |

### Recommended Update Schedule

| Database      | Update Frequency |
| ------------- | ---------------- |
| Feodo Tracker | Daily            |
| URLhaus       | Daily            |
| MalwareBazaar | Weekly           |

---

## Usage Examples

### Basic Usage (PowerShell)

```powershell
cd "C:\Users\Kareem H\Music\Track\Forensics-Agent\Challange-4-salamanca"
$env:PYTHONPATH = "src"

python -c "
from cai.tools.threat_intelligence.threat_intelligence import (
    _normalize_ioc,
    _check_ioc_local_impl,
    _enrich_ioc_impl
)
import json

# 1. Normalize a defanged IOC
print('Normalized:', _normalize_ioc('evil[.]com', 'domain'))

# 2. Check against local databases
result = _check_ioc_local_impl({'ioc_value': '1.2.3.4', 'ioc_type': 'ip'})
print(json.loads(result))

# 3. Full enrichment (local + OTX + scoring)
result = _enrich_ioc_impl({'ioc_value': 'malware.com', 'ioc_type': 'domain'})
print(json.loads(result))
"
```

### Check Different IOC Types

```python
from cai.tools.threat_intelligence.threat_intelligence import _enrich_ioc_impl
import json

# Check IP address
result = _enrich_ioc_impl({'ioc_value': '185.215.113.66', 'ioc_type': 'ip'})
print(json.loads(result))

# Check domain
result = _enrich_ioc_impl({'ioc_value': 'evil-domain.com', 'ioc_type': 'domain'})
print(json.loads(result))

# Check URL (domain is extracted automatically)
result = _enrich_ioc_impl({'ioc_value': 'hxxps://evil[.]com/malware.exe', 'ioc_type': 'url'})
print(json.loads(result))

# Check file hash (MD5, SHA-1, or SHA-256)
result = _enrich_ioc_impl({
    'ioc_value': '44d88612fea8a8f36de82e1278abb02f',  # EICAR test hash
    'ioc_type': 'hash'
})
print(json.loads(result))
```

### Create STIX Bundle from Findings

```python
from cai.tools.threat_intelligence.threat_intelligence import _build_stix_bundle_impl
import json

# Your forensic findings
findings = [
    {
        'remote_ip': '185.215.113.66',
        'confidence': 0.85,
        'event_type': 'network_connection'
    },
    {
        'yara_rule': 'emotet_loader',
        'mitre_technique_id': 'T1059.001',
        'mitre_technique_name': 'PowerShell',
        'confidence': 0.9
    },
    {
        'file_hash': 'abc123def456789...',
        'process_name': 'malware.exe'
    }
]

# Generate STIX 2.1 bundle
result = _build_stix_bundle_impl({
    'case_id': 'CASE-2024-001',
    'findings': json.dumps(findings)
})

data = json.loads(result)
print(f"Created {data['object_count']} STIX objects")
print(f"Summary: {data['summary']}")

# Save bundle to file
with open('stix_bundle.json', 'w') as f:
    json.dump(data['bundle'], f, indent=2)
```

---

## API Reference

### `check_ioc_local(query: IOCQuery) -> str`

Check IOC against offline databases (abuse.ch).

**Parameters:**

```python
{
    "ioc_value": str,  # The IOC to check
    "ioc_type": str    # One of: "ip", "domain", "hash", "url"
}
```

**Returns:**

```json
{
    "matched": true,
    "ioc_type": "ip",
    "ioc_value": "185.215.113.66",
    "source": "Feodo Tracker (abuse.ch)",
    "threat_info": "Known botnet C2 server",
    "malware_family": null,
    "mitre_techniques": ["T1071.001", "T1105"],
    "databases_checked": ["feodo_tracker"]
}
```

---

### `check_ioc_otx(query: IOCQuery) -> str`

Check IOC against AlienVault OTX (requires API key).

**Parameters:**

```python
{
    "ioc_value": str,  # The IOC to check
    "ioc_type": str    # One of: "ip", "domain", "hash", "url"
}
```

**Returns:**

```json
{
    "matched": true,
    "ioc_type": "domain",
    "ioc_value": "evil.com",
    "pulse_count": 47,
    "malware_families": ["emotet", "banking trojan"],
    "country": "Russia",
    "threat_score": 0.94,
    "source": "AlienVault OTX",
    "from_cache": false
}
```

---

### `enrich_ioc(query: IOCQuery) -> str`

**Recommended.** Unified enrichment combining all sources.

**Parameters:**

```python
{
    "ioc_value": str,  # The IOC to check
    "ioc_type": str    # One of: "ip", "domain", "hash", "url"
}
```

**Returns:**

```json
{
    "ioc_type": "ip",
    "ioc_value": "185.215.113.66",
    "matched": true,
    "threat_score": 0.55,
    "severity": "high",
    "signals": ["MalwareBazaar hash match", "OTX high (15 pulses)"],
    "sources": {
        "local": { "matched": true, "source": "Feodo Tracker" },
        "otx": { "matched": true, "pulse_count": 15 }
    },
    "mitre_techniques": ["T1071.001", "T1059.001"]
}
```

---

### `build_stix_bundle(input: STIXBundleInput) -> str`

Create STIX 2.1 bundle from forensic findings.

**Parameters:**

```python
{
    "case_id": str,     # Case identifier
    "findings": str     # JSON array of forensic events
}
```

**Returns:**

```json
{
    "status": "success",
    "case_id": "CASE-001",
    "object_count": 12,
    "bundle": {
        /* STIX 2.1 bundle */
    },
    "summary": {
        "malicious_ips": 3,
        "malware_families": 1,
        "attack_patterns": 2,
        "file_hashes": 1
    }
}
```

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      IOC Input                               │
│         (IP, Domain, URL, Hash - possibly defanged)         │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                  _normalize_ioc()                            │
│     • Defang: evil[.]com → evil.com                         │
│     • Lowercase, strip whitespace                           │
│     • Extract domain from URL                               │
└─────────────────────────┬───────────────────────────────────┘
                          │
          ┌───────────────┴───────────────┐
          │                               │
          ▼                               ▼
┌─────────────────────┐       ┌─────────────────────┐
│  _check_ioc_local() │       │  _check_ioc_otx()   │
│  • Feodo Tracker    │       │  • AlienVault OTX   │
│  • URLhaus          │       │  • 200k+ users      │
│  • MalwareBazaar    │       │  • Cached (1 hour)  │
│  (OFFLINE)          │       │  (ONLINE)           │
└─────────┬───────────┘       └─────────┬───────────┘
          │                               │
          └───────────────┬───────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              _calculate_threat_score()                       │
│     • Combines signals from all sources                      │
│     • Returns 0.0-1.0 score + severity level                │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│              _map_malware_to_mitre()                         │
│     • Emotet → T1059.001, T1027, T1547.001                  │
│     • 20+ malware families mapped                           │
└─────────────────────────┬───────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    enrich_ioc()                              │
│              Unified Result Output                           │
└─────────────────────────────────────────────────────────────┘
```

---

## Troubleshooting

### "OTX_API_KEY not set"

**Problem:** OTX checks return error about missing API key.

**Solution:**

```powershell
$env:OTX_API_KEY = "your-api-key-here"
```

---

### "No matches found" for known bad IOCs

**Problem:** Known malicious IOCs return `matched: false`.

**Causes:**

1. Databases not downloaded
2. Database files in wrong location
3. IOC not in database (new threat)

**Solution:**

```powershell
# Verify database files exist
ls "C:\...\knowledge\*.csv"
ls "C:\...\knowledge\*.txt"

# Re-download if missing
Invoke-WebRequest -Uri "https://feodotracker.abuse.ch/downloads/ipblocklist.csv" -OutFile "knowledge\feodo_c2.csv"
```

---

### "Module not found" errors

**Problem:** Python can't find the module.

**Solution:**

```powershell
# Set PYTHONPATH correctly
$env:PYTHONPATH = "src"

# Import with full path
python -c "from cai.tools.threat_intelligence.threat_intelligence import enrich_ioc"
```

---

### STIX bundle creation fails

**Problem:** `stix2 not installed` error.

**Solution:**

```bash
pip install stix2
```

---

## Severity Levels

| Score     | Severity   | Meaning                                            |
| --------- | ---------- | -------------------------------------------------- |
| 0.7+      | `critical` | Confirmed active threat, immediate action required |
| 0.5-0.69  | `high`     | Strong indicators, investigate immediately         |
| 0.3-0.49  | `medium`   | Suspicious, warrants investigation                 |
| 0.01-0.29 | `low`      | Weak indicators, monitor                           |
| 0.0       | `none`     | No threat indicators found                         |

---

## MITRE ATT&CK Mappings

The module automatically maps these malware families to ATT&CK techniques:

| Malware                           | Techniques                                    |
| --------------------------------- | --------------------------------------------- |
| Emotet                            | T1059.001, T1027, T1547.001, T1071.001, T1055 |
| TrickBot                          | T1059.001, T1055, T1003.001, T1071.001        |
| QakBot                            | T1059.001, T1218.011, T1055, T1071.001        |
| Cobalt Strike                     | T1059.001, T1055, T1071.001, T1105, T1021.002 |
| Mimikatz                          | T1003.001, T1003.002, T1003.003               |
| Ransomware (Conti, LockBit, Ryuk) | T1486, T1490, T1027                           |

---

## Support

For issues or questions:

- Check the [Troubleshooting](#troubleshooting) section
- Review error messages (they include suggestions)
- Ensure all prerequisites are installed

---

_Last Updated: March 2024_
_Module Version: 1.0.0_
