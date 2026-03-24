"""
Threat Intelligence enrichment tools for the forensic agent.

Tools provided:
  1. check_ioc_local    — offline lookup against pre-downloaded databases
                          (MalwareBazaar hashes, Feodo Tracker C2 IPs, URLhaus domains)
  2. check_ioc_otx      — online lookup via AlienVault OTX free API (cached)
  3. enrich_ioc         — unified enrichment: local + OTX + threat scoring + MITRE mapping
  4. build_stix_bundle  — creates a professional STIX2.1 bundle from agent findings

Install:  pip install stix2 OTXv2

Offline data (download before use):
  MalwareBazaar:  curl -o knowledge/malwarebazaar.csv "https://bazaar.abuse.ch/export/csv/recent/"
  Feodo Tracker:  curl -o knowledge/feodo_c2.csv "https://feodotracker.abuse.ch/downloads/ipblocklist.csv"
  URLhaus:        curl -o knowledge/urlhaus_domains.txt "https://urlhaus.abuse.ch/downloads/text/"

Environment variables:
  OTX_API_KEY=your_otx_api_key   (free at otx.alienvault.com)
  TI_DATA_PATH=./knowledge       (directory with offline CSV files)
"""
from __future__ import annotations

import csv
import json
import os
import re
import threading
import time
from typing import Any, Optional

from typing_extensions import TypedDict

from cai.sdk.agents import function_tool


# ── Configuration ────────────────────────────────────────────────────────────
OTX_API_KEY = os.environ.get("OTX_API_KEY", "")
TI_DATA_PATH = os.environ.get("TI_DATA_PATH",
    os.path.join(os.path.dirname(__file__), "../../../../knowledge"))


# ── Thread-safe lazy-loaded local databases ──────────────────────────────────
_known_bad_hashes: set[str] | None = None
_known_bad_ips: set[str] | None = None
_known_bad_domains: set[str] | None = None
_hash_to_family: dict[str, str] = {}
_db_lock = threading.Lock()


def _load_local_databases() -> None:
    """Load threat intel databases once (thread-safe)."""
    global _known_bad_hashes, _known_bad_ips, _known_bad_domains, _hash_to_family

    if _known_bad_hashes is not None:
        return

    with _db_lock:
        # Double-check after acquiring lock
        if _known_bad_hashes is not None:
            return

        _known_bad_hashes = set()
        _known_bad_ips = set()
        _known_bad_domains = set()

        # MalwareBazaar — SHA-256 hashes with malware family
        bazaar_path = os.path.join(TI_DATA_PATH, "malwarebazaar.csv")
        if os.path.exists(bazaar_path):
            try:
                with open(bazaar_path, encoding="utf-8", errors="ignore") as f:
                    # Skip comment lines
                    lines = [l for l in f if not l.startswith("#")]
                    reader = csv.DictReader(lines)
                    for row in reader:
                        h = (row.get("sha256_hash") or "").strip().lower()
                        family = (row.get("signature") or row.get("tags") or "unknown").strip()
                        if h and len(h) == 64:
                            _known_bad_hashes.add(h)
                            _hash_to_family[h] = family
            except Exception:
                pass  # Gracefully handle malformed files

        # Feodo Tracker — C2 IP addresses for major botnets
        # CSV columns: first_seen_utc, dst_ip, dst_port, c2_status, last_online, malware
        feodo_path = os.path.join(TI_DATA_PATH, "feodo_c2.csv")
        if os.path.exists(feodo_path):
            try:
                with open(feodo_path, encoding="utf-8", errors="ignore") as f:
                    # Skip comment lines
                    lines = [l for l in f if not l.startswith("#")]
                    reader = csv.DictReader(lines)
                    for row in reader:
                        ip = (row.get("dst_ip") or "").strip().strip('"')
                        if ip and ip[0].isdigit():
                            _known_bad_ips.add(ip)
            except Exception:
                pass

        # URLhaus — malicious domains
        urlhaus_path = os.path.join(TI_DATA_PATH, "urlhaus_domains.txt")
        if os.path.exists(urlhaus_path):
            try:
                with open(urlhaus_path, encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        domain = line.strip().lower()
                        if domain and not domain.startswith("#"):
                            # Extract domain from URL if needed
                            if "://" in domain:
                                domain = domain.split("://")[1].split("/")[0]
                            _known_bad_domains.add(domain)
            except Exception:
                pass


# ── OTX Cache (thread-safe) ──────────────────────────────────────────────────
_otx_cache: dict[str, tuple[str, float]] = {}  # key -> (result_json, timestamp)
_otx_cache_lock = threading.Lock()
_OTX_CACHE_TTL = 3600  # 1 hour


def _get_otx_cached(cache_key: str) -> str | None:
    """Get cached OTX result if not expired."""
    with _otx_cache_lock:
        if cache_key in _otx_cache:
            result, ts = _otx_cache[cache_key]
            if time.time() - ts < _OTX_CACHE_TTL:
                return result
            else:
                del _otx_cache[cache_key]  # Expired
    return None


def _set_otx_cache(cache_key: str, result: str) -> None:
    """Cache OTX result with timestamp."""
    with _otx_cache_lock:
        _otx_cache[cache_key] = (result, time.time())


# ── IOC Normalization ────────────────────────────────────────────────────────
def _normalize_ioc(value: str, ioc_type: str) -> str:
    """
    Normalize IOC for consistent matching.

    Handles:
    - Defanging: evil[.]com -> evil.com, hxxp:// -> http://
    - Case normalization
    - Protocol stripping for domains
    - Whitespace and trailing dots
    """
    if not value:
        return ""

    value = value.strip().lower()

    # Defang common patterns (order matters - do brackets first)
    value = value.replace("[.]", ".")
    value = value.replace("[:]", ":")
    value = value.replace("[:] ", ":")  # Handle spaces after colon brackets
    value = value.replace("[", "")
    value = value.replace("]", "")
    value = value.replace("hxxp://", "http://")
    value = value.replace("hxxps://", "https://")
    value = value.replace("hXXp://", "http://")
    value = value.replace("hXXps://", "https://")

    # Remove trailing dots
    value = value.rstrip(".")

    if ioc_type in ("domain", "url"):
        # Extract domain from URL
        if "://" in value:
            value = value.split("://")[1]
        # Remove path
        value = value.split("/")[0]
        # Remove port
        value = value.split(":")[0]

    if ioc_type == "hash":
        # Remove common separators
        value = value.replace("-", "").replace(" ", "").replace(":", "")

    return value


# ── Private IP detection ─────────────────────────────────────────────────────
_PRIVATE_PREFIXES = (
    "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
    "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.",
    "172.27.", "172.28.", "172.29.", "172.30.", "172.31.",
    "192.168.", "127.", "0.", "::1", "fe80:", "fc00:", "fd00:"
)
_SAFE_IPS = {"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1", "9.9.9.9"}


def _is_private_ip(ip: str) -> bool:
    """Check if IP is private, loopback, or known-safe."""
    ip = ip.strip().lower()
    return ip in _SAFE_IPS or any(ip.startswith(p) for p in _PRIVATE_PREFIXES)


# ── Subdomain matching ───────────────────────────────────────────────────────
def _check_domain_hierarchy(domain: str, known_domains: set[str]) -> tuple[bool, str | None]:
    """
    Check domain and all parent domains against known bad list.

    Example: sub.evil.com checks: sub.evil.com, evil.com
    Returns: (matched, matched_domain)
    """
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        check = ".".join(parts[i:])
        if check in known_domains:
            return True, check
    return False, None


# ── Malware to MITRE mapping ─────────────────────────────────────────────────
_MALWARE_TO_MITRE: dict[str, list[str]] = {
    # Major botnets and malware families
    "emotet": ["T1059.001", "T1027", "T1547.001", "T1071.001", "T1055"],
    "trickbot": ["T1059.001", "T1055", "T1003.001", "T1071.001"],
    "qakbot": ["T1059.001", "T1218.011", "T1055", "T1071.001"],
    "qbot": ["T1059.001", "T1218.011", "T1055", "T1071.001"],
    "icedid": ["T1059.001", "T1055", "T1071.001", "T1547.001"],
    "dridex": ["T1059.001", "T1055", "T1071.001"],
    "cobalt strike": ["T1059.001", "T1055", "T1071.001", "T1105", "T1021.002"],
    "cobaltstrike": ["T1059.001", "T1055", "T1071.001", "T1105", "T1021.002"],
    "mimikatz": ["T1003.001", "T1003.002", "T1003.003"],
    "metasploit": ["T1059", "T1055", "T1071.001", "T1105"],
    "remcos": ["T1059.001", "T1055", "T1071.001", "T1547.001"],
    "njrat": ["T1059.001", "T1055", "T1071.001", "T1547.001"],
    "asyncrat": ["T1059.001", "T1055", "T1071.001"],
    "agent tesla": ["T1059.001", "T1555", "T1056.001"],
    "agenttesla": ["T1059.001", "T1555", "T1056.001"],
    "formbook": ["T1055", "T1056.001", "T1555"],
    "lokibot": ["T1055", "T1555", "T1071.001"],
    "raccoon": ["T1555", "T1539", "T1071.001"],
    "redline": ["T1555", "T1539", "T1071.001"],
    "vidar": ["T1555", "T1539", "T1071.001"],
    "conti": ["T1486", "T1490", "T1027"],
    "lockbit": ["T1486", "T1490", "T1027"],
    "ryuk": ["T1486", "T1490", "T1059.001"],
    "revil": ["T1486", "T1490", "T1027"],
    "sodinokibi": ["T1486", "T1490", "T1027"],
}


def _map_malware_to_mitre(family: str) -> list[str]:
    """Map malware family name to known MITRE ATT&CK techniques."""
    if not family:
        return []
    family_lower = family.lower().strip()
    return _MALWARE_TO_MITRE.get(family_lower, [])


# ── Confidence weights ───────────────────────────────────────────────────────
_CONFIDENCE_WEIGHTS = {
    "malwarebazaar_hash": 0.30,    # Confirmed malware hash
    "feodo_c2_ip": 0.25,           # Known botnet C2
    "urlhaus_domain": 0.20,        # Malware distribution
    "otx_high_pulse": 0.25,        # 10+ OTX pulses
    "otx_medium_pulse": 0.15,      # 5-9 pulses
    "otx_low_pulse": 0.10,         # 1-4 pulses
}


def _calculate_threat_score(
    local_match: bool,
    local_source: str | None,
    otx_pulse_count: int
) -> dict[str, Any]:
    """Calculate unified threat score from all sources."""
    score = 0.0
    signals: list[str] = []

    # Local database matches
    if local_match and local_source:
        if "malwarebazaar" in local_source.lower():
            score += _CONFIDENCE_WEIGHTS["malwarebazaar_hash"]
            signals.append("MalwareBazaar hash match")
        elif "feodo" in local_source.lower():
            score += _CONFIDENCE_WEIGHTS["feodo_c2_ip"]
            signals.append("Feodo Tracker C2 IP")
        elif "urlhaus" in local_source.lower():
            score += _CONFIDENCE_WEIGHTS["urlhaus_domain"]
            signals.append("URLhaus malicious domain")

    # OTX pulses
    if otx_pulse_count >= 10:
        score += _CONFIDENCE_WEIGHTS["otx_high_pulse"]
        signals.append(f"OTX high ({otx_pulse_count} pulses)")
    elif otx_pulse_count >= 5:
        score += _CONFIDENCE_WEIGHTS["otx_medium_pulse"]
        signals.append(f"OTX medium ({otx_pulse_count} pulses)")
    elif otx_pulse_count >= 1:
        score += _CONFIDENCE_WEIGHTS["otx_low_pulse"]
        signals.append(f"OTX low ({otx_pulse_count} pulses)")

    # Cap at 1.0
    score = min(score, 1.0)

    # Severity classification
    if score >= 0.7:
        severity = "critical"
    elif score >= 0.5:
        severity = "high"
    elif score >= 0.3:
        severity = "medium"
    elif score > 0:
        severity = "low"
    else:
        severity = "none"

    return {
        "threat_score": round(score, 2),
        "severity": severity,
        "signals": signals
    }


# ── Type definitions ─────────────────────────────────────────────────────────
class IOCQuery(TypedDict):
    ioc_value: str
    ioc_type: str   # "ip", "domain", "hash", "url"


class STIXBundleInput(TypedDict):
    case_id: str
    findings: str   # JSON string of forensic findings list


# ── Tool 1: Local offline IOC check ──────────────────────────────────────────
def _check_ioc_local_impl(query: IOCQuery) -> str:
    """Check IOC against local offline databases."""
    # Input validation
    raw_value = (query.get("ioc_value") or "").strip()
    ioc_type = (query.get("ioc_type") or "").strip().lower()

    if not raw_value:
        return json.dumps({"error": "ioc_value is required"})
    if not ioc_type:
        return json.dumps({"error": "ioc_type is required"})
    if ioc_type not in ("ip", "domain", "hash", "url"):
        return json.dumps({"error": f"Invalid ioc_type '{ioc_type}'. Use: ip, domain, hash, url"})

    # Normalize IOC
    value = _normalize_ioc(raw_value, ioc_type)

    # Load databases
    _load_local_databases()

    result: dict[str, Any] = {
        "matched": False,
        "ioc_type": ioc_type,
        "ioc_value": value,
        "ioc_raw": raw_value,
        "source": None,
        "threat_info": None,
        "malware_family": None,
        "mitre_techniques": [],
        "databases_checked": []
    }

    if ioc_type == "ip":
        if _is_private_ip(value):
            result["note"] = "Private/loopback/safe IP — skipped"
            return json.dumps(result, indent=2)

        result["databases_checked"].append("feodo_tracker")
        if value in _known_bad_ips:
            result["matched"] = True
            result["source"] = "Feodo Tracker (abuse.ch)"
            result["threat_info"] = "Known botnet C2 server — Emotet/TrickBot/QakBot infrastructure"
            result["mitre_techniques"] = ["T1071.001", "T1105"]

    elif ioc_type in ("domain", "url"):
        result["databases_checked"].append("urlhaus")
        matched, matched_domain = _check_domain_hierarchy(value, _known_bad_domains)
        if matched:
            result["matched"] = True
            result["source"] = "URLhaus (abuse.ch)"
            result["threat_info"] = f"Known malware distribution domain (matched: {matched_domain})"
            result["matched_domain"] = matched_domain
            result["mitre_techniques"] = ["T1071.001", "T1105"]

    elif ioc_type == "hash":
        result["databases_checked"].append("malwarebazaar")
        if value in _known_bad_hashes:
            family = _hash_to_family.get(value, "unknown")
            result["matched"] = True
            result["source"] = "MalwareBazaar (abuse.ch)"
            result["threat_info"] = f"Known malware sample — family: {family}"
            result["malware_family"] = family
            result["mitre_techniques"] = _map_malware_to_mitre(family)
        else:
            result["note"] = "Hash not in MalwareBazaar — may be new, modified, or benign"

    return json.dumps(result, indent=2)


@function_tool
def check_ioc_local(query: IOCQuery) -> str:
    """
    Check an IOC against local offline threat intelligence databases.

    Works entirely offline — no internet required. Databases cover:
      - 1M+ malware file hashes (MalwareBazaar)
      - Known botnet C2 IP addresses (Feodo Tracker: Emotet, TrickBot, QakBot)
      - Malware distribution domains (URLhaus)

    IOCs are automatically normalized (defanged, lowercased, etc).
    Subdomain matching is supported — sub.evil.com matches if evil.com is known bad.

    Use this first for every IOC. Only call OTX if this returns no match.

    Args:
        query: Dict with:
            - ioc_value: the indicator to check — IP, domain, or hash string
            - ioc_type: one of 'ip', 'domain', 'hash', 'url'

    Returns:
        JSON with: matched (bool), ioc_type, ioc_value, source, threat_info,
        malware_family (for hashes), and mitre_techniques mapping.
    """
    return _check_ioc_local_impl(query)


# ── Tool 2: OTX online IOC check (cached) ────────────────────────────────────
def _check_ioc_otx_impl(query: IOCQuery) -> str:
    """Check IOC against AlienVault OTX with caching."""
    # Input validation
    raw_value = (query.get("ioc_value") or "").strip()
    ioc_type = (query.get("ioc_type") or "").strip().lower()

    if not raw_value:
        return json.dumps({"error": "ioc_value is required"})
    if not ioc_type:
        return json.dumps({"error": "ioc_type is required"})

    if not OTX_API_KEY:
        return json.dumps({
            "error": "OTX_API_KEY not set. Get a free key at otx.alienvault.com",
            "matched": False
        })

    # Normalize IOC
    value = _normalize_ioc(raw_value, ioc_type)

    if ioc_type == "ip" and _is_private_ip(value):
        return json.dumps({"matched": False, "note": "Private IP — skipped"})

    # Check cache first
    cache_key = f"{ioc_type}:{value}"
    cached = _get_otx_cached(cache_key)
    if cached:
        result = json.loads(cached)
        result["from_cache"] = True
        return json.dumps(result, indent=2)

    try:
        from OTXv2 import IndicatorTypes, OTXv2
        otx = OTXv2(OTX_API_KEY)

        result: dict[str, Any] = {
            "matched": False,
            "ioc_type": ioc_type,
            "ioc_value": value,
            "pulse_count": 0,
            "malware_families": [],
            "threat_score": 0,
            "country": None,
            "source": "AlienVault OTX",
            "from_cache": False
        }

        # Determine indicator type
        if ioc_type == "hash":
            clean = value.replace("-", "").replace(" ", "")
            if len(clean) == 32:
                ind_type = IndicatorTypes.FILE_HASH_MD5
            elif len(clean) == 40:
                ind_type = IndicatorTypes.FILE_HASH_SHA1
            else:
                ind_type = IndicatorTypes.FILE_HASH_SHA256
            details = otx.get_indicator_details_full(ind_type, clean)
        elif ioc_type == "ip":
            details = otx.get_indicator_details_full(IndicatorTypes.IPv4, value)
        elif ioc_type == "domain":
            details = otx.get_indicator_details_full(IndicatorTypes.DOMAIN, value)
        elif ioc_type == "url":
            details = otx.get_indicator_details_full(IndicatorTypes.URL, value)
        else:
            return json.dumps({"error": f"Unsupported ioc_type: {ioc_type}"})

        # Extract pulse info
        general = details.get("general", {})
        pulse_info = general.get("pulse_info", {})
        pulse_count = pulse_info.get("count", 0)
        pulses = pulse_info.get("pulses", [])

        # Extract malware families from pulse tags
        families: set[str] = set()
        for pulse in pulses[:10]:
            for tag in pulse.get("tags", []):
                tag_lower = tag.lower()
                if tag_lower not in ("apt", "malware", "rat", "trojan", "ransomware", "phishing"):
                    families.add(tag)

        result["pulse_count"] = pulse_count
        result["malware_families"] = list(families)[:5]
        result["country"] = general.get("country_name")

        if pulse_count > 0:
            result["matched"] = True
            result["threat_score"] = min(pulse_count / 50.0, 1.0)

        # Cache the result
        result_json = json.dumps(result, indent=2)
        _set_otx_cache(cache_key, result_json)

        return result_json

    except ImportError:
        return json.dumps({
            "error": "OTXv2 not installed. Run: pip install OTXv2",
            "matched": False
        })
    except Exception as e:
        return json.dumps({
            "error": f"OTX API error: {str(e)[:200]}",
            "matched": False
        })


@function_tool
def check_ioc_otx(query: IOCQuery) -> str:
    """
    Check an IOC against AlienVault OTX (Open Threat Exchange).

    OTX is the world's largest open threat intelligence community with 200,000+
    participants sharing threat data. Results are cached for 1 hour to prevent
    API spam and improve latency.

    Requires: OTX_API_KEY environment variable (free at otx.alienvault.com)

    Only call this when:
      1. Local check found no match, OR
      2. You want additional context beyond local DB

    Args:
        query: Dict with:
            - ioc_value: the indicator to check
            - ioc_type: one of 'ip', 'domain', 'hash', 'url'

    Returns:
        JSON with: matched (bool), pulse_count, malware_families, country,
        threat_score, and from_cache flag.
    """
    return _check_ioc_otx_impl(query)


# ── Tool 3: Unified IOC enrichment ───────────────────────────────────────────
def _enrich_ioc_impl(query: IOCQuery) -> str:
    """Enrich IOC with all sources and unified scoring."""
    # Input validation
    raw_value = (query.get("ioc_value") or "").strip()
    ioc_type = (query.get("ioc_type") or "").strip().lower()

    if not raw_value:
        return json.dumps({"error": "ioc_value is required"})
    if not ioc_type:
        return json.dumps({"error": "ioc_type is required"})

    value = _normalize_ioc(raw_value, ioc_type)

    # Check local first
    local_result = json.loads(_check_ioc_local_impl(query))

    # Check OTX if API key available
    otx_result: dict[str, Any] = {"matched": False, "pulse_count": 0}
    if OTX_API_KEY:
        try:
            otx_result = json.loads(_check_ioc_otx_impl(query))
        except Exception:
            pass

    # Calculate unified threat score
    threat_assessment = _calculate_threat_score(
        local_match=local_result.get("matched", False),
        local_source=local_result.get("source"),
        otx_pulse_count=otx_result.get("pulse_count", 0)
    )

    # Combine MITRE techniques from all sources
    mitre_techniques: list[str] = list(set(
        local_result.get("mitre_techniques", []) +
        _map_malware_to_mitre(local_result.get("malware_family", ""))
    ))

    # Build unified result
    result = {
        "ioc_type": ioc_type,
        "ioc_value": value,
        "ioc_raw": raw_value,
        "matched": local_result.get("matched", False) or otx_result.get("matched", False),
        "threat_score": threat_assessment["threat_score"],
        "severity": threat_assessment["severity"],
        "signals": threat_assessment["signals"],
        "sources": {
            "local": {
                "matched": local_result.get("matched", False),
                "source": local_result.get("source"),
                "threat_info": local_result.get("threat_info"),
                "malware_family": local_result.get("malware_family")
            },
            "otx": {
                "matched": otx_result.get("matched", False),
                "pulse_count": otx_result.get("pulse_count", 0),
                "malware_families": otx_result.get("malware_families", []),
                "country": otx_result.get("country"),
                "from_cache": otx_result.get("from_cache", False)
            }
        },
        "mitre_techniques": mitre_techniques
    }

    return json.dumps(result, indent=2)


@function_tool
def enrich_ioc(query: IOCQuery) -> str:
    """
    Unified IOC enrichment: local databases + OTX + threat scoring + MITRE mapping.

    This is the recommended tool for IOC analysis. It:
      1. Normalizes the IOC (defang, lowercase, etc)
      2. Checks local offline databases (abuse.ch)
      3. Checks OTX if API key is available (cached)
      4. Calculates unified threat score (0.0-1.0)
      5. Maps to MITRE ATT&CK techniques
      6. Returns combined intelligence

    Args:
        query: Dict with:
            - ioc_value: the indicator to check
            - ioc_type: one of 'ip', 'domain', 'hash', 'url'

    Returns:
        JSON with unified intelligence: matched, threat_score, severity,
        signals from each source, and mitre_techniques mapping.
    """
    return _enrich_ioc_impl(query)


# ── Tool 4: Create STIX2 bundle from forensic findings ───────────────────────
def _build_stix_bundle_impl(input_data: STIXBundleInput) -> str:
    """Create STIX 2.1 bundle from forensic findings."""
    # Input validation
    case_id = (input_data.get("case_id") or "").strip()
    findings_raw = input_data.get("findings")

    if not case_id:
        return json.dumps({"error": "case_id is required"})
    if not findings_raw:
        return json.dumps({"error": "findings is required"})

    try:
        import stix2
        from datetime import datetime, timezone
    except ImportError:
        return json.dumps({"error": "stix2 not installed. Run: pip install stix2"})

    try:
        events = json.loads(findings_raw) if isinstance(findings_raw, str) else findings_raw
    except Exception as e:
        return json.dumps({"error": f"Could not parse findings JSON: {str(e)}"})

    if not isinstance(events, list):
        return json.dumps({"error": "findings must be a JSON array"})

    now = datetime.now(timezone.utc)
    objects: list[Any] = []

    # TLP:CLEAR marking
    try:
        tlp_clear = stix2.MarkingDefinition(
            definition_type="statement",
            definition=stix2.StatementMarking(statement="TLP:CLEAR")
        )
        objects.append(tlp_clear)
        common_refs = {"object_marking_refs": [tlp_clear.id]}
    except Exception:
        common_refs = {}

    # Track created objects
    seen_ips: dict[str, str] = {}
    seen_domains: dict[str, str] = {}
    seen_hashes: dict[str, str] = {}
    seen_malware: dict[str, str] = {}
    seen_patterns: dict[str, str] = {}
    relationships: list[tuple[str, str, str]] = []

    for event in events:
        if not isinstance(event, dict):
            continue

        # ── IPv4Address SCOs ─────────────────────────────────────────────────
        remote_ip = event.get("remote_ip")
        if remote_ip and not _is_private_ip(remote_ip) and remote_ip not in seen_ips:
            try:
                ip_obj = stix2.IPv4Address(value=remote_ip)
                seen_ips[remote_ip] = ip_obj.id
                objects.append(ip_obj)

                # Create Indicator for this IP
                pattern = f"[ipv4-addr:value = '{remote_ip}']"
                confidence = int(float(event.get("confidence", 0.5)) * 100)
                ind = stix2.Indicator(
                    name=f"Malicious IP: {remote_ip}",
                    pattern=pattern,
                    pattern_type="stix",
                    indicator_types=["malicious-activity"],
                    confidence=confidence,
                    description=f"IP found in forensic artifact — {event.get('event_type', '')}",
                    valid_from=now,
                    **common_refs
                )
                objects.append(ind)
                relationships.append((ind.id, ip_obj.id, "based-on"))
            except Exception:
                pass

        # ── Malware SDOs from YARA ───────────────────────────────────────────
        yara_rule = event.get("yara_rule")
        if yara_rule and yara_rule not in seen_malware:
            try:
                malware_name = yara_rule.replace("_", " ").replace("-", " ").title()
                mal = stix2.Malware(
                    name=malware_name,
                    is_family=True,
                    description=f"Detected via YARA rule: {yara_rule}",
                    **common_refs
                )
                seen_malware[yara_rule] = mal.id
                objects.append(mal)
            except Exception:
                pass

        # ── AttackPattern SDOs from MITRE ────────────────────────────────────
        mitre_id = event.get("mitre_technique_id")
        mitre_name = event.get("mitre_technique_name")
        if mitre_id and mitre_id not in seen_patterns:
            try:
                ap = stix2.AttackPattern(
                    name=mitre_name or mitre_id,
                    description=f"MITRE ATT&CK: {mitre_id}",
                    external_references=[
                        stix2.ExternalReference(
                            source_name="mitre-attack",
                            external_id=mitre_id,
                            url=f"https://attack.mitre.org/techniques/{mitre_id.replace('.', '/')}/"
                        )
                    ],
                    **common_refs
                )
                seen_patterns[mitre_id] = ap.id
                objects.append(ap)

                # Link malware to THIS specific technique if both present in same event
                if yara_rule and yara_rule in seen_malware:
                    relationships.append((seen_malware[yara_rule], ap.id, "uses"))
            except Exception:
                pass

        # ── File SCOs from hashes ────────────────────────────────────────────
        file_hash = event.get("file_hash")
        if file_hash and file_hash not in seen_hashes:
            try:
                hash_type = "MD5" if len(file_hash) == 32 else "SHA-1" if len(file_hash) == 40 else "SHA-256"
                file_obj = stix2.File(
                    name=event.get("process_name") or "unknown",
                    hashes={hash_type: file_hash}
                )
                seen_hashes[file_hash] = file_obj.id
                objects.append(file_obj)
            except Exception:
                pass

    # ── Create relationships ─────────────────────────────────────────────────
    seen_rels: set[str] = set()
    for source_id, target_id, rel_type in relationships:
        rel_key = f"{source_id}-{rel_type}-{target_id}"
        if rel_key not in seen_rels:
            try:
                rel = stix2.Relationship(
                    relationship_type=rel_type,
                    source_ref=source_id,
                    target_ref=target_id,
                    **common_refs
                )
                objects.append(rel)
                seen_rels.add(rel_key)
            except Exception:
                pass

    # ── Report SDO ───────────────────────────────────────────────────────────
    try:
        report_refs = [o.id for o in objects if hasattr(o, 'id')][:50]
        report = stix2.Report(
            name=f"Forensic Analysis — {case_id}",
            description=f"Automated forensic analysis. Case: {case_id}",
            published=now,
            report_types=["threat-actor", "malware", "attack-pattern"],
            object_refs=report_refs if report_refs else [tlp_clear.id] if 'tlp_clear' in dir() else [],
            **common_refs
        )
        objects.append(report)
    except Exception:
        pass

    # ── Bundle ───────────────────────────────────────────────────────────────
    try:
        bundle = stix2.Bundle(objects=objects, allow_custom=True)
        bundle_json = json.loads(bundle.serialize())
    except Exception as e:
        return json.dumps({"error": f"Failed to create bundle: {str(e)}"})

    return json.dumps({
        "status": "success",
        "case_id": case_id,
        "object_count": len(objects),
        "bundle": bundle_json,
        "summary": {
            "malicious_ips": len(seen_ips),
            "malware_families": len(seen_malware),
            "attack_patterns": len(seen_patterns),
            "file_hashes": len(seen_hashes),
            "relationships": len(seen_rels)
        }
    }, indent=2)


@function_tool
def build_stix_bundle(input_data: STIXBundleInput) -> str:
    """
    Create a professional STIX 2.1 bundle from forensic findings.

    Converts normalized forensic events into machine-readable threat intelligence
    that any SIEM, TIP, or security tool can import. Relationships are created
    ONLY when evidence links objects (e.g., malware → technique in same event).

    The bundle contains:
      - IPv4Address SCOs for malicious IPs
      - Indicator SDOs with STIX patterns
      - Malware SDOs from YARA matches
      - AttackPattern SDOs from MITRE mappings
      - Relationship objects (evidence-based only)
      - Report SDO summarizing the case

    Args:
        input_data: Dict with:
            - case_id: the case identifier string
            - findings: JSON string — list of forensic event dicts

    Returns:
        JSON with status, object_count, the complete STIX bundle,
        and a summary of created objects.
    """
    return _build_stix_bundle_impl(input_data)
