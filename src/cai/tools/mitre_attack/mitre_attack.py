"""
MITRE ATT&CK forensic correlation tools.

Uses the official mitreattack-python library to map forensic findings
to ATT&CK techniques, tactics, and sub-techniques entirely offline.

Install: pip install mitreattack-python
Download data: python -c "from mitreattack.stix20 import MitreAttackData; MitreAttackData('enterprise-attack.json')"

Or download manually from:
  https://github.com/mitre/cti/raw/master/enterprise-attack/enterprise-attack.json
Place the file at: knowledge/enterprise-attack.json
"""
from __future__ import annotations

import json
import os
import threading
from typing import Optional

from typing_extensions import TypedDict

from cai.sdk.agents import function_tool


# ── Data file path ───────────────────────────────────────────────────────────
# Default location. Override with MITRE_ATTACK_DATA env var.
_DEFAULT_DATA_PATH = os.path.join(
    os.path.dirname(__file__), "../../../../knowledge/enterprise-attack.json"
)
MITRE_DATA_PATH = os.environ.get("MITRE_ATTACK_DATA", _DEFAULT_DATA_PATH)


# ── Thread-safe lazy-loaded singleton ────────────────────────────────────────
_attack_data = None
_attack_data_lock = threading.Lock()


def _get_attack_data():
    """Load ATT&CK data once and cache it for the process lifetime (thread-safe)."""
    global _attack_data
    if _attack_data is None:
        with _attack_data_lock:
            # Double-check after acquiring lock
            if _attack_data is None:
                try:
                    from mitreattack.stix20 import MitreAttackData
                    _attack_data = MitreAttackData(MITRE_DATA_PATH)
                except FileNotFoundError:
                    raise RuntimeError(
                        f"MITRE ATT&CK data file not found at: {MITRE_DATA_PATH}\n"
                        "Download it from: https://github.com/mitre/cti/raw/master/"
                        "enterprise-attack/enterprise-attack.json\n"
                        "Then set MITRE_ATTACK_DATA env var to its path."
                    )
                except ImportError:
                    raise RuntimeError(
                        "mitreattack-python not installed. Run: pip install mitreattack-python"
                    )
    return _attack_data


# ── Type definitions ─────────────────────────────────────────────────────────
class TechniqueQuery(TypedDict):
    technique_id: str


class KeywordQuery(TypedDict):
    keyword: str


class TacticQuery(TypedDict):
    tactic_name: str


class ForensicEventQuery(TypedDict):
    process_name: Optional[str]
    command_line: Optional[str]
    registry_key: Optional[str]
    network_port: Optional[int]
    source_tool: Optional[str]


# ── Tools ────────────────────────────────────────────────────────────────────
def _get_technique_by_id_impl(query: TechniqueQuery) -> str:
    """Look up a MITRE ATT&CK technique by its ID and return full details."""
    # Input validation
    tid = (query.get("technique_id") or "").strip().upper()
    if not tid:
        return json.dumps({"error": "technique_id is required"})

    attack = _get_attack_data()

    technique = attack.get_object_by_attack_id(tid, "attack-pattern")
    if not technique:
        return json.dumps({"error": f"Technique {tid} not found in ATT&CK dataset"})

    # Extract tactic(s) from kill chain phases
    tactics = []
    for phase in getattr(technique, "kill_chain_phases", []) or []:
        if getattr(phase, "kill_chain_name", "") == "mitre-attack":
            tactics.append(phase.phase_name.replace("-", " ").title())

    # Extract data sources
    data_sources = getattr(technique, "x_mitre_data_sources", []) or []

    # Extract detection text
    detection = getattr(technique, "x_mitre_detection", "No detection guidance available.") or "No detection guidance available."

    description = getattr(technique, "description", "") or ""
    if len(description) > 500:
        description = description[:500] + "..."

    result = {
        "technique_id":   tid,
        "technique_name": getattr(technique, "name", "Unknown"),
        "tactics":        tactics,
        "description":    description,
        "detection":      detection[:600] if len(detection) > 600 else detection,
        "data_sources":   data_sources[:8],   # cap to avoid flooding context
        "is_subtechnique": "." in tid,
        "url": f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
    }
    return json.dumps(result, indent=2)


@function_tool
def get_technique_by_id(query: TechniqueQuery) -> str:
    """
    Look up a MITRE ATT&CK technique by its ID and return full details.

    Use this when you already know the technique ID (e.g. T1059.001) and
    need the full description, tactic, detection guidance, and data sources.

    Args:
        query: Dict with key 'technique_id' — the ATT&CK ID such as
               'T1059', 'T1059.001', 'T1055', 'T1003.001'.

    Returns:
        JSON string with technique name, ID, tactic, description (truncated),
        detection guidance, and relevant data sources. Returns an error
        message if the technique is not found.
    """
    return _get_technique_by_id_impl(query)


def _search_techniques_by_keyword_impl(query: KeywordQuery) -> str:
    """Search MITRE ATT&CK techniques by keyword in name or description."""
    # Input validation
    keyword = (query.get("keyword") or "").strip().lower()
    if not keyword:
        return json.dumps({"error": "keyword is required"})

    attack = _get_attack_data()
    all_techniques = attack.get_techniques(remove_revoked_deprecated=True)

    matches = []
    for technique in all_techniques:
        name = getattr(technique, "name", "").lower()
        desc = getattr(technique, "description", "").lower()

        if keyword in name or keyword in desc:
            tactics = []
            for phase in getattr(technique, "kill_chain_phases", []) or []:
                if getattr(phase, "kill_chain_name", "") == "mitre-attack":
                    tactics.append(phase.phase_name.replace("-", " ").title())

            # Get the ATT&CK ID from external references
            attack_id = ""
            for ref in getattr(technique, "external_references", []) or []:
                if getattr(ref, "source_name", "") == "mitre-attack":
                    attack_id = getattr(ref, "external_id", "")
                    break

            if attack_id:
                desc_text = getattr(technique, "description", "") or ""
                matches.append({
                    "technique_id":   attack_id,
                    "technique_name": getattr(technique, "name", ""),
                    "tactics":        tactics,
                    "description":    desc_text[:200] + "..." if len(desc_text) > 200 else desc_text,
                })

        if len(matches) >= 5:
            break

    return json.dumps(matches, indent=2)


@function_tool
def search_techniques_by_keyword(query: KeywordQuery) -> str:
    """
    Search MITRE ATT&CK techniques by keyword in name or description.

    Use this when you have a forensic observation (e.g. 'encoded PowerShell',
    'process injection', 'registry run key', 'LSASS dump') and need to find
    the matching ATT&CK technique ID and tactic.

    Args:
        query: Dict with key 'keyword' — a forensic term or attack concept
               such as 'powershell', 'process injection', 'credential dump',
               'registry persistence', 'lateral movement smb'.

    Returns:
        JSON list of up to 5 matching techniques, each with ID, name, tactic,
        and a short description. Returns empty list if no match found.
    """
    return _search_techniques_by_keyword_impl(query)


def _get_techniques_by_tactic_impl(query: TacticQuery) -> str:
    """List all ATT&CK techniques that belong to a specific tactic."""
    # Input validation
    tactic_slug = (query.get("tactic_name") or "").strip().lower().replace(" ", "-")
    if not tactic_slug:
        return json.dumps({"error": "tactic_name is required"})

    attack = _get_attack_data()
    all_techniques = attack.get_techniques_by_tactic(
        tactic_shortname=tactic_slug,
        domain="enterprise-attack",
        remove_revoked_deprecated=True
    )

    if not all_techniques:
        valid = [
            "initial-access", "execution", "persistence", "privilege-escalation",
            "defense-evasion", "credential-access", "discovery", "lateral-movement",
            "collection", "command-and-control", "exfiltration", "impact"
        ]
        return json.dumps({
            "error": f"Tactic '{tactic_slug}' not found.",
            "valid_tactics": valid
        })

    results = []
    for t in all_techniques:
        attack_id = ""
        for ref in getattr(t, "external_references", []) or []:
            if getattr(ref, "source_name", "") == "mitre-attack":
                attack_id = getattr(ref, "external_id", "")
                break
        if attack_id:
            results.append({
                "technique_id":   attack_id,
                "technique_name": getattr(t, "name", ""),
                "is_subtechnique": "." in attack_id,
            })

    results.sort(key=lambda x: x["technique_id"])
    return json.dumps({
        "tactic":          tactic_slug,
        "technique_count": len(results),
        "techniques":      results
    }, indent=2)


@function_tool
def get_techniques_by_tactic(query: TacticQuery) -> str:
    """
    List all ATT&CK techniques that belong to a specific tactic.

    Use this when the analyst needs to understand all possible attack techniques
    for a given kill-chain phase — for example listing all 'Execution' techniques
    to check if a suspicious process matches any of them.

    Valid tactic names (case-insensitive):
        initial-access, execution, persistence, privilege-escalation,
        defense-evasion, credential-access, discovery, lateral-movement,
        collection, command-and-control, exfiltration, impact

    Args:
        query: Dict with key 'tactic_name' — one of the valid tactic names above.

    Returns:
        JSON list of techniques in that tactic, each with ID, name, and
        sub-technique count. Returns error if tactic name is invalid.
    """
    return _get_techniques_by_tactic_impl(query)


def _map_forensic_event_to_mitre_impl(query: ForensicEventQuery) -> str:
    """Map a forensic observation to the most likely MITRE ATT&CK technique(s)."""
    pname    = (query.get("process_name") or "").lower()
    cmdline  = (query.get("command_line") or "").lower()
    reg_key  = (query.get("registry_key") or "").lower()
    port     = query.get("network_port")
    src_tool = (query.get("source_tool") or "").lower()

    # Rule-based matching — deterministic, no LLM required
    # Each rule: (technique_id, confidence, signal_description)
    matches: list[tuple[str, str, str]] = []

    # ── Execution ────────────────────────────────────────────────────────────
    if "powershell" in pname or "powershell" in cmdline:
        confidence = "high" if any(x in cmdline for x in ["-enc", "-encodedcommand", "iex", "invoke-expression", "downloadstring"]) else "medium"
        matches.append(("T1059.001", confidence, "PowerShell process or command detected"))

    if "cmd.exe" in pname:
        matches.append(("T1059.003", "medium", "Windows Command Shell (cmd.exe) execution"))

    if any(x in pname for x in ["wscript.exe", "cscript.exe"]):
        matches.append(("T1059.005", "medium", "Windows Script Host execution (wscript/cscript)"))

    if any(x in pname for x in ["mshta.exe"]):
        matches.append(("T1218.005", "high", "Signed binary proxy execution via mshta.exe"))

    if any(x in pname for x in ["regsvr32.exe"]):
        matches.append(("T1218.010", "high", "Signed binary proxy execution via regsvr32.exe"))

    if any(x in pname for x in ["rundll32.exe"]):
        matches.append(("T1218.011", "medium", "Signed binary proxy execution via rundll32.exe"))

    # ── Defense Evasion ──────────────────────────────────────────────────────
    if src_tool == "volatility_malfind":
        matches.append(("T1055", "high", "Process injection detected by malfind (execute+write VAD region)"))

    if any(x in cmdline for x in ["-enc", "-encodedcommand", "frombase64string"]):
        matches.append(("T1140", "high", "Deobfuscate/Decode — base64-encoded command found"))

    if any(x in cmdline for x in ["bypass", "-executionpolicy bypass"]):
        matches.append(("T1562.001", "medium", "Execution policy bypass — defense impairment"))

    # ── Credential Access ────────────────────────────────────────────────────
    if "lsass" in pname:
        matches.append(("T1003.001", "high", "LSASS memory access — credential dumping indicator"))

    if any(x in cmdline for x in ["mimikatz", "sekurlsa", "logonpasswords"]):
        matches.append(("T1003.001", "high", "Mimikatz credential dumping tool detected"))

    if any(x in pname for x in ["hashdump", "wce.exe", "pwdump"]):
        matches.append(("T1003", "high", "Known credential dumping tool name detected"))

    # ── Persistence ──────────────────────────────────────────────────────────
    if "currentversion\\run" in reg_key or "currentversion\\runonce" in reg_key:
        matches.append(("T1547.001", "high", "Registry Run key modification — persistence mechanism"))

    if "\\services\\" in reg_key:
        matches.append(("T1543.003", "medium", "Windows Service registry modification"))

    if any(x in cmdline for x in ["schtasks", "at.exe"]):
        matches.append(("T1053.005", "medium", "Scheduled task creation via schtasks or at.exe"))

    # ── C2 / Network ─────────────────────────────────────────────────────────
    if port in (4444, 4445, 8443, 1337, 31337):
        matches.append(("T1071.001", "high", f"Known malware C2 port {port} in network connection"))

    if port in (443, 80, 8080) and pname and pname not in ("chrome.exe", "firefox.exe", "msedge.exe", "iexplore.exe"):
        matches.append(("T1071.001", "medium", f"Unexpected process {pname} communicating on web port {port}"))

    if port == 445:
        matches.append(("T1021.002", "medium", "SMB connection on port 445 — lateral movement indicator"))

    if port == 3389:
        matches.append(("T1021.001", "medium", "RDP connection on port 3389 — lateral movement indicator"))

    # ── Discovery ────────────────────────────────────────────────────────────
    if any(x in cmdline for x in ["net user", "net group", "whoami", "ipconfig", "systeminfo"]):
        matches.append(("T1033", "medium", "User/system discovery commands in command line"))

    if any(x in cmdline for x in ["net view", "nltest", "nslookup", "ping"]):
        matches.append(("T1018", "low", "Remote system discovery commands detected"))

    # ── Impact ───────────────────────────────────────────────────────────────
    if any(x in cmdline for x in ["vssadmin delete", "wbadmin delete", "bcdedit /set"]):
        matches.append(("T1490", "high", "Inhibit system recovery — ransomware preparation indicator"))

    if not matches:
        return json.dumps({
            "matches": [],
            "message": "No ATT&CK technique could be mapped from the provided forensic evidence. "
                       "Try searching with search_techniques_by_keyword instead."
        })

    # Enrich each match with full technique details from the ATT&CK dataset
    attack = _get_attack_data()
    enriched = []
    seen_ids: set[str] = set()
    for tid, confidence, signal in matches:
        if tid in seen_ids:
            continue
        seen_ids.add(tid)

        technique = attack.get_object_by_attack_id(tid, "attack-pattern")
        tactic_name = "Unknown"
        technique_name = tid

        if technique:
            technique_name = getattr(technique, "name", tid)
            for phase in getattr(technique, "kill_chain_phases", []) or []:
                if getattr(phase, "kill_chain_name", "") == "mitre-attack":
                    tactic_name = phase.phase_name.replace("-", " ").title()
                    break

        enriched.append({
            "technique_id":   tid,
            "technique_name": technique_name,
            "tactic":         tactic_name,
            "confidence":     confidence,
            "forensic_signal": signal,
            "url":            f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"
        })

    # Sort: high confidence first
    order = {"high": 0, "medium": 1, "low": 2}
    enriched.sort(key=lambda x: order.get(x["confidence"], 3))

    return json.dumps({"matches": enriched}, indent=2)


@function_tool
def map_forensic_event_to_mitre(query: ForensicEventQuery) -> str:
    """
    Map a forensic observation to the most likely MITRE ATT&CK technique(s).

    This is the primary tool for the forensic agent. Given a forensic event
    from memory or disk analysis, return the matching ATT&CK technique(s)
    with confidence reasoning.

    Provide as many fields as available for better matching accuracy.
    At least one field must be non-null.

    Args:
        query: Dict with optional forensic evidence fields:
            - process_name: process name e.g. 'powershell.exe', 'lsass.exe'
            - command_line: full command line e.g. 'powershell -enc aQBlAHgA'
            - registry_key: registry path e.g. 'HKLM\\...\\CurrentVersion\\Run'
            - network_port: remote port number e.g. 4444, 443, 445
            - source_tool:  which forensic tool produced this e.g. 'volatility_malfind'

    Returns:
        JSON object with a ranked list of matching MITRE techniques, each with
        technique ID, name, tactic, confidence (high/medium/low), and the
        specific forensic signal that triggered the match.
    """
    return _map_forensic_event_to_mitre_impl(query)
