"""
Forensic Tools - Simplified
Uses cai.tools directly. The heavy lifting is done by:
- cai.tools.reconnaissance.generic_linux_command (command execution with guardrails)
- cai.tools.mitre_attack.mitre_attack (MITRE ATT&CK mapping)
- cai.tools.forensics_common (IOC extraction, artifact enrichment)

This module provides:
- ALLOWED_TOOLS: list of allowed forensic tool names (for display/catalog)
- ForensicTools: thin wrapper that integrates with cai tools
"""
from typing import List, Dict, Any, Optional


# ============================================================================
# Allowed Tools Catalog
# ============================================================================

ALLOWED_TOOLS = [
    # Memory Forensics
    "volatility", "vol3", "vol.py", "rekall",
    # Disk Forensics
    "mmls", "fls", "icat", "fsstat", "binwalk", "foremost", "bulk_extractor",
    # Malware Analysis
    "yara", "clamscan", "peframe", "objdump", "readelf", "exiftool",
    # Network Forensics
    "tshark", "tcpdump", "zeek", "suricata", "tcpflow",
    # Log Analysis
    "chainsaw", "hayabusa", "evtxdump", "journalctl", "ausearch",
    # General Tools
    "strings", "file", "xxd", "hexdump", "md5sum", "sha256sum",
    "grep", "python3", "cat", "head", "tail", "awk", "sed",
    "find", "ls", "stat", "wc", "sort", "uniq", "base64",
]
