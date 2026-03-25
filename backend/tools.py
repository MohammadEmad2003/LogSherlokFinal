"""
Forensic Tools and Command Execution Module
Provides safe, generic command execution with guardrails
"""
import subprocess
import shlex
import re
import time
import hashlib
from typing import List, Dict, Tuple, Optional, Any
from pathlib import Path
from datetime import datetime

from schemas import CommandExecution, ToolResult, Evidence, GuardrailCheck, SafetyViolation


# ============================================================================
# Guardrails and Safety Checks
# ============================================================================

# Dangerous commands that should never be executed
BLOCKED_COMMANDS = [
    'rm -rf /',
    'dd if=/dev/zero',
    'mkfs',
    'format',
    ':(){ :|:& };:',  # Fork bomb
    'chmod -R 777 /',
    'wget', 'curl',  # Prevent network access
    'nc', 'netcat',
    'shutdown', 'reboot', 'halt',
    'init 0', 'init 6',
]

# Allowed forensic tools - comprehensive list
ALLOWED_TOOLS = [
    # Memory Forensics
    'volatility', 'vol.py', 'vol3', 'rekall',

    # Disk Forensics - Sleuth Kit
    'mmls', 'fls', 'icat', 'ils', 'fsstat', 'blkcat', 'blkls', 'blkstat',
    'ffind', 'ifind', 'istat', 'jcat', 'jls', 'mactime', 'sigfind', 'sorter',

    # File Analysis & Recovery
    'binwalk', 'foremost', 'bulk_extractor', 'scalpel', 'photorec',

    # Malware Analysis
    'yara', 'clamav', 'clamscan', 'clamdscan',
    'pefile', 'peframe', 'pescanner', 'pescan',
    'objdump', 'readelf', 'nm', 'ldd',

    # Network Forensics
    'tshark', 'tcpdump', 'ngrep', 'tcpflow', 'tcpxtract',
    'zeek', 'bro', 'snort', 'suricata',

    # Log Analysis - Windows
    'evtxdump', 'evtx_dump', 'chainsaw', 'hayabusa',
    'logparser', 'wevtutil',

    # Log Analysis - Linux
    'journalctl', 'ausearch', 'aureport',

    # General System Tools
    'strings', 'file', 'stat', 'ls', 'cat', 'grep', 'find',
    'head', 'tail', 'less', 'more', 'wc', 'sort', 'uniq',
    'awk', 'sed', 'cut', 'tr', 'xargs',

    # Metadata & Hashing
    'exiftool', 'xxd', 'hexdump', 'od',
    'md5sum', 'sha1sum', 'sha256sum', 'sha512sum', 'ssdeep',

    # MITRE ATT&CK Tools
    'mitre_attack', 'attack_lookup', 'mitre_navigator',
    'atomic_red_team', 'caldera',

    # Threat Intelligence
    'threat_intel', 'ioc_lookup', 'virustotal', 'vt',
    'greynoise', 'shodan', 'censys', 'otx',
    'misp', 'opencti', 'yeti',

    # Timeline Analysis
    'log2timeline', 'plaso', 'psort', 'psteal',

    # Registry Analysis (Windows)
    'regripper', 'rip', 'reglookup',

    # Browser Forensics
    'hindsight', 'browserhist',

    # Email Forensics
    'pffexport', 'readpst',

    # Mobile Forensics
    'adb', 'idevice',

    # Container/Cloud
    'docker', 'kubectl',

    # Scripting
    'python', 'python3', 'ruby', 'perl',
    'bash', 'sh', 'zsh',

    # JSON/Data Processing
    'jq', 'yq', 'xmllint',
]

# Maximum execution time (seconds)
MAX_EXECUTION_TIME = 300  # 5 minutes

# Maximum consecutive failed commands
MAX_FAILED_COMMANDS = 5


class CommandGuardrail:
    """Validates and sanitizes commands before execution"""

    def __init__(self):
        self.failed_commands_count = 0
        self.command_history: List[str] = []
        self.loop_detection_window = 10

    def validate_command(self, command: str) -> GuardrailCheck:
        """Validate command for safety"""

        # Check for blocked patterns
        for blocked in BLOCKED_COMMANDS:
            if blocked in command.lower():
                return GuardrailCheck(
                    check_type="command_safety",
                    passed=False,
                    reason=f"Blocked dangerous pattern: {blocked}",
                    severity="critical"
                )

        # Check if command uses allowed tools
        cmd_parts = shlex.split(command)
        if not cmd_parts:
            return GuardrailCheck(
                check_type="command_safety",
                passed=False,
                reason="Empty command",
                severity="warning"
            )

        tool = cmd_parts[0]

        # Allow absolute paths to tools
        if '/' in tool:
            tool = Path(tool).name

        # Check if tool is in allowed list
        tool_allowed = any(allowed in tool.lower() for allowed in ALLOWED_TOOLS)

        if not tool_allowed:
            return GuardrailCheck(
                check_type="command_safety",
                passed=False,
                reason=f"Tool '{tool}' not in allowed list. Use forensic tools only.",
                severity="critical"
            )

        # Check for command injection attempts
        dangerous_chars = [';', '&&', '||', '`', '$(', '|']
        # Allow pipes for forensic tools (grep, etc.)
        if '|' in command:
            # Validate pipe is used properly
            pipe_parts = command.split('|')
            for part in pipe_parts:
                part_cmd = shlex.split(part.strip())[0] if shlex.split(part.strip()) else ""
                part_tool = Path(part_cmd).name if '/' in part_cmd else part_cmd
                if not any(allowed in part_tool.lower() for allowed in ALLOWED_TOOLS):
                    return GuardrailCheck(
                        check_type="command_safety",
                        passed=False,
                        reason=f"Piped command uses disallowed tool: {part_tool}",
                        severity="critical"
                    )

        for char in [';', '&&', '||', '`', '$(']:
            if char in command:
                return GuardrailCheck(
                    check_type="command_safety",
                    passed=False,
                    reason=f"Potential command injection: {char}",
                    severity="critical"
                )

        # Loop detection - check for repeated commands
        if len(self.command_history) >= self.loop_detection_window:
            recent_commands = self.command_history[-self.loop_detection_window:]
            if recent_commands.count(command) > 3:
                return GuardrailCheck(
                    check_type="loop_detection",
                    passed=False,
                    reason=f"Command repeated {recent_commands.count(command)} times - possible loop",
                    severity="warning"
                )

        return GuardrailCheck(
            check_type="command_safety",
            passed=True,
            reason="Command passed safety checks",
            severity="info"
        )

    def check_hallucination(self, command: str, reasoning: str) -> GuardrailCheck:
        """Check if command seems like hallucination"""

        # Check for non-existent tools
        made_up_tools = [
            'super_analyzer', 'magic_tool', 'auto_forensics',
            'smart_scanner', 'detect_all', 'find_malware_instantly'
        ]

        for fake_tool in made_up_tools:
            if fake_tool in command.lower():
                return GuardrailCheck(
                    check_type="hallucination",
                    passed=False,
                    reason=f"Possible hallucination - non-existent tool: {fake_tool}",
                    severity="critical"
                )

        # Check for overly confident reasoning without basis
        overconfident_phrases = [
            'definitely', 'certainly', 'absolutely sure', '100% confident',
            'without doubt', 'guaranteed'
        ]

        confidence_count = sum(1 for phrase in overconfident_phrases if phrase in reasoning.lower())
        if confidence_count > 2:
            return GuardrailCheck(
                check_type="hallucination",
                passed=False,
                reason="Reasoning shows overconfidence - possible hallucination",
                severity="warning"
            )

        return GuardrailCheck(
            check_type="hallucination",
            passed=True,
            reason="No hallucination detected",
            severity="info"
        )

    def update_history(self, command: str, success: bool):
        """Update command history"""
        self.command_history.append(command)
        if not success:
            self.failed_commands_count += 1
        else:
            self.failed_commands_count = 0

    def check_failed_limit(self) -> GuardrailCheck:
        """Check if too many commands have failed"""
        if self.failed_commands_count >= MAX_FAILED_COMMANDS:
            return GuardrailCheck(
                check_type="resource_limit",
                passed=False,
                reason=f"Too many failed commands ({self.failed_commands_count})",
                severity="critical"
            )
        return GuardrailCheck(
            check_type="resource_limit",
            passed=True,
            reason="Within failure limits",
            severity="info"
        )


# ============================================================================
# Command Execution
# ============================================================================

class CommandExecutor:
    """Safe command execution with timeout and resource limits"""

    def __init__(self, guardrail: CommandGuardrail):
        self.guardrail = guardrail

    def execute(self, command: str, timeout: int = MAX_EXECUTION_TIME) -> CommandExecution:
        """Execute command safely with timeout"""

        start_time = time.time()

        try:
            # Execute command
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                timeout=timeout,
                cwd=None  # Run in current directory
            )

            execution_time = time.time() - start_time
            success = result.returncode == 0

            # Update guardrail history
            self.guardrail.update_history(command, success)

            return CommandExecution(
                command=command,
                stdout=result.stdout,
                stderr=result.stderr,
                exit_code=result.returncode,
                execution_time=execution_time,
                success=success
            )

        except subprocess.TimeoutExpired:
            execution_time = time.time() - start_time
            self.guardrail.update_history(command, False)

            return CommandExecution(
                command=command,
                stdout="",
                stderr=f"Command timed out after {timeout} seconds",
                exit_code=-1,
                execution_time=execution_time,
                success=False
            )

        except Exception as e:
            execution_time = time.time() - start_time
            self.guardrail.update_history(command, False)

            return CommandExecution(
                command=command,
                stdout="",
                stderr=f"Execution error: {str(e)}",
                exit_code=-1,
                execution_time=execution_time,
                success=False
            )


# ============================================================================
# Evidence Extraction
# ============================================================================

class EvidenceExtractor:
    """Extract evidence from command outputs"""

    # Regex patterns for evidence extraction
    PATTERNS = {
        'ip': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        'domain': r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b',
        'md5': r'\b[a-fA-F0-9]{32}\b',
        'sha1': r'\b[a-fA-F0-9]{40}\b',
        'sha256': r'\b[a-fA-F0-9]{64}\b',
        'url': r'https?://[^\s<>"{}|\\^`\[\]]+',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'registry_key': r'HKEY_[A-Z_]+\\[^\n\r]+',
        'file_path': r'(?:[A-Z]:\\|/)[^\s"\'<>|*?]+',
    }

    def extract(self, output: str, source: str, context: Dict[str, Any] = None) -> List[Evidence]:
        """Extract evidence from command output"""
        evidence_list = []

        for ev_type, pattern in self.PATTERNS.items():
            matches = re.findall(pattern, output)

            for match in set(matches):  # Remove duplicates
                # Filter out common false positives
                if self._is_valid_evidence(ev_type, match):
                    confidence = self._calculate_confidence(ev_type, match, output)
                    threat_score = self._calculate_threat_score(ev_type, match, output)

                    evidence = Evidence(
                        type=ev_type,
                        value=match,
                        confidence=confidence,
                        threat_score=threat_score,
                        source=source,
                        context=context or {},
                        mitre_tactics=self._infer_mitre_tactics(ev_type, match),
                        mitre_techniques=self._infer_mitre_techniques(ev_type, match, output)
                    )
                    evidence_list.append(evidence)

        # Extract process names
        process_evidence = self._extract_processes(output, source, context)
        evidence_list.extend(process_evidence)

        return evidence_list

    def _is_valid_evidence(self, ev_type: str, value: str) -> bool:
        """Filter false positives"""

        # Filter private/local IPs
        if ev_type == 'ip':
            parts = value.split('.')
            first_octet = int(parts[0])

            # Skip localhost, private ranges
            if first_octet in [0, 10, 127] or \
               (first_octet == 172 and 16 <= int(parts[1]) <= 31) or \
               (first_octet == 192 and int(parts[1]) == 168):
                return False

        # Filter common benign domains
        if ev_type == 'domain':
            benign_domains = ['microsoft.com', 'windows.com', 'apple.com', 'google.com']
            if any(benign in value.lower() for benign in benign_domains):
                return False

        return True

    def _calculate_confidence(self, ev_type: str, value: str, context: str) -> float:
        """Calculate confidence score for evidence"""

        base_confidence = 0.7

        # Increase confidence if mentioned multiple times
        count = context.count(value)
        if count > 2:
            base_confidence += 0.1

        # Increase confidence for specific types
        if ev_type in ['md5', 'sha1', 'sha256']:
            base_confidence += 0.2

        return min(base_confidence, 1.0)

    def _calculate_threat_score(self, ev_type: str, value: str, context: str) -> float:
        """Calculate threat score for evidence"""

        threat_score = 0.3  # Base threat

        # Check for suspicious keywords in context
        suspicious_keywords = [
            'malware', 'trojan', 'backdoor', 'ransomware', 'exploit',
            'shell', 'payload', 'injection', 'suspicious', 'malicious',
            'infected', 'virus', 'worm', 'rootkit'
        ]

        for keyword in suspicious_keywords:
            if keyword in context.lower():
                threat_score += 0.15

        # Higher threat for certain types
        if ev_type in ['url', 'domain']:
            threat_indicators = ['bit.ly', 'tinyurl', 'suspicious', 'unknown']
            if any(indicator in value.lower() for indicator in threat_indicators):
                threat_score += 0.3

        return min(threat_score, 1.0)

    def _infer_mitre_tactics(self, ev_type: str, value: str) -> List[str]:
        """Infer MITRE tactics from evidence type"""

        tactics_map = {
            'ip': ['command-and-control', 'exfiltration'],
            'domain': ['command-and-control'],
            'url': ['initial-access', 'command-and-control'],
            'process': ['execution', 'persistence'],
            'registry_key': ['persistence', 'privilege-escalation'],
            'file_path': ['execution'],
        }

        return tactics_map.get(ev_type, [])

    def _infer_mitre_techniques(self, ev_type: str, value: str, context: str) -> List[str]:
        """Infer MITRE techniques from evidence"""

        techniques = []

        # Context-based technique inference
        if 'powershell' in context.lower():
            techniques.append('T1059.001')  # PowerShell

        if 'cmd.exe' in context.lower() or 'cmd' in value.lower():
            techniques.append('T1059.003')  # Windows Command Shell

        if 'schtasks' in context.lower() or 'scheduled task' in context.lower():
            techniques.append('T1053.005')  # Scheduled Task

        if 'registry' in context.lower() or ev_type == 'registry_key':
            techniques.append('T1112')  # Modify Registry

        return techniques

    def _extract_processes(self, output: str, source: str, context: Dict[str, Any]) -> List[Evidence]:
        """Extract process names from output"""

        evidence_list = []

        # Common process name patterns
        process_patterns = [
            r'\b[A-Za-z0-9_\-]+\.exe\b',
            r'\b[A-Za-z0-9_\-]+\.dll\b',
            r'process[:\s]+([A-Za-z0-9_\-\.]+)',
        ]

        for pattern in process_patterns:
            matches = re.findall(pattern, output, re.IGNORECASE)
            for match in set(matches):
                if len(match) > 3:  # Filter very short names
                    evidence = Evidence(
                        type='process',
                        value=match,
                        confidence=0.6,
                        threat_score=0.4,
                        source=source,
                        context=context or {},
                        mitre_tactics=['execution'],
                        mitre_techniques=['T1059']
                    )
                    evidence_list.append(evidence)

        return evidence_list


# ============================================================================
# Forensic Tool Wrappers
# ============================================================================

class ForensicTools:
    """High-level forensic tool wrappers"""

    def __init__(self, guardrail: CommandGuardrail, executor: CommandExecutor, extractor: EvidenceExtractor):
        self.guardrail = guardrail
        self.executor = executor
        self.extractor = extractor

    def execute_tool(self, command: str, reasoning: str = "") -> ToolResult:
        """Execute a forensic tool with full safety checks"""

        # Validate command
        safety_check = self.guardrail.validate_command(command)
        if not safety_check.passed:
            return ToolResult(
                tool_name="unknown",
                command=command,
                output="",
                evidence_extracted=[],
                success=False,
                error=f"Guardrail blocked: {safety_check.reason}",
                execution_time=0.0
            )

        # Check for hallucination
        if reasoning:
            hallucination_check = self.guardrail.check_hallucination(command, reasoning)
            if not hallucination_check.passed:
                return ToolResult(
                    tool_name="unknown",
                    command=command,
                    output="",
                    evidence_extracted=[],
                    success=False,
                    error=f"Possible hallucination: {hallucination_check.reason}",
                    execution_time=0.0
                )

        # Check failure limit
        failure_check = self.guardrail.check_failed_limit()
        if not failure_check.passed:
            return ToolResult(
                tool_name="unknown",
                command=command,
                output="",
                evidence_extracted=[],
                success=False,
                error=f"Failure limit reached: {failure_check.reason}",
                execution_time=0.0
            )

        # Execute command
        execution = self.executor.execute(command)

        # Extract evidence from output
        evidence = []
        if execution.success and execution.stdout:
            tool_name = command.split()[0]
            evidence = self.extractor.extract(
                execution.stdout,
                source=tool_name,
                context={"command": command}
            )

        return ToolResult(
            tool_name=command.split()[0],
            command=command,
            output=execution.stdout if execution.success else execution.stderr,
            evidence_extracted=evidence,
            success=execution.success,
            error=execution.stderr if not execution.success else None,
            execution_time=execution.execution_time
        )

    def suggest_commands(self, artifact_type: str, artifact_path: str, phase: str) -> List[str]:
        """Suggest appropriate commands based on artifact type and phase"""

        suggestions = []

        if artifact_type == "memory_dump":
            suggestions.extend([
                f"vol.py -f {artifact_path} windows.info",
                f"vol.py -f {artifact_path} windows.pslist",
                f"vol.py -f {artifact_path} windows.netscan",
                f"vol.py -f {artifact_path} windows.malfind",
                f"strings {artifact_path} | grep -i http",
                f"strings {artifact_path} | grep -i powershell",
            ])

        elif artifact_type == "disk_image":
            suggestions.extend([
                f"mmls {artifact_path}",
                f"fls -r {artifact_path}",
                f"file {artifact_path}",
            ])

        elif artifact_type == "pcap":
            suggestions.extend([
                f"tshark -r {artifact_path} -Y 'http.request' -T fields -e http.host",
                f"tshark -r {artifact_path} -Y 'dns' -T fields -e dns.qry.name",
                f"tshark -r {artifact_path} -q -z conv,ip",
            ])

        elif artifact_type == "evtx":
            suggestions.extend([
                f"evtx_dump {artifact_path}",
                f"python3 -c 'import json; print(json.dumps(dict()))'",  # Placeholder for parsing
            ])

        else:  # Generic file analysis
            suggestions.extend([
                f"file {artifact_path}",
                f"strings {artifact_path}",
                f"stat {artifact_path}",
                f"exiftool {artifact_path}",
            ])

        return suggestions[:5]  # Return top 5 suggestions


# ============================================================================
# Public API
# ============================================================================

def create_forensic_tools() -> ForensicTools:
    """Factory function to create forensic tools instance"""
    guardrail = CommandGuardrail()
    executor = CommandExecutor(guardrail)
    extractor = EvidenceExtractor()
    return ForensicTools(guardrail, executor, extractor)


# ============================================================================
# MITRE ATT&CK Integration
# ============================================================================

class MITREAttackTool:
    """MITRE ATT&CK framework integration for threat mapping"""

    # Complete MITRE ATT&CK Enterprise Tactics
    TACTICS = {
        'TA0043': {'name': 'Reconnaissance', 'description': 'Gathering information for planning'},
        'TA0042': {'name': 'Resource Development', 'description': 'Establishing resources for operations'},
        'TA0001': {'name': 'Initial Access', 'description': 'Trying to get into your network'},
        'TA0002': {'name': 'Execution', 'description': 'Trying to run malicious code'},
        'TA0003': {'name': 'Persistence', 'description': 'Trying to maintain foothold'},
        'TA0004': {'name': 'Privilege Escalation', 'description': 'Trying to gain higher-level permissions'},
        'TA0005': {'name': 'Defense Evasion', 'description': 'Trying to avoid being detected'},
        'TA0006': {'name': 'Credential Access', 'description': 'Stealing credentials'},
        'TA0007': {'name': 'Discovery', 'description': 'Trying to figure out your environment'},
        'TA0008': {'name': 'Lateral Movement', 'description': 'Moving through your environment'},
        'TA0009': {'name': 'Collection', 'description': 'Gathering data of interest'},
        'TA0011': {'name': 'Command and Control', 'description': 'Communicating with compromised systems'},
        'TA0010': {'name': 'Exfiltration', 'description': 'Stealing data'},
        'TA0040': {'name': 'Impact', 'description': 'Manipulate, interrupt, or destroy systems'},
    }

    # Common techniques with detection signatures
    TECHNIQUES = {
        'T1059.001': {
            'name': 'PowerShell',
            'tactic': 'TA0002',
            'description': 'Adversaries may abuse PowerShell commands and scripts',
            'indicators': ['powershell', 'pwsh', '-enc', '-encodedcommand', 'invoke-expression', 'iex'],
            'severity': 'high'
        },
        'T1059.003': {
            'name': 'Windows Command Shell',
            'tactic': 'TA0002',
            'description': 'Adversaries may abuse cmd.exe',
            'indicators': ['cmd.exe', '/c', '/k', 'cmd /'],
            'severity': 'medium'
        },
        'T1055': {
            'name': 'Process Injection',
            'tactic': 'TA0004',
            'description': 'Adversaries may inject code into processes',
            'indicators': ['VirtualAlloc', 'WriteProcessMemory', 'CreateRemoteThread', 'NtCreateThreadEx'],
            'severity': 'critical'
        },
        'T1003.001': {
            'name': 'LSASS Memory',
            'tactic': 'TA0006',
            'description': 'Adversaries may access LSASS memory',
            'indicators': ['lsass.exe', 'mimikatz', 'sekurlsa', 'procdump'],
            'severity': 'critical'
        },
        'T1053.005': {
            'name': 'Scheduled Task',
            'tactic': 'TA0003',
            'description': 'Adversaries may abuse the Windows Task Scheduler',
            'indicators': ['schtasks', 'at.exe', 'taskschd.msc'],
            'severity': 'high'
        },
        'T1547.001': {
            'name': 'Registry Run Keys',
            'tactic': 'TA0003',
            'description': 'Adversaries may achieve persistence via Registry run keys',
            'indicators': ['HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run', 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'],
            'severity': 'high'
        },
        'T1071.001': {
            'name': 'Web Protocols',
            'tactic': 'TA0011',
            'description': 'Adversaries may communicate using HTTP/HTTPS',
            'indicators': ['http://', 'https://', 'POST', 'GET', 'User-Agent'],
            'severity': 'medium'
        },
        'T1071.004': {
            'name': 'DNS',
            'tactic': 'TA0011',
            'description': 'Adversaries may communicate using DNS',
            'indicators': ['dns', 'nslookup', 'TXT record', 'dns tunneling'],
            'severity': 'high'
        },
        'T1486': {
            'name': 'Data Encrypted for Impact',
            'tactic': 'TA0040',
            'description': 'Adversaries may encrypt data on target systems',
            'indicators': ['ransomware', 'encrypt', '.locked', '.crypt', 'bitcoin'],
            'severity': 'critical'
        },
        'T1490': {
            'name': 'Inhibit System Recovery',
            'tactic': 'TA0040',
            'description': 'Adversaries may delete or disable system recovery features',
            'indicators': ['vssadmin', 'wmic shadowcopy', 'bcdedit', 'recoveryenabled'],
            'severity': 'critical'
        },
        'T1082': {
            'name': 'System Information Discovery',
            'tactic': 'TA0007',
            'description': 'Adversaries may attempt to get system information',
            'indicators': ['systeminfo', 'hostname', 'ver', 'uname'],
            'severity': 'low'
        },
        'T1018': {
            'name': 'Remote System Discovery',
            'tactic': 'TA0007',
            'description': 'Adversaries may attempt to get a listing of other systems',
            'indicators': ['net view', 'ping', 'arp -a', 'nltest'],
            'severity': 'medium'
        },
        'T1021.001': {
            'name': 'Remote Desktop Protocol',
            'tactic': 'TA0008',
            'description': 'Adversaries may use RDP to move laterally',
            'indicators': ['mstsc', 'rdp', '3389', 'termsrv'],
            'severity': 'high'
        },
        'T1021.002': {
            'name': 'SMB/Windows Admin Shares',
            'tactic': 'TA0008',
            'description': 'Adversaries may use Windows admin shares',
            'indicators': ['C$', 'ADMIN$', 'IPC$', 'net use'],
            'severity': 'high'
        },
        'T1105': {
            'name': 'Ingress Tool Transfer',
            'tactic': 'TA0011',
            'description': 'Adversaries may transfer tools or files',
            'indicators': ['certutil', 'bitsadmin', 'curl', 'wget', 'Invoke-WebRequest'],
            'severity': 'high'
        },
        'T1027': {
            'name': 'Obfuscated Files or Information',
            'tactic': 'TA0005',
            'description': 'Adversaries may obfuscate executable files',
            'indicators': ['base64', '-enc', 'frombase64', 'gzip', 'compress'],
            'severity': 'high'
        },
        'T1562.001': {
            'name': 'Disable or Modify Tools',
            'tactic': 'TA0005',
            'description': 'Adversaries may disable security tools',
            'indicators': ['Set-MpPreference', 'DisableRealtimeMonitoring', 'netsh advfirewall'],
            'severity': 'critical'
        },
        'T1078': {
            'name': 'Valid Accounts',
            'tactic': 'TA0001',
            'description': 'Adversaries may use valid credentials',
            'indicators': ['logon', 'runas', 'psexec', 'winrm'],
            'severity': 'high'
        },
    }

    def detect_techniques(self, evidence_value: str, evidence_context: str = "") -> List[Dict[str, Any]]:
        """Detect MITRE techniques based on evidence value and context"""
        detected = []
        combined_text = f"{evidence_value} {evidence_context}".lower()

        for tech_id, tech_info in self.TECHNIQUES.items():
            for indicator in tech_info['indicators']:
                if indicator.lower() in combined_text:
                    detected.append({
                        'technique_id': tech_id,
                        'technique_name': tech_info['name'],
                        'tactic_id': tech_info['tactic'],
                        'tactic_name': self.TACTICS.get(tech_info['tactic'], {}).get('name', 'Unknown'),
                        'matched_indicator': indicator,
                        'severity': tech_info['severity'],
                        'description': tech_info['description']
                    })
                    break  # One match per technique is enough

        return detected

    def get_tactic_by_technique(self, technique_id: str) -> Optional[Dict[str, str]]:
        """Get tactic info for a given technique"""
        tech = self.TECHNIQUES.get(technique_id)
        if tech:
            tactic_id = tech['tactic']
            return {
                'tactic_id': tactic_id,
                **self.TACTICS.get(tactic_id, {})
            }
        return None

    def get_attack_chain(self, techniques: List[str]) -> List[Dict[str, Any]]:
        """Build attack chain from detected techniques"""
        chain = []
        tactic_order = ['TA0043', 'TA0042', 'TA0001', 'TA0002', 'TA0003', 'TA0004',
                        'TA0005', 'TA0006', 'TA0007', 'TA0008', 'TA0009', 'TA0011',
                        'TA0010', 'TA0040']

        tech_by_tactic = {}
        for tech_id in techniques:
            tech = self.TECHNIQUES.get(tech_id)
            if tech:
                tactic_id = tech['tactic']
                if tactic_id not in tech_by_tactic:
                    tech_by_tactic[tactic_id] = []
                tech_by_tactic[tactic_id].append({
                    'technique_id': tech_id,
                    'technique_name': tech['name'],
                    'severity': tech['severity']
                })

        for tactic_id in tactic_order:
            if tactic_id in tech_by_tactic:
                chain.append({
                    'tactic_id': tactic_id,
                    'tactic_name': self.TACTICS[tactic_id]['name'],
                    'techniques': tech_by_tactic[tactic_id]
                })

        return chain


# ============================================================================
# Threat Intelligence Integration
# ============================================================================

class ThreatIntelligenceTool:
    """Threat intelligence enrichment and IOC analysis"""

    # Known malicious indicators (sample data - in production, use threat feeds)
    KNOWN_BAD_IPS = {
        '185.220.101.': 'Tor Exit Node',
        '91.121.': 'Known C2 Infrastructure',
        '45.33.32.156': 'Suspicious European Server',
        '198.51.100.': 'Example Malicious Range',
    }

    KNOWN_BAD_DOMAINS = {
        '.onion': 'Tor Hidden Service',
        'pastebin.com': 'Potential Data Exfil',
        'hastebin.com': 'Potential Data Exfil',
        '.ru': 'Russian Domain (suspicious context)',
        '.cn': 'Chinese Domain (suspicious context)',
        'bit.ly': 'URL Shortener (potential phishing)',
        'tinyurl.com': 'URL Shortener (potential phishing)',
    }

    KNOWN_MALWARE_HASHES = {
        # Sample known malware hashes (MD5, SHA1, SHA256)
        '44d88612fea8a8f36de82e1278abb02f': {'name': 'EICAR Test', 'type': 'test', 'severity': 'info'},
        'a50d10e7e78a93dbfa9c8c8b9679e1d8': {'name': 'Mimikatz', 'type': 'credential_theft', 'severity': 'critical'},
        '3b6a8e4b0e3b87c0e4e9e7f3c2a1d5b9': {'name': 'Cobalt Strike', 'type': 'c2_framework', 'severity': 'critical'},
    }

    SUSPICIOUS_PROCESSES = {
        'mimikatz': {'type': 'credential_theft', 'severity': 'critical', 'mitre': 'T1003'},
        'psexec': {'type': 'lateral_movement', 'severity': 'high', 'mitre': 'T1570'},
        'powershell': {'type': 'execution', 'severity': 'medium', 'mitre': 'T1059.001'},
        'wmic': {'type': 'execution', 'severity': 'medium', 'mitre': 'T1047'},
        'certutil': {'type': 'download', 'severity': 'high', 'mitre': 'T1105'},
        'bitsadmin': {'type': 'download', 'severity': 'high', 'mitre': 'T1105'},
        'mshta': {'type': 'execution', 'severity': 'high', 'mitre': 'T1218.005'},
        'regsvr32': {'type': 'execution', 'severity': 'high', 'mitre': 'T1218.010'},
        'rundll32': {'type': 'execution', 'severity': 'medium', 'mitre': 'T1218.011'},
        'cscript': {'type': 'execution', 'severity': 'medium', 'mitre': 'T1059.005'},
        'wscript': {'type': 'execution', 'severity': 'medium', 'mitre': 'T1059.005'},
        'nc.exe': {'type': 'network', 'severity': 'critical', 'mitre': 'T1095'},
        'netcat': {'type': 'network', 'severity': 'critical', 'mitre': 'T1095'},
    }

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Enrich IP address with threat intelligence"""
        result = {
            'ip': ip,
            'is_malicious': False,
            'threat_type': None,
            'confidence': 0.0,
            'context': []
        }

        # Check against known bad IPs
        for bad_prefix, threat_type in self.KNOWN_BAD_IPS.items():
            if ip.startswith(bad_prefix):
                result['is_malicious'] = True
                result['threat_type'] = threat_type
                result['confidence'] = 0.85
                result['context'].append(f"Matched known threat: {threat_type}")
                break

        # Check for private IPs (not malicious but notable)
        if ip.startswith(('10.', '172.16.', '172.17.', '172.18.', '192.168.')):
            result['context'].append("Private/internal IP address")

        # Check for known cloud/CDN ranges (context)
        if ip.startswith(('13.', '52.', '54.')):
            result['context'].append("Possible AWS IP range")

        return result

    def enrich_domain(self, domain: str) -> Dict[str, Any]:
        """Enrich domain with threat intelligence"""
        result = {
            'domain': domain,
            'is_suspicious': False,
            'threat_type': None,
            'confidence': 0.0,
            'context': []
        }

        domain_lower = domain.lower()

        for bad_pattern, threat_type in self.KNOWN_BAD_DOMAINS.items():
            if bad_pattern in domain_lower:
                result['is_suspicious'] = True
                result['threat_type'] = threat_type
                result['confidence'] = 0.7
                result['context'].append(f"Pattern match: {threat_type}")
                break

        # Check domain age/reputation indicators
        if len(domain) > 50:
            result['context'].append("Long domain name (possible DGA)")
            result['confidence'] = max(result['confidence'], 0.5)

        # Check for IP in domain (suspicious)
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            result['is_suspicious'] = True
            result['context'].append("IP address used as domain")
            result['confidence'] = 0.6

        return result

    def enrich_hash(self, hash_value: str) -> Dict[str, Any]:
        """Enrich hash with threat intelligence"""
        result = {
            'hash': hash_value,
            'hash_type': self._detect_hash_type(hash_value),
            'is_malicious': False,
            'malware_info': None,
            'confidence': 0.0
        }

        # Check known malware hashes
        hash_lower = hash_value.lower()
        if hash_lower in self.KNOWN_MALWARE_HASHES:
            info = self.KNOWN_MALWARE_HASHES[hash_lower]
            result['is_malicious'] = True
            result['malware_info'] = info
            result['confidence'] = 0.95

        return result

    def enrich_process(self, process_name: str) -> Dict[str, Any]:
        """Enrich process name with threat intelligence"""
        result = {
            'process': process_name,
            'is_suspicious': False,
            'threat_info': None,
            'confidence': 0.0,
            'mitre_technique': None
        }

        process_lower = process_name.lower().replace('.exe', '')

        if process_lower in self.SUSPICIOUS_PROCESSES:
            info = self.SUSPICIOUS_PROCESSES[process_lower]
            result['is_suspicious'] = True
            result['threat_info'] = info
            result['confidence'] = 0.8
            result['mitre_technique'] = info.get('mitre')

        return result

    def _detect_hash_type(self, hash_value: str) -> str:
        """Detect hash type based on length"""
        length = len(hash_value)
        if length == 32:
            return 'MD5'
        elif length == 40:
            return 'SHA1'
        elif length == 64:
            return 'SHA256'
        elif length == 128:
            return 'SHA512'
        return 'Unknown'

    def calculate_threat_score(self, enrichments: List[Dict[str, Any]]) -> float:
        """Calculate overall threat score from multiple enrichments"""
        if not enrichments:
            return 0.0

        scores = []
        for enrich in enrichments:
            confidence = enrich.get('confidence', 0.0)
            is_malicious = enrich.get('is_malicious', False) or enrich.get('is_suspicious', False)

            if is_malicious:
                scores.append(confidence)
            else:
                scores.append(confidence * 0.3)  # Lower score for non-malicious context

        return min(sum(scores) / len(scores) * 1.5, 1.0)  # Normalize and cap at 1.0


# ============================================================================
# Integrated Forensic Analysis Tool
# ============================================================================

class ForensicAnalysisTool:
    """Integrated forensic analysis combining all tools"""

    def __init__(self):
        self.forensic_tools = create_forensic_tools()
        self.mitre_tool = MITREAttackTool()
        self.ti_tool = ThreatIntelligenceTool()

    def analyze_evidence(self, evidence: Evidence) -> Dict[str, Any]:
        """Perform comprehensive analysis on evidence"""
        result = {
            'evidence': {
                'type': evidence.type,
                'value': evidence.value,
                'source': evidence.source
            },
            'mitre_analysis': [],
            'threat_intel': {},
            'threat_score': 0.0,
            'recommendations': []
        }

        # MITRE ATT&CK analysis
        mitre_detections = self.mitre_tool.detect_techniques(
            evidence.value,
            str(evidence.context)
        )
        result['mitre_analysis'] = mitre_detections

        # Threat intelligence enrichment
        if evidence.type == 'ip':
            result['threat_intel'] = self.ti_tool.enrich_ip(evidence.value)
        elif evidence.type == 'domain':
            result['threat_intel'] = self.ti_tool.enrich_domain(evidence.value)
        elif evidence.type in ['md5', 'sha1', 'sha256', 'hash']:
            result['threat_intel'] = self.ti_tool.enrich_hash(evidence.value)
        elif evidence.type == 'process':
            result['threat_intel'] = self.ti_tool.enrich_process(evidence.value)

        # Calculate threat score
        enrichments = [result['threat_intel']] if result['threat_intel'] else []
        if mitre_detections:
            for det in mitre_detections:
                enrichments.append({
                    'confidence': 0.8 if det['severity'] == 'critical' else 0.6,
                    'is_malicious': det['severity'] in ['critical', 'high']
                })

        result['threat_score'] = self.ti_tool.calculate_threat_score(enrichments)

        # Generate recommendations
        if result['threat_score'] > 0.7:
            result['recommendations'].append("CRITICAL: Immediate investigation required")
        if mitre_detections:
            result['recommendations'].append(f"Review MITRE techniques: {', '.join([d['technique_id'] for d in mitre_detections])}")
        if result['threat_intel'].get('is_malicious'):
            result['recommendations'].append("Block indicator and search for related activity")

        return result

