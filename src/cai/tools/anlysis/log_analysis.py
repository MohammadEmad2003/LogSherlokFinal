"""
Log Analysis Tools for CAI Forensic Agent
==========================================
Tools: python-evtx, Hayabusa, Chainsaw, apache-log-parser, auditd, journalctl,
       CloudTrail
"""
import os
import json
import re
from cai.tools.common import run_command
from cai.sdk.agents import function_tool


# ---------------------------------------------------------------------------
# python-evtx: Windows Event Log parsing
# ---------------------------------------------------------------------------
@function_tool
def parse_evtx(file_path: str, event_ids: str = "",
               max_events: int = 100, ctf=None) -> str:
    """
    Parse Windows Event Log (.evtx) files. Extracts security events,
    PowerShell logs, login events, service installations, and more.
    Filter by Event ID to focus on specific activity.

    Common forensic Event IDs:
    - 4624/4625: Successful/failed logon
    - 4688: Process creation
    - 4720: User account created
    - 4732: User added to privileged group
    - 1102: Audit log cleared
    - 7045: Service installed
    - 4104: PowerShell script block logging

    Args:
        file_path: Path to the .evtx file
        event_ids: Comma-separated Event IDs to filter (empty = all)
        max_events: Maximum events to return (default: 100)
    Returns:
        str: JSON with parsed events, summary statistics, and suspicious indicators
    """
    try:
        import Evtx.Evtx as evtx
        import Evtx.Views as evtx_views
    except ImportError:
        return json.dumps({"error": "python-evtx not installed. Run: pip install python-evtx"})

    if not os.path.isfile(file_path):
        return json.dumps({"error": f"File not found: {file_path}"})

    filter_ids = set()
    if event_ids:
        filter_ids = {int(x.strip()) for x in event_ids.split(",") if x.strip()}

    try:
        import xml.etree.ElementTree as ET

        events = []
        event_id_counts = {}
        total_parsed = 0

        with evtx.Evtx(file_path) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    root = ET.fromstring(xml_str)

                    # Namespace handling
                    ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
                    eid_elem = root.find(".//e:EventID", ns)
                    eid = int(eid_elem.text) if eid_elem is not None else 0

                    # Count all events
                    event_id_counts[eid] = event_id_counts.get(eid, 0) + 1
                    total_parsed += 1

                    # Apply filter
                    if filter_ids and eid not in filter_ids:
                        continue

                    if len(events) >= max_events:
                        continue

                    # Extract core fields
                    time_elem = root.find(".//e:TimeCreated", ns)
                    timestamp = time_elem.get("SystemTime", "") if time_elem is not None else ""

                    computer_elem = root.find(".//e:Computer", ns)
                    computer = computer_elem.text if computer_elem is not None else ""

                    channel_elem = root.find(".//e:Channel", ns)
                    channel = channel_elem.text if channel_elem is not None else ""

                    # Extract EventData fields
                    event_data = {}
                    for data_elem in root.findall(".//e:EventData/e:Data", ns):
                        name = data_elem.get("Name", f"field_{len(event_data)}")
                        event_data[name] = data_elem.text or ""

                    events.append({
                        "event_id": eid,
                        "timestamp": timestamp,
                        "computer": computer,
                        "channel": channel,
                        "record_id": record.record_num(),
                        "data": event_data,
                    })
                except Exception:
                    continue

        # Identify suspicious events
        suspicious = []
        SUSPICIOUS_IDS = {
            1102: "Audit log was cleared",
            4720: "User account was created",
            4732: "Member added to security-enabled local group",
            4648: "Logon using explicit credentials",
            7045: "New service installed",
            4697: "Service installed in the system",
        }
        for eid, count in event_id_counts.items():
            if eid in SUSPICIOUS_IDS:
                suspicious.append(f"Event {eid} ({SUSPICIOUS_IDS[eid]}): {count} occurrences")

        result = {
            "file_path": file_path,
            "total_events_in_file": total_parsed,
            "events_returned": len(events),
            "filter_applied": list(filter_ids) if filter_ids else "none",
            "event_id_distribution": dict(sorted(event_id_counts.items(),
                                                  key=lambda x: x[1], reverse=True)[:25]),
            "suspicious_events": suspicious,
            "events": events,
        }

        return json.dumps(result, indent=2, default=str)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Hayabusa: Windows event log timeline generation with Sigma rules
# ---------------------------------------------------------------------------
@function_tool
def run_hayabusa(evidence_path: str, args: str = "", output_format: str = "json",
                 min_level: str = "medium", ctf=None) -> str:
    """
    Run Hayabusa on Windows event logs to generate a detailed timeline
    using Sigma-based threat detection rules. Produces output compatible
    with Timeline Explorer. Best tool for structured EVTX timeline analysis.

    Args:
        evidence_path: Path to .evtx file or directory containing .evtx files
        args: Additional Hayabusa arguments
        output_format: Output format: 'json', 'csv', or 'jsonl' (default: json)
        min_level: Minimum alert level: 'informational', 'low', 'medium', 'high', 'critical'
    Returns:
        str: Hayabusa detection results with timeline events
    """
    output_file = f"/tmp/hayabusa_results.{output_format}"

    cmd = (
        f'hayabusa csv-timeline '
        f'--directory "{evidence_path}" '
        f'--output "{output_file}" '
        f'--min-level {min_level} '
        f'--no-wizard '
        f'--UTC '
        f'{args}'
    )

    run_result = run_command(cmd, ctf=ctf)

    # Read results
    if os.path.isfile(output_file):
        with open(output_file, "r") as f:
            content = f.read()
        # Truncate if too large
        if len(content) > 50000:
            content = content[:50000] + f"\n... [TRUNCATED — full output at {output_file}]"
        return json.dumps({
            "command": cmd,
            "output_file": output_file,
            "execution_log": run_result[:2000],
            "results": content,
        }, indent=2)
    else:
        return json.dumps({
            "command": cmd,
            "output": run_result,
            "note": "No output file generated — check if Hayabusa is installed and evidence path is correct"
        }, indent=2)


# ---------------------------------------------------------------------------
# Chainsaw: Fast Sigma rule hunting across event logs
# ---------------------------------------------------------------------------
@function_tool
def run_chainsaw(evidence_path: str, args: str = "",
                 search_term: str = "", ctf=None) -> str:
    """
    Run Chainsaw for fast keyword and Sigma rule hunting across Windows
    event logs. Ideal for rapid threat hunting and indicator searching.

    Args:
        evidence_path: Path to .evtx file or directory of logs
        args: Additional Chainsaw arguments
        search_term: Keyword to search for (if provided, runs search mode)
    Returns:
        str: Chainsaw detection results
    """
    if search_term:
        cmd = f'chainsaw search "{search_term}" "{evidence_path}" --json {args}'
    else:
        cmd = f'chainsaw hunt "{evidence_path}" --sigma-rules /opt/chainsaw/sigma/ --json {args}'

    return run_command(cmd, ctf=ctf)


# ---------------------------------------------------------------------------
# Apache/Nginx log parsing
# ---------------------------------------------------------------------------
@function_tool
def parse_apache_log(file_path: str, max_lines: int = 500,
                     filter_status: str = "", filter_ip: str = "", ctf=None) -> str:
    """
    Parse Apache/Nginx access logs. Extracts IPs, URIs, status codes,
    user agents, and identifies suspicious patterns (SQL injection,
    path traversal, command injection, scanners).

    Args:
        file_path: Path to the access log file
        max_lines: Maximum lines to parse (default: 500)
        filter_status: Filter by HTTP status code (e.g., '404', '500')
        filter_ip: Filter by source IP address
    Returns:
        str: JSON with parsed entries, IP statistics, and attack indicators
    """
    if not os.path.isfile(file_path):
        return json.dumps({"error": f"File not found: {file_path}"})

    # Combined log format regex
    log_pattern = re.compile(
        r'(?P<ip>[\d.]+)\s+\S+\s+\S+\s+'
        r'\[(?P<timestamp>[^\]]+)\]\s+'
        r'"(?P<method>\S+)\s+(?P<uri>[^\s"]+)\s*(?P<protocol>[^"]*)?"\s+'
        r'(?P<status>\d+)\s+(?P<bytes>\S+)'
        r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?'
    )

    # Attack pattern signatures
    attack_patterns = {
        "sql_injection": re.compile(r"(union\s+select|or\s+1=1|'\s*or\s*'|--\s*$|;\s*drop\s)", re.I),
        "path_traversal": re.compile(r"(\.\./|\.\.\\|%2e%2e|/etc/passwd|/proc/self)", re.I),
        "command_injection": re.compile(r"(;\s*cat\s|;\s*ls\s|;\s*wget\s|\|.*bash|`.*`)", re.I),
        "xss": re.compile(r"(<script|javascript:|onerror=|onload=|%3cscript)", re.I),
        "scanner": re.compile(r"(nikto|sqlmap|nmap|dirbuster|gobuster|wfuzz|burp)", re.I),
        "shell_upload": re.compile(r"\.(php|asp|aspx|jsp|cgi|py)\?", re.I),
    }

    try:
        entries = []
        ip_counts = {}
        status_counts = {}
        attacks_detected = []
        total_lines = 0

        with open(file_path, "r", errors="replace") as f:
            for line in f:
                total_lines += 1
                if total_lines > max_lines * 3:  # Scan more for stats
                    break

                match = log_pattern.match(line.strip())
                if not match:
                    continue

                entry = match.groupdict()
                ip = entry["ip"]
                status = entry["status"]

                # Statistics
                ip_counts[ip] = ip_counts.get(ip, 0) + 1
                status_counts[status] = status_counts.get(status, 0) + 1

                # Apply filters
                if filter_status and status != filter_status:
                    continue
                if filter_ip and ip != filter_ip:
                    continue

                # Check for attack patterns
                uri = entry.get("uri", "")
                ua = entry.get("user_agent", "")
                for attack_name, pattern in attack_patterns.items():
                    if pattern.search(uri) or pattern.search(ua):
                        attacks_detected.append({
                            "type": attack_name,
                            "ip": ip,
                            "uri": uri[:200],
                            "timestamp": entry["timestamp"],
                            "status": status,
                        })

                if len(entries) < max_lines:
                    entries.append(entry)

        # Top IPs
        top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:20]

        result = {
            "file_path": file_path,
            "total_lines_scanned": total_lines,
            "entries_returned": len(entries),
            "top_source_ips": [{"ip": ip, "count": c} for ip, c in top_ips],
            "status_distribution": status_counts,
            "attacks_detected": attacks_detected[:50],
            "attack_summary": {},
            "entries": entries[:100],
        }

        # Attack summary
        for attack in attacks_detected:
            atype = attack["type"]
            result["attack_summary"][atype] = result["attack_summary"].get(atype, 0) + 1

        if attacks_detected:
            result["risk_level"] = "HIGH"
            result["warning"] = f"Detected {len(attacks_detected)} potential attack patterns"

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# Linux auditd log parsing
# ---------------------------------------------------------------------------
@function_tool
def parse_auditd(file_path: str, filter_type: str = "",
                 max_entries: int = 200, ctf=None) -> str:
    """
    Parse Linux auditd logs (audit.log). Critical for detecting system-level
    events: command execution, file access, user changes, network connections.

    Common audit types:
    - SYSCALL: System call events
    - EXECVE: Command execution with full arguments
    - PATH: File path access
    - USER_AUTH / USER_LOGIN: Authentication events
    - SOCKADDR: Network socket connections

    Args:
        file_path: Path to audit.log file
        filter_type: Filter by audit record type (e.g., 'EXECVE', 'USER_AUTH')
        max_entries: Maximum entries to return (default: 200)
    Returns:
        str: JSON with parsed audit events and suspicious indicators
    """
    if not os.path.isfile(file_path):
        return json.dumps({"error": f"File not found: {file_path}"})

    try:
        entries = []
        type_counts = {}
        suspicious = []
        total = 0

        audit_pattern = re.compile(
            r'type=(?P<type>\S+)\s+msg=audit\((?P<epoch>[\d.]+):(?P<serial>\d+)\):\s*(?P<data>.*)'
        )

        with open(file_path, "r", errors="replace") as f:
            for line in f:
                total += 1
                match = audit_pattern.match(line.strip())
                if not match:
                    continue

                record = match.groupdict()
                rec_type = record["type"]
                type_counts[rec_type] = type_counts.get(rec_type, 0) + 1

                if filter_type and rec_type != filter_type:
                    continue

                # Parse key=value pairs from data
                data_dict = {}
                for kv in re.findall(r'(\w+)=("[^"]*"|\S+)', record["data"]):
                    data_dict[kv[0]] = kv[1].strip('"')

                entry = {
                    "type": rec_type,
                    "timestamp": record["epoch"],
                    "serial": record["serial"],
                    "data": data_dict,
                }

                # Flag suspicious activity
                if rec_type == "EXECVE" and any(
                    cmd in record["data"].lower()
                    for cmd in ["wget", "curl", "nc ", "ncat", "bash -i",
                               "python -c", "perl -e", "/dev/tcp"]
                ):
                    suspicious.append({
                        "type": "suspicious_command",
                        "details": record["data"][:300],
                        "timestamp": record["epoch"],
                    })

                if rec_type in ("USER_AUTH", "USER_LOGIN"):
                    if "res=failed" in record["data"].lower():
                        suspicious.append({
                            "type": "failed_authentication",
                            "details": record["data"][:300],
                            "timestamp": record["epoch"],
                        })

                if len(entries) < max_entries:
                    entries.append(entry)

        result = {
            "file_path": file_path,
            "total_records": total,
            "entries_returned": len(entries),
            "type_distribution": dict(sorted(type_counts.items(),
                                              key=lambda x: x[1], reverse=True)),
            "suspicious_activity": suspicious[:30],
            "entries": entries,
        }

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})


# ---------------------------------------------------------------------------
# journalctl: systemd journal access
# ---------------------------------------------------------------------------
@function_tool
def query_journalctl(unit: str = "", since: str = "", until: str = "",
                     priority: str = "", grep: str = "",
                     max_lines: int = 200, args: str = "", ctf=None) -> str:
    """
    Query systemd journal logs. Includes service logs, kernel messages,
    authentication events, and more.

    Args:
        unit: Filter by systemd unit (e.g., 'sshd', 'docker', 'nginx')
        since: Start time (e.g., '2024-01-15 00:00:00', 'yesterday', '-1h')
        until: End time (e.g., '2024-01-16 00:00:00', 'now')
        priority: Min priority: 'emerg','alert','crit','err','warning','notice','info','debug'
        grep: Grep pattern to filter messages
        max_lines: Maximum lines to return (default: 200)
        args: Additional journalctl arguments
    Returns:
        str: Journal log entries
    """
    cmd = f"journalctl --no-pager -n {max_lines} --output=json"

    if unit:
        cmd += f" -u {unit}"
    if since:
        cmd += f' --since="{since}"'
    if until:
        cmd += f' --until="{until}"'
    if priority:
        cmd += f" -p {priority}"
    if grep:
        cmd += f' -g "{grep}"'
    if args:
        cmd += f" {args}"

    return run_command(cmd, ctf=ctf)


# ---------------------------------------------------------------------------
# AWS CloudTrail log parsing
# ---------------------------------------------------------------------------
@function_tool
def parse_cloudtrail(file_path: str, filter_event: str = "",
                     filter_user: str = "", filter_source_ip: str = "",
                     max_events: int = 200, ctf=None) -> str:
    """
    Parse AWS CloudTrail JSON logs into structured forensic data.
    Extracts API calls, source IPs, user identities, error codes,
    and timestamps for cloud incident investigation.

    Args:
        file_path: Path to CloudTrail JSON log file
        filter_event: Filter by event name (e.g., 'ConsoleLogin', 'RunInstances')
        filter_user: Filter by user name or ARN substring
        filter_source_ip: Filter by source IP address
        max_events: Maximum events to return (default: 200)
    Returns:
        str: JSON with parsed CloudTrail events and activity summary
    """
    if not os.path.isfile(file_path):
        return json.dumps({"error": f"File not found: {file_path}"})

    try:
        with open(file_path, "r") as f:
            data = json.load(f)

        records = data.get("Records", []) if isinstance(data, dict) else data
        if not isinstance(records, list):
            records = [data]

        events = []
        event_counts = {}
        user_counts = {}
        ip_counts = {}
        errors = []
        total = 0

        for record in records:
            total += 1
            event_name = record.get("eventName", "unknown")
            event_counts[event_name] = event_counts.get(event_name, 0) + 1

            user_id = record.get("userIdentity", {})
            username = (user_id.get("userName", "") or
                       user_id.get("arn", "") or
                       user_id.get("principalId", "unknown"))
            user_counts[username] = user_counts.get(username, 0) + 1

            src_ip = record.get("sourceIPAddress", "")
            if src_ip:
                ip_counts[src_ip] = ip_counts.get(src_ip, 0) + 1

            # Apply filters
            if filter_event and event_name != filter_event:
                continue
            if filter_user and filter_user.lower() not in username.lower():
                continue
            if filter_source_ip and src_ip != filter_source_ip:
                continue

            # Track errors
            error_code = record.get("errorCode")
            if error_code:
                errors.append({
                    "event": event_name,
                    "error_code": error_code,
                    "error_message": record.get("errorMessage", "")[:200],
                    "timestamp": record.get("eventTime", ""),
                    "user": username,
                })

            if len(events) < max_events:
                events.append({
                    "event_name": event_name,
                    "event_time": record.get("eventTime", ""),
                    "event_source": record.get("eventSource", ""),
                    "source_ip": src_ip,
                    "user_agent": record.get("userAgent", "")[:100],
                    "user_identity": username,
                    "aws_region": record.get("awsRegion", ""),
                    "error_code": error_code,
                    "request_params": str(record.get("requestParameters", {}))[:300],
                    "response": str(record.get("responseElements", {}))[:300],
                })

        # Suspicious indicators
        suspicious = []
        suspicious_events = {
            "ConsoleLogin", "CreateUser", "CreateAccessKey",
            "AttachUserPolicy", "PutBucketPolicy", "StopLogging",
            "DeleteTrail", "AuthorizeSecurityGroupIngress",
        }
        for evt, count in event_counts.items():
            if evt in suspicious_events:
                suspicious.append(f"{evt}: {count} occurrences")

        if errors:
            suspicious.append(f"{len(errors)} API errors (possible recon/access attempts)")

        result = {
            "file_path": file_path,
            "total_records": total,
            "events_returned": len(events),
            "top_events": dict(sorted(event_counts.items(),
                                       key=lambda x: x[1], reverse=True)[:20]),
            "top_users": dict(sorted(user_counts.items(),
                                      key=lambda x: x[1], reverse=True)[:10]),
            "top_source_ips": dict(sorted(ip_counts.items(),
                                           key=lambda x: x[1], reverse=True)[:10]),
            "api_errors": errors[:20],
            "suspicious_activity": suspicious,
            "events": events,
        }

        return json.dumps(result, indent=2)
    except Exception as e:
        return json.dumps({"error": str(e)})
