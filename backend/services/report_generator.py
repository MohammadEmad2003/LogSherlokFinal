"""
Report Generator - Generates comprehensive forensic investigation reports
Supports JSON, HTML, and STIX 2.1 formats
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any, Dict, List
import logging

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generates forensic investigation reports in multiple formats.
    """

    def __init__(self, session_data: Dict[str, Any]):
        self.session = session_data
        self.session_id = session_data.get("session_id", "unknown")

    def generate_json_report(self) -> Dict[str, Any]:
        """Generate comprehensive JSON report."""
        # Generate attack scenario from evidence and hypotheses
        attack_scenario = self._generate_attack_scenario()
        
        return {
            "report_metadata": {
                "report_id": str(uuid.uuid4()),
                "session_id": self.session_id,
                "generated_at": datetime.utcnow().isoformat(),
                "report_version": "1.0",
                "generator": "Autonomous Forensic Orchestrator",
            },
            "artifact_info": {
                "name": self.session.get("artifact_name") or "Unknown",
                "type": self.session.get("artifact_type") or "Unknown",
                "size": self.session.get("artifact_size") or 0,
                "analyzed_at": self.session.get("created_at") or datetime.utcnow().isoformat(),
            },
            "executive_summary": {
                "status": self.session.get("status") or "unknown",
                "summary": self.session.get("summary") or "Investigation summary not available.",
                "conclusion": self.session.get("conclusion") or "Investigation conclusion pending.",
                "threat_level": self._calculate_threat_level(),
                "total_steps": len(self.session.get("steps", [])),
                "total_evidence": len(self.session.get("evidence", [])),
            },
            "attack_scenario": attack_scenario,
            "investigation_workflow": self._generate_workflow_section(),
            "evidence": self._generate_evidence_section(),
            "timeline": self._generate_timeline_section(),
            "mitre_mapping": self._generate_mitre_section(),
            "hypotheses": self.session.get("hypotheses", []),
            "iocs": self._generate_ioc_section(),
            "recommendations": self._generate_recommendations(),
        }

    def generate_html_report(self) -> str:
        """Generate HTML report."""
        json_report = self.generate_json_report()

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Forensic Investigation Report - {self.session_id}</title>
    <style>
        :root {{
            --bg-primary: #0a0e17;
            --bg-secondary: #141b2d;
            --bg-tertiary: #1a2035;
            --text-primary: #e4e6eb;
            --text-secondary: #8b949e;
            --accent-blue: #00d4ff;
            --accent-green: #00ff88;
            --accent-red: #ff4757;
            --accent-yellow: #ffd93d;
            --accent-purple: #a855f7;
            --border-color: #2d3748;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: 'Segoe UI', 'SF Pro Display', -apple-system, sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.6;
            padding: 2rem;
        }}

        .report-container {{
            max-width: 1200px;
            margin: 0 auto;
        }}

        .report-header {{
            text-align: center;
            padding: 2rem;
            background: linear-gradient(135deg, var(--bg-secondary) 0%, var(--bg-tertiary) 100%);
            border-radius: 12px;
            margin-bottom: 2rem;
            border: 1px solid var(--border-color);
        }}

        .report-header h1 {{
            font-size: 2rem;
            background: linear-gradient(90deg, var(--accent-blue), var(--accent-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}

        .report-header .meta {{
            color: var(--text-secondary);
            font-size: 0.9rem;
        }}

        .section {{
            background: var(--bg-secondary);
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1.5rem;
            border: 1px solid var(--border-color);
        }}

        .section h2 {{
            color: var(--accent-blue);
            margin-bottom: 1rem;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border-color);
        }}

        .severity-critical {{
            color: var(--accent-red);
            font-weight: bold;
        }}

        .severity-high {{
            color: #ff8c00;
            font-weight: bold;
        }}

        .severity-medium {{
            color: var(--accent-yellow);
        }}

        .severity-low {{
            color: var(--accent-green);
        }}

        .step-card {{
            background: var(--bg-tertiary);
            border-radius: 8px;
            padding: 1rem;
            margin-bottom: 1rem;
            border-left: 4px solid var(--accent-blue);
        }}

        .step-card .step-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 0.5rem;
        }}

        .step-card .step-number {{
            background: var(--accent-blue);
            color: var(--bg-primary);
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-weight: bold;
            font-size: 0.85rem;
        }}

        .step-card .tool-name {{
            color: var(--accent-purple);
            font-family: monospace;
        }}

        .step-card .thought {{
            color: var(--text-secondary);
            font-style: italic;
            margin: 0.5rem 0;
        }}

        .step-card .action {{
            color: var(--accent-green);
            margin: 0.5rem 0;
        }}

        .io-section {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1rem;
            margin: 1rem 0;
        }}

        .io-box {{
            background: var(--bg-primary);
            padding: 0.75rem;
            border-radius: 6px;
            font-family: monospace;
            font-size: 0.85rem;
            max-height: 200px;
            overflow-y: auto;
        }}

        .io-box h4 {{
            color: var(--accent-blue);
            margin-bottom: 0.5rem;
        }}

        .evidence-list {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 1rem;
        }}

        .evidence-card {{
            background: var(--bg-tertiary);
            padding: 1rem;
            border-radius: 8px;
            border: 1px solid var(--border-color);
        }}

        .evidence-card .type {{
            text-transform: uppercase;
            font-size: 0.75rem;
            color: var(--accent-purple);
            letter-spacing: 1px;
        }}

        .evidence-card .value {{
            font-family: monospace;
            color: var(--accent-green);
            word-break: break-all;
            margin: 0.5rem 0;
        }}

        .evidence-card .confidence {{
            display: flex;
            align-items: center;
            gap: 0.5rem;
        }}

        .confidence-bar {{
            flex: 1;
            height: 6px;
            background: var(--bg-primary);
            border-radius: 3px;
            overflow: hidden;
        }}

        .confidence-fill {{
            height: 100%;
            background: linear-gradient(90deg, var(--accent-green), var(--accent-blue));
            transition: width 0.3s ease;
        }}

        .timeline-event {{
            display: flex;
            gap: 1rem;
            padding: 1rem 0;
            border-bottom: 1px solid var(--border-color);
        }}

        .timeline-event:last-child {{
            border-bottom: none;
        }}

        .timeline-event .time {{
            min-width: 120px;
            color: var(--accent-blue);
            font-family: monospace;
        }}

        .mitre-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(250px, 1fr));
            gap: 1rem;
        }}

        .mitre-tactic {{
            background: var(--bg-tertiary);
            padding: 1rem;
            border-radius: 8px;
        }}

        .mitre-tactic h4 {{
            color: var(--accent-purple);
            margin-bottom: 0.5rem;
        }}

        .technique-tag {{
            display: inline-block;
            background: var(--bg-primary);
            padding: 0.25rem 0.5rem;
            border-radius: 4px;
            margin: 0.25rem;
            font-size: 0.85rem;
            font-family: monospace;
        }}

        .hypothesis-card {{
            background: var(--bg-tertiary);
            padding: 1.5rem;
            border-radius: 8px;
            margin-bottom: 1rem;
            border-left: 4px solid var(--accent-yellow);
        }}

        .hypothesis-card .confidence-badge {{
            display: inline-block;
            padding: 0.25rem 0.75rem;
            border-radius: 20px;
            font-size: 0.85rem;
            margin-left: 0.5rem;
        }}

        .high-confidence {{
            background: var(--accent-green);
            color: var(--bg-primary);
        }}

        .medium-confidence {{
            background: var(--accent-yellow);
            color: var(--bg-primary);
        }}

        .ioc-table {{
            width: 100%;
            border-collapse: collapse;
        }}

        .ioc-table th, .ioc-table td {{
            padding: 0.75rem;
            text-align: left;
            border-bottom: 1px solid var(--border-color);
        }}

        .ioc-table th {{
            color: var(--accent-blue);
            text-transform: uppercase;
            font-size: 0.85rem;
            letter-spacing: 1px;
        }}

        .ioc-table td {{
            font-family: monospace;
        }}

        .recommendations-list {{
            list-style: none;
        }}

        .recommendations-list li {{
            padding: 0.75rem;
            margin-bottom: 0.5rem;
            background: var(--bg-tertiary);
            border-radius: 6px;
            border-left: 4px solid var(--accent-green);
        }}

        .recommendations-list li::before {{
            content: "→ ";
            color: var(--accent-green);
        }}

        @media print {{
            body {{
                background: white;
                color: black;
            }}
            .section {{
                break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="report-container">
        <header class="report-header">
            <h1>Forensic Investigation Report</h1>
            <div class="meta">
                Session ID: {self.session_id} | Generated: {json_report['report_metadata']['generated_at']}
            </div>
        </header>

        <section class="section">
            <h2>Executive Summary</h2>
            <p><strong>Artifact:</strong> {json_report['artifact_info']['name'] or 'Unknown'} ({json_report['artifact_info']['type'] or 'Unknown'})</p>
            <p><strong>Threat Level:</strong> <span class="severity-{(json_report['executive_summary']['threat_level'] or 'low').lower()}">{json_report['executive_summary']['threat_level'] or 'Unknown'}</span></p>
            <p><strong>Analysis Steps:</strong> {json_report['executive_summary']['total_steps']}</p>
            <p><strong>Evidence Items:</strong> {json_report['executive_summary']['total_evidence']}</p>
            <div style="margin-top: 1rem;">
                <pre style="white-space: pre-wrap; background: var(--bg-tertiary); padding: 1rem; border-radius: 8px;">{json_report['executive_summary']['summary'] or 'Summary pending...'}</pre>
            </div>
        </section>

        <section class="section">
            <h2>Attack Scenario</h2>
            {self._render_attack_scenario_html(json_report.get('attack_scenario', {}))}
        </section>

        <section class="section">
            <h2>Investigation Workflow</h2>
            {self._render_workflow_html(json_report['investigation_workflow'])}
        </section>

        <section class="section">
            <h2>Evidence Collected</h2>
            <div class="evidence-list">
                {self._render_evidence_html(json_report['evidence'])}
            </div>
        </section>

        <section class="section">
            <h2>Attack Timeline</h2>
            {self._render_timeline_html(json_report['timeline'])}
        </section>

        <section class="section">
            <h2>MITRE ATT&CK Mapping</h2>
            <div class="mitre-grid">
                {self._render_mitre_html(json_report['mitre_mapping'])}
            </div>
        </section>

        <section class="section">
            <h2>Attack Hypotheses</h2>
            {self._render_hypotheses_html(json_report['hypotheses'])}
        </section>

        <section class="section">
            <h2>Indicators of Compromise (IOCs)</h2>
            {self._render_iocs_html(json_report['iocs'])}
        </section>

        <section class="section">
            <h2>Recommendations</h2>
            <ul class="recommendations-list">
                {''.join(f'<li>{r}</li>' for r in json_report['recommendations'])}
            </ul>
        </section>

        <section class="section">
            <h2>Conclusion</h2>
            <p>{json_report['executive_summary']['conclusion'] or 'Investigation conclusion pending.'}</p>
        </section>
    </div>
</body>
</html>"""
        return html

    def generate_stix_bundle(self) -> Dict[str, Any]:
        """Generate STIX 2.1 bundle from investigation findings."""
        objects = []
        bundle_id = f"bundle--{uuid.uuid4()}"

        # Create Identity for the analyst
        analyst_id = f"identity--{uuid.uuid4()}"
        objects.append({
            "type": "identity",
            "spec_version": "2.1",
            "id": analyst_id,
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": "Autonomous Forensic Orchestrator",
            "identity_class": "system",
        })

        # Create Report object
        report_id = f"report--{uuid.uuid4()}"
        object_refs = [analyst_id]

        # Process evidence into STIX objects
        for ev in self.session.get("evidence", []):
            stix_obj = self._evidence_to_stix(ev)
            if stix_obj:
                objects.append(stix_obj)
                object_refs.append(stix_obj["id"])

        # Create Attack Patterns from MITRE techniques
        for tactic, techniques in self.session.get("mitre_coverage", {}).items():
            for tech_id in techniques:
                attack_pattern_id = f"attack-pattern--{uuid.uuid4()}"
                objects.append({
                    "type": "attack-pattern",
                    "spec_version": "2.1",
                    "id": attack_pattern_id,
                    "created": datetime.utcnow().isoformat() + "Z",
                    "modified": datetime.utcnow().isoformat() + "Z",
                    "name": tech_id,
                    "external_references": [{
                        "source_name": "mitre-attack",
                        "external_id": tech_id,
                        "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}"
                    }],
                })
                object_refs.append(attack_pattern_id)

        # Create Malware objects if detected
        malware_families = set()
        for ev in self.session.get("evidence", []):
            if ev.get("type") == "malware":
                family = ev.get("value", "").split()[0]
                if family not in malware_families:
                    malware_families.add(family)
                    malware_id = f"malware--{uuid.uuid4()}"
                    objects.append({
                        "type": "malware",
                        "spec_version": "2.1",
                        "id": malware_id,
                        "created": datetime.utcnow().isoformat() + "Z",
                        "modified": datetime.utcnow().isoformat() + "Z",
                        "name": family,
                        "is_family": True,
                        "malware_types": ["backdoor"] if "Cobalt" in family else ["trojan"],
                    })
                    object_refs.append(malware_id)

        # Create the Report
        objects.append({
            "type": "report",
            "spec_version": "2.1",
            "id": report_id,
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": f"Forensic Investigation Report - {self.session_id}",
            "description": self.session.get("summary", ""),
            "report_types": ["threat-report"],
            "published": datetime.utcnow().isoformat() + "Z",
            "object_refs": object_refs,
        })

        return {
            "type": "bundle",
            "id": bundle_id,
            "objects": objects,
        }

    def _evidence_to_stix(self, evidence: Dict[str, Any]) -> Dict[str, Any] | None:
        """Convert evidence to STIX Indicator."""
        ev_type = evidence.get("type", "")
        ev_value = evidence.get("value", "")

        if ev_type == "ip":
            pattern = f"[ipv4-addr:value = '{ev_value}']"
        elif ev_type == "domain":
            pattern = f"[domain-name:value = '{ev_value}']"
        elif ev_type == "url":
            pattern = f"[url:value = '{ev_value}']"
        elif ev_type == "hash":
            if len(ev_value) == 32:
                pattern = f"[file:hashes.MD5 = '{ev_value}']"
            elif len(ev_value) == 64:
                pattern = f"[file:hashes.'SHA-256' = '{ev_value}']"
            else:
                return None
        elif ev_type == "file":
            pattern = f"[file:name = '{ev_value.split(chr(92))[-1]}']"
        else:
            return None

        return {
            "type": "indicator",
            "spec_version": "2.1",
            "id": f"indicator--{uuid.uuid4()}",
            "created": datetime.utcnow().isoformat() + "Z",
            "modified": datetime.utcnow().isoformat() + "Z",
            "name": f"{ev_type.upper()}: {ev_value[:50]}",
            "description": evidence.get("context", ""),
            "pattern": pattern,
            "pattern_type": "stix",
            "valid_from": datetime.utcnow().isoformat() + "Z",
            "confidence": int(evidence.get("confidence", 0.5) * 100),
        }

    def _calculate_threat_level(self) -> str:
        """Calculate overall threat level from evidence."""
        evidence = self.session.get("evidence", [])
        if not evidence:
            return "Low"

        max_score = max(ev.get("threat_score", 0) for ev in evidence)

        if max_score >= 0.9:
            return "CRITICAL"
        elif max_score >= 0.7:
            return "HIGH"
        elif max_score >= 0.5:
            return "MEDIUM"
        else:
            return "LOW"

    def _generate_workflow_section(self) -> List[Dict[str, Any]]:
        """Generate workflow section from steps."""
        workflow = []
        for step in self.session.get("steps", []):
            workflow.append({
                "step_number": step.get("step_number"),
                "timestamp": step.get("timestamp"),
                "phase": step.get("phase"),
                "tool": step.get("tool"),
                "tool_category": step.get("tool_category"),
                "thought": step.get("thought"),
                "action": step.get("action"),
                "input": step.get("input"),
                "output": step.get("output"),
                "evidence_extracted": len(step.get("evidence", [])),
                "next_step_reasoning": step.get("next_step_reasoning"),
                "duration_ms": step.get("duration_ms"),
            })
        return workflow

    def _generate_evidence_section(self) -> List[Dict[str, Any]]:
        """Generate evidence section."""
        return self.session.get("evidence", [])

    def _generate_timeline_section(self) -> List[Dict[str, Any]]:
        """Generate timeline section."""
        return self.session.get("timeline", [])

    def _generate_mitre_section(self) -> Dict[str, List[str]]:
        """Generate MITRE mapping section."""
        return self.session.get("mitre_coverage", {})

    def _generate_ioc_section(self) -> Dict[str, List[str]]:
        """Generate IOC section grouped by type."""
        iocs = {}
        for ev in self.session.get("evidence", []):
            ev_type = ev.get("type", "other")
            if ev_type in ["ip", "domain", "url", "hash", "file", "registry"]:
                if ev_type not in iocs:
                    iocs[ev_type] = []
                if ev.get("value") not in iocs[ev_type]:
                    iocs[ev_type].append(ev.get("value"))
        return iocs

    def _generate_attack_scenario(self) -> Dict[str, Any]:
        """Generate attack scenario from investigation findings."""
        steps = self.session.get("steps", [])
        evidence = self.session.get("evidence", [])
        hypotheses = self.session.get("hypotheses", [])
        mitre = self.session.get("mitre_coverage", {})
        
        # Extract attack phases from evidence and steps
        phases = {
            "initial_access": [],
            "execution": [],
            "persistence": [],
            "privilege_escalation": [],
            "defense_evasion": [],
            "credential_access": [],
            "discovery": [],
            "lateral_movement": [],
            "collection": [],
            "command_and_control": [],
            "exfiltration": [],
            "impact": [],
        }
        
        # Map evidence to attack phases based on MITRE tactics
        for ev in evidence:
            tactics = ev.get("mitre_tactics", [])
            for tactic in tactics:
                tactic_key = tactic.lower().replace("-", "_").replace(" ", "_")
                if tactic_key in phases:
                    phases[tactic_key].append({
                        "type": ev.get("type", "unknown"),
                        "value": ev.get("value", ""),
                        "confidence": ev.get("confidence", 0),
                    })
        
        # Build narrative from steps
        narrative_parts = []
        for step in steps[-10:]:  # Use last 10 steps for narrative
            if step.get("observation"):
                narrative_parts.append(step.get("observation", "")[:200])
        
        # Build primary hypothesis
        primary_hypothesis = None
        if hypotheses:
            sorted_hyps = sorted(hypotheses, key=lambda x: x.get("confidence", 0), reverse=True)
            primary_hypothesis = {
                "hypothesis": sorted_hyps[0].get("hypothesis", "Unknown attack pattern"),
                "confidence": sorted_hyps[0].get("confidence", 0),
                "supporting_evidence": sorted_hyps[0].get("supporting_evidence", []),
            }
        
        return {
            "narrative": " → ".join(narrative_parts) if narrative_parts else "Attack scenario analysis in progress.",
            "phases": {k: v for k, v in phases.items() if v},  # Only include non-empty phases
            "primary_hypothesis": primary_hypothesis,
            "mitre_techniques_used": list(set(
                tech for techs in mitre.values() if isinstance(techs, list) for tech in techs
            )) if isinstance(mitre, dict) else [],
            "total_evidence_items": len(evidence),
            "investigation_steps": len(steps),
        }

    def _generate_recommendations(self) -> List[str]:
        """Generate recommendations based on findings."""
        recommendations = [
            "Immediately isolate affected systems from the network",
            "Block identified C2 IP addresses at perimeter firewall",
            "Reset credentials for all potentially compromised accounts",
            "Deploy EDR signatures for identified malware families",
            "Conduct enterprise-wide threat hunt using identified IOCs",
            "Review and enhance email security to prevent similar phishing attacks",
            "Implement PowerShell script block logging and constrained language mode",
            "Enable LSASS protection (Credential Guard) on critical systems",
            "Review and audit Windows services and Run keys for unauthorized entries",
            "Preserve forensic images for potential legal proceedings",
        ]
        return recommendations

    def _render_workflow_html(self, workflow: List[Dict]) -> str:
        """Render workflow as HTML."""
        if not workflow:
            return "<p>No investigation workflow steps recorded yet.</p>"
        html = ""
        for step in workflow:
            input_data = step.get("input", {})
            output_data = step.get("output", {})
            input_str = json.dumps(input_data, indent=2) if input_data else "{}"
            output_parsed = output_data.get("parsed", {}) if isinstance(output_data, dict) else {}
            output_str = json.dumps(output_parsed, indent=2) if output_parsed else "{}"
            
            step_num = step.get('step_number', '?')
            tool = step.get('tool') or step.get('action_type') or 'Analysis'
            phase = step.get('phase') or 'Unknown'
            thought = step.get('thought') or step.get('reasoning') or 'N/A'
            action = step.get('action') or 'N/A'
            evidence_count = step.get('evidence_extracted', 0)
            next_reasoning = step.get('next_step_reasoning') or ''

            html += f"""
            <div class="step-card">
                <div class="step-header">
                    <span class="step-number">Step {step_num}</span>
                    <span class="tool-name">{tool}</span>
                    <span style="color: var(--text-secondary);">{phase}</span>
                </div>
                <p class="thought"><strong>Thought:</strong> {thought[:200]}...</p>
                <p class="action"><strong>Action:</strong> {action[:200]}...</p>
                <div class="io-section">
                    <div class="io-box">
                        <h4>Input</h4>
                        <pre>{input_str[:500]}</pre>
                    </div>
                    <div class="io-box">
                        <h4>Output</h4>
                        <pre>{output_str[:500]}</pre>
                    </div>
                </div>
                <p><strong>Evidence Extracted:</strong> {evidence_count} items</p>
                <p style="color: var(--text-secondary);"><strong>Next Step Reasoning:</strong> {next_reasoning}</p>
            </div>
            """
        return html

    def _render_evidence_html(self, evidence: List[Dict]) -> str:
        """Render evidence as HTML cards."""
        if not evidence:
            return "<p>No evidence collected yet.</p>"
        html = ""
        for ev in evidence[:20]:  # Limit to 20 for HTML
            confidence = (ev.get("confidence", 0) or 0) * 100
            ev_type = ev.get('type', 'unknown') or 'unknown'
            ev_value = ev.get('value', '') or ''
            html += f"""
            <div class="evidence-card">
                <div class="type">{ev_type}</div>
                <div class="value">{ev_value[:100]}</div>
                <div class="confidence">
                    <span>Confidence:</span>
                    <div class="confidence-bar">
                        <div class="confidence-fill" style="width: {confidence}%;"></div>
                    </div>
                    <span>{confidence:.0f}%</span>
                </div>
                <div style="color: var(--text-secondary); font-size: 0.85rem; margin-top: 0.5rem;">
                    {ev.get('context', '')}
                </div>
            </div>
            """
        return html

    def _render_timeline_html(self, timeline: List[Dict]) -> str:
        """Render timeline as HTML."""
        html = ""
        for event in timeline:
            severity_class = f"severity-{event.get('severity', 'info')}"
            html += f"""
            <div class="timeline-event">
                <div class="time">{event.get('timestamp', '')}</div>
                <div>
                    <span class="{severity_class}">[{event.get('severity', 'INFO').upper()}]</span>
                    {event.get('event', '')}
                </div>
            </div>
            """
        return html

    def _render_attack_scenario_html(self, scenario: Dict[str, Any]) -> str:
        """Render attack scenario as HTML."""
        if not scenario:
            return "<p>Attack scenario analysis pending...</p>"
        
        narrative = scenario.get("narrative", "No narrative available yet.")
        phases = scenario.get("phases", {})
        primary_hyp = scenario.get("primary_hypothesis")
        mitre_techs = scenario.get("mitre_techniques_used", [])
        
        html = f"""
        <div style="margin-bottom: 1.5rem;">
            <h3 style="color: var(--accent-purple);">Attack Narrative</h3>
            <p style="background: var(--bg-tertiary); padding: 1rem; border-radius: 8px; line-height: 1.8;">
                {narrative}
            </p>
        </div>
        """
        
        if primary_hyp:
            conf = primary_hyp.get("confidence", 0) * 100
            html += f"""
            <div style="margin-bottom: 1.5rem;">
                <h3 style="color: var(--accent-yellow);">Primary Attack Hypothesis</h3>
                <div style="background: var(--bg-tertiary); padding: 1rem; border-radius: 8px; border-left: 4px solid var(--accent-yellow);">
                    <p><strong>{primary_hyp.get('hypothesis', 'Unknown')}</strong></p>
                    <p style="color: var(--accent-green);">Confidence: {conf:.0f}%</p>
                </div>
            </div>
            """
        
        if phases:
            html += """
            <h3 style="color: var(--accent-blue);">Attack Phases (MITRE ATT&CK)</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 1rem;">
            """
            for phase_name, phase_evidence in phases.items():
                phase_display = phase_name.replace("_", " ").title()
                evidence_html = "".join(
                    f'<div style="font-family: monospace; font-size: 0.85rem; margin: 0.25rem 0;">• {ev.get("value", "")[:50]}</div>'
                    for ev in phase_evidence[:3]
                )
                if len(phase_evidence) > 3:
                    evidence_html += f'<div style="color: var(--text-secondary);">... and {len(phase_evidence) - 3} more</div>'
                
                html += f"""
                <div style="background: var(--bg-tertiary); padding: 1rem; border-radius: 8px;">
                    <h4 style="color: var(--accent-purple); margin-bottom: 0.5rem;">{phase_display}</h4>
                    <div style="color: var(--text-secondary);">{len(phase_evidence)} evidence items</div>
                    {evidence_html}
                </div>
                """
            html += "</div>"
        
        if mitre_techs:
            html += f"""
            <div style="margin-top: 1.5rem;">
                <h3 style="color: var(--accent-red);">MITRE ATT&CK Techniques Used</h3>
                <div style="display: flex; flex-wrap: wrap; gap: 0.5rem;">
                    {''.join(f'<span class="technique-tag">{t}</span>' for t in mitre_techs[:15])}
                </div>
            </div>
            """
        
        return html

    def _render_mitre_html(self, mitre_mapping: Dict[str, List[str]]) -> str:
        """Render MITRE mapping as HTML."""
        if not mitre_mapping:
            return "<p>No MITRE ATT&CK mappings identified yet.</p>"
        html = ""
        for tactic, techniques in mitre_mapping.items():
            if not isinstance(techniques, list):
                continue
            techniques_html = "".join(f'<span class="technique-tag">{t}</span>' for t in techniques)
            html += f"""
            <div class="mitre-tactic">
                <h4>{tactic or 'Unknown Tactic'}</h4>
                {techniques_html}
            </div>
            """
        return html if html else "<p>No MITRE ATT&CK mappings identified yet.</p>"

    def _render_hypotheses_html(self, hypotheses: List[Dict]) -> str:
        """Render hypotheses as HTML."""
        if not hypotheses:
            return "<p>No attack hypotheses generated yet.</p>"
        html = ""
        for hyp in hypotheses:
            confidence = hyp.get("confidence", 0) or 0
            conf_class = "high-confidence" if confidence >= 0.8 else "medium-confidence"
            title = hyp.get('title') or hyp.get('hypothesis') or 'Unknown Hypothesis'
            threat_actor = hyp.get('threat_actor') or 'Unknown'
            objective = hyp.get('objective') or hyp.get('description') or 'Unknown'
            html += f"""
            <div class="hypothesis-card">
                <h3>{title}
                    <span class="confidence-badge {conf_class}">{confidence*100:.0f}% confidence</span>
                </h3>
                <p><strong>Threat Actor:</strong> {threat_actor}</p>
                <p><strong>Objective:</strong> {objective}</p>
            </div>
            """
        return html

    def _render_iocs_html(self, iocs: Dict[str, List[str]]) -> str:
        """Render IOCs as HTML table."""
        if not iocs:
            return "<p>No IOCs extracted.</p>"

        html = """<table class="ioc-table"><thead><tr><th>Type</th><th>Value</th></tr></thead><tbody>"""
        for ioc_type, values in iocs.items():
            for value in values[:10]:  # Limit per type
                html += f"<tr><td>{ioc_type.upper()}</td><td>{value}</td></tr>"
        html += "</tbody></table>"
        return html
