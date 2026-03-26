"""
Utility Functions for Autonomous Forensic Agent
State management, MITRE mapping, TODO management, and helpers.

NOTE: LLMClient has been removed. The orchestrator now uses the
CAI DFIR Agent via Runner.run() for all LLM interactions.
"""
import json
import hashlib
from typing import List, Dict, Any, Optional
from datetime import datetime

from schemas import (
    ModelOutput, Evidence,
    MITRECoverage, AttackHypothesis, TodoItem, FullState, AgentStep
)


# ============================================================================
# MITRE ATT&CK Mapping
# ============================================================================

class MITREMapper:
    """Map evidence to MITRE ATT&CK framework"""

    # MITRE ATT&CK Tactics (enterprise matrix)
    TACTICS = {
        'reconnaissance': 'Reconnaissance',
        'resource-development': 'Resource Development',
        'initial-access': 'Initial Access',
        'execution': 'Execution',
        'persistence': 'Persistence',
        'privilege-escalation': 'Privilege Escalation',
        'defense-evasion': 'Defense Evasion',
        'credential-access': 'Credential Access',
        'discovery': 'Discovery',
        'lateral-movement': 'Lateral Movement',
        'collection': 'Collection',
        'command-and-control': 'Command and Control',
        'exfiltration': 'Exfiltration',
        'impact': 'Impact'
    }

    # Common techniques mapping
    TECHNIQUES = {
        'T1059': {'name': 'Command and Scripting Interpreter', 'tactics': ['execution']},
        'T1059.001': {'name': 'PowerShell', 'tactics': ['execution']},
        'T1059.003': {'name': 'Windows Command Shell', 'tactics': ['execution']},
        'T1053': {'name': 'Scheduled Task/Job', 'tactics': ['execution', 'persistence', 'privilege-escalation']},
        'T1053.005': {'name': 'Scheduled Task', 'tactics': ['execution', 'persistence', 'privilege-escalation']},
        'T1055': {'name': 'Process Injection', 'tactics': ['defense-evasion', 'privilege-escalation']},
        'T1071': {'name': 'Application Layer Protocol', 'tactics': ['command-and-control']},
        'T1071.001': {'name': 'Web Protocols', 'tactics': ['command-and-control']},
        'T1090': {'name': 'Proxy', 'tactics': ['command-and-control']},
        'T1105': {'name': 'Ingress Tool Transfer', 'tactics': ['command-and-control']},
        'T1112': {'name': 'Modify Registry', 'tactics': ['defense-evasion']},
        'T1486': {'name': 'Data Encrypted for Impact', 'tactics': ['impact']},
        'T1490': {'name': 'Inhibit System Recovery', 'tactics': ['impact']},
        'T1496': {'name': 'Resource Hijacking', 'tactics': ['impact']},
        'T1498': {'name': 'Network Denial of Service', 'tactics': ['impact']},
        'T1489': {'name': 'Service Stop', 'tactics': ['impact']},
        'T1078': {'name': 'Valid Accounts', 'tactics': ['defense-evasion', 'persistence', 'privilege-escalation', 'initial-access']},
        'T1003': {'name': 'OS Credential Dumping', 'tactics': ['credential-access']},
        'T1021': {'name': 'Remote Services', 'tactics': ['lateral-movement']},
        'T1018': {'name': 'Remote System Discovery', 'tactics': ['discovery']},
        'T1082': {'name': 'System Information Discovery', 'tactics': ['discovery']},
        'T1083': {'name': 'File and Directory Discovery', 'tactics': ['discovery']},
    }

    def update_coverage(self, evidence_list: List[Evidence]) -> MITRECoverage:
        """Calculate MITRE coverage from evidence"""

        tactics_count = {}
        techniques_dict = {}

        for evidence in evidence_list:
            # Count tactics
            for tactic in evidence.mitre_tactics:
                tactics_count[tactic] = tactics_count.get(tactic, 0) + 1

            # Count techniques
            for technique in evidence.mitre_techniques:
                if technique not in techniques_dict:
                    technique_info = self.TECHNIQUES.get(technique, {})
                    techniques_dict[technique] = {
                        'name': technique_info.get('name', technique),
                        'description': f"Technique {technique}",
                        'evidence_count': 0
                    }
                techniques_dict[technique]['evidence_count'] += 1

        coverage_score = len(techniques_dict) / max(len(self.TECHNIQUES), 1)

        return MITRECoverage(
            tactics=tactics_count,
            techniques=techniques_dict,
            total_tactics=len(tactics_count),
            total_techniques=len(techniques_dict),
            coverage_score=min(coverage_score, 1.0)
        )

    def enrich_evidence(self, evidence: Evidence) -> Evidence:
        """Enrich evidence with MITRE mappings"""

        # Infer tactics/techniques if not already set
        if not evidence.mitre_tactics or not evidence.mitre_techniques:
            tactics, techniques = self._infer_mitre(evidence)
            evidence.mitre_tactics = list(set(evidence.mitre_tactics + tactics))
            evidence.mitre_techniques = list(set(evidence.mitre_techniques + techniques))

        return evidence

    def _infer_mitre(self, evidence: Evidence) -> tuple[List[str], List[str]]:
        """Infer MITRE tactics and techniques from evidence"""

        tactics = []
        techniques = []

        # Evidence type based inference
        if evidence.type == 'ip' or evidence.type == 'domain':
            tactics.extend(['command-and-control'])
            techniques.extend(['T1071'])

        if evidence.type == 'process':
            tactics.extend(['execution'])
            if 'powershell' in evidence.value.lower():
                techniques.extend(['T1059.001'])
            elif 'cmd' in evidence.value.lower():
                techniques.extend(['T1059.003'])
            else:
                techniques.extend(['T1059'])

        if evidence.type == 'registry_key':
            tactics.extend(['persistence', 'defense-evasion'])
            techniques.extend(['T1112'])

        # Context-based inference
        if evidence.context:
            context_str = json.dumps(evidence.context).lower()

            if 'scheduled task' in context_str:
                tactics.extend(['persistence'])
                techniques.extend(['T1053.005'])

            if 'injection' in context_str:
                tactics.extend(['defense-evasion', 'privilege-escalation'])
                techniques.extend(['T1055'])

        return tactics, techniques


# ============================================================================
# State Management
# ============================================================================

class StateManager:
    """Manage investigation state"""

    def __init__(self):
        self.states: Dict[str, FullState] = {}

    def get_state(self, session_id: str) -> Optional[FullState]:
        """Get state for session"""
        return self.states.get(session_id)

    def update_state(self, session_id: str, state: FullState):
        """Update state for session"""
        self.states[session_id] = state

    def calculate_threat_score(self, state: FullState) -> float:
        """Calculate overall threat score from evidence"""

        if not state.evidence:
            return 0.0

        # Weighted average of threat scores
        total_score = sum(ev.threat_score * ev.confidence for ev in state.evidence)
        total_weight = sum(ev.confidence for ev in state.evidence)

        if total_weight == 0:
            return 0.0

        return total_score / total_weight

    def calculate_confidence(self, state: FullState) -> float:
        """Calculate overall investigation confidence"""

        if not state.steps:
            return 0.0

        # Average confidence of recent steps
        recent_steps = state.steps[-10:]
        avg_confidence = sum(step.confidence for step in recent_steps) / len(recent_steps)

        # Boost confidence if evidence is correlated
        evidence_count = len(state.evidence)
        if evidence_count > 10:
            avg_confidence = min(avg_confidence + 0.1, 1.0)

        return avg_confidence

    def update_phase(self, state: FullState):
        """Update investigation phase based on progress"""

        step_count = len(state.steps)
        evidence_count = len(state.evidence)

        if step_count < 3:
            state.current_phase = 'initialization'
        elif step_count < 10:
            state.current_phase = 'initial_analysis'
        elif evidence_count < 5:
            state.current_phase = 'deep_analysis'
        elif evidence_count < 15:
            state.current_phase = 'threat_hunting'
        else:
            state.current_phase = 'correlation'


# ============================================================================
# Todo Management
# ============================================================================

class TodoManager:
    """Manage dynamic to-do list"""

    def create_todo(self, task: str, priority: str = "medium", rationale: str = None) -> TodoItem:
        """Create a new todo item"""

        todo_id = hashlib.md5(f"{task}{datetime.utcnow()}".encode()).hexdigest()[:8]

        return TodoItem(
            id=todo_id,
            task=task,
            priority=priority,
            status="pending",
            rationale=rationale
        )

    def generate_initial_todos(self, artifact_type: str, artifact_path: str) -> List[TodoItem]:
        """Generate initial to-do list based on artifact type"""

        todos = []

        # Universal tasks
        todos.append(self.create_todo(
            "Identify artifact type and basic metadata",
            priority="critical",
            rationale="Need to understand what we're analyzing"
        ))

        # Type-specific tasks
        if artifact_type == "memory_dump":
            todos.extend([
                self.create_todo("Extract process list and identify suspicious processes", priority="high"),
                self.create_todo("Analyze network connections", priority="high"),
                self.create_todo("Scan for malware signatures in memory", priority="high"),
                self.create_todo("Extract command history", priority="medium"),
            ])

        elif artifact_type == "disk_image":
            todos.extend([
                self.create_todo("Analyze partition table", priority="high"),
                self.create_todo("Extract file system timeline", priority="high"),
                self.create_todo("Identify suspicious files", priority="high"),
            ])

        elif artifact_type == "pcap":
            todos.extend([
                self.create_todo("Extract unique IP addresses", priority="high"),
                self.create_todo("Analyze DNS queries", priority="high"),
                self.create_todo("Identify HTTP/HTTPS traffic", priority="medium"),
            ])

        elif artifact_type == "evtx":
            todos.extend([
                self.create_todo("Parse Windows Event Logs", priority="high"),
                self.create_todo("Identify security events", priority="high"),
                self.create_todo("Extract logon/logoff events", priority="medium"),
            ])

        # General fallback tasks for unknown/binary/archive types
        else:
            todos.extend([
                self.create_todo("Extract strings and inspect for IOCs", priority="high"),
                self.create_todo("Check for embedded files and metadata", priority="high"),
                self.create_todo("Hash the artifact for reputation lookup", priority="medium"),
            ])

        # Final tasks
        todos.append(self.create_todo(
            "Correlate findings and build attack timeline",
            priority="medium",
            rationale="Connect evidence pieces"
        ))

        todos.append(self.create_todo(
            "Generate final report",
            priority="low",
            rationale="Summarize investigation"
        ))

        return todos

    def update_todo_status(self, todos: List[TodoItem], todo_id: str, status: str) -> List[TodoItem]:
        """Update status of a todo item"""

        for todo in todos:
            if todo.id == todo_id:
                todo.status = status
                if status == "completed":
                    todo.completed_at = datetime.utcnow()
                break

        return todos

    def get_next_pending_todo(self, todos: List[TodoItem]) -> Optional[TodoItem]:
        """Get next pending todo by priority"""

        priority_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}

        pending_todos = [t for t in todos if t.status == 'pending']
        if not pending_todos:
            return None

        # Sort by priority
        pending_todos.sort(key=lambda t: priority_order.get(t.priority, 99))

        return pending_todos[0]


# ============================================================================
# Helper Functions
# ============================================================================

def generate_session_id() -> str:
    """Generate unique session ID"""
    return hashlib.md5(f"{datetime.utcnow()}{id(object())}".encode()).hexdigest()[:16]


def format_evidence_for_display(evidence: Evidence) -> Dict[str, Any]:
    """Format evidence for dashboard display"""
    return {
        'type': evidence.type,
        'value': evidence.value,
        'confidence': evidence.confidence,
        'threat_score': evidence.threat_score,
        'source': evidence.source,
        'context': evidence.context,
        'mitre_tactics': evidence.mitre_tactics,
        'mitre_techniques': evidence.mitre_techniques,
        'timestamp': evidence.timestamp.isoformat()
    }


def format_step_for_display(step: AgentStep) -> Dict[str, Any]:
    """Format agent step for dashboard display"""
    return {
        'step_number': step.step_number,
        'phase': step.phase,
        'reasoning': step.reasoning or f"Analysis step {step.step_number}",
        'action': step.action or "Forensic analysis",
        'observation': step.observation or "",
        'confidence': step.confidence,
        'evidence_count': len(step.evidence_found),
        'timestamp': step.timestamp.isoformat(),
        'error': step.error
    }


def should_continue_investigation(state: FullState, max_steps: int = 50) -> bool:
    """Determine if investigation should continue"""

    # Stop if max steps reached
    if len(state.steps) >= max_steps:
        return False

    # Stop if status is completed or error
    if state.status in ['completed', 'error']:
        return False

    # Stop if recent steps show completion
    if len(state.steps) >= 3:
        recent_steps = state.steps[-3:]
        if all(step.phase == 'complete' for step in recent_steps):
            return False

    return True
