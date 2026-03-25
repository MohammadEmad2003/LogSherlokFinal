"""
Utility Functions for Autonomous Forensic Agent
LLM integration, state management, MITRE mapping, and helpers
"""
import json
import hashlib
import re
from typing import List, Dict, Any, Optional
from datetime import datetime
import aiohttp
import asyncio

from schemas import (
    LLMRequest, LLMResponse, ModelOutput, Evidence,
    MITRECoverage, AttackHypothesis, TodoItem, FullState
)


# ============================================================================
# LLM Integration
# ============================================================================

class LLMClient:
    """Client for interacting with OpenAI-compatible LLM API"""

    def __init__(self, base_url: str, api_key: str = "dummy", model: str = "gpt-4"):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.model = model
        self.max_retries = 2  # Reduced for faster response
        self.timeout = 30  # Reduced from 60 for faster timeout

    async def generate(self, request: LLMRequest) -> LLMResponse:
        """Generate completion from LLM"""

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": self._get_system_prompt()},
                {"role": "user", "content": request.prompt}
            ],
            "max_tokens": request.max_tokens,
            "temperature": request.temperature,
        }

        # Add JSON mode if requested
        if request.response_format == "json":
            payload["response_format"] = {"type": "json_object"}

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}"
        }

        for attempt in range(self.max_retries):
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.post(
                        f"{self.base_url}/chat/completions",
                        json=payload,
                        headers=headers,
                        timeout=aiohttp.ClientTimeout(total=self.timeout)
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            content = data['choices'][0]['message']['content'] or ""

                            # Parse JSON if requested
                            parsed_output = None
                            if request.response_format == "json" and content.strip():
                                try:
                                    parsed_json = json.loads(content)
                                    parsed_output = ModelOutput(**parsed_json)
                                except Exception as e:
                                    print(f"Failed to parse JSON: {e}")
                                    # Try to extract JSON from markdown code blocks
                                    json_match = re.search(r'```(?:json)?\s*\n?(.*?)\n?```', content, re.DOTALL)
                                    if json_match:
                                        try:
                                            parsed_json = json.loads(json_match.group(1).strip())
                                            parsed_output = ModelOutput(**parsed_json)
                                        except Exception as e2:
                                            print(f"Failed to parse extracted JSON: {e2}")
                                    # Also try to find a raw JSON object in the content
                                    if not parsed_output:
                                        obj_match = re.search(r'\{[^{}]*"reasoning"[^{}]*\}', content, re.DOTALL)
                                        if obj_match:
                                            try:
                                                parsed_json = json.loads(obj_match.group(0))
                                                parsed_output = ModelOutput(**parsed_json)
                                            except Exception:
                                                pass

                            return LLMResponse(
                                content=content,
                                parsed_output=parsed_output,
                                model=data.get('model', self.model),
                                usage=data.get('usage', {}),
                                finish_reason=data['choices'][0].get('finish_reason', 'stop')
                            )
                        else:
                            error_text = await response.text()
                            print(f"LLM API error (attempt {attempt + 1}): {response.status} - {error_text}")

                            if attempt == self.max_retries - 1:
                                raise Exception(f"LLM API failed after {self.max_retries} attempts")

                            await asyncio.sleep(1)  # Quick retry

            except asyncio.TimeoutError:
                print(f"LLM request timed out (attempt {attempt + 1})")
                if attempt == self.max_retries - 1:
                    raise Exception(f"LLM request timed out after {self.max_retries} attempts")
                await asyncio.sleep(1)

            except Exception as e:
                print(f"LLM request failed (attempt {attempt + 1}): {e}")
                if attempt == self.max_retries - 1:
                    raise

                await asyncio.sleep(1)

    def _get_system_prompt(self) -> str:
        """Get system prompt for forensic agent"""
        return """You are an expert forensic analyst AI agent performing autonomous digital forensic investigations.

Your goal is to analyze forensic artifacts (memory dumps, disk images, PCAP files, etc.) by:
1. REASONING about what to investigate next based on current evidence
2. ACTING by executing forensic commands/tools
3. OBSERVING the results and extracting evidence

IMPORTANT GUIDELINES:
- Use ONLY standard Linux forensic tools: volatility, strings, file, grep, tshark, etc.
- Do NOT make up tool names or commands
- Base your reasoning on actual evidence found, not assumptions
- Be specific about what you're looking for and why
- If a command fails, try alternative approaches
- Build hypotheses progressively from evidence
- Map findings to MITRE ATT&CK framework when relevant

OUTPUT FORMAT (JSON):
{
    "reasoning": "Explain your thought process and why this action makes sense",
    "action": "The exact command to execute (use real tools only)",
    "action_type": "command|analysis|query|complete",
    "expected_output": "What you expect to find from this action",
    "confidence": 0.7,
    "should_continue": true,
    "priority": "critical|high|medium|low"
}

When investigation is complete, set action_type to "complete" and should_continue to false."""

    async def generate_reasoning(self, context: Dict[str, Any]) -> ModelOutput:
        """Generate next reasoning step"""

        # Build context-aware prompt
        prompt = self._build_reasoning_prompt(context)

        request = LLMRequest(
            prompt=prompt,
            context=context,
            max_tokens=1500,
            temperature=0.7,
            response_format="json"
        )

        response = await self.generate(request)

        if response.parsed_output:
            return response.parsed_output
        else:
            # Fallback if parsing failed
            print("Warning: LLM response parsing failed, using fallback")
            return ModelOutput(
                reasoning="Failed to parse LLM response",
                action="echo 'Error: Could not parse LLM output'",
                action_type="command",
                expected_output="Error message",
                confidence=0.1,
                should_continue=True,
                priority="low"
            )

    def _build_reasoning_prompt(self, context: Dict[str, Any]) -> str:
        """Build comprehensive prompt with investigation context"""

        artifact_type = context.get('artifact_type', 'unknown')
        artifact_path = context.get('artifact_path', 'unknown')
        steps_taken = context.get('steps_count', 0)
        evidence_found = context.get('evidence', [])
        recent_observations = context.get('recent_observations', [])
        current_phase = context.get('current_phase', 'initialization')
        todos = context.get('todos', [])

        prompt = f"""FORENSIC INVESTIGATION STATUS

Artifact Type: {artifact_type}
Artifact Path: {artifact_path}
Investigation Phase: {current_phase}
Steps Taken: {steps_taken}

"""

        # Add evidence summary
        if evidence_found:
            prompt += f"EVIDENCE FOUND ({len(evidence_found)} items):\n"
            # Group by type
            evidence_by_type = {}
            for ev in evidence_found[-20:]:  # Last 20 pieces of evidence
                ev_type = ev.get('type', 'unknown')
                if ev_type not in evidence_by_type:
                    evidence_by_type[ev_type] = []
                evidence_by_type[ev_type].append(ev.get('value', ''))

            for ev_type, values in evidence_by_type.items():
                prompt += f"  - {ev_type}: {', '.join(values[:5])}"
                if len(values) > 5:
                    prompt += f" ... and {len(values) - 5} more"
                prompt += "\n"
        else:
            prompt += "EVIDENCE FOUND: None yet\n"

        # Add recent observations
        if recent_observations:
            prompt += f"\nRECENT OBSERVATIONS:\n"
            for obs in recent_observations[-3:]:
                prompt += f"  - {obs}\n"

        # Add pending todos
        pending_todos = [t for t in todos if t.get('status') == 'pending']
        if pending_todos:
            prompt += f"\nPENDING TASKS:\n"
            for todo in pending_todos[:5]:
                prompt += f"  - [{todo.get('priority', 'medium')}] {todo.get('task', '')}\n"

        # Add phase-specific guidance
        phase_guidance = {
            'initialization': 'Start with basic artifact identification and metadata extraction',
            'initial_analysis': 'Perform broad analysis to understand artifact contents',
            'deep_analysis': 'Focus on suspicious findings and extract detailed evidence',
            'threat_hunting': 'Hunt for specific indicators of compromise',
            'correlation': 'Connect evidence pieces and build attack timeline',
            'finalization': 'Summarize findings and complete investigation'
        }

        guidance = phase_guidance.get(current_phase, 'Continue investigation')
        prompt += f"\nPHASE GUIDANCE: {guidance}\n"

        prompt += """\n\nBased on the above context, determine the NEXT BEST ACTION to take.
Respond in JSON format with your reasoning and the exact command to execute.
Use ONLY real forensic tools (volatility, strings, grep, tshark, etc).
Be specific and goal-oriented."""

        return prompt


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


def format_step_for_display(step: 'AgentStep') -> Dict[str, Any]:
    """Format agent step for dashboard display"""
    return {
        'step_number': step.step_number,
        'phase': step.phase,
        'reasoning': step.reasoning,
        'action': step.action,
        'observation': step.observation,
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
