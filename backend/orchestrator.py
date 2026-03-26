"""
Autonomous Forensic Orchestrator
Uses the CAI DFIR Agent via Runner.run() for forensic investigation.
Implements iterative agent invocation with per-step dashboard updates.
"""
import asyncio
import os
import re
import json
import traceback
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime

from backend.schemas import (
    ForensicScenario, AgentStep, Evidence, ModelOutput,
    FullState, DashboardPayload, AttackHypothesis,
    TodoItem, MITRECoverage
)

# Handle imports for both running as module and standalone
try:
    from backend.utils import (
        MITREMapper, StateManager, TodoManager,
        generate_session_id, format_evidence_for_display,
        format_step_for_display, should_continue_investigation
    )
except ImportError:
    from backend.utils import (
        MITREMapper, StateManager, TodoManager,
        generate_session_id, format_evidence_for_display,
        format_step_for_display, should_continue_investigation
    )

# Evidence extraction patterns (kept from original, used to parse agent output)
EVIDENCE_PATTERNS = {
    'ip': re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'),
    'domain': re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'),
    'md5': re.compile(r'\b[a-fA-F0-9]{32}\b'),
    'sha1': re.compile(r'\b[a-fA-F0-9]{40}\b'),
    'sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
    'url': re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+'),
    'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'),
    'file_path': re.compile(r'(?:[A-Z]:\\|/)[^\s"\'<>|*?]+'),
}

# Private/benign filters
PRIVATE_IP_PREFIXES = ('0.', '10.', '127.', '169.254.')
BENIGN_DOMAINS = {'microsoft.com', 'windows.com', 'apple.com', 'google.com',
                  'github.com', 'localhost', 'example.com'}


def _is_private_ip(ip: str) -> bool:
    """Check if IP is private/local."""
    parts = ip.split('.')
    try:
        first = int(parts[0])
        second = int(parts[1])
        if first in (0, 10, 127):
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
    except (ValueError, IndexError):
        pass
    return False


def extract_evidence_from_text(text: str, source: str) -> List[Evidence]:
    """Extract evidence items from text output using regex patterns."""
    evidence_list = []
    for ev_type, pattern in EVIDENCE_PATTERNS.items():
        matches = pattern.findall(text)
        for match in set(matches):
            # Filter false positives
            if ev_type == 'ip' and _is_private_ip(match):
                continue
            if ev_type == 'domain' and any(b in match.lower() for b in BENIGN_DOMAINS):
                continue
            if ev_type == 'domain' and len(match) < 5:
                continue

            # Infer MITRE tactics
            tactics = []
            techniques = []
            if ev_type in ('ip', 'domain', 'url'):
                tactics = ['command-and-control']
                techniques = ['T1071']
            elif ev_type in ('md5', 'sha1', 'sha256'):
                tactics = ['defense-evasion']
                techniques = ['T1027']
            elif ev_type == 'file_path':
                tactics = ['execution']
                techniques = ['T1059']

            evidence_list.append(Evidence(
                type=ev_type,
                value=match,
                confidence=0.7,
                threat_score=0.4,
                source=source,
                context={"extracted_from": "agent_output"},
                mitre_tactics=tactics,
                mitre_techniques=techniques,
            ))

    # Extract process names (.exe, .dll)
    proc_pattern = re.compile(r'\b[A-Za-z0-9_\-]+\.(?:exe|dll)\b', re.IGNORECASE)
    for match in set(proc_pattern.findall(text)):
        if len(match) > 4:
            evidence_list.append(Evidence(
                type='process',
                value=match,
                confidence=0.6,
                threat_score=0.4,
                source=source,
                context={"extracted_from": "agent_output"},
                mitre_tactics=['execution'],
                mitre_techniques=['T1059'],
            ))

    return evidence_list


class TerminalStream:
    def __init__(self, orchestrator, original_stdout):
        self.orchestrator = orchestrator
        self.original_stdout = original_stdout
        self.buffer = ""

    def write(self, s):
        self.original_stdout.write(s)
        self.original_stdout.flush()
        if not hasattr(self.orchestrator, "current_session") or not self.orchestrator.current_session:
            return
            
        if s.endswith('\n'):
            line = self.buffer + s
            self.buffer = ""
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    loop.create_task(self.orchestrator._send_dashboard_update('terminal_log', {'content': line}))
            except Exception:
                pass
        else:
            self.buffer += s

    def flush(self):
        self.original_stdout.flush()

class ForensicOrchestrator:
    """
    Autonomous forensic investigation orchestrator.
    Uses the CAI DFIR Agent via Runner.run() for each investigation step.
    """

    def __init__(
        self,
        websocket_callback: Optional[Callable] = None,
        max_steps: int = 50
    ):
        self.websocket_callback = websocket_callback
        self.max_steps = max_steps

        # Initialize components
        self.mitre_mapper = MITREMapper()
        self.state_manager = StateManager()
        self.todo_manager = TodoManager()

        # DFIR Agent (lazy-loaded)
        self._dfir_agent = None

        # Tracking
        self.current_session: Optional[str] = None

    def _get_dfir_agent(self):
        """Lazy-load the DFIR agent from cai.agents."""
        if self._dfir_agent is None:
            try:
                from cai.agents.dfir import dfir_agent
                self._dfir_agent = dfir_agent
                print("[ORCHESTRATOR] DFIR Agent loaded successfully")
            except ImportError as e:
                print(f"[ORCHESTRATOR] Failed to import DFIR agent: {e}")
                raise RuntimeError(
                    "Could not import DFIR agent from cai.agents.dfir. "
                    "Make sure the cai package is installed and accessible."
                ) from e
        return self._dfir_agent

    async def start_investigation(
        self,
        artifact_path: str,
        artifact_type: str,
        artifact_name: str,
        description: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> str:
        """
        Start a new autonomous investigation.
        Returns session_id
        """
        if not session_id:
            session_id = generate_session_id()
        self.current_session = session_id

        # Create initial scenario
        scenario = ForensicScenario(
            artifact_name=artifact_name,
            artifact_type=artifact_type,
            artifact_path=artifact_path,
            description=description,
            session_id=session_id,
            initial_hypothesis=description
        )

        # Initialize state
        state = FullState(
            session_id=session_id,
            scenario=scenario,
            status="active",
            current_phase="initialization"
        )

        # Generate initial to-do list
        initial_todos = self.todo_manager.generate_initial_todos(artifact_type, artifact_path)
        state.todos = initial_todos

        # Save state
        self.state_manager.update_state(session_id, state)

        # Send initial dashboard update
        await self._send_dashboard_update("step", {
            "message": f"Investigation started for {artifact_name}",
            "phase": "initialization",
            "artifact_type": artifact_type,
            "step_number": 0,
            "reasoning": f"Starting forensic investigation of {artifact_type} artifact: {artifact_name}",
            "action": "Initializing investigation...",
            "observation": f"Artifact uploaded: {artifact_name} ({artifact_type})",
            "confidence": 0.5,
            "evidence_count": 0,
        })

        await self._send_dashboard_update("todo", {
            "todos": [self._format_todo(t) for t in initial_todos]
        })

        # Start investigation loop
        asyncio.create_task(self._investigation_loop(session_id))

        return session_id

    async def _investigation_loop(self, session_id: str):
        """
        Main investigation loop — iteratively calls the DFIR Agent.
        Each step: build prompt → Runner.run(dfir_agent) → parse result → update state.
        """
        import sys
        original_stdout = sys.stdout
        original_stderr = sys.stderr
        sys.stdout = TerminalStream(self, original_stdout)
        sys.stderr = TerminalStream(self, original_stderr)

        state = self.state_manager.get_state(session_id)
        if not state:
            print(f"Error: No state found for session {session_id}")
            return

        step_number = 1

        try:
            # Lazy-load Runner and agent
            from cai.sdk.agents import Runner
            agent = self._get_dfir_agent()

            while should_continue_investigation(state, self.max_steps):
                print(f"\n{'=' * 60}")
                print(f"STEP {step_number}: Running DFIR Agent")
                print(f"{'=' * 60}")

                # Build the investigation prompt for this step
                prompt = self._build_investigation_prompt(state)

                try:
                    # Call the DFIR agent via Runner.run()
                    result = await Runner.run(
                        starting_agent=agent,
                        input=prompt,
                        max_turns=5,  # Allow agent to make more tool calls per step for thorough investigation
                    )

                    # Parse the agent result
                    agent_output_text = str(result.final_output) if result.final_output else ""

                    # Extract tool calls info from run items
                    tool_calls_made = []
                    tool_outputs = []
                    reasoning_text = ""

                    for item in result.new_items:
                        item_dict = item.to_input_item() if hasattr(item, 'to_input_item') else {}

                        # Handle different item types
                        if hasattr(item, 'raw_item'):
                            raw = item.raw_item
                            # Check for tool call items
                            if hasattr(raw, 'type'):
                                if raw.type == 'function_call':
                                    tool_name = getattr(raw, 'name', 'unknown_tool')
                                    tool_args = getattr(raw, 'arguments', '{}')
                                    tool_calls_made.append(f"{tool_name}({tool_args[:200]})")
                                elif raw.type == 'function_call_output':
                                    output_text = getattr(raw, 'output', '')
                                    if output_text:
                                        tool_outputs.append(str(output_text)[:2000])
                            # Check for message items
                            if hasattr(raw, 'role') and raw.role == 'assistant':
                                content = getattr(raw, 'content', '')
                                if isinstance(content, str) and content:
                                    reasoning_text += content + "\n"
                                elif isinstance(content, list):
                                    for part in content:
                                        if hasattr(part, 'text'):
                                            reasoning_text += part.text + "\n"

                    # Build clear reasoning and action descriptions
                    if not reasoning_text and agent_output_text:
                        reasoning_text = agent_output_text

                    action_description = ""
                    if tool_calls_made:
                        action_description = " → ".join(tool_calls_made[:3])
                    elif reasoning_text:
                        # Extract first meaningful sentence
                        first_line = reasoning_text.strip().split('\n')[0][:200]
                        action_description = first_line

                    # Combine all text for evidence extraction
                    all_output = "\n".join([reasoning_text] + tool_outputs + [agent_output_text])

                    # Extract evidence from the output
                    new_evidence = extract_evidence_from_text(all_output, f"dfir_agent_step_{step_number}")

                    # Build observation summary
                    observation = ""
                    if new_evidence:
                        evidence_summary = {}
                        for ev in new_evidence:
                            evidence_summary[ev.type] = evidence_summary.get(ev.type, 0) + 1
                        summary_parts = [f"{count} {t}(s)" for t, count in evidence_summary.items()]
                        observation = f"Agent analysis complete. Found {len(new_evidence)} evidence items: {', '.join(summary_parts)}"
                    elif tool_outputs:
                        observation = f"Agent executed {len(tool_calls_made)} tool(s). Output received for analysis."
                    else:
                        observation = "Agent completed reasoning step. No new evidence extracted."

                    if agent_output_text and len(agent_output_text) > 10:
                        # Add a snippet of the agent's analysis
                        snippet = agent_output_text[:300].replace('\n', ' ')
                        observation += f" Analysis: {snippet}"

                    # Check if the agent indicates the investigation is complete
                    # Only mark complete if attack scenario is described or flag is found (for CTF)
                    is_complete = any(phrase in agent_output_text.lower() for phrase in [
                        "investigation complete",
                        "analysis is complete",
                        "investigation is done",
                        "concludes the investigation",
                        "no further analysis needed",
                        "final report",
                        "attack scenario:",
                        "attack narrative:",
                        "flag found:",
                        "ctf flag:",
                        "flag{",
                        "flag:",
                    ])
                    
                    # Require minimum steps before allowing completion to ensure thorough investigation
                    if is_complete and step_number < 5:
                        # Don't complete too early - continue investigation
                        is_complete = False

                    # Determine confidence based on evidence found
                    confidence = 0.5
                    if new_evidence:
                        confidence = min(0.6 + len(new_evidence) * 0.05, 0.95)
                    if tool_calls_made:
                        confidence = max(confidence, 0.6)

                    print(f"[STEP {step_number}] Tools called: {len(tool_calls_made)}")
                    print(f"[STEP {step_number}] Evidence found: {len(new_evidence)}")
                    print(f"[STEP {step_number}] Reasoning: {reasoning_text[:120] if reasoning_text else 'N/A'}")

                except Exception as e:
                    print(f"[STEP {step_number}] Agent error: {e}")
                    traceback.print_exc()
                    state.error_log.append(f"Step {step_number} error: {str(e)}")

                    # Fallback: use generic analysis
                    reasoning_text = f"Agent encountered an error: {str(e)}. Attempting fallback analysis."
                    action_description = f"strings '{state.scenario.artifact_path}' | head -100"
                    observation = f"Error in agent execution: {str(e)}"
                    new_evidence = []
                    is_complete = False
                    confidence = 0.3
                    tool_calls_made = []
                    tool_outputs = []

                # Create agent step
                agent_step = AgentStep(
                    step_number=step_number,
                    phase="complete",
                    reasoning=reasoning_text[:500] if reasoning_text else f"Analysis step {step_number}",
                    action=action_description or f"Forensic analysis step {step_number}",
                    action_type="command" if tool_calls_made else "analysis",
                    observation=observation,
                    evidence_found=new_evidence,
                    confidence=confidence,
                    error=None if not state.error_log else state.error_log[-1] if state.error_log else None
                )

                # Update state
                state.steps.append(agent_step)
                state.evidence.extend(new_evidence)

                # Enrich evidence with MITRE mappings
                for ev in new_evidence:
                    self.mitre_mapper.enrich_evidence(ev)

                # Update MITRE coverage
                state.mitre_coverage = self.mitre_mapper.update_coverage(state.evidence)

                # Update threat score and confidence
                state.threat_score = self.state_manager.calculate_threat_score(state)
                state.overall_confidence = self.state_manager.calculate_confidence(state)

                # Update phase
                self.state_manager.update_phase(state)

                # Update hypotheses
                await self._update_hypotheses(state)

                # Update todos
                await self._update_todos(state, action_description)

                # Save state
                self.state_manager.update_state(session_id, state)

                # Send dashboard updates
                await self._send_step_update(agent_step)
                for evidence in new_evidence:
                    await self._send_evidence_update(evidence)

                # Send MITRE mappings for new evidence
                for ev in new_evidence:
                    for i, tactic in enumerate(ev.mitre_tactics):
                        technique_id = ev.mitre_techniques[i] if i < len(ev.mitre_techniques) else ""
                        if technique_id:
                            await self._send_dashboard_update("mitre_mapping", {
                                "tactic": tactic,
                                "technique_id": technique_id,
                                "technique_name": technique_id,
                                "evidence_value": ev.value,
                                "evidence_type": ev.type,
                            })

                # Send timeline event for this step
                await self._send_dashboard_update("timeline_event", {
                    "timestamp": agent_step.timestamp.isoformat(),
                    "event": action_description or f"Step {step_number} analysis",
                    "description": observation[:200] if observation else f"Step {step_number} completed",
                    "severity": "high" if confidence > 0.8 else ("medium" if confidence > 0.5 else "info"),
                    "step_number": step_number,
                    "evidence_count": len(new_evidence),
                })

                # Send progress update
                progress_pct = min((step_number / self.max_steps) * 100, 95)
                await self._send_dashboard_update("progress", {
                    "progress": progress_pct,
                    "phase": state.current_phase,
                    "step_number": step_number,
                    "evidence_total": len(state.evidence),
                })

                # Check if complete
                if is_complete:
                    await self._complete_investigation(
                        state,
                        reasoning_text or "Investigation completed by DFIR agent."
                    )
                    break

                step_number += 1
                await asyncio.sleep(0.5)

            # If loop ended without explicit completion
            if state.status != "completed":
                await self._complete_investigation(
                    state,
                    f"Investigation completed after {len(state.steps)} analysis steps."
                )

        except Exception as e:
            print(f"Error in investigation loop: {e}")
            traceback.print_exc()
            state.status = "error"
            state.error_log.append(f"Investigation loop error: {str(e)}")
            await self._send_dashboard_update("error", {
                "message": f"Investigation error: {str(e)}"
            })
        finally:
            self.state_manager.update_state(session_id, state)
            import sys
            sys.stdout = original_stdout
            sys.stderr = original_stderr

    def _build_investigation_prompt(self, state: FullState) -> str:
        """Build a prompt for the DFIR agent based on current investigation state."""
        artifact_type = state.scenario.artifact_type
        artifact_path = state.scenario.artifact_path
        artifact_name = state.scenario.artifact_name
        steps_count = len(state.steps)
        phase = state.current_phase

        prompt = f"""FORENSIC INVESTIGATION TASK

You are investigating a {artifact_type} forensic artifact.
Artifact: {artifact_name}
Path: {artifact_path}
Investigation Phase: {phase}
Steps Completed: {steps_count}

"""
        # Add evidence summary
        if state.evidence:
            evidence_by_type = {}
            for ev in state.evidence[-20:]:
                if ev.type not in evidence_by_type:
                    evidence_by_type[ev.type] = []
                evidence_by_type[ev.type].append(ev.value)

            prompt += f"EVIDENCE FOUND SO FAR ({len(state.evidence)} items):\n"
            for ev_type, values in evidence_by_type.items():
                display = ', '.join(values[:5])
                if len(values) > 5:
                    display += f" ... and {len(values) - 5} more"
                prompt += f"  - {ev_type}: {display}\n"
        else:
            prompt += "EVIDENCE FOUND: None yet\n"

        # Add recent observations
        if state.steps:
            prompt += "\nRECENT ANALYSIS:\n"
            for step in state.steps[-3:]:
                if step.observation:
                    prompt += f"  Step {step.step_number}: {step.observation[:150]}\n"

        # Add pending todos
        pending = [t for t in state.todos if t.status == 'pending']
        if pending:
            prompt += "\nPENDING TASKS:\n"
            for todo in pending[:5]:
                prompt += f"  - [{todo.priority}] {todo.task}\n"

        # Phase-specific guidance
        guidance = {
            'initialization': f'Start by identifying the artifact type and extracting basic metadata. Run: file "{artifact_path}" and strings "{artifact_path}" | head -200',
            'initial_analysis': 'Perform broad analysis to understand artifact contents. Look for suspicious strings, IPs, domains, executables. For memory dumps use: vol -f <file> windows.pslist or linux.pslist',
            'deep_analysis': 'Focus on suspicious findings. Extract detailed evidence. Investigate IOCs found. Use vol for memory analysis, yara for malware scanning.',
            'threat_hunting': 'Hunt for specific indicators of compromise. Check for malware signatures, C2 communication patterns. Use vol -f <file> windows.malfind for injection detection.',
            'correlation': 'Connect evidence pieces and build COMPLETE attack scenario. Document: Initial Access, Execution, Persistence, Privilege Escalation, Defense Evasion, Credential Access, Discovery, Lateral Movement, Collection, C2, Exfiltration, Impact.',
            'finalization': 'Provide complete attack narrative with all MITRE ATT&CK mappings. Only mark complete if full scenario is documented.'
        }.get(phase, 'Continue the investigation based on current evidence.')

        prompt += f"\nGUIDANCE: {guidance}\n"

        if steps_count >= self.max_steps - 2:
            prompt += "\nNOTE: Investigation is nearing the step limit. Please summarize ALL findings and provide COMPLETE attack scenario before concluding.\n"

        prompt += """
Execute the next most valuable forensic analysis action. Use generic_linux_command to run commands.
IMPORTANT: 
- Use 'vol' command for Volatility3, NOT 'volatility'
- For memory analysis: vol -f <memory.raw> windows.pslist, vol -f <memory.raw> windows.malfind, etc.
- Continue until you have a COMPLETE attack scenario or found all flags (for CTF challenges)
- Be specific and explain your reasoning clearly."""

        return prompt

    async def _update_hypotheses(self, state: FullState):
        """Update attack hypotheses based on evidence."""
        evidence_types = {}
        for ev in state.evidence:
            evidence_types[ev.type] = evidence_types.get(ev.type, 0) + 1

        new_hypotheses = []

        if evidence_types.get('ip', 0) > 3 or evidence_types.get('domain', 0) > 3:
            new_hypotheses.append(AttackHypothesis(
                hypothesis="Possible C2 (Command and Control) communication detected",
                confidence=min(0.6 + (evidence_types.get('ip', 0) * 0.05), 0.95),
                supporting_evidence=[ev.value for ev in state.evidence if ev.type in ('ip', 'domain')][:5],
                mitre_tactics=['command-and-control'],
                mitre_techniques=['T1071'],
                severity='high'
            ))

        if evidence_types.get('process', 0) > 5:
            new_hypotheses.append(AttackHypothesis(
                hypothesis="Suspicious process execution pattern detected",
                confidence=0.7,
                supporting_evidence=[ev.value for ev in state.evidence if ev.type == 'process'][:5],
                mitre_tactics=['execution'],
                mitre_techniques=['T1059'],
                severity='medium'
            ))

        if evidence_types.get('url', 0) > 2:
            new_hypotheses.append(AttackHypothesis(
                hypothesis="Potential data exfiltration or malicious download activity",
                confidence=0.65,
                supporting_evidence=[ev.value for ev in state.evidence if ev.type == 'url'][:5],
                mitre_tactics=['exfiltration', 'command-and-control'],
                mitre_techniques=['T1071.001'],
                severity='high'
            ))

        for new_hyp in new_hypotheses:
            if not any(h.hypothesis == new_hyp.hypothesis for h in state.hypotheses):
                state.hypotheses.append(new_hyp)
                await self._send_dashboard_update("hypothesis", {
                    'hypothesis': new_hyp.hypothesis,
                    'confidence': new_hyp.confidence,
                    'severity': new_hyp.severity,
                    'supporting_evidence': new_hyp.supporting_evidence
                })

    async def _update_todos(self, state: FullState, action_description: str):
        """Update dynamic to-do list based on progress."""
        action_lower = action_description.lower() if action_description else ""

        for todo in state.todos:
            if todo.status == 'pending':
                if any(keyword in action_lower for keyword in todo.task.lower().split()[:3]):
                    todo.status = 'completed'
                    todo.completed_at = datetime.utcnow()
                    print(f"[TODO] Completed: {todo.task}")
                    await self._send_dashboard_update("todo", {
                        "todos": [self._format_todo(t) for t in state.todos]
                    })
                    break

        # Add new todos based on evidence
        evidence_types = {}
        for ev in state.evidence:
            evidence_types[ev.type] = evidence_types.get(ev.type, 0) + 1

        if evidence_types.get('ip', 0) > 0 and not any('investigate IP' in t.task for t in state.todos):
            new_todo = self.todo_manager.create_todo(
                f"Investigate suspicious IP connections ({evidence_types['ip']} found)",
                priority="high",
                rationale="New IPs discovered in analysis"
            )
            state.todos.append(new_todo)
            await self._send_dashboard_update("todo", {
                "todos": [self._format_todo(t) for t in state.todos]
            })

    async def _complete_investigation(self, state: FullState, final_reasoning: str):
        """Complete the investigation."""
        print(f"\n[COMPLETE] Investigation completed")
        print(f"Reasoning: {final_reasoning[:200]}")

        state.status = "completed"
        state.completed_at = datetime.utcnow()
        state.current_phase = "complete"

        for todo in state.todos:
            if todo.status == 'pending':
                todo.status = 'completed'
                todo.completed_at = datetime.utcnow()

        self.state_manager.update_state(state.session_id, state)

        await self._send_dashboard_update("complete", {
            'message': final_reasoning[:500],
            'total_steps': len(state.steps),
            'evidence_count': len(state.evidence),
            'threat_score': state.threat_score,
            'confidence': state.overall_confidence,
            'mitre_coverage': {
                'tactics': state.mitre_coverage.total_tactics,
                'techniques': state.mitre_coverage.total_techniques
            }
        })

    def _format_todo(self, todo: TodoItem) -> Dict[str, Any]:
        """Format todo for display."""
        return {
            'id': todo.id,
            'task': todo.task,
            'priority': todo.priority,
            'status': todo.status,
            'created_at': todo.created_at.isoformat(),
            'completed_at': todo.completed_at.isoformat() if todo.completed_at else None,
            'rationale': todo.rationale
        }

    async def _send_dashboard_update(self, update_type: str, data: Dict[str, Any]):
        """Send update to dashboard via WebSocket."""
        if self.websocket_callback and self.current_session:
            payload = DashboardPayload(
                type=update_type,
                data=data,
                session_id=self.current_session
            )
            try:
                await self.websocket_callback(payload.model_dump(mode='json'))
            except Exception as e:
                print(f"Error sending dashboard update: {e}")

    async def _send_step_update(self, step: AgentStep):
        """Send step update to dashboard."""
        await self._send_dashboard_update("step", format_step_for_display(step))

    async def _send_evidence_update(self, evidence: Evidence):
        """Send evidence update to dashboard."""
        await self._send_dashboard_update("evidence", format_evidence_for_display(evidence))

    def get_state(self, session_id: str) -> Optional[FullState]:
        """Get investigation state."""
        return self.state_manager.get_state(session_id)

    def list_sessions(self) -> List[Dict[str, Any]]:
        """List all investigation sessions."""
        sessions = []
        for session_id, state in self.state_manager.states.items():
            sessions.append({
                'session_id': session_id,
                'artifact_name': state.scenario.artifact_name,
                'artifact_type': state.scenario.artifact_type,
                'status': state.status,
                'steps_count': len(state.steps),
                'evidence_count': len(state.evidence),
                'started_at': state.started_at.isoformat(),
                'current_phase': state.current_phase
            })
        return sessions

    async def chat_with_agent(self, message: str, context: Dict[str, Any]) -> str:
        """Process a chat message using the DFIR agent."""
        try:
            from cai.sdk.agents import Runner
            agent = self._get_dfir_agent()

            # Build chat prompt with investigation context
            prompt = f"""You are a forensic analyst assistant. Answer based on these investigation findings:

Artifact: {context.get('artifact_name', 'unknown')} ({context.get('artifact_type', 'unknown')})
Phase: {context.get('current_phase', 'unknown')}
Threat Score: {context.get('threat_score', 0):.0%}

Evidence ({len(context.get('evidence', []))} items):
"""
            for ev in context.get('evidence', [])[:10]:
                prompt += f"  - [{ev.get('type', '?')}] {ev.get('value', 'N/A')} (threat: {ev.get('threat_score', 0):.0%})\n"

            hypotheses = context.get('hypotheses', [])
            if hypotheses:
                prompt += "\nHypotheses:\n"
                for h in hypotheses[:3]:
                    prompt += f"  - {h.get('hypothesis', 'N/A')} ({h.get('severity', '?')})\n"

            prompt += f"\nUSER QUESTION: {message}\n"
            prompt += "\nProvide a clear, detailed response based on the evidence above. Use markdown formatting."

            result = await Runner.run(
                starting_agent=agent,
                input=prompt,
                max_turns=1,
            )

            return str(result.final_output) if result.final_output else "No response generated."

        except Exception as e:
            print(f"Chat agent error: {e}")
            return f"I encountered an error processing your question: {str(e)}"
