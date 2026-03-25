"""
Autonomous Forensic Orchestrator
Implements ReAct pattern: Reason → Act → Observe loop
"""
import asyncio
from typing import List, Dict, Any, Optional, Callable
from datetime import datetime
import json

from schemas import (
    ForensicScenario, AgentStep, Evidence, ModelOutput,
    FullState, DashboardPayload, AttackHypothesis,
    TodoItem, MITRECoverage
)

# Handle imports for both running as module and standalone
try:
    from backend.tools import create_forensic_tools, ForensicTools
except ImportError:
    from tools import create_forensic_tools, ForensicTools

try:
    from backend.utils import (
        LLMClient, MITREMapper, StateManager, TodoManager,
        generate_session_id, format_evidence_for_display,
        format_step_for_display, should_continue_investigation
    )
except ImportError:
    from utils import (
        LLMClient, MITREMapper, StateManager, TodoManager,
        generate_session_id, format_evidence_for_display,
        format_step_for_display, should_continue_investigation
    )


class ForensicOrchestrator:
    """
    Autonomous forensic investigation orchestrator
    Implements ReAct pattern for iterative analysis
    """

    def __init__(
        self,
        llm_client: LLMClient,
        websocket_callback: Optional[Callable] = None,
        max_steps: int = 50
    ):
        self.llm_client = llm_client
        self.websocket_callback = websocket_callback
        self.max_steps = max_steps

        # Initialize components
        self.forensic_tools: ForensicTools = create_forensic_tools()
        self.mitre_mapper = MITREMapper()
        self.state_manager = StateManager()
        self.todo_manager = TodoManager()

        # Tracking
        self.current_session: Optional[str] = None

    async def start_investigation(
        self,
        artifact_path: str,
        artifact_type: str,
        artifact_name: str,
        description: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> str:
        """
        Start a new autonomous investigation
        Returns session_id
        """

        # Use provided session_id (from WebSocket/upload) or generate a new one
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
            "artifact_type": artifact_type
        })

        await self._send_dashboard_update("todo", {
            "todos": [self._format_todo(t) for t in initial_todos]
        })

        # Start ReAct loop
        asyncio.create_task(self._react_loop(session_id))

        return session_id

    async def _react_loop(self, session_id: str):
        """
        Main ReAct loop: Reason → Act → Observe
        """

        state = self.state_manager.get_state(session_id)
        if not state:
            print(f"Error: No state found for session {session_id}")
            return

        step_number = 1

        try:
            while should_continue_investigation(state, self.max_steps):
                print(f"\n{'=' * 60}")
                print(f"STEP {step_number}: Starting ReAct cycle")
                print(f"{'=' * 60}")

                # === PHASE 1: REASON ===
                reasoning_result = await self._reason_phase(state)

                if not reasoning_result:
                    print("Reasoning failed, stopping investigation")
                    break

                # Check if investigation should complete
                if not reasoning_result.should_continue or reasoning_result.action_type == "complete":
                    await self._complete_investigation(state, reasoning_result.reasoning)
                    break

                # === PHASE 2: ACT ===
                action_result = await self._act_phase(state, reasoning_result)

                # === PHASE 3: OBSERVE ===
                observation_result = await self._observe_phase(state, action_result, reasoning_result)

                # Create agent step
                agent_step = AgentStep(
                    step_number=step_number,
                    phase="complete",
                    reasoning=reasoning_result.reasoning,
                    action=reasoning_result.action,
                    action_type=reasoning_result.action_type,
                    observation=observation_result['observation'],
                    evidence_found=observation_result.get('evidence', []),
                    confidence=reasoning_result.confidence,
                    error=observation_result.get('error')
                )

                # Update state
                state.steps.append(agent_step)
                state.evidence.extend(observation_result.get('evidence', []))

                # Update MITRE coverage
                state.mitre_coverage = self.mitre_mapper.update_coverage(state.evidence)

                # Update threat score and confidence
                state.threat_score = self.state_manager.calculate_threat_score(state)
                state.overall_confidence = self.state_manager.calculate_confidence(state)

                # Update phase
                self.state_manager.update_phase(state)

                # Update hypotheses
                await self._update_hypotheses(state, observation_result)

                # Update todos
                await self._update_todos(state, reasoning_result, action_result)

                # Save state
                self.state_manager.update_state(session_id, state)

                # Send dashboard updates
                await self._send_step_update(agent_step)
                for evidence in observation_result.get('evidence', []):
                    await self._send_evidence_update(evidence)

                # Increment step
                step_number += 1

                # Minimal delay between steps (just enough for UI updates)
                await asyncio.sleep(0.5)

        except Exception as e:
            print(f"Error in ReAct loop: {e}")
            state.status = "error"
            state.error_log.append(f"ReAct loop error: {str(e)}")
            await self._send_dashboard_update("error", {
                "message": f"Investigation error: {str(e)}"
            })

        finally:
            # Ensure state is saved
            self.state_manager.update_state(session_id, state)

    async def _reason_phase(self, state: FullState) -> Optional[ModelOutput]:
        """
        REASON: Determine next best action using LLM
        """

        print("\n[REASON] Analyzing current state and determining next action...")

        # Build context for LLM
        context = self._build_context(state)

        try:
            # Generate reasoning
            model_output = await self.llm_client.generate_reasoning(context)

            print(f"[REASON] Reasoning: {model_output.reasoning[:120]}")
            print(f"[REASON] Planned Action: {model_output.action}")
            print(f"[REASON] Confidence: {model_output.confidence:.2f}")

            return model_output

        except Exception as e:
            print(f"[REASON] LLM error (using fallback): {e}")
            state.error_log.append(f"Reasoning error: {str(e)}")

            # Return a safe fallback that keeps the investigation alive
            artifact_type = state.scenario.artifact_type
            fallback_commands = {
                "memory_dump": f"strings '{state.scenario.artifact_path}' | head -200",
                "disk_image": f"file '{state.scenario.artifact_path}'",
                "evtx": f"strings '{state.scenario.artifact_path}' | grep -i 'event\\|error\\|fail' | head -50",
                "pcap": f"strings '{state.scenario.artifact_path}' | grep -E '([0-9]{{1,3}}\\.?){{4}}' | head -50",
                "malware_sample": f"strings '{state.scenario.artifact_path}' | head -100",
            }
            fallback_cmd = fallback_commands.get(
                artifact_type,
                f"file '{state.scenario.artifact_path}' && strings '{state.scenario.artifact_path}' | head -100"
            )

            return ModelOutput(
                reasoning=f"LLM unavailable, executing fallback analysis for {artifact_type} artifact",
                action=fallback_cmd,
                action_type="command",
                expected_output="Basic artifact metadata and string extraction",
                confidence=0.3,
                should_continue=True,
                priority="medium"
            )

    async def _act_phase(self, state: FullState, reasoning: ModelOutput) -> Dict[str, Any]:
        """
        ACT: Execute the planned action
        """

        print(f"\n[ACT] Executing: {reasoning.action}")

        # Handle different action types
        if reasoning.action_type == "command":
            # Execute forensic command
            result = self.forensic_tools.execute_tool(
                command=reasoning.action,
                reasoning=reasoning.reasoning
            )

            print(f"[ACT] Command executed: {result.success}")
            if result.error:
                print(f"[ACT] Error: {result.error}")

            return {
                'type': 'command',
                'success': result.success,
                'output': result.output,
                'error': result.error,
                'evidence': result.evidence_extracted,
                'execution_time': result.execution_time
            }

        elif reasoning.action_type == "analysis":
            # Analytical action (no command execution)
            print(f"[ACT] Performing analysis: {reasoning.action}")
            return {
                'type': 'analysis',
                'success': True,
                'output': f"Analysis: {reasoning.expected_output}",
                'evidence': []
            }

        elif reasoning.action_type == "query":
            # Query existing evidence
            print(f"[ACT] Querying evidence: {reasoning.action}")
            # Search in existing evidence
            query_results = self._query_evidence(state, reasoning.action)
            return {
                'type': 'query',
                'success': True,
                'output': json.dumps(query_results, indent=2),
                'evidence': []
            }

        else:
            return {
                'type': 'unknown',
                'success': False,
                'output': '',
                'error': f"Unknown action type: {reasoning.action_type}",
                'evidence': []
            }

    async def _observe_phase(
        self,
        state: FullState,
        action_result: Dict[str, Any],
        reasoning: ModelOutput
    ) -> Dict[str, Any]:
        """
        OBSERVE: Process action results and extract insights
        """

        print(f"\n[OBSERVE] Processing action results...")

        observation = ""
        evidence = action_result.get('evidence', [])
        error = action_result.get('error')

        if action_result['success']:
            output = action_result.get('output', '')

            # Format observation
            if action_result['type'] == 'command':
                observation = f"Command executed successfully. "
                if evidence:
                    observation += f"Found {len(evidence)} pieces of evidence: "
                    # Summarize evidence
                    evidence_summary = {}
                    for ev in evidence:
                        ev_type = ev.type
                        evidence_summary[ev_type] = evidence_summary.get(ev_type, 0) + 1

                    summary_parts = [f"{count} {ev_type}(s)" for ev_type, count in evidence_summary.items()]
                    observation += ", ".join(summary_parts)

                    # Enrich evidence with MITRE mappings
                    evidence = [self.mitre_mapper.enrich_evidence(ev) for ev in evidence]
                else:
                    observation += "No specific evidence extracted, but output available for analysis."

            elif action_result['type'] == 'analysis':
                observation = f"Analysis completed. {reasoning.expected_output}"

            elif action_result['type'] == 'query':
                observation = f"Query completed. {action_result.get('output', '')}"

            print(f"[OBSERVE] {observation}")

        else:
            observation = f"Action failed: {error}"
            print(f"[OBSERVE] ERROR: {observation}")

        return {
            'observation': observation,
            'evidence': evidence,
            'error': error
        }

    async def _update_hypotheses(self, state: FullState, observation_result: Dict[str, Any]):
        """Update attack hypotheses based on new evidence"""

        # Simple hypothesis generation based on evidence
        evidence_types = {}
        for ev in state.evidence:
            ev_type = ev.type
            evidence_types[ev_type] = evidence_types.get(ev_type, 0) + 1

        # Generate hypotheses
        new_hypotheses = []

        if evidence_types.get('ip', 0) > 3 or evidence_types.get('domain', 0) > 3:
            new_hypotheses.append(AttackHypothesis(
                hypothesis="Possible C2 (Command and Control) communication detected",
                confidence=min(0.6 + (evidence_types.get('ip', 0) * 0.05), 0.95),
                supporting_evidence=[ev.value for ev in state.evidence if ev.type in ['ip', 'domain']][:5],
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

        # Update state hypotheses (avoid duplicates)
        for new_hyp in new_hypotheses:
            if not any(h.hypothesis == new_hyp.hypothesis for h in state.hypotheses):
                state.hypotheses.append(new_hyp)
                # Send hypothesis update
                await self._send_dashboard_update("hypothesis", {
                    'hypothesis': new_hyp.hypothesis,
                    'confidence': new_hyp.confidence,
                    'severity': new_hyp.severity,
                    'supporting_evidence': new_hyp.supporting_evidence
                })

    async def _update_todos(
        self,
        state: FullState,
        reasoning: ModelOutput,
        action_result: Dict[str, Any]
    ):
        """Update dynamic to-do list based on progress"""

        # Mark related todos as completed
        for todo in state.todos:
            if todo.status == 'pending':
                # Check if this action addresses the todo
                if any(keyword in reasoning.action.lower()
                       for keyword in todo.task.lower().split()[:3]):  # Match key words
                    todo.status = 'completed'
                    todo.completed_at = datetime.utcnow()
                    print(f"[TODO] Completed: {todo.task}")

                    # Send todo update
                    await self._send_dashboard_update("todo", {
                        "todos": [self._format_todo(t) for t in state.todos]
                    })
                    break

        # Add new todos based on findings
        if action_result.get('evidence'):
            evidence = action_result['evidence']

            # If we found IPs, add todo to investigate them
            ips = [ev for ev in evidence if ev.type == 'ip']
            if ips and not any('investigate IP' in t.task for t in state.todos):
                new_todo = self.todo_manager.create_todo(
                    f"Investigate suspicious IP connections ({len(ips)} found)",
                    priority="high",
                    rationale="New IPs discovered in analysis"
                )
                state.todos.append(new_todo)

                await self._send_dashboard_update("todo", {
                    "todos": [self._format_todo(t) for t in state.todos]
                })

    async def _complete_investigation(self, state: FullState, final_reasoning: str):
        """Complete the investigation"""

        print("\n[COMPLETE] Investigation completed")
        print(f"Reasoning: {final_reasoning}")

        state.status = "completed"
        state.completed_at = datetime.utcnow()
        state.current_phase = "complete"

        # Mark all remaining todos as completed
        for todo in state.todos:
            if todo.status == 'pending':
                todo.status = 'completed'
                todo.completed_at = datetime.utcnow()

        # Save final state
        self.state_manager.update_state(state.session_id, state)

        # Send completion update
        await self._send_dashboard_update("complete", {
            'message': final_reasoning,
            'total_steps': len(state.steps),
            'evidence_count': len(state.evidence),
            'threat_score': state.threat_score,
            'confidence': state.overall_confidence,
            'mitre_coverage': {
                'tactics': state.mitre_coverage.total_tactics,
                'techniques': state.mitre_coverage.total_techniques
            }
        })

    def _build_context(self, state: FullState) -> Dict[str, Any]:
        """Build context dictionary for LLM"""

        # Get recent observations
        recent_observations = []
        for step in state.steps[-5:]:
            if step.observation:
                recent_observations.append(step.observation)

        return {
            'artifact_type': state.scenario.artifact_type,
            'artifact_path': state.scenario.artifact_path,
            'artifact_name': state.scenario.artifact_name,
            'steps_count': len(state.steps),
            'evidence': [format_evidence_for_display(ev) for ev in state.evidence],
            'recent_observations': recent_observations,
            'current_phase': state.current_phase,
            'todos': [self._format_todo(t) for t in state.todos],
            'threat_score': state.threat_score,
            'confidence': state.overall_confidence
        }

    def _query_evidence(self, state: FullState, query: str) -> List[Dict[str, Any]]:
        """Query existing evidence"""

        results = []
        query_lower = query.lower()

        for evidence in state.evidence:
            if (query_lower in evidence.value.lower() or
                query_lower in evidence.type.lower() or
                query_lower in evidence.source.lower()):
                results.append(format_evidence_for_display(evidence))

        return results[:10]  # Return top 10 matches

    def _format_todo(self, todo: TodoItem) -> Dict[str, Any]:
        """Format todo for display"""
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
        """Send update to dashboard via WebSocket"""

        if self.websocket_callback and self.current_session:
            payload = DashboardPayload(
                type=update_type,
                data=data,
                session_id=self.current_session
            )

            try:
                # mode='json' ensures datetime objects are serialized to ISO strings
                await self.websocket_callback(payload.model_dump(mode='json'))
            except Exception as e:
                print(f"Error sending dashboard update: {e}")

    async def _send_step_update(self, step: AgentStep):
        """Send step update to dashboard"""
        await self._send_dashboard_update("step", format_step_for_display(step))

    async def _send_evidence_update(self, evidence: Evidence):
        """Send evidence update to dashboard"""
        await self._send_dashboard_update("evidence", format_evidence_for_display(evidence))

    def get_state(self, session_id: str) -> Optional[FullState]:
        """Get investigation state"""
        return self.state_manager.get_state(session_id)

    def list_sessions(self) -> List[Dict[str, Any]]:
        """List all investigation sessions"""
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
