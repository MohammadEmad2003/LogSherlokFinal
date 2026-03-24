"""
Session Manager - Manages forensic investigation sessions
Tracks state, steps, evidence, and progress for each investigation
"""
from __future__ import annotations

import threading
from datetime import datetime
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
import json
import logging

logger = logging.getLogger(__name__)


@dataclass
class InvestigationStep:
    """Represents a single step in the forensic investigation."""
    step_id: str
    step_number: int
    timestamp: str
    phase: str  # analysis, enrichment, detection, correlation, reporting
    thought: str  # Why this step is needed
    action: str  # What the agent decides to do
    tool: str  # Tool being used
    tool_category: str  # Category: memory_forensics, disk_forensics, etc.
    input_data: Dict[str, Any]  # Input to the tool
    output_data: Dict[str, Any]  # Output from the tool
    evidence: List[Dict[str, Any]]  # Evidence extracted
    next_step_reasoning: str  # Why next step is chosen
    duration_ms: int  # How long the step took
    status: str  # pending, running, completed, failed

    def to_dict(self) -> Dict[str, Any]:
        return {
            "step_id": self.step_id,
            "step_number": self.step_number,
            "timestamp": self.timestamp,
            "phase": self.phase,
            "thought": self.thought,
            "action": self.action,
            "tool": self.tool,
            "tool_category": self.tool_category,
            "input": self.input_data,
            "output": self.output_data,
            "evidence": self.evidence,
            "next_step_reasoning": self.next_step_reasoning,
            "duration_ms": self.duration_ms,
            "status": self.status,
        }


@dataclass
class Evidence:
    """Represents a piece of evidence discovered during investigation."""
    evidence_id: str
    type: str  # ip, domain, hash, process, file, registry, command, ioc
    value: str
    confidence: float  # 0.0 to 1.0
    source_step: str  # Which step discovered this
    source_tool: str  # Which tool found it
    context: str  # Additional context
    mitre_techniques: List[str]  # Related MITRE techniques
    threat_score: float  # 0.0 to 1.0
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "evidence_id": self.evidence_id,
            "type": self.type,
            "value": self.value,
            "confidence": self.confidence,
            "source_step": self.source_step,
            "source_tool": self.source_tool,
            "context": self.context,
            "mitre_techniques": self.mitre_techniques,
            "threat_score": self.threat_score,
            "timestamp": self.timestamp,
        }


@dataclass
class Session:
    """Represents a forensic investigation session."""
    session_id: str
    artifact_path: str
    artifact_name: str
    artifact_type: str
    artifact_size: int
    description: str
    created_at: str
    status: str = "initialized"  # initialized, running, paused, completed, failed
    current_phase: str = "initializing"
    progress: float = 0.0
    steps: List[InvestigationStep] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    instructions: List[Dict[str, str]] = field(default_factory=list)
    mitre_coverage: Dict[str, List[str]] = field(default_factory=dict)
    timeline: List[Dict[str, Any]] = field(default_factory=list)
    hypotheses: List[Dict[str, Any]] = field(default_factory=list)
    summary: str = ""
    conclusion: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "artifact_path": self.artifact_path,
            "artifact_name": self.artifact_name,
            "artifact_type": self.artifact_type,
            "artifact_size": self.artifact_size,
            "description": self.description,
            "created_at": self.created_at,
            "status": self.status,
            "current_phase": self.current_phase,
            "progress": self.progress,
            "steps": [s.to_dict() for s in self.steps],
            "evidence": [e.to_dict() for e in self.evidence],
            "instructions": self.instructions,
            "mitre_coverage": self.mitre_coverage,
            "timeline": self.timeline,
            "hypotheses": self.hypotheses,
            "summary": self.summary,
            "conclusion": self.conclusion,
        }


class SessionManager:
    """
    Thread-safe session manager for forensic investigations.
    Manages creation, updates, and retrieval of investigation sessions.
    """

    def __init__(self):
        self._sessions: Dict[str, Session] = {}
        self._lock = threading.RLock()
        logger.info("SessionManager initialized")

    def create_session(
        self,
        session_id: str,
        artifact_path: str,
        artifact_name: str,
        artifact_type: str,
        artifact_size: int,
        description: str = "",
    ) -> Session:
        """Create a new investigation session."""
        with self._lock:
            session = Session(
                session_id=session_id,
                artifact_path=artifact_path,
                artifact_name=artifact_name,
                artifact_type=artifact_type,
                artifact_size=artifact_size,
                description=description,
                created_at=datetime.utcnow().isoformat(),
            )
            self._sessions[session_id] = session
            logger.info(f"Created session: {session_id}")
            return session

    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data as dictionary."""
        with self._lock:
            session = self._sessions.get(session_id)
            return session.to_dict() if session else None

    def get_session_object(self, session_id: str) -> Optional[Session]:
        """Get the actual Session object."""
        with self._lock:
            return self._sessions.get(session_id)

    def update_session(self, session_id: str, **updates) -> bool:
        """Update session attributes."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False

            for key, value in updates.items():
                if hasattr(session, key):
                    setattr(session, key, value)

            return True

    def add_step(self, session_id: str, step: InvestigationStep) -> bool:
        """Add a step to the investigation."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False

            session.steps.append(step)
            logger.info(f"Session {session_id}: Added step {step.step_number} - {step.tool}")
            return True

    def add_evidence(self, session_id: str, evidence: Evidence) -> bool:
        """Add evidence to the investigation."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False

            # Check for duplicates
            for existing in session.evidence:
                if existing.type == evidence.type and existing.value == evidence.value:
                    return False  # Already exists

            session.evidence.append(evidence)
            logger.info(f"Session {session_id}: Added evidence {evidence.type}: {evidence.value}")
            return True

    def add_instruction(self, session_id: str, instruction: str) -> bool:
        """Add a user instruction to the session."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False

            session.instructions.append({
                "timestamp": datetime.utcnow().isoformat(),
                "instruction": instruction,
            })
            return True

    def add_mitre_technique(self, session_id: str, tactic: str, technique: str) -> bool:
        """Add MITRE technique to coverage map."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False

            if tactic not in session.mitre_coverage:
                session.mitre_coverage[tactic] = []

            if technique not in session.mitre_coverage[tactic]:
                session.mitre_coverage[tactic].append(technique)

            return True

    def add_timeline_event(self, session_id: str, event: Dict[str, Any]) -> bool:
        """Add an event to the attack timeline."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False

            session.timeline.append(event)
            # Sort by timestamp
            session.timeline.sort(key=lambda x: x.get("timestamp", ""))
            return True

    def add_hypothesis(self, session_id: str, hypothesis: Dict[str, Any]) -> bool:
        """Add an attack hypothesis."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False

            session.hypotheses.append(hypothesis)
            return True

    def set_progress(self, session_id: str, progress: float, phase: str = None) -> bool:
        """Update investigation progress."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False

            session.progress = min(100.0, max(0.0, progress))
            if phase:
                session.current_phase = phase

            return True

    def complete_session(self, session_id: str, summary: str, conclusion: str) -> bool:
        """Mark session as completed with final summary."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return False

            session.status = "completed"
            session.progress = 100.0
            session.summary = summary
            session.conclusion = conclusion
            session.current_phase = "completed"

            logger.info(f"Session {session_id} completed")
            return True

    def list_sessions(self) -> List[Dict[str, Any]]:
        """List all sessions with basic info."""
        with self._lock:
            return [
                {
                    "session_id": s.session_id,
                    "artifact_name": s.artifact_name,
                    "artifact_type": s.artifact_type,
                    "status": s.status,
                    "progress": s.progress,
                    "created_at": s.created_at,
                    "steps_count": len(s.steps),
                    "evidence_count": len(s.evidence),
                }
                for s in self._sessions.values()
            ]

    def delete_session(self, session_id: str) -> bool:
        """Delete a session."""
        with self._lock:
            if session_id in self._sessions:
                del self._sessions[session_id]
                logger.info(f"Deleted session: {session_id}")
                return True
            return False

    def export_session(self, session_id: str) -> Optional[str]:
        """Export session as JSON string."""
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            return json.dumps(session.to_dict(), indent=2)


# Global session manager instance
session_manager = SessionManager()
