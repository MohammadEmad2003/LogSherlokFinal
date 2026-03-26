"""
Pydantic v2 Schemas for Autonomous Forensic Agent
"""
from typing import List, Dict, Any, Optional, Literal
from pydantic import BaseModel, Field, ConfigDict
from datetime import datetime


# ============================================================================
# Core Forensic Models
# ============================================================================

class ForensicScenario(BaseModel):
    """Describes the initial forensic investigation scenario"""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    artifact_name: str = Field(..., description="Name of the forensic artifact")
    artifact_type: str = Field(
        ...,
        description="Type of artifact being analyzed"
    )
    artifact_path: str = Field(..., description="Path to the uploaded artifact")
    description: Optional[str] = Field(None, description="User-provided description of the incident")
    session_id: str = Field(..., description="Unique session identifier")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Timestamp of scenario creation")
    initial_hypothesis: Optional[str] = Field(None, description="Initial hypothesis about the incident")


class Evidence(BaseModel):
    """Represents a single piece of evidence found during investigation"""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    type: str = Field(..., description="Type of evidence (ip, domain, process, file, hash, etc.)")
    value: str = Field(..., description="The actual evidence value")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence score (0-1)")
    threat_score: float = Field(default=0.5, ge=0.0, le=1.0, description="Threat severity (0-1)")
    source: str = Field(..., description="Tool or analysis that found this evidence")
    context: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Additional context")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="When evidence was discovered")
    mitre_tactics: List[str] = Field(default_factory=list, description="Associated MITRE ATT&CK tactics")
    mitre_techniques: List[str] = Field(default_factory=list, description="Associated MITRE ATT&CK techniques")


class AgentStep(BaseModel):
    """Represents a single step in the investigation"""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    step_number: int = Field(..., description="Sequential step number")
    phase: Literal["reasoning", "action", "observation", "complete"] = Field(..., description="Current phase")
    reasoning: Optional[str] = Field(None, description="Agent's reasoning about what to do next")
    action: Optional[str] = Field(None, description="Action to execute (command or tool)")
    action_type: Optional[Literal["command", "analysis", "query", "complete"]] = Field(None, description="Type of action")
    observation: Optional[str] = Field(None, description="Result/observation from the action")
    evidence_found: List[Evidence] = Field(default_factory=list, description="Evidence discovered in this step")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0, description="Confidence in this step")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Step timestamp")
    error: Optional[str] = Field(None, description="Error message if step failed")


# ============================================================================
# LLM Communication Models (Kept for backward compat with ModelOutput parsing)
# ============================================================================

class ModelOutput(BaseModel):
    """Structured output from agent following ReAct pattern"""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    reasoning: str = Field(..., description="Agent's reasoning about current state and next action")
    action: str = Field(..., description="Command or action to execute")
    action_type: Literal["command", "analysis", "query", "complete"] = Field(
        ...,
        description="Type of action to perform"
    )
    expected_output: str = Field(..., description="What the agent expects from this action")
    confidence: float = Field(default=0.7, ge=0.0, le=1.0, description="Confidence in this decision")
    should_continue: bool = Field(default=True, description="Whether investigation should continue")
    priority: Literal["critical", "high", "medium", "low"] = Field(default="medium", description="Priority of this action")


# ============================================================================
# Investigation State Models
# ============================================================================

class AttackHypothesis(BaseModel):
    """Represents a hypothesis about the attack"""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    hypothesis: str = Field(..., description="Description of the attack hypothesis")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in this hypothesis")
    supporting_evidence: List[str] = Field(default_factory=list, description="Evidence IDs supporting this")
    mitre_tactics: List[str] = Field(default_factory=list, description="Associated MITRE tactics")
    mitre_techniques: List[str] = Field(default_factory=list, description="Associated MITRE techniques")
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(default="medium", description="Severity level")
    status: Literal["active", "confirmed", "dismissed"] = Field(default="active", description="Hypothesis status")


class IncidentTimeline(BaseModel):
    """Timeline entry for the incident"""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    timestamp: datetime = Field(..., description="When this event occurred")
    event_type: str = Field(..., description="Type of event")
    description: str = Field(..., description="Event description")
    evidence_ids: List[str] = Field(default_factory=list, description="Related evidence")
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(default="info", description="Event severity")
    actor: Optional[str] = Field(None, description="Actor/process responsible")


class MITRECoverage(BaseModel):
    """MITRE ATT&CK coverage tracking"""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    tactics: Dict[str, int] = Field(default_factory=dict, description="Tactic name -> count")
    techniques: Dict[str, Dict[str, Any]] = Field(
        default_factory=dict,
        description="Technique ID -> {name, description, evidence_count}"
    )
    total_tactics: int = Field(default=0, description="Total unique tactics identified")
    total_techniques: int = Field(default=0, description="Total unique techniques identified")
    coverage_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Overall coverage score")


class TodoItem(BaseModel):
    """Dynamic to-do list item"""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    id: str = Field(..., description="Unique todo ID")
    task: str = Field(..., description="Task description")
    priority: Literal["critical", "high", "medium", "low"] = Field(default="medium", description="Task priority")
    status: Literal["pending", "in_progress", "completed", "blocked"] = Field(default="pending", description="Task status")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="When task was created")
    completed_at: Optional[datetime] = Field(None, description="When task was completed")
    dependencies: List[str] = Field(default_factory=list, description="IDs of dependent tasks")
    rationale: Optional[str] = Field(None, description="Why this task is needed")


class FullState(BaseModel):
    """Complete state of the forensic investigation"""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    session_id: str = Field(..., description="Session identifier")
    scenario: ForensicScenario = Field(..., description="Initial scenario")
    steps: List[AgentStep] = Field(default_factory=list, description="All investigation steps")
    evidence: List[Evidence] = Field(default_factory=list, description="All evidence collected")
    hypotheses: List[AttackHypothesis] = Field(default_factory=list, description="Attack hypotheses")
    timeline: List[IncidentTimeline] = Field(default_factory=list, description="Incident timeline")
    mitre_coverage: MITRECoverage = Field(default_factory=MITRECoverage, description="MITRE ATT&CK coverage")
    todos: List[TodoItem] = Field(default_factory=list, description="Dynamic to-do list")
    current_phase: str = Field(default="initialization", description="Current investigation phase")
    overall_confidence: float = Field(default=0.0, ge=0.0, le=1.0, description="Overall investigation confidence")
    threat_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Overall threat score")
    status: Literal["initializing", "active", "paused", "completed", "error"] = Field(
        default="initializing",
        description="Investigation status"
    )
    started_at: datetime = Field(default_factory=datetime.utcnow, description="Investigation start time")
    completed_at: Optional[datetime] = Field(None, description="Investigation completion time")
    error_log: List[str] = Field(default_factory=list, description="Errors encountered during investigation")


# ============================================================================
# API Communication Models
# ============================================================================

class DashboardPayload(BaseModel):
    """Payload sent to dashboard via WebSocket"""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    type: Literal[
        "step", "evidence", "hypothesis", "timeline", "todo", "complete", "error",
        "progress", "mitre_mapping", "timeline_event", "chat_response",
        "llm_response", "state_sync", "instruction_ack"
    ] = Field(
        ...,
        description="Type of update"
    )
    data: Dict[str, Any] = Field(..., description="Update data")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Update timestamp")
    session_id: str = Field(..., description="Session ID")


class UploadArtifactRequest(BaseModel):
    """Request for artifact upload"""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    artifact_type: str = Field(
        default="auto",
        description="Type of artifact"
    )
    description: Optional[str] = Field(None, description="Description of the artifact")


class ChatRequest(BaseModel):
    """Request for chat interaction"""
    model_config = ConfigDict(arbitrary_types_allowed=True)

    session_id: str = Field(..., description="Session ID")
    message: str = Field(..., description="User message")
    context_type: Literal["investigation", "evidence", "hypothesis", "general"] = Field(
        default="general",
        description="Type of context for the query"
    )
