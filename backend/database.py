"""
Database Configuration and SQLAlchemy Models
Neon PostgreSQL Database Connection
"""
import os
from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    create_engine, Column, String, Integer, Boolean, DateTime, Text,
    ForeignKey, DECIMAL, BigInteger, ARRAY, Index, text
)
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from sqlalchemy.pool import QueuePool
import uuid

# Database URL from environment or default
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://neondb_owner:npg_4jVhy6cJiYNS@ep-flat-band-ajm740d6-pooler.c-3.us-east-2.aws.neon.tech/neondb?sslmode=require"
)

# Create engine with connection pooling optimized for Neon
engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=5,
    max_overflow=10,
    pool_timeout=30,
    pool_recycle=1800,
    pool_pre_ping=True,  # Helps with Neon's serverless nature
    echo=False  # Set to True for debugging SQL
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for models
Base = declarative_base()


def get_db():
    """Dependency to get database session"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ============================================================================
# User Models
# ============================================================================

class User(Base):
    """User account model"""
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    full_name = Column(String(255))
    role = Column(String(50), default="analyst")
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    avatar_url = Column(String(500))
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login_at = Column(DateTime(timezone=True))
    login_count = Column(Integer, default=0)

    # Relationships
    investigations = relationship("Investigation", back_populates="user", cascade="all, delete-orphan")
    chat_messages = relationship("ChatMessage", back_populates="user", cascade="all, delete-orphan")
    otp_tokens = relationship("OTPToken", back_populates="user", cascade="all, delete-orphan")
    refresh_tokens = relationship("RefreshToken", back_populates="user", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": str(self.id),
            "email": self.email,
            "username": self.username,
            "full_name": self.full_name,
            "role": self.role,
            "is_active": self.is_active,
            "is_verified": self.is_verified,
            "avatar_url": self.avatar_url,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "last_login_at": self.last_login_at.isoformat() if self.last_login_at else None
        }


class OTPToken(Base):
    """OTP tokens for password reset and email verification"""
    __tablename__ = "otp_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token = Column(String(6), nullable=False)
    token_type = Column(String(50), nullable=False)  # password_reset, email_verification
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_used = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    user = relationship("User", back_populates="otp_tokens")


class RefreshToken(Base):
    """Refresh tokens for JWT authentication"""
    __tablename__ = "refresh_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(255), nullable=False)
    device_info = Column(String(500))
    ip_address = Column(String(50))
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_revoked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    user = relationship("User", back_populates="refresh_tokens")


# ============================================================================
# Investigation Models
# ============================================================================

class Investigation(Base):
    """Forensic investigation session"""
    __tablename__ = "investigations"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    session_id = Column(String(20), unique=True, nullable=False, index=True)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    artifact_name = Column(String(500), nullable=False)
    artifact_path = Column(String(1000), nullable=False)
    artifact_type = Column(String(100), nullable=False)
    artifact_size = Column(BigInteger, nullable=False)
    artifact_hash_md5 = Column(String(32))
    artifact_hash_sha256 = Column(String(64))
    description = Column(Text)
    status = Column(String(50), default="initializing")
    current_phase = Column(String(100), default="initialization")
    progress = Column(DECIMAL(5, 2), default=0)
    threat_score = Column(DECIMAL(5, 4), default=0)
    overall_confidence = Column(DECIMAL(5, 4), default=0)
    started_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    completed_at = Column(DateTime(timezone=True))
    error_message = Column(Text)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    user = relationship("User", back_populates="investigations")
    steps = relationship("InvestigationStep", back_populates="investigation", cascade="all, delete-orphan")
    evidence = relationship("Evidence", back_populates="investigation", cascade="all, delete-orphan")
    hypotheses = relationship("Hypothesis", back_populates="investigation", cascade="all, delete-orphan")
    todos = relationship("InvestigationTodo", back_populates="investigation", cascade="all, delete-orphan")
    chat_messages = relationship("ChatMessage", back_populates="investigation", cascade="all, delete-orphan")
    mitre_coverage = relationship("MITRECoverage", back_populates="investigation", cascade="all, delete-orphan")
    timeline_events = relationship("TimelineEvent", back_populates="investigation", cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": str(self.id),
            "session_id": self.session_id,
            "artifact_name": self.artifact_name,
            "artifact_type": self.artifact_type,
            "artifact_size": self.artifact_size,
            "description": self.description,
            "status": self.status,
            "current_phase": self.current_phase,
            "progress": float(self.progress) if self.progress else 0,
            "threat_score": float(self.threat_score) if self.threat_score else 0,
            "overall_confidence": float(self.overall_confidence) if self.overall_confidence else 0,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class InvestigationStep(Base):
    """ReAct loop step"""
    __tablename__ = "investigation_steps"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    step_number = Column(Integer, nullable=False)
    phase = Column(String(50), nullable=False)
    reasoning = Column(Text)
    action = Column(Text)
    action_type = Column(String(50))
    observation = Column(Text)
    confidence = Column(DECIMAL(5, 4), default=0.5)
    error_message = Column(Text)
    execution_time_ms = Column(Integer)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    investigation = relationship("Investigation", back_populates="steps")
    evidence = relationship("Evidence", back_populates="step")

    def to_dict(self):
        return {
            "id": str(self.id),
            "step_number": self.step_number,
            "phase": self.phase,
            "reasoning": self.reasoning,
            "action": self.action,
            "action_type": self.action_type,
            "observation": self.observation,
            "confidence": float(self.confidence) if self.confidence else 0.5,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class Evidence(Base):
    """Evidence collected during investigation"""
    __tablename__ = "evidence"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    step_id = Column(UUID(as_uuid=True), ForeignKey("investigation_steps.id", ondelete="SET NULL"))
    type = Column(String(100), nullable=False)
    value = Column(Text, nullable=False)
    confidence = Column(DECIMAL(5, 4), default=0.5)
    threat_score = Column(DECIMAL(5, 4), default=0.3)
    source = Column(String(255))
    context = Column(JSONB, default={})
    mitre_tactics = Column(ARRAY(Text), default=[])
    mitre_techniques = Column(ARRAY(Text), default=[])
    is_ioc = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    investigation = relationship("Investigation", back_populates="evidence")
    step = relationship("InvestigationStep", back_populates="evidence")

    def to_dict(self):
        return {
            "id": str(self.id),
            "type": self.type,
            "value": self.value,
            "confidence": float(self.confidence) if self.confidence else 0.5,
            "threat_score": float(self.threat_score) if self.threat_score else 0.3,
            "source": self.source,
            "context": self.context,
            "mitre_tactics": self.mitre_tactics or [],
            "mitre_techniques": self.mitre_techniques or [],
            "is_ioc": self.is_ioc,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class Hypothesis(Base):
    """Attack hypothesis"""
    __tablename__ = "hypotheses"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    hypothesis = Column(Text, nullable=False)
    confidence = Column(DECIMAL(5, 4), default=0.5)
    severity = Column(String(50), default="medium")
    supporting_evidence = Column(ARRAY(Text), default=[])
    mitre_tactics = Column(ARRAY(Text), default=[])
    mitre_techniques = Column(ARRAY(Text), default=[])
    status = Column(String(50), default="active")
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    updated_at = Column(DateTime(timezone=True), default=datetime.utcnow, onupdate=datetime.utcnow)

    investigation = relationship("Investigation", back_populates="hypotheses")

    def to_dict(self):
        return {
            "id": str(self.id),
            "hypothesis": self.hypothesis,
            "confidence": float(self.confidence) if self.confidence else 0.5,
            "severity": self.severity,
            "supporting_evidence": self.supporting_evidence or [],
            "mitre_tactics": self.mitre_tactics or [],
            "mitre_techniques": self.mitre_techniques or [],
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


class MITRECoverage(Base):
    """MITRE ATT&CK coverage tracking"""
    __tablename__ = "mitre_coverage"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    tactic_id = Column(String(20), nullable=False)
    tactic_name = Column(String(100), nullable=False)
    technique_id = Column(String(20))
    technique_name = Column(String(255))
    evidence_count = Column(Integer, default=1)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    investigation = relationship("Investigation", back_populates="mitre_coverage")


class InvestigationTodo(Base):
    """Dynamic to-do list items"""
    __tablename__ = "investigation_todos"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    task = Column(Text, nullable=False)
    priority = Column(String(20), default="medium")
    status = Column(String(50), default="pending")
    rationale = Column(Text)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)
    completed_at = Column(DateTime(timezone=True))

    investigation = relationship("Investigation", back_populates="todos")

    def to_dict(self):
        return {
            "id": str(self.id),
            "task": self.task,
            "priority": self.priority,
            "status": self.status,
            "rationale": self.rationale,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None
        }


# ============================================================================
# Chat Models
# ============================================================================

class ChatMessage(Base):
    """Chat messages with forensic AI assistant"""
    __tablename__ = "chat_messages"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role = Column(String(20), nullable=False)  # user, assistant, system
    content = Column(Text, nullable=False)
    context = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    investigation = relationship("Investigation", back_populates="chat_messages")
    user = relationship("User", back_populates="chat_messages")

    def to_dict(self):
        return {
            "id": str(self.id),
            "role": self.role,
            "content": self.content,
            "context": self.context,
            "created_at": self.created_at.isoformat() if self.created_at else None
        }


# ============================================================================
# Timeline Events
# ============================================================================

class TimelineEvent(Base):
    """Investigation timeline events"""
    __tablename__ = "timeline_events"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    investigation_id = Column(UUID(as_uuid=True), ForeignKey("investigations.id", ondelete="CASCADE"), nullable=False)
    event_timestamp = Column(DateTime(timezone=True), nullable=False)
    event_type = Column(String(100), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(50), default="info")
    actor = Column(String(255))
    evidence_ids = Column(ARRAY(UUID(as_uuid=True)), default=[])
    event_metadata = Column(JSONB, default={})
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)

    investigation = relationship("Investigation", back_populates="timeline_events")


# ============================================================================
# Audit Log
# ============================================================================

class AuditLog(Base):
    """Audit trail for compliance"""
    __tablename__ = "audit_log"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"))
    action = Column(String(100), nullable=False)
    resource_type = Column(String(100))
    resource_id = Column(UUID(as_uuid=True))
    details = Column(JSONB, default={})
    ip_address = Column(String(50))
    user_agent = Column(Text)
    created_at = Column(DateTime(timezone=True), default=datetime.utcnow)


# ============================================================================
# Database Initialization
# ============================================================================

def init_db():
    """Initialize database tables"""
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully")


def test_connection():
    """Test database connection"""
    try:
        with engine.connect() as conn:
            result = conn.execute(text("SELECT 1"))
            print("Database connection successful")
            return True
    except Exception as e:
        print(f"Database connection failed: {e}")
        return False


if __name__ == "__main__":
    print("Testing database connection...")
    if test_connection():
        print("Initializing database...")
        init_db()
