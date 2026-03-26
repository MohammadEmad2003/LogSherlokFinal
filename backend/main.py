"""
Autonomous Forensic Orchestrator - FastAPI Backend
Main application entry point

Uses the CAI DFIR Agent for investigation. The orchestrator calls
Runner.run(dfir_agent) for each investigation step.
"""
from __future__ import annotations

import os
import sys
import uuid
import logging
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any, List

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

# Load .env from project root BEFORE any env var access
from dotenv import load_dotenv as _load_dotenv
_env_file = Path(__file__).parent.parent / ".env"
if _env_file.exists():
    _load_dotenv(str(_env_file), override=True)
    print(f"[BACKEND] Loaded .env from {_env_file}")
else:
    _load_dotenv(override=True)


from fastapi import FastAPI, WebSocket, WebSocketDisconnect, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse, HTMLResponse, Response
from pydantic import BaseModel

# Import services
try:
    from backend.services.session_manager import SessionManager, session_manager
    from backend.services.websocket_manager import WebSocketManager, ws_manager
    from backend.services.report_generator import ReportGenerator
except ImportError:
    from services.session_manager import SessionManager, session_manager
    from services.websocket_manager import WebSocketManager, ws_manager
    from services.report_generator import ReportGenerator

# Import database and authentication
try:
    from backend.database import get_db, init_db, User, Investigation, ChatMessage as DBChatMessage
    from backend.auth import (
        UserCreate, UserLogin, TokenResponse, ForgotPasswordRequest,
        ResetPasswordRequest, RefreshTokenRequest, get_current_user,
        create_user, authenticate_user, create_tokens_for_user,
        create_password_reset_otp, verify_otp_and_reset_password,
        refresh_access_token, logout_user, get_optional_user
    )
    from backend.email_service import email_service
except ImportError:
    from backend.database import get_db, init_db, User, Investigation, ChatMessage as DBChatMessage
    from backend.auth import (
        UserCreate, UserLogin, TokenResponse, ForgotPasswordRequest,
        ResetPasswordRequest, RefreshTokenRequest, get_current_user,
        create_user, authenticate_user, create_tokens_for_user,
        create_password_reset_otp, verify_otp_and_reset_password,
        refresh_access_token, logout_user, get_optional_user
    )
    from backend.email_service import email_service

from sqlalchemy.orm import Session
from fastapi import Depends, Request

# Import autonomous agent components (simplified - no more LLMClient)
try:
    from backend.orchestrator import ForensicOrchestrator
    from backend.schemas import UploadArtifactRequest, ChatRequest as AgentChatRequest
    from backend.tools import ALLOWED_TOOLS
except ImportError:
    from orchestrator import ForensicOrchestrator
    from backend.schemas import UploadArtifactRequest, ChatRequest as AgentChatRequest
    from tools import ALLOWED_TOOLS

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# ============================================================================
# Environment setup for CAI SDK
# ============================================================================
# The CAI SDK uses OPENAI_BASE_URL and OPENAI_API_KEY env vars.
# Map legacy LLM_BASE_URL to OPENAI_BASE_URL if needed.
if os.getenv("LLM_BASE_URL") and not os.getenv("OPENAI_BASE_URL"):
    os.environ["OPENAI_BASE_URL"] = os.getenv("LLM_BASE_URL")
    logger.info(f"Mapped LLM_BASE_URL to OPENAI_BASE_URL: {os.getenv('OPENAI_BASE_URL')}")

if os.getenv("LLM_API_KEY") and not os.getenv("OPENAI_API_KEY"):
    os.environ["OPENAI_API_KEY"] = os.getenv("LLM_API_KEY", "dummy")

# Ensure OPENAI_API_KEY is set (CAI SDK requires it)
if not os.getenv("OPENAI_API_KEY"):
    os.environ["OPENAI_API_KEY"] = "dummy"

LLM_BASE_URL = os.getenv("OPENAI_BASE_URL", "not set")
logger.info(f"CAI SDK will use OPENAI_BASE_URL: {LLM_BASE_URL}")

# Create FastAPI app
app = FastAPI(
    title="Autonomous Forensic Orchestrator",
    description="AI-powered DFIR analysis pipeline with real-time investigation tracking",
    version="2.0.0",
)

# CORS middleware - allow all origins for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Determine paths
BACKEND_DIR = Path(__file__).parent.resolve()
PROJECT_ROOT = BACKEND_DIR.parent
UI_DIR = PROJECT_ROOT / "ui"
UPLOAD_DIR = PROJECT_ROOT / "uploads"
REPORTS_DIR = PROJECT_ROOT / "reports"

# Create directories
UPLOAD_DIR.mkdir(exist_ok=True)
REPORTS_DIR.mkdir(exist_ok=True)

logger.info(f"Backend directory: {BACKEND_DIR}")
logger.info(f"UI directory: {UI_DIR}")
logger.info(f"Upload directory: {UPLOAD_DIR}")

# ============================================================================
# Initialize Autonomous Agent Components (No more LLMClient)
# ============================================================================

# Global orchestrator instance
orchestrator: Optional[ForensicOrchestrator] = None


def get_orchestrator() -> ForensicOrchestrator:
    """Get or create orchestrator instance"""
    global orchestrator
    if orchestrator is None:
        orchestrator = ForensicOrchestrator(
            websocket_callback=None,
            max_steps=50
        )
    return orchestrator


# ============================================================================
# Pydantic Models
# ============================================================================

class UploadResponse(BaseModel):
    session_id: str
    status: str
    message: str
    artifact_name: str
    artifact_size: int


class ChatMessage(BaseModel):
    session_id: str
    message: str


class ChatResponse(BaseModel):
    session_id: str
    response: str
    status: str


class SessionStatus(BaseModel):
    session_id: str
    status: str
    current_phase: str
    steps_completed: int
    total_evidence: int
    progress_percent: float


# ============================================================================
# Authentication Endpoints
# ============================================================================

@app.post("/auth/register", tags=["Authentication"])
async def register(
    user_data: UserCreate,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """Register a new user account."""
    user = create_user(db, user_data)

    # Send welcome email
    email_service.send_welcome_email(user.email, user.username)

    # Create tokens
    token_data = create_tokens_for_user(
        db, user,
        device_info=request.headers.get("User-Agent"),
        ip_address=request.client.host if request.client else None
    )

    # Set HTTP-only cookies
    response.set_cookie(
        key="access_token",
        value=token_data.access_token,
        httponly=True,
        secure=False,  # Set to True in production with HTTPS
        samesite="lax",
        max_age=token_data.expires_in
    )
    response.set_cookie(
        key="refresh_token",
        value=token_data.refresh_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=7 * 24 * 60 * 60  # 7 days
    )

    return {"user": token_data.user, "message": "Registration successful"}


@app.post("/auth/login", tags=["Authentication"])
async def login(
    credentials: UserLogin,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    """Login with email and password."""
    user = authenticate_user(db, credentials.email, credentials.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid email or password"
        )

    token_data = create_tokens_for_user(
        db, user,
        device_info=request.headers.get("User-Agent"),
        ip_address=request.client.host if request.client else None
    )

    # Set HTTP-only cookies
    response.set_cookie(
        key="access_token",
        value=token_data.access_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=token_data.expires_in
    )
    response.set_cookie(
        key="refresh_token",
        value=token_data.refresh_token,
        httponly=True,
        secure=False,
        samesite="lax",
        max_age=7 * 24 * 60 * 60
    )

    return {"user": token_data.user, "message": "Login successful"}


@app.post("/auth/forgot-password", tags=["Authentication"])
async def forgot_password(
    request_data: ForgotPasswordRequest,
    db: Session = Depends(get_db)
):
    """Request a password reset OTP."""
    otp = create_password_reset_otp(db, request_data.email)

    if otp:
        # Send OTP email
        email_service.send_otp_email(request_data.email, otp, "password reset")
        logger.info(f"Password reset OTP sent to {request_data.email}")

    # Always return success to prevent email enumeration
    return {
        "message": "If an account exists with this email, you will receive a password reset code.",
        "email": request_data.email
    }


@app.post("/auth/reset-password", tags=["Authentication"])
async def reset_password(
    request_data: ResetPasswordRequest,
    db: Session = Depends(get_db)
):
    """Reset password using OTP."""
    verify_otp_and_reset_password(
        db,
        request_data.email,
        request_data.otp,
        request_data.new_password
    )

    return {"message": "Password reset successfully. Please login with your new password."}


@app.post("/auth/refresh", response_model=TokenResponse, tags=["Authentication"])
async def refresh_token(
    request_data: RefreshTokenRequest,
    db: Session = Depends(get_db)
):
    """Refresh access token using refresh token."""
    return refresh_access_token(db, request_data.refresh_token)


@app.post("/auth/logout", tags=["Authentication"])
async def logout(
    response: Response,
    request: Request,
    db: Session = Depends(get_db)
):
    """Logout current user (revoke tokens and clear cookies)."""
    # Get token from cookie
    token = request.cookies.get("access_token")

    if token:
        try:
            from backend.auth import decode_token
            payload = decode_token(token)
            user_id = payload.get("sub")

            if user_id:
                user = db.query(User).filter(User.id == user_id).first()
                if user:
                    logout_user(db, user)
        except:
            pass

    # Clear cookies
    response.delete_cookie("access_token")
    response.delete_cookie("refresh_token")

    return {"message": "Logged out successfully"}


@app.get("/auth/me", tags=["Authentication"])
async def get_me(request: Request, db: Session = Depends(get_db)):
    """Get current user profile from cookie."""
    token = request.cookies.get("access_token")

    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")

    try:
        from backend.auth import decode_token
        payload = decode_token(token)
        user_id = payload.get("sub")

        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")

        user = db.query(User).filter(User.id == user_id).first()
        if not user or not user.is_active:
            raise HTTPException(status_code=401, detail="User not found or inactive")

        return user.to_dict()
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Auth error: {e}")
        raise HTTPException(status_code=401, detail="Invalid token")


# ============================================================================
# Static Files - Serve UI
# ============================================================================

# Serve static files (CSS, JS)
if UI_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(UI_DIR)), name="static")
    logger.info(f"Mounted UI static files from {UI_DIR}")


# Serve HTML pages
@app.get("/", response_class=HTMLResponse)
async def serve_index():
    """Serve the main landing page."""
    index_path = UI_DIR / "index.html"
    if index_path.exists():
        return FileResponse(str(index_path), media_type="text/html")
    return HTMLResponse("<h1>LogSherlock</h1><p>UI not found. Go to <a href='/docs'>/docs</a></p>")


@app.get("/auth.html", response_class=HTMLResponse)
async def serve_auth():
    """Serve the authentication page."""
    auth_path = UI_DIR / "auth.html"
    if auth_path.exists():
        return FileResponse(str(auth_path), media_type="text/html")
    raise HTTPException(status_code=404, detail="Auth page not found")


@app.get("/dashboard", response_class=HTMLResponse)
@app.get("/dashboard.html", response_class=HTMLResponse)
async def serve_dashboard():
    """Serve the investigation dashboard."""
    dashboard_path = UI_DIR / "dashboard.html"
    if dashboard_path.exists():
        return FileResponse(str(dashboard_path), media_type="text/html")
    raise HTTPException(status_code=404, detail="Dashboard not found")


@app.get("/index.html", response_class=HTMLResponse)
async def serve_index_html():
    return await serve_index()


# Serve individual static files
@app.get("/styles.css")
async def serve_styles():
    css_path = UI_DIR / "styles.css"
    if css_path.exists():
        return FileResponse(str(css_path), media_type="text/css")
    raise HTTPException(status_code=404, detail="styles.css not found")


@app.get("/app.js")
async def serve_app_js():
    js_path = UI_DIR / "app.js"
    if js_path.exists():
        return FileResponse(str(js_path), media_type="application/javascript")
    raise HTTPException(status_code=404, detail="app.js not found")


@app.get("/auth.js")
async def serve_auth_js():
    js_path = UI_DIR / "auth.js"
    if js_path.exists():
        return FileResponse(str(js_path), media_type="application/javascript")
    raise HTTPException(status_code=404, detail="auth.js not found")


@app.get("/dashboard.js")
async def serve_dashboard_js():
    js_path = UI_DIR / "dashboard.js"
    if js_path.exists():
        return FileResponse(str(js_path), media_type="application/javascript")
    raise HTTPException(status_code=404, detail="dashboard.js not found")


# ============================================================================
# API Endpoints
# ============================================================================

@app.post("/upload_artefact", response_model=UploadResponse)
async def upload_artefact(
    file: UploadFile = File(...),
    artifact_type: str = Form(default="auto"),
    description: str = Form(default=""),
):
    """Upload a forensic artifact to start autonomous investigation."""
    import shutil as _shutil

    session_id = str(uuid.uuid4())[:8]
    file_ext = Path(file.filename).suffix.lower() if file.filename else ".bin"
    saved_filename = f"{session_id}_{file.filename}"
    file_path = UPLOAD_DIR / saved_filename

    try:
        # Check available disk space before reading (require at least 512 MB free)
        disk = _shutil.disk_usage(UPLOAD_DIR)
        MIN_FREE_BYTES = 512 * 1024 * 1024  # 512 MB safety margin
        if disk.free < MIN_FREE_BYTES:
            free_gb = disk.free / (1024 ** 3)
            raise HTTPException(
                status_code=507,
                detail=f"Insufficient disk space on server. Only {free_gb:.2f} GB free. "
                       f"Please free up space and try again."
            )

        # Stream-write the file in chunks to avoid loading it all into RAM
        CHUNK = 1024 * 1024  # 1 MB chunks
        file_size = 0
        header_bytes = b""

        try:
            with open(file_path, "wb") as f:
                while True:
                    chunk = await file.read(CHUNK)
                    if not chunk:
                        break
                    # Check space before each chunk write
                    remaining = _shutil.disk_usage(UPLOAD_DIR).free
                    if remaining < len(chunk) + MIN_FREE_BYTES:
                        raise OSError(28, "No space left on device")
                    f.write(chunk)
                    if file_size == 0:
                        header_bytes = chunk[:1024]
                    file_size += len(chunk)
        except OSError as e:
            # Clean up partial file
            if file_path.exists():
                file_path.unlink(missing_ok=True)
            if e.errno == 28:
                raise HTTPException(
                    status_code=507,
                    detail="Server ran out of disk space while saving the file. "
                           "Please ask the administrator to free up disk space."
                )
            raise HTTPException(status_code=500, detail=f"File write error: {e.strerror}")

        if file_size == 0:
            if file_path.exists():
                file_path.unlink(missing_ok=True)
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        if artifact_type == "auto":
            artifact_type = _detect_artifact_type(file_ext, header_bytes)

        session_manager.create_session(
            session_id=session_id,
            artifact_path=str(file_path),
            artifact_name=file.filename or "unknown",
            artifact_type=artifact_type,
            artifact_size=file_size,
            description=description,
        )

        logger.info(f"Created session {session_id} for artifact: {file.filename} ({file_size:,} bytes)")

        return UploadResponse(
            session_id=session_id,
            status="started",
            message=f"Investigation initialized for {artifact_type} artifact.",
            artifact_name=file.filename or "unknown",
            artifact_size=file_size,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.exception("Failed to upload artifact")
        # Clean up any partial file
        if file_path.exists():
            file_path.unlink(missing_ok=True)
        raise HTTPException(status_code=500, detail=f"Upload failed: {str(e)}")


@app.post("/chat", response_model=ChatResponse)
async def chat(message: ChatMessage):
    """Send a message to the forensic agent - uses CAI DFIR Agent."""
    session = session_manager.get_session(message.session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    # Get orchestrator state for context
    orch = get_orchestrator()
    state = orch.get_state(message.session_id)

    # Build context from real investigation state
    context = _build_chat_context(state, session)

    # Process query with DFIR agent
    response = await orch.chat_with_agent(message.message, context)

    # Also broadcast to WebSocket
    await ws_manager.broadcast(message.session_id, {
        "type": "chat_response",
        "timestamp": datetime.utcnow().isoformat(),
        "query": message.message,
        "response": response,
    })

    return ChatResponse(
        session_id=message.session_id,
        response=response,
        status="completed",
    )


@app.get("/status/{session_id}", response_model=SessionStatus)
async def get_status(session_id: str):
    """Get the current status of an investigation - from REAL state."""
    orch = get_orchestrator()
    state = orch.get_state(session_id)

    if state:
        return SessionStatus(
            session_id=session_id,
            status=state.status,
            current_phase=state.current_phase,
            steps_completed=len(state.steps),
            total_evidence=len(state.evidence),
            progress_percent=min((len(state.steps) / 50.0) * 100, 100),
        )

    # Fallback to session manager
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    return SessionStatus(
        session_id=session_id,
        status=session.get("status", "initializing"),
        current_phase=session.get("current_phase", "initializing"),
        steps_completed=len(session.get("steps", [])),
        total_evidence=len(session.get("evidence", [])),
        progress_percent=session.get("progress", 0),
    )


@app.get("/report/{session_id}")
async def get_report(session_id: str, format: str = "json"):
    """Get the investigation report - from REAL state."""
    orch = get_orchestrator()
    state = orch.get_state(session_id)

    if state:
        report = _generate_real_report(state, format)
        return JSONResponse(report)

    # Fallback
    session = session_manager.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")

    generator = ReportGenerator(session)
    if format == "json":
        return JSONResponse(generator.generate_json_report())
    elif format == "html":
        return JSONResponse({"html": generator.generate_html_report()})
    elif format == "stix":
        return JSONResponse(generator.generate_stix_bundle())
    else:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")


@app.get("/sessions")
async def list_sessions():
    """List all investigation sessions from both session_manager and orchestrator."""
    # Start with sessions from session_manager (created on upload)
    all_sessions: Dict[str, Any] = {}
    for session_id, session in session_manager._sessions.items():
        all_sessions[session_id] = {
            "session_id": session_id,
            "artifact_name": session.artifact_name,
            "artifact_type": session.artifact_type,
            "status": session.status,
            "steps_count": len(session.steps),
            "evidence_count": len(session.evidence),
            "started_at": session.created_at,
            "current_phase": session.current_phase,
        }

    # Override/enrich with orchestrator state if available (more up-to-date)
    orch = get_orchestrator()
    for s in orch.list_sessions():
        sid = s["session_id"]
        all_sessions[sid] = s

    return list(all_sessions.values())


@app.delete("/session/{session_id}")
async def delete_session(session_id: str):
    """Delete/close an investigation session."""
    if session_manager.delete_session(session_id):
        return {"status": "deleted", "session_id": session_id}
    raise HTTPException(status_code=404, detail="Session not found")


@app.get("/tools")
async def list_tools():
    """List all available forensic tools as structured objects."""
    tool_catalog = [
        # Memory Forensics
        {"name": "volatility", "description": "Memory forensics framework for analyzing RAM dumps and process memory", "category": "memory_forensics"},
        {"name": "vol3", "description": "Volatility 3 - modern, plugin-based memory forensics framework", "category": "memory_forensics"},
        {"name": "vol.py", "description": "Volatility 2 legacy interface for Windows/Linux memory analysis", "category": "memory_forensics"},
        {"name": "rekall", "description": "Advanced memory forensics framework with live memory support", "category": "memory_forensics"},
        # Disk Forensics
        {"name": "mmls", "description": "Display partition layout of volume system (Sleuth Kit)", "category": "disk_forensics"},
        {"name": "fls", "description": "List files and directories in a disk image (Sleuth Kit)", "category": "disk_forensics"},
        {"name": "icat", "description": "Output contents of a file based on inode (Sleuth Kit)", "category": "disk_forensics"},
        {"name": "fsstat", "description": "Display file system details and statistics (Sleuth Kit)", "category": "disk_forensics"},
        {"name": "binwalk", "description": "Firmware analysis and embedded file extraction tool", "category": "disk_forensics"},
        {"name": "foremost", "description": "File carving tool for recovering deleted files from disk images", "category": "disk_forensics"},
        {"name": "bulk_extractor", "description": "High-performance digital forensics scanner for feature extraction", "category": "disk_forensics"},
        # Malware Analysis
        {"name": "yara", "description": "Pattern matching tool for malware identification and classification", "category": "malware_analysis"},
        {"name": "clamscan", "description": "ClamAV antivirus scanner for malware signature detection", "category": "malware_analysis"},
        {"name": "peframe", "description": "Static analysis tool for PE (Portable Executable) malware samples", "category": "malware_analysis"},
        {"name": "objdump", "description": "Display information from object/binary files (disassembly, headers)", "category": "malware_analysis"},
        {"name": "readelf", "description": "Display information about ELF format executable files", "category": "malware_analysis"},
        {"name": "exiftool", "description": "Read, write and edit metadata in files (EXIF, IPTC, XMP)", "category": "malware_analysis"},
        # Network Forensics
        {"name": "tshark", "description": "Terminal-based network protocol analyzer (Wireshark CLI)", "category": "network_forensics"},
        {"name": "tcpdump", "description": "Packet analyzer for capturing and analyzing network traffic", "category": "network_forensics"},
        {"name": "zeek", "description": "Network security monitor and traffic analyzer", "category": "network_forensics"},
        {"name": "suricata", "description": "High-performance network IDS, IPS and security monitoring engine", "category": "network_forensics"},
        {"name": "tcpflow", "description": "TCP/IP packet demultiplexer for reconstructing data streams", "category": "network_forensics"},
        # Log Analysis
        {"name": "chainsaw", "description": "Rapidly search and hunt through Windows Event Logs using Sigma rules", "category": "log_analysis"},
        {"name": "hayabusa", "description": "Windows event log fast forensics timeline generator", "category": "log_analysis"},
        {"name": "evtxdump", "description": "Parse and convert Windows EVTX event log files to JSON/XML", "category": "log_analysis"},
        {"name": "journalctl", "description": "Query and display messages from the systemd journal", "category": "log_analysis"},
        {"name": "ausearch", "description": "Search Linux audit daemon log files for events", "category": "log_analysis"},
        # Threat Intelligence
        {"name": "mitre_attack", "description": "MITRE ATT&CK framework technique lookup and mapping", "category": "threat_intelligence"},
        {"name": "threat_intel", "description": "Integrated threat intelligence lookup across multiple feeds", "category": "threat_intelligence"},
        {"name": "ioc_lookup", "description": "Indicator of Compromise lookup across threat intelligence platforms", "category": "threat_intelligence"},
        {"name": "virustotal", "description": "VirusTotal API for file/URL/hash reputation scanning", "category": "threat_intelligence"},
        {"name": "otx", "description": "AlienVault OTX (Open Threat Exchange) threat intelligence lookup", "category": "threat_intelligence"},
        {"name": "misp", "description": "MISP threat intelligence platform integration for IOC sharing", "category": "threat_intelligence"},
        # General Tools
        {"name": "strings", "description": "Extract printable strings from binary files for analysis", "category": "general"},
        {"name": "file", "description": "Determine file type using magic bytes and heuristics", "category": "general"},
        {"name": "xxd", "description": "Create hex dump of a file for binary analysis", "category": "general"},
        {"name": "hexdump", "description": "Display file contents in hexadecimal and ASCII format", "category": "general"},
        {"name": "md5sum", "description": "Compute and verify MD5 message digest checksums", "category": "general"},
        {"name": "sha256sum", "description": "Compute and verify SHA-256 cryptographic hash values", "category": "general"},
        {"name": "grep", "description": "Search files for patterns using regular expressions", "category": "general"},
        {"name": "python3", "description": "Python 3 interpreter for custom forensic scripts and analysis", "category": "general"},
    ]

    return {
        "tools": tool_catalog,
        "total": len(tool_catalog),
    }


@app.get("/agent/state/{session_id}")
async def get_agent_state(session_id: str):
    """Get full agent state for debugging."""
    orch = get_orchestrator()
    state = orch.get_state(session_id)

    if not state:
        raise HTTPException(status_code=404, detail="No agent state found")

    return {
        "session_id": session_id,
        "status": state.status,
        "current_phase": state.current_phase,
        "steps": [
            {
                "step_number": s.step_number,
                "phase": s.phase,
                "reasoning": s.reasoning,
                "action": s.action,
                "evidence_count": len(s.evidence_found),
                "confidence": s.confidence
            }
            for s in state.steps
        ],
        "evidence": [
            {
                "type": e.type,
                "value": e.value,
                "confidence": e.confidence,
                "threat_score": e.threat_score,
                "source": e.source,
                "mitre_tactics": e.mitre_tactics,
                "mitre_techniques": e.mitre_techniques
            }
            for e in state.evidence
        ],
        "hypotheses": [
            {
                "hypothesis": h.hypothesis,
                "confidence": h.confidence,
                "severity": h.severity,
                "mitre_tactics": h.mitre_tactics
            }
            for h in state.hypotheses
        ],
        "mitre_coverage": {
            "tactics": state.mitre_coverage.tactics,
            "techniques": dict(state.mitre_coverage.techniques),
            "total_tactics": state.mitre_coverage.total_tactics,
            "total_techniques": state.mitre_coverage.total_techniques
        },
        "todos": [
            {
                "id": t.id,
                "task": t.task,
                "priority": t.priority,
                "status": t.status
            }
            for t in state.todos
        ],
        "threat_score": state.threat_score,
        "overall_confidence": state.overall_confidence
    }


# ============================================================================
# Chat Context Building
# ============================================================================

def _build_chat_context(state, session: dict) -> Dict[str, Any]:
    """Build context from real investigation state for chat."""
    context = {
        "artifact_name": session.get("artifact_name", "unknown"),
        "artifact_type": session.get("artifact_type", "unknown"),
        "evidence": [],
        "steps": [],
        "hypotheses": [],
        "mitre": {"tactics": {}, "techniques": {}},
        "todos": []
    }

    if state:
        context["evidence"] = [
            {
                "type": e.type,
                "value": e.value,
                "confidence": e.confidence,
                "threat_score": e.threat_score,
                "source": e.source,
                "mitre_tactics": e.mitre_tactics,
                "mitre_techniques": e.mitre_techniques
            }
            for e in state.evidence
        ]
        context["steps"] = [
            {
                "step_number": s.step_number,
                "reasoning": s.reasoning,
                "action": s.action,
                "observation": s.observation
            }
            for s in state.steps
        ]
        context["hypotheses"] = [
            {
                "hypothesis": h.hypothesis,
                "confidence": h.confidence,
                "severity": h.severity,
                "supporting_evidence": h.supporting_evidence
            }
            for h in state.hypotheses
        ]
        context["mitre"] = {
            "tactics": state.mitre_coverage.tactics,
            "techniques": dict(state.mitre_coverage.techniques)
        }
        context["todos"] = [
            {"task": t.task, "status": t.status, "priority": t.priority}
            for t in state.todos
        ]
        context["threat_score"] = state.threat_score
        context["current_phase"] = state.current_phase

    return context


def _generate_real_report(state, format: str) -> Dict[str, Any]:
    """Generate report from real agent state."""
    report = {
        "session_id": state.session_id,
        "artifact": {
            "name": state.scenario.artifact_name,
            "type": state.scenario.artifact_type,
            "path": state.scenario.artifact_path
        },
        "investigation": {
            "status": state.status,
            "current_phase": state.current_phase,
            "total_steps": len(state.steps),
            "total_evidence": len(state.evidence),
            "threat_score": state.threat_score,
            "confidence": state.overall_confidence,
            "started_at": state.started_at.isoformat(),
            "completed_at": state.completed_at.isoformat() if state.completed_at else None
        },
        "evidence": [
            {
                "type": e.type,
                "value": e.value,
                "confidence": e.confidence,
                "threat_score": e.threat_score,
                "source": e.source,
                "mitre_tactics": e.mitre_tactics,
                "mitre_techniques": e.mitre_techniques
            }
            for e in state.evidence
        ],
        "hypotheses": [
            {
                "hypothesis": h.hypothesis,
                "confidence": h.confidence,
                "severity": h.severity,
                "supporting_evidence": h.supporting_evidence,
                "mitre_tactics": h.mitre_tactics
            }
            for h in state.hypotheses
        ],
        "mitre_coverage": {
            "tactics": state.mitre_coverage.tactics,
            "techniques": dict(state.mitre_coverage.techniques),
            "total_tactics": state.mitre_coverage.total_tactics,
            "total_techniques": state.mitre_coverage.total_techniques
        },
        "timeline": [
            {
                "step_number": s.step_number,
                "timestamp": s.timestamp.isoformat(),
                "action": s.action,
                "evidence_found": len(s.evidence_found)
            }
            for s in state.steps
        ]
    }

    return report


# ============================================================================
# WebSocket Endpoint - DFIR Agent
# ============================================================================

@app.websocket("/ws/agent/{session_id}")
async def websocket_agent(websocket: WebSocket, session_id: str):
    """WebSocket endpoint for real-time autonomous investigation."""
    session = session_manager.get_session(session_id)
    if not session:
        await websocket.close(code=4004, reason="Session not found")
        return

    await ws_manager.connect(websocket, session_id)
    logger.info(f"WebSocket connected for session {session_id}")

    try:
        orch = get_orchestrator()

        async def ws_callback(payload: dict):
            try:
                await ws_manager.send_to_session(session_id, payload)
            except Exception as e:
                logger.error(f"Failed to send WebSocket update: {e}")

        orch.websocket_callback = ws_callback
        state = orch.get_state(session_id)

        if not state:
            logger.info(f"Starting autonomous investigation for session {session_id}")

            import asyncio
            asyncio.create_task(
                orch.start_investigation(
                    session_id=session_id,
                    artifact_path=session['artifact_path'],
                    artifact_type=session['artifact_type'],
                    artifact_name=session['artifact_name'],
                    description=session.get('description', '')
                )
            )
        else:
            logger.info(f"Reconnected to investigation for session {session_id}")
            await ws_manager.send_to_session(session_id, {
                "type": "state_sync",
                "data": {
                    "steps": [{"step_number": s.step_number, "reasoning": s.reasoning[:100] if s.reasoning else ""} for s in state.steps],
                    "evidence_count": len(state.evidence),
                    "progress": min((len(state.steps) / 50.0) * 100, 100)
                }
            })

        while True:
            try:
                data = await websocket.receive_json()

                if data.get("type") == "llm_query":
                    state = orch.get_state(session_id)
                    context = _build_chat_context(state, session)
                    response = await orch.chat_with_agent(data.get("message", ""), context)

                    await ws_manager.send_to_session(session_id, {
                        "type": "llm_response",
                        "data": {"response": response}
                    })

                elif data.get("type") == "instruction":
                    session_manager.add_instruction(session_id, data.get("message", ""))
                    await ws_manager.send_to_session(session_id, {
                        "type": "instruction_ack",
                        "message": data.get("message"),
                    })

                elif data.get("type") == "stop":
                    logger.info(f"Stopping investigation for session {session_id}")
                    state = orch.get_state(session_id)
                    if state:
                        state.status = "completed"
                    break

            except WebSocketDisconnect:
                logger.info(f"WebSocket disconnected for session {session_id}")
                break
            except Exception as e:
                logger.error(f"Error processing WebSocket message: {e}")
                await ws_manager.send_to_session(session_id, {
                    "type": "error",
                    "message": f"Error: {str(e)}"
                })

    except Exception as e:
        logger.exception(f"WebSocket error for session {session_id}")
        await ws_manager.send_to_session(session_id, {"type": "error", "message": str(e)})
    finally:
        ws_manager.disconnect(websocket, session_id)


# ============================================================================
# Utility Functions
# ============================================================================

def _detect_artifact_type(extension: str, header_bytes: bytes) -> str:
    """Auto-detect artifact type from extension and file header."""
    ext_mapping = {
        ".raw": "memory_dump", ".mem": "memory_dump", ".dmp": "memory_dump", ".vmem": "memory_dump",
        ".img": "disk_image", ".dd": "disk_image", ".e01": "disk_image",
        ".evtx": "evtx", ".pcap": "pcap", ".pcapng": "pcap",
        ".exe": "malware_sample", ".dll": "malware_sample",
        ".bin": "binary", ".zip": "archive", ".tar": "archive",
    }

    if header_bytes[:2] == b"MZ":
        return "malware_sample"
    if header_bytes[:4] == b"\x7fELF":
        return "malware_sample"
    if header_bytes[:8] == b"ElfChnk\x00":
        return "evtx"
    if header_bytes[:4] in [b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"]:
        return "pcap"

    return ext_mapping.get(extension.lower(), "unknown")


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    orch = get_orchestrator()
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
        "active_sessions": len(orch.list_sessions()),
        "llm_endpoint": os.getenv("OPENAI_BASE_URL", "not set"),
    }


if __name__ == "__main__":
    import uvicorn
    print("\n" + "="*60)
    print("  Autonomous Forensic Orchestrator v2.0")
    print("  CAI DFIR Agent Integration")
    print("="*60)
    print(f"\n  UI:   http://localhost:8000")
    print(f"  API:  http://localhost:8000/docs")
    print(f"  LLM:  {os.getenv('OPENAI_BASE_URL', 'not set')}")
    print("\n" + "="*60 + "\n")

    uvicorn.run(app, host="0.0.0.0", port=8080, log_level="info")
