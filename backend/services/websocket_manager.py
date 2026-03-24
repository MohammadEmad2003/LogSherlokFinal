"""
WebSocket Manager - Handles real-time communication with clients
Manages WebSocket connections, broadcasting, and session-specific messaging
"""
from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Dict, List, Set
from collections import defaultdict

from fastapi import WebSocket

logger = logging.getLogger(__name__)


class WebSocketManager:
    """
    Manages WebSocket connections for real-time investigation updates.
    Supports multiple clients per session and broadcast messaging.
    """

    def __init__(self):
        # Map session_id -> set of connected websockets
        self._connections: Dict[str, Set[WebSocket]] = defaultdict(set)
        self._lock = asyncio.Lock()
        logger.info("WebSocketManager initialized")

    async def connect(self, websocket: WebSocket, session_id: str) -> None:
        """Accept and register a WebSocket connection for a session."""
        await websocket.accept()
        async with self._lock:
            self._connections[session_id].add(websocket)
        logger.info(f"WebSocket connected for session {session_id}")

    def disconnect(self, websocket: WebSocket, session_id: str) -> None:
        """Remove a WebSocket connection."""
        if session_id in self._connections:
            self._connections[session_id].discard(websocket)
            if not self._connections[session_id]:
                del self._connections[session_id]
        logger.info(f"WebSocket disconnected from session {session_id}")

    async def send_to_session(self, session_id: str, message: Dict[str, Any]) -> None:
        """Send a message to all clients connected to a session."""
        if session_id not in self._connections:
            return

        dead_connections = set()
        json_message = json.dumps(message)

        for websocket in self._connections[session_id]:
            try:
                await websocket.send_text(json_message)
            except Exception as e:
                logger.warning(f"Failed to send to websocket: {e}")
                dead_connections.add(websocket)

        # Clean up dead connections
        for ws in dead_connections:
            self._connections[session_id].discard(ws)

    async def broadcast(self, session_id: str, message: Dict[str, Any]) -> None:
        """Alias for send_to_session - broadcast to all session clients."""
        await self.send_to_session(session_id, message)

    async def send_step(self, session_id: str, step_data: Dict[str, Any]) -> None:
        """Send a new investigation step to clients."""
        await self.send_to_session(session_id, {
            "type": "step",
            "data": step_data,
        })

    async def send_evidence(self, session_id: str, evidence_data: Dict[str, Any]) -> None:
        """Send newly discovered evidence to clients."""
        await self.send_to_session(session_id, {
            "type": "evidence",
            "data": evidence_data,
        })

    async def send_progress(self, session_id: str, progress: float, phase: str) -> None:
        """Send progress update to clients."""
        await self.send_to_session(session_id, {
            "type": "progress",
            "data": {
                "progress": progress,
                "phase": phase,
            },
        })

    async def send_timeline_event(self, session_id: str, event: Dict[str, Any]) -> None:
        """Send a timeline event to clients."""
        await self.send_to_session(session_id, {
            "type": "timeline_event",
            "data": event,
        })

    async def send_hypothesis(self, session_id: str, hypothesis: Dict[str, Any]) -> None:
        """Send an attack hypothesis to clients."""
        await self.send_to_session(session_id, {
            "type": "hypothesis",
            "data": hypothesis,
        })

    async def send_mitre_mapping(self, session_id: str, mapping: Dict[str, Any]) -> None:
        """Send MITRE ATT&CK mapping to clients."""
        await self.send_to_session(session_id, {
            "type": "mitre_mapping",
            "data": mapping,
        })

    async def send_complete(self, session_id: str, summary: str, conclusion: str) -> None:
        """Send investigation complete notification."""
        await self.send_to_session(session_id, {
            "type": "complete",
            "data": {
                "summary": summary,
                "conclusion": conclusion,
            },
        })

    async def send_error(self, session_id: str, error_message: str) -> None:
        """Send error notification to clients."""
        await self.send_to_session(session_id, {
            "type": "error",
            "data": {
                "message": error_message,
            },
        })

    async def send_full_state(self, session_id: str, state: Dict[str, Any]) -> None:
        """Send full investigation state to clients (for reconnection)."""
        await self.send_to_session(session_id, {
            "type": "full_state",
            "data": state,
        })

    def get_connection_count(self, session_id: str) -> int:
        """Get number of connected clients for a session."""
        return len(self._connections.get(session_id, set()))

    def has_connections(self, session_id: str) -> bool:
        """Check if session has any connected clients."""
        return session_id in self._connections and len(self._connections[session_id]) > 0


# Global WebSocket manager instance
ws_manager = WebSocketManager()
