"""
Session Management Module for MCP-Orchestrated Platform
"""

import asyncio
import uuid
import json
import time
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from pathlib import Path
import structlog

logger = structlog.get_logger()

class Session:
    def __init__(self, session_id: str, binary_path: str, analysis_goals: List[str]):
        self.session_id = session_id
        self.binary_path = binary_path
        self.analysis_goals = analysis_goals
        self.created_at = datetime.now()
        self.status = "active"
        self.metadata = {}
        self.analysis_results = {}
        self.events = []
        
    def to_dict(self) -> Dict[str, Any]:
        return {
            "session_id": self.session_id,
            "binary_path": self.binary_path,
            "analysis_goals": self.analysis_goals,
            "created_at": self.created_at.isoformat(),
            "status": self.status,
            "metadata": self.metadata,
            "analysis_results": self.analysis_results,
            "events": self.events
        }

class SessionManager:
    def __init__(self, data_dir: str = "/app/data/sessions"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.active_sessions: Dict[str, Session] = {}
        logger.info("Session manager initialized", data_dir=str(self.data_dir))
        
    async def create_session(self, binary_path: str, analysis_goals: List[str]) -> str:
        """Create a new analysis session"""
        session_id = f"session_{uuid.uuid4().hex[:8]}"
        
        session = Session(session_id, binary_path, analysis_goals)
        self.active_sessions[session_id] = session
        
        # Persist session to disk
        await self._save_session(session)
        
        logger.info("Created new session", session_id=session_id, goals=analysis_goals)
        return session_id
        
    async def get_session(self, session_id: str) -> Optional[Session]:
        """Get session by ID"""
        if session_id in self.active_sessions:
            return self.active_sessions[session_id]
            
        # Try to load from disk
        session = await self._load_session(session_id)
        if session:
            self.active_sessions[session_id] = session
            
        return session
        
    async def update_session(self, session_id: str, **updates):
        """Update session with new data"""
        session = await self.get_session(session_id)
        if not session:
            logger.error("Session not found", session_id=session_id)
            return
            
        for key, value in updates.items():
            if hasattr(session, key):
                setattr(session, key, value)
            else:
                session.metadata[key] = value
                
        await self._save_session(session)
        logger.debug("Updated session", session_id=session_id, updates=list(updates.keys()))
        
    async def add_event(self, session_id: str, event_type: str, event_data: Dict[str, Any]):
        """Add an event to the session"""
        session = await self.get_session(session_id)
        if not session:
            return
            
        event = {
            "timestamp": datetime.now().isoformat(),
            "type": event_type,
            "data": event_data
        }
        
        session.events.append(event)
        await self._save_session(session)
        
    async def add_analysis_result(self, session_id: str, tool_name: str, result: Dict[str, Any]):
        """Add analysis result from a tool"""
        session = await self.get_session(session_id)
        if not session:
            return
            
        if tool_name not in session.analysis_results:
            session.analysis_results[tool_name] = []
            
        session.analysis_results[tool_name].append({
            "timestamp": datetime.now().isoformat(),
            "result": result
        })
        
        await self._save_session(session)
        
    async def list_sessions(self) -> List[Session]:
        """List all sessions"""
        sessions = []
        
        # Add active sessions
        sessions.extend(self.active_sessions.values())
        
        # Load sessions from disk
        for session_file in self.data_dir.glob("session_*.json"):
            session_id = session_file.stem
            if session_id not in self.active_sessions:
                session = await self._load_session(session_id)
                if session:
                    sessions.append(session)
                    
        return sessions
        
    async def close_session(self, session_id: str):
        """Close and archive session"""
        session = await self.get_session(session_id)
        if not session:
            return
            
        session.status = "completed"
        await self._save_session(session)
        
        # Remove from active sessions
        if session_id in self.active_sessions:
            del self.active_sessions[session_id]
            
        logger.info("Closed session", session_id=session_id)
        
    async def _save_session(self, session: Session):
        """Save session to disk"""
        session_file = self.data_dir / f"{session.session_id}.json"
        
        try:
            with open(session_file, 'w') as f:
                json.dump(session.to_dict(), f, indent=2)
        except Exception as e:
            logger.error("Failed to save session", session_id=session.session_id, error=str(e))
            
    async def _load_session(self, session_id: str) -> Optional[Session]:
        """Load session from disk"""
        session_file = self.data_dir / f"{session_id}.json"
        
        if not session_file.exists():
            return None
            
        try:
            with open(session_file, 'r') as f:
                data = json.load(f)
                
            session = Session(
                data["session_id"],
                data["binary_path"], 
                data["analysis_goals"]
            )
            
            session.created_at = datetime.fromisoformat(data["created_at"])
            session.status = data["status"]
            session.metadata = data["metadata"]
            session.analysis_results = data["analysis_results"]
            session.events = data["events"]
            
            return session
            
        except Exception as e:
            logger.error("Failed to load session", session_id=session_id, error=str(e))
            return None
            
    async def cleanup_old_sessions(self, max_age_days: int = 30):
        """Clean up old session files"""
        cutoff = datetime.now() - timedelta(days=max_age_days)
        
        for session_file in self.data_dir.glob("session_*.json"):
            try:
                if session_file.stat().st_mtime < cutoff.timestamp():
                    session_file.unlink()
                    logger.info("Cleaned up old session", file=str(session_file))
            except Exception as e:
                logger.error("Failed to cleanup session file", file=str(session_file), error=str(e))
