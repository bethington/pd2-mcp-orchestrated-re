"""
Session manager for tracking Diablo 2 analysis sessions
"""

import logging
import time
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime

logger = logging.getLogger(__name__)

class SessionManager:
    """Manages analysis sessions for Diablo 2 monitoring"""
    
    def __init__(self):
        self.active_sessions = {}
        self.session_history = []
        logger.info("SessionManager initialized")
    
    def create_session(self, session_name: str = None) -> str:
        """Create a new analysis session"""
        session_id = str(uuid.uuid4())
        
        if session_name is None:
            session_name = f"D2_Session_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        session_data = {
            'id': session_id,
            'name': session_name,
            'created_at': time.time(),
            'started_at': None,
            'ended_at': None,
            'status': 'created',
            'data': {
                'character_data': {},
                'memory_snapshots': [],
                'network_events': [],
                'behavioral_events': [],
                'screenshots': []
            },
            'metadata': {
                'game_version': None,
                'character_name': None,
                'character_level': None,
                'total_events': 0
            }
        }
        
        self.active_sessions[session_id] = session_data
        logger.info(f"Created session: {session_name} (ID: {session_id})")
        
        return session_id
    
    def start_session(self, session_id: str) -> bool:
        """Start an existing session"""
        if session_id not in self.active_sessions:
            logger.error(f"Session not found: {session_id}")
            return False
        
        session = self.active_sessions[session_id]
        session['started_at'] = time.time()
        session['status'] = 'active'
        
        logger.info(f"Started session: {session['name']} (ID: {session_id})")
        return True
    
    def stop_session(self, session_id: str) -> bool:
        """Stop an active session"""
        if session_id not in self.active_sessions:
            logger.error(f"Session not found: {session_id}")
            return False
        
        session = self.active_sessions[session_id]
        session['ended_at'] = time.time()
        session['status'] = 'completed'
        
        # Move to history
        self.session_history.append(session)
        del self.active_sessions[session_id]
        
        logger.info(f"Stopped session: {session['name']} (ID: {session_id})")
        return True
    
    def add_session_data(self, session_id: str, data_type: str, data: Any) -> bool:
        """Add data to an active session"""
        if session_id not in self.active_sessions:
            logger.error(f"Session not found: {session_id}")
            return False
        
        session = self.active_sessions[session_id]
        
        if data_type in session['data']:
            if isinstance(session['data'][data_type], list):
                session['data'][data_type].append({
                    'timestamp': time.time(),
                    'data': data
                })
            else:
                session['data'][data_type] = data
            
            session['metadata']['total_events'] += 1
            return True
        else:
            logger.warning(f"Unknown data type: {data_type}")
            return False
    
    def get_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session data"""
        if session_id in self.active_sessions:
            return self.active_sessions[session_id].copy()
        
        # Check history
        for session in self.session_history:
            if session['id'] == session_id:
                return session.copy()
        
        return None
    
    def get_active_sessions(self) -> List[Dict[str, Any]]:
        """Get all active sessions"""
        return [session.copy() for session in self.active_sessions.values()]
    
    def get_session_history(self) -> List[Dict[str, Any]]:
        """Get session history"""
        return self.session_history.copy()
    
    def update_session_metadata(self, session_id: str, metadata: Dict[str, Any]) -> bool:
        """Update session metadata"""
        if session_id not in self.active_sessions:
            logger.error(f"Session not found: {session_id}")
            return False
        
        session = self.active_sessions[session_id]
        session['metadata'].update(metadata)
        
        return True
    
    def get_session_summary(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get session summary"""
        session = self.get_session(session_id)
        if not session:
            return None
        
        duration = None
        if session['started_at'] and session['ended_at']:
            duration = session['ended_at'] - session['started_at']
        elif session['started_at']:
            duration = time.time() - session['started_at']
        
        summary = {
            'id': session['id'],
            'name': session['name'],
            'status': session['status'],
            'created_at': session['created_at'],
            'duration': duration,
            'total_events': session['metadata']['total_events'],
            'character_name': session['metadata'].get('character_name'),
            'character_level': session['metadata'].get('character_level'),
            'data_counts': {
                key: len(value) if isinstance(value, list) else (1 if value else 0)
                for key, value in session['data'].items()
            }
        }
        
        return summary
