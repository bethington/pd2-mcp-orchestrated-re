"""
Pattern detector for analyzing Diablo 2 gameplay behaviors
"""

import logging
import time
from typing import Dict, List, Any, Optional
from collections import deque

logger = logging.getLogger(__name__)

class PatternDetector:
    """Detects patterns in Diablo 2 gameplay behavior"""
    
    def __init__(self, max_events: int = 1000):
        self.events = deque(maxlen=max_events)
        self.patterns = {
            'movement_patterns': [],
            'combat_patterns': [],
            'item_usage_patterns': [],
            'suspicious_activity': []
        }
        self.analysis_config = {
            'movement_threshold': 10,  # movements per second
            'combat_threshold': 5,     # attacks per second
            'pattern_window': 60       # seconds to analyze
        }
        logger.info(f"PatternDetector initialized with max_events: {max_events}")
    
    def add_event(self, event_type: str, event_data: Dict[str, Any]) -> None:
        """Add a gameplay event for pattern analysis"""
        event = {
            'timestamp': time.time(),
            'type': event_type,
            'data': event_data
        }
        self.events.append(event)
        
        # Trigger pattern analysis if we have enough events
        if len(self.events) >= 10:
            self._analyze_recent_events()
    
    def _analyze_recent_events(self) -> None:
        """Analyze recent events for patterns"""
        current_time = time.time()
        window_start = current_time - self.analysis_config['pattern_window']
        
        # Filter events within the analysis window
        recent_events = [
            event for event in self.events 
            if event['timestamp'] >= window_start
        ]
        
        if not recent_events:
            return
        
        self._detect_movement_patterns(recent_events)
        self._detect_combat_patterns(recent_events)
        self._detect_item_patterns(recent_events)
        self._detect_suspicious_activity(recent_events)
    
    def _detect_movement_patterns(self, events: List[Dict[str, Any]]) -> None:
        """Detect movement patterns"""
        movement_events = [e for e in events if e['type'] == 'movement']
        
        if len(movement_events) > self.analysis_config['movement_threshold']:
            pattern = {
                'type': 'high_frequency_movement',
                'count': len(movement_events),
                'timestamp': time.time()
            }
            self.patterns['movement_patterns'].append(pattern)
    
    def _detect_combat_patterns(self, events: List[Dict[str, Any]]) -> None:
        """Detect combat patterns"""
        combat_events = [e for e in events if e['type'] in ['attack', 'skill_use']]
        
        if len(combat_events) > self.analysis_config['combat_threshold']:
            pattern = {
                'type': 'high_frequency_combat',
                'count': len(combat_events),
                'timestamp': time.time()
            }
            self.patterns['combat_patterns'].append(pattern)
    
    def _detect_item_patterns(self, events: List[Dict[str, Any]]) -> None:
        """Detect item usage patterns"""
        item_events = [e for e in events if e['type'] in ['item_pickup', 'item_drop', 'item_use']]
        
        if len(item_events) > 20:  # High item activity
            pattern = {
                'type': 'high_item_activity',
                'count': len(item_events),
                'timestamp': time.time()
            }
            self.patterns['item_usage_patterns'].append(pattern)
    
    def _detect_suspicious_activity(self, events: List[Dict[str, Any]]) -> None:
        """Detect potentially suspicious activity patterns"""
        # Example: Repetitive exact movements
        movement_events = [e for e in events if e['type'] == 'movement']
        
        if len(movement_events) >= 5:
            # Check for identical consecutive movements
            identical_moves = 0
            for i in range(1, len(movement_events)):
                if movement_events[i]['data'] == movement_events[i-1]['data']:
                    identical_moves += 1
            
            if identical_moves >= 3:
                pattern = {
                    'type': 'repetitive_movement',
                    'count': identical_moves,
                    'timestamp': time.time(),
                    'severity': 'medium'
                }
                self.patterns['suspicious_activity'].append(pattern)
    
    def get_patterns(self, pattern_type: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
        """Get detected patterns"""
        if pattern_type:
            return {pattern_type: self.patterns.get(pattern_type, [])}
        return self.patterns.copy()
    
    def clear_patterns(self) -> None:
        """Clear all detected patterns"""
        self.patterns = {
            'movement_patterns': [],
            'combat_patterns': [],
            'item_usage_patterns': [],
            'suspicious_activity': []
        }
        logger.info("All patterns cleared")
    
    def get_events_summary(self) -> Dict[str, Any]:
        """Get summary of recent events"""
        if not self.events:
            return {'total_events': 0}
        
        event_types = {}
        for event in self.events:
            event_type = event['type']
            event_types[event_type] = event_types.get(event_type, 0) + 1
        
        return {
            'total_events': len(self.events),
            'event_types': event_types,
            'oldest_event': min(e['timestamp'] for e in self.events),
            'newest_event': max(e['timestamp'] for e in self.events)
        }
