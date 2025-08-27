"""
Common test fixtures and mock data generators
"""

import json
import random
import tempfile
from datetime import datetime, timedelta
from typing import Dict, List, Any
from pathlib import Path


class MockGameData:
    """Generates mock game data for testing"""
    
    CHARACTER_CLASSES = ['Amazon', 'Barbarian', 'Necromancer', 'Paladin', 'Sorceress']
    
    @classmethod
    def character_info(cls, **overrides) -> Dict[str, Any]:
        """Generate mock character information"""
        base_data = {
            'name': f'TestChar_{random.randint(1000, 9999)}',
            'class': random.choice(cls.CHARACTER_CLASSES),
            'level': random.randint(1, 99),
            'experience': random.randint(0, 2000000000),
            'health': {
                'current': random.randint(100, 500),
                'maximum': random.randint(200, 600)
            },
            'mana': {
                'current': random.randint(50, 300),
                'maximum': random.randint(100, 400)
            },
            'stats': {
                'strength': random.randint(30, 200),
                'dexterity': random.randint(30, 200),
                'vitality': random.randint(30, 200),
                'energy': random.randint(30, 200)
            },
            'location': {
                'act': random.randint(1, 5),
                'area': f'Area_{random.randint(1, 50)}',
                'x': random.randint(0, 1000),
                'y': random.randint(0, 1000)
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
        base_data.update(overrides)
        return base_data
    
    @classmethod
    def inventory_data(cls, num_items: int = 5) -> Dict[str, Any]:
        """Generate mock inventory data"""
        items = []
        for i in range(num_items):
            items.append({
                'id': f'item_{i}',
                'name': f'Mock Item {i}',
                'type': random.choice(['weapon', 'armor', 'jewelry', 'consumable']),
                'quality': random.choice(['normal', 'magic', 'rare', 'unique']),
                'position': {'x': i % 10, 'y': i // 10},
                'properties': {
                    'damage': random.randint(10, 100) if random.random() > 0.5 else None,
                    'defense': random.randint(10, 100) if random.random() > 0.5 else None,
                }
            })
        
        return {
            'items': items,
            'gold': random.randint(0, 1000000),
            'capacity': 40,
            'timestamp': datetime.utcnow().isoformat()
        }
    
    @classmethod
    def game_state(cls) -> Dict[str, Any]:
        """Generate complete mock game state"""
        return {
            'game_id': f'game_{random.randint(10000, 99999)}',
            'character': cls.character_info(),
            'inventory': cls.inventory_data(),
            'difficulty': random.choice(['Normal', 'Nightmare', 'Hell']),
            'players_in_game': random.randint(1, 8),
            'game_type': random.choice(['Single Player', 'Battle.net', 'TCP/IP']),
            'session_duration': random.randint(60, 7200),  # seconds
            'timestamp': datetime.utcnow().isoformat()
        }


class MockMemoryDump:
    """Generates mock memory dump data"""
    
    @classmethod
    def memory_region(cls, size: int = 1024) -> Dict[str, Any]:
        """Generate mock memory region data"""
        base_address = random.randint(0x10000000, 0x7FFFFFFF)
        
        return {
            'address': hex(base_address),
            'size': size,
            'protection': random.choice(['r--', 'rw-', 'r-x', 'rwx']),
            'content_type': random.choice(['game_data', 'heap', 'stack', 'code']),
            'analysis': {
                'structures_found': random.sample(
                    ['player_stats', 'inventory_data', 'game_state', 'network_buffer'],
                    k=random.randint(0, 3)
                ),
                'anomalies': [],
                'confidence': round(random.uniform(0.5, 1.0), 2)
            },
            'timestamp': datetime.utcnow().isoformat()
        }
    
    @classmethod
    def snapshot_data(cls, num_regions: int = 10) -> Dict[str, Any]:
        """Generate complete memory snapshot"""
        return {
            'snapshot_id': f'snapshot_{int(datetime.utcnow().timestamp())}',
            'process_id': random.randint(1000, 9999),
            'process_name': 'Game.exe',
            'total_memory': random.randint(100 * 1024 * 1024, 2 * 1024 * 1024 * 1024),
            'regions': [cls.memory_region() for _ in range(num_regions)],
            'captured_at': datetime.utcnow().isoformat()
        }


class TestDatabase:
    """Mock database for testing"""
    
    def __init__(self):
        self._sessions = {}
        self._characters = {}
        self._memory_dumps = {}
        self._analysis_results = {}
    
    def add_session(self, session_id: str, data: Dict[str, Any]):
        """Add a test session"""
        self._sessions[session_id] = {
            **data,
            'created_at': datetime.utcnow().isoformat()
        }
    
    def get_session(self, session_id: str) -> Dict[str, Any]:
        """Get session data"""
        return self._sessions.get(session_id)
    
    def add_character(self, char_id: str, data: Dict[str, Any]):
        """Add character data"""
        self._characters[char_id] = data
    
    def get_character(self, char_id: str) -> Dict[str, Any]:
        """Get character data"""
        return self._characters.get(char_id)
    
    def add_memory_dump(self, dump_id: str, data: Dict[str, Any]):
        """Add memory dump"""
        self._memory_dumps[dump_id] = data
    
    def get_memory_dump(self, dump_id: str) -> Dict[str, Any]:
        """Get memory dump"""
        return self._memory_dumps.get(dump_id)
    
    def clear(self):
        """Clear all test data"""
        self._sessions.clear()
        self._characters.clear()
        self._memory_dumps.clear()
        self._analysis_results.clear()


class TemporaryGameFiles:
    """Creates temporary game files for testing"""
    
    def __init__(self):
        self.temp_dir = None
        self.game_files = {}
    
    def __enter__(self):
        self.temp_dir = tempfile.mkdtemp()
        self.create_mock_files()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.temp_dir:
            import shutil
            shutil.rmtree(self.temp_dir)
    
    def create_mock_files(self):
        """Create mock game files"""
        game_dir = Path(self.temp_dir) / "pd2"
        game_dir.mkdir(exist_ok=True)
        
        # Create mock game executable
        game_exe = game_dir / "Game.exe"
        game_exe.write_bytes(b'Mock game executable')
        self.game_files['exe'] = str(game_exe)
        
        # Create mock data files
        for mpq in ['d2data.mpq', 'd2char.mpq', 'd2exp.mpq']:
            mpq_file = game_dir / mpq
            mpq_file.write_bytes(b'Mock MPQ data')
            self.game_files[mpq] = str(mpq_file)
        
        # Create mock config file
        config_file = game_dir / "config.json"
        config_data = {
            'resolution': '800x600',
            'windowed': True,
            'sound': True
        }
        config_file.write_text(json.dumps(config_data))
        self.game_files['config'] = str(config_file)
    
    @property
    def game_path(self) -> str:
        """Get path to mock game directory"""
        return str(Path(self.temp_dir) / "pd2")


class TestDataLoader:
    """Loads test data from fixtures"""
    
    @staticmethod
    def load_json_fixture(fixture_name: str) -> Dict[str, Any]:
        """Load JSON test fixture"""
        fixture_path = Path(__file__).parent / "fixtures" / f"{fixture_name}.json"
        
        if fixture_path.exists():
            with open(fixture_path, 'r') as f:
                return json.load(f)
        else:
            # Return mock data if fixture doesn't exist
            if fixture_name == 'character_data':
                return MockGameData.character_info()
            elif fixture_name == 'memory_dump':
                return MockMemoryDump.snapshot_data()
            else:
                return {}
    
    @staticmethod
    def create_fixture_file(fixture_name: str, data: Dict[str, Any]):
        """Create a fixture file for reuse"""
        fixture_dir = Path(__file__).parent / "fixtures"
        fixture_dir.mkdir(exist_ok=True)
        
        fixture_path = fixture_dir / f"{fixture_name}.json"
        with open(fixture_path, 'w') as f:
            json.dump(data, f, indent=2)