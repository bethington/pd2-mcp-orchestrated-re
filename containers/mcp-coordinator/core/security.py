"""
Security module for sandboxing and secure analysis execution
"""

import os
import subprocess
import tempfile
import logging
from pathlib import Path
from typing import Dict, List, Optional, Any
import hashlib
import json
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class SecurityLevel(Enum):
    """Security levels for analysis operations"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class SecurityContext:
    """Security context for analysis operations"""
    level: SecurityLevel
    sandbox_enabled: bool
    allowed_paths: List[str]
    blocked_operations: List[str]
    resource_limits: Dict[str, Any]
    audit_enabled: bool

class SecurityManager:
    """Manages security aspects of analysis operations"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._default_config()
        self.audit_log = []
        self.active_contexts = {}
        
    def _default_config(self) -> Dict[str, Any]:
        """Default security configuration"""
        return {
            "default_security_level": SecurityLevel.MEDIUM,
            "sandbox_enabled": True,
            "max_memory_mb": 2048,
            "max_cpu_percent": 50,
            "allowed_network_hosts": ["localhost", "127.0.0.1"],
            "blocked_file_extensions": [".exe", ".dll", ".bat", ".ps1"],
            "audit_enabled": True,
            "quarantine_directory": "./data/quarantine/"
        }
    
    def create_security_context(self, 
                              session_id: str,
                              security_level: SecurityLevel = SecurityLevel.MEDIUM) -> SecurityContext:
        """Create a security context for an analysis session"""
        context = SecurityContext(
            level=security_level,
            sandbox_enabled=self.config["sandbox_enabled"],
            allowed_paths=[
                "./data/outputs/",
                "./data/game_files/",
                "/tmp/",
                tempfile.gettempdir()
            ],
            blocked_operations=[
                "network_connect",
                "file_write_system",
                "process_spawn_elevated"
            ],
            resource_limits={
                "memory_mb": self.config["max_memory_mb"],
                "cpu_percent": self.config["max_cpu_percent"],
                "disk_mb": 1024,
                "network_connections": 10
            },
            audit_enabled=self.config["audit_enabled"]
        )
        
        self.active_contexts[session_id] = context
        self._log_audit_event("context_created", {
            "session_id": session_id,
            "security_level": security_level.value
        })
        
        return context
    
    def validate_file_access(self, filepath: str, context: SecurityContext) -> bool:
        """Validate if file access is allowed in security context"""
        filepath = os.path.abspath(filepath)
        
        # Check allowed paths
        for allowed_path in context.allowed_paths:
            if filepath.startswith(os.path.abspath(allowed_path)):
                return True
        
        # Check file extension restrictions
        file_ext = Path(filepath).suffix.lower()
        if file_ext in self.config["blocked_file_extensions"]:
            self._log_audit_event("file_access_blocked", {
                "filepath": filepath,
                "reason": "blocked_extension",
                "extension": file_ext
            })
            return False
        
        return False
    
    def create_sandbox_environment(self, session_id: str) -> Dict[str, str]:
        """Create a sandboxed environment for analysis"""
        context = self.active_contexts.get(session_id)
        if not context or not context.sandbox_enabled:
            return {}
        
        sandbox_dir = Path(f"./data/sandbox/{session_id}")
        sandbox_dir.mkdir(parents=True, exist_ok=True)
        
        # Create isolated environment variables
        env = os.environ.copy()
        env.update({
            "ANALYSIS_SANDBOX": "true",
            "SANDBOX_DIR": str(sandbox_dir),
            "SESSION_ID": session_id,
            "SECURITY_LEVEL": context.level.value,
            # Restrict PATH to essential directories
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            # Clear potentially dangerous variables
            "LD_PRELOAD": "",
            "LD_LIBRARY_PATH": ""
        })
        
        self._log_audit_event("sandbox_created", {
            "session_id": session_id,
            "sandbox_dir": str(sandbox_dir)
        })
        
        return env
    
    def quarantine_file(self, filepath: str, reason: str) -> str:
        """Move a suspicious file to quarantine"""
        quarantine_dir = Path(self.config["quarantine_directory"])
        quarantine_dir.mkdir(parents=True, exist_ok=True)
        
        # Generate safe filename with hash
        file_hash = self._calculate_file_hash(filepath)
        quarantine_filename = f"{file_hash}_{Path(filepath).name}"
        quarantine_path = quarantine_dir / quarantine_filename
        
        try:
            # Move file to quarantine
            import shutil
            shutil.move(filepath, quarantine_path)
            
            # Create quarantine metadata
            metadata = {
                "original_path": filepath,
                "quarantine_time": str(datetime.utcnow()),
                "reason": reason,
                "file_hash": file_hash
            }
            
            with open(quarantine_path.with_suffix('.meta'), 'w') as f:
                json.dump(metadata, f, indent=2)
            
            self._log_audit_event("file_quarantined", {
                "original_path": filepath,
                "quarantine_path": str(quarantine_path),
                "reason": reason
            })
            
            return str(quarantine_path)
            
        except Exception as e:
            logger.error(f"Failed to quarantine file {filepath}: {e}")
            raise
    
    def validate_network_access(self, host: str, port: int, context: SecurityContext) -> bool:
        """Validate network access permissions"""
        if context.level == SecurityLevel.CRITICAL:
            # Critical security level blocks all network access
            return False
        
        # Check allowed hosts
        allowed_hosts = self.config.get("allowed_network_hosts", [])
        if host not in allowed_hosts:
            self._log_audit_event("network_access_blocked", {
                "host": host,
                "port": port,
                "reason": "host_not_allowed"
            })
            return False
        
        # Check port restrictions
        restricted_ports = [22, 23, 25, 53, 80, 443, 993, 995]
        if port in restricted_ports and context.level in [SecurityLevel.HIGH, SecurityLevel.CRITICAL]:
            self._log_audit_event("network_access_blocked", {
                "host": host,
                "port": port,
                "reason": "restricted_port"
            })
            return False
        
        return True
    
    def monitor_resource_usage(self, session_id: str) -> Dict[str, Any]:
        """Monitor resource usage for a session"""
        context = self.active_contexts.get(session_id)
        if not context:
            return {}
        
        try:
            import psutil
            
            # Get process information
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'memory_info', 'cpu_percent']):
                try:
                    if session_id in proc.info.get('name', ''):
                        processes.append(proc.info)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # Calculate total resource usage
            total_memory = sum(p['memory_info'].rss for p in processes if p['memory_info'])
            total_cpu = sum(p['cpu_percent'] for p in processes if p['cpu_percent'])
            
            usage = {
                "memory_mb": total_memory / 1024 / 1024,
                "cpu_percent": total_cpu,
                "process_count": len(processes),
                "within_limits": True
            }
            
            # Check limits
            if usage["memory_mb"] > context.resource_limits["memory_mb"]:
                usage["within_limits"] = False
                self._log_audit_event("resource_limit_exceeded", {
                    "session_id": session_id,
                    "resource": "memory",
                    "usage": usage["memory_mb"],
                    "limit": context.resource_limits["memory_mb"]
                })
            
            if usage["cpu_percent"] > context.resource_limits["cpu_percent"]:
                usage["within_limits"] = False
                self._log_audit_event("resource_limit_exceeded", {
                    "session_id": session_id,
                    "resource": "cpu",
                    "usage": usage["cpu_percent"],
                    "limit": context.resource_limits["cpu_percent"]
                })
            
            return usage
            
        except ImportError:
            logger.warning("psutil not available for resource monitoring")
            return {"error": "monitoring_unavailable"}
    
    def cleanup_session(self, session_id: str):
        """Clean up security context and sandbox for a session"""
        if session_id in self.active_contexts:
            del self.active_contexts[session_id]
        
        # Clean up sandbox directory
        sandbox_dir = Path(f"./data/sandbox/{session_id}")
        if sandbox_dir.exists():
            import shutil
            try:
                shutil.rmtree(sandbox_dir)
                self._log_audit_event("sandbox_cleaned", {
                    "session_id": session_id
                })
            except Exception as e:
                logger.error(f"Failed to clean sandbox for {session_id}: {e}")
    
    def get_audit_log(self, session_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get audit log entries"""
        if session_id:
            return [entry for entry in self.audit_log 
                   if entry.get("data", {}).get("session_id") == session_id]
        return self.audit_log
    
    def _calculate_file_hash(self, filepath: str) -> str:
        """Calculate SHA256 hash of a file"""
        hash_sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            logger.error(f"Failed to calculate hash for {filepath}: {e}")
            return "unknown"
    
    def _log_audit_event(self, event_type: str, data: Dict[str, Any]):
        """Log security audit event"""
        from datetime import datetime
        
        audit_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "data": data
        }
        
        self.audit_log.append(audit_entry)
        
        if self.config.get("audit_enabled", True):
            logger.info(f"Security audit: {event_type}", extra=audit_entry)
        
        # Keep audit log size manageable
        if len(self.audit_log) > 10000:
            self.audit_log = self.audit_log[-5000:]

# Global security manager instance
security_manager = SecurityManager()
