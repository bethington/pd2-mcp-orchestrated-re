"""
Ghidra Project Manager
Manages persistent storage and retrieval of Ghidra projects and analysis files
"""

import os
import shutil
import json
import subprocess
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
import structlog

logger = structlog.get_logger()

class GhidraProjectManager:
    """
    Manages Ghidra project persistence, export, and storage for long-term use
    """
    
    def __init__(self):
        self.ghidra_install = os.environ.get('GHIDRA_INSTALL_DIR', '/home/analysis/ghidra')
        self.headless_script = os.path.join(self.ghidra_install, 'support', 'analyzeHeadless')
        
        # Project directories  
        self.temp_projects_dir = '/home/analysis/projects'  # Local temp projects
        self.persistent_projects_dir = '/app/outputs/ghidra/projects'  # Host-mounted persistent storage
        self.exports_dir = '/app/outputs/ghidra/exports'  # Host-mounted exports storage
        
        # Ensure directories exist
        Path(self.temp_projects_dir).mkdir(exist_ok=True, parents=True)
        Path(self.persistent_projects_dir).mkdir(exist_ok=True, parents=True)
        Path(self.exports_dir).mkdir(exist_ok=True, parents=True)
        
        # Core binaries that should have persistent storage
        self.core_binaries = [
            "D2Client.dll", "D2Common.dll", "D2Game.dll", 
            "Game.exe", "D2Win.dll", "D2Lang.dll", "D2Net.dll",
            "D2Launch.dll", "D2CMP.dll", "Fog.dll", "Storm.dll"
        ]
        
        logger.info("Ghidra project manager initialized", 
                   persistent_dir=self.persistent_projects_dir,
                   exports_dir=self.exports_dir)
    
    def is_core_binary(self, binary_path: str) -> bool:
        """Check if binary should have persistent project storage"""
        binary_name = os.path.basename(binary_path).lower()
        return any(core.lower() in binary_name for core in self.core_binaries)
    
    def get_persistent_project_name(self, binary_path: str) -> str:
        """Generate consistent persistent project name"""
        binary_name = os.path.basename(binary_path)
        # Remove file extension and create safe name
        clean_name = os.path.splitext(binary_name)[0]
        return f"persistent_{clean_name}"
    
    def get_persistent_project_path(self, binary_path: str) -> str:
        """Get the path where persistent project should be stored"""
        project_name = self.get_persistent_project_name(binary_path)
        return os.path.join(self.persistent_projects_dir, project_name)
    
    def project_exists(self, binary_path: str) -> bool:
        """Check if persistent project already exists for binary"""
        project_path = self.get_persistent_project_path(binary_path)
        project_file = os.path.join(project_path, f"{self.get_persistent_project_name(binary_path)}.gpr")
        return os.path.exists(project_file)
    
    def create_or_get_project_path(self, binary_path: str) -> tuple[str, str, bool]:
        """
        Create or get project path for binary analysis
        
        Returns:
            (project_path, project_name, should_preserve)
        """
        is_core = self.is_core_binary(binary_path)
        
        if is_core:
            # Use persistent project for core binaries
            project_name = self.get_persistent_project_name(binary_path)
            project_path = self.get_persistent_project_path(binary_path)
            
            # Ensure directory exists
            os.makedirs(project_path, exist_ok=True)
            
            logger.info("Using persistent project for core binary",
                       binary=os.path.basename(binary_path),
                       project_name=project_name,
                       project_path=project_path)
            
            return project_path, project_name, True
        else:
            # Use temporary project for non-core binaries
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            project_name = f"temp_analysis_{timestamp}"
            project_path = os.path.join(self.temp_projects_dir, project_name)
            
            logger.info("Using temporary project for non-core binary",
                       binary=os.path.basename(binary_path),
                       project_name=project_name)
            
            return project_path, project_name, False
    
    def export_project_analysis(self, binary_path: str, project_path: str, project_name: str) -> Dict[str, str]:
        """
        Export Ghidra project analysis to persistent storage
        
        Args:
            binary_path: Path to the analyzed binary
            project_path: Path to Ghidra project
            project_name: Name of Ghidra project
            
        Returns:
            Dictionary with export file paths
        """
        try:
            binary_name = os.path.basename(binary_path)
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            
            # Create export subdirectory
            export_subdir = os.path.join(self.exports_dir, f"{binary_name}_{timestamp}")
            os.makedirs(export_subdir, exist_ok=True)
            
            exports = {}
            
            # 1. Export project analysis using our custom script
            json_export_path = os.path.join(export_subdir, f"{binary_name}_analysis.json")
            export_cmd = [
                self.headless_script,
                project_path,
                project_name,
                "-process", binary_name,
                "-postScript", "export_project.py",
                json_export_path,
                "-scriptPath", "/home/analysis/scripts"
            ]
            
            try:
                subprocess.run(export_cmd, capture_output=True, text=True, timeout=60)
                if os.path.exists(json_export_path):
                    exports['json_analysis'] = json_export_path
                    logger.info("JSON analysis export completed", path=json_export_path)
            except Exception as e:
                logger.warning("JSON analysis export failed", error=str(e))
            
            # 2. Copy project files if they exist
            project_file = os.path.join(project_path, f"{project_name}.gpr")
            if os.path.exists(project_file):
                project_copy = os.path.join(export_subdir, f"{project_name}.gpr")
                shutil.copy2(project_file, project_copy)
                exports['project'] = project_copy
                logger.info("Project file copied", path=project_copy)
                
                # Copy associated project directory
                project_data_dir = os.path.join(project_path, f"{project_name}.rep")
                if os.path.exists(project_data_dir):
                    data_copy = os.path.join(export_subdir, f"{project_name}.rep")
                    shutil.copytree(project_data_dir, data_copy, dirs_exist_ok=True)
                    exports['project_data'] = data_copy
                    logger.info("Project data copied", path=data_copy)
            
            # 3. Create analysis metadata
            metadata = {
                "binary_path": binary_path,
                "binary_name": binary_name,
                "project_name": project_name,
                "analysis_timestamp": timestamp,
                "ghidra_version": "11.0.1",
                "exports": exports,
                "is_core_binary": self.is_core_binary(binary_path)
            }
            
            metadata_path = os.path.join(export_subdir, "analysis_metadata.json")
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            exports['metadata'] = metadata_path
            
            logger.info("Analysis export completed",
                       binary=binary_name,
                       export_dir=export_subdir,
                       files_exported=len(exports))
            
            return exports
            
        except Exception as e:
            logger.error("Project export failed",
                        binary=binary_path,
                        project=project_name,
                        error=str(e))
            return {}
    
    def list_persistent_projects(self) -> List[Dict[str, Any]]:
        """List all persistent projects"""
        projects = []
        
        try:
            if os.path.exists(self.persistent_projects_dir):
                for project_dir in os.listdir(self.persistent_projects_dir):
                    project_path = os.path.join(self.persistent_projects_dir, project_dir)
                    
                    if os.path.isdir(project_path):
                        # Look for .gpr file
                        gpr_file = os.path.join(project_path, f"{project_dir}.gpr")
                        
                        project_info = {
                            "name": project_dir,
                            "path": project_path,
                            "has_gpr_file": os.path.exists(gpr_file),
                            "created": datetime.fromtimestamp(os.path.getctime(project_path)).isoformat() if os.path.exists(project_path) else None
                        }
                        
                        projects.append(project_info)
                        
        except Exception as e:
            logger.error("Failed to list persistent projects", error=str(e))
        
        return projects
    
    def list_exported_analyses(self) -> List[Dict[str, Any]]:
        """List all exported analyses"""
        exports = []
        
        try:
            if os.path.exists(self.exports_dir):
                for export_dir in os.listdir(self.exports_dir):
                    export_path = os.path.join(self.exports_dir, export_dir)
                    
                    if os.path.isdir(export_path):
                        # Look for metadata file
                        metadata_file = os.path.join(export_path, "analysis_metadata.json")
                        
                        export_info = {
                            "name": export_dir,
                            "path": export_path,
                            "has_metadata": os.path.exists(metadata_file),
                            "created": datetime.fromtimestamp(os.path.getctime(export_path)).isoformat() if os.path.exists(export_path) else None
                        }
                        
                        # Load metadata if available
                        if os.path.exists(metadata_file):
                            try:
                                with open(metadata_file, 'r') as f:
                                    metadata = json.load(f)
                                export_info.update({
                                    "binary_name": metadata.get("binary_name"),
                                    "analysis_timestamp": metadata.get("analysis_timestamp"),
                                    "is_core_binary": metadata.get("is_core_binary"),
                                    "exports": metadata.get("exports", {})
                                })
                            except Exception as e:
                                logger.warning("Failed to load metadata", file=metadata_file, error=str(e))
                        
                        exports.append(export_info)
                        
        except Exception as e:
            logger.error("Failed to list exported analyses", error=str(e))
        
        return exports
    
    def cleanup_temp_projects(self, max_age_hours: int = 24):
        """Clean up old temporary projects"""
        try:
            current_time = datetime.now().timestamp()
            cutoff_time = current_time - (max_age_hours * 3600)
            
            cleaned = 0
            for project_dir in os.listdir(self.temp_projects_dir):
                if project_dir.startswith("temp_") or project_dir.startswith("decompile_"):
                    project_path = os.path.join(self.temp_projects_dir, project_dir)
                    
                    if os.path.isdir(project_path):
                        try:
                            creation_time = os.path.getctime(project_path)
                            if creation_time < cutoff_time:
                                shutil.rmtree(project_path)
                                cleaned += 1
                                logger.info("Cleaned up old temporary project", project=project_dir)
                        except Exception as e:
                            logger.warning("Failed to clean up project", project=project_dir, error=str(e))
            
            logger.info("Temporary project cleanup completed", cleaned=cleaned, max_age_hours=max_age_hours)
            return cleaned
            
        except Exception as e:
            logger.error("Cleanup failed", error=str(e))
            return 0
    
    def get_project_stats(self) -> Dict[str, Any]:
        """Get statistics about projects and exports"""
        stats = {
            "persistent_projects": len(self.list_persistent_projects()),
            "exported_analyses": len(self.list_exported_analyses()),
            "temp_projects": 0,
            "storage_paths": {
                "persistent_projects": self.persistent_projects_dir,
                "exports": self.exports_dir,
                "temp_projects": self.temp_projects_dir
            }
        }
        
        # Count temp projects
        try:
            if os.path.exists(self.temp_projects_dir):
                temp_count = len([d for d in os.listdir(self.temp_projects_dir) 
                                if os.path.isdir(os.path.join(self.temp_projects_dir, d))])
                stats["temp_projects"] = temp_count
        except Exception as e:
            logger.warning("Failed to count temp projects", error=str(e))
        
        return stats