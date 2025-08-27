#!/usr/bin/env python3
"""
Pre-deployment validation and setup completion script
"""

import os
import sys
from pathlib import Path
import subprocess
import json

class DeploymentValidator:
    def __init__(self):
        self.project_root = Path.cwd()
        self.issues = []
        self.warnings = []
        
    def check_docker_environment(self):
        """Check Docker and Docker Compose availability"""
        try:
            result = subprocess.run(['docker', '--version'], capture_output=True, text=True)
            if result.returncode != 0:
                self.issues.append("Docker is not available")
            else:
                print(f"✅ Docker: {result.stdout.strip()}")
                
            result = subprocess.run(['docker-compose', '--version'], capture_output=True, text=True)
            if result.returncode != 0:
                self.issues.append("Docker Compose is not available")
            else:
                print(f"✅ Docker Compose: {result.stdout.strip()}")
        except FileNotFoundError:
            self.issues.append("Docker tools not found in PATH")
    
    def check_environment_config(self):
        """Check environment configuration"""
        env_example = self.project_root / '.env.example'
        env_file = self.project_root / '.env'
        
        if not env_example.exists():
            self.issues.append("Missing .env.example file")
        else:
            print("✅ Environment template found")
            
        if not env_file.exists():
            self.warnings.append("No .env file found - will use defaults")
            print("⚠️  No .env file - consider copying from .env.example")
        else:
            print("✅ Environment configuration found")
    
    def check_game_files(self):
        """Check Project Diablo 2 game files"""
        game_dir = self.project_root / 'data' / 'game_files' / 'pd2' / 'ProjectD2'
        game_exe = game_dir / 'Game.exe'
        
        if not game_dir.exists():
            self.issues.append("Project D2 game directory not found")
            return
            
        if not game_exe.exists():
            self.issues.append("Game.exe not found - game files incomplete")
            return
            
        # Count key files
        dll_files = list(game_dir.glob('*.dll'))
        mpq_files = list((self.project_root / 'data' / 'game_files' / 'pd2').glob('*.mpq'))
        
        print(f"✅ Game executable found")
        print(f"✅ {len(dll_files)} DLL files found")
        print(f"✅ {len(mpq_files)} MPQ archives found")
    
    def check_container_definitions(self):
        """Check container definitions and Dockerfiles"""
        containers_dir = self.project_root / 'containers'
        if not containers_dir.exists():
            self.issues.append("Containers directory not found")
            return
            
        expected_containers = [
            'd2-analysis', 'mcp-coordinator', 'analysis-engine', 
            'network-monitor', 'web-dashboard'
        ]
        
        for container in expected_containers:
            dockerfile = containers_dir / container / 'Dockerfile'
            if dockerfile.exists():
                print(f"✅ {container}: Dockerfile found")
            else:
                self.issues.append(f"Missing Dockerfile for {container}")
    
    def check_source_implementation(self):
        """Check core source code implementation status"""
        src_dir = self.project_root / 'src'
        if not src_dir.exists():
            self.issues.append("Source directory not found")
            return
            
        core_modules = [
            'core/session_manager.py',
            'core/event_bus.py', 
            'core/security.py',
            'mcp/clients/mcp_client.py',
            'mcp/clients/orchestrator.py'
        ]
        
        implemented_count = 0
        for module in core_modules:
            module_path = src_dir / module
            if module_path.exists() and module_path.stat().st_size > 1000:  # Assume >1KB = implemented
                implemented_count += 1
                print(f"✅ {module}: Implemented")
            else:
                self.warnings.append(f"Module {module} may need completion")
                
        if implemented_count < len(core_modules) / 2:
            self.issues.append("Core implementation appears incomplete")
        else:
            print(f"✅ Core implementation: {implemented_count}/{len(core_modules)} modules ready")
    
    def generate_deployment_plan(self):
        """Generate deployment plan based on findings"""
        plan = {
            "deployment_ready": len(self.issues) == 0,
            "critical_issues": self.issues,
            "warnings": self.warnings,
            "next_steps": []
        }
        
        if self.issues:
            plan["next_steps"].extend([
                "Fix critical issues listed above",
                "Complete core module implementations",
                "Test container builds with 'make build'",
                "Run development deployment with 'make dev'",
                "Validate all services with 'make health'"
            ])
        else:
            plan["next_steps"].extend([
                "Create .env file from .env.example",
                "Run 'make build' to build all containers",
                "Start with 'make dev' for development testing",
                "Use 'make prod' for production deployment",
                "Monitor with 'make logs' for any issues"
            ])
            
        return plan
    
    def run_validation(self):
        """Run complete validation"""
        print("🔍 Running Pre-Deployment Validation...")
        print("=" * 50)
        
        self.check_docker_environment()
        self.check_environment_config()  
        self.check_game_files()
        self.check_container_definitions()
        self.check_source_implementation()
        
        print("\n" + "=" * 50)
        print("📋 DEPLOYMENT ASSESSMENT")
        print("=" * 50)
        
        plan = self.generate_deployment_plan()
        
        if plan["deployment_ready"]:
            print("🎉 PROJECT IS READY FOR DEPLOYMENT!")
        else:
            print("⚠️  PROJECT NEEDS COMPLETION BEFORE DEPLOYMENT")
            print("\n🚨 Critical Issues:")
            for issue in plan["critical_issues"]:
                print(f"   - {issue}")
                
        if plan["warnings"]:
            print("\n⚠️  Warnings:")
            for warning in plan["warnings"]:
                print(f"   - {warning}")
                
        print("\n📝 Next Steps:")
        for step in plan["next_steps"]:
            print(f"   {step}")
            
        # Save detailed report
        with open('deployment_assessment.json', 'w') as f:
            json.dump(plan, f, indent=2)
            
        print(f"\n📄 Detailed assessment saved to: deployment_assessment.json")
        return plan

if __name__ == "__main__":
    validator = DeploymentValidator()
    result = validator.run_validation()
    sys.exit(0 if result["deployment_ready"] else 1)
