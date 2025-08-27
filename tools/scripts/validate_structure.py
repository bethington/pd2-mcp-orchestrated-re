#!/usr/bin/env python3
"""
Container-focused structure validation script.
Verifies the new project organization is correct.
"""

import os
import sys
from pathlib import Path

def validate_structure():
    """Validate the container-focused project structure."""
    project_root = Path(__file__).parent.parent.parent  # Go up 3 levels from tools/scripts/
    
    print("🔍 Validating container-focused project structure...")
    
    # Required container directories
    required_containers = [
        "d2-analysis",
        "mcp-coordinator", 
        "analysis-engine",
        "network-monitor",
        "web-dashboard"
    ]
    
    # Required shared directories
    required_shared = [
        "mcp",
        "analysis", 
        "game",
        "data",
        "claude"
    ]
    
    # Check containers
    containers_dir = project_root / "containers"
    if not containers_dir.exists():
        print("❌ containers/ directory missing!")
        return False
        
    print("✅ containers/ directory found")
    
    for container in required_containers:
        container_path = containers_dir / container
        if container_path.exists():
            print(f"✅ containers/{container}/ found")
        else:
            print(f"❌ containers/{container}/ missing")
            return False
    
    # Check shared
    shared_dir = project_root / "shared"
    if not shared_dir.exists():
        print("❌ shared/ directory missing!")
        return False
        
    print("✅ shared/ directory found")
    
    for shared in required_shared:
        shared_path = shared_dir / shared
        if shared_path.exists():
            print(f"✅ shared/{shared}/ found")
        else:
            print(f"❌ shared/{shared}/ missing")
            return False
    
    # Check data structure
    data_dir = project_root / "data"
    if data_dir.exists():
        print("✅ data/ directory found")
    else:
        print("⚠️  data/ directory missing (may need to be created)")
    
    print("\n🎉 Container-focused structure validation complete!")
    return True

if __name__ == "__main__":
    success = validate_structure()
    sys.exit(0 if success else 1)
