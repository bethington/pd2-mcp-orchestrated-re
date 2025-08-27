#!/usr/bin/env python3
"""
Container Build Validation Script

Validates that all containers can build successfully with the new container-focused architecture.
"""

import subprocess
import sys
from pathlib import Path

def run_command(cmd, description):
    """Run a command and return success status"""
    print(f"🔧 {description}")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=600)
        if result.returncode == 0:
            print(f"✅ {description} - SUCCESS")
            return True
        else:
            print(f"❌ {description} - FAILED")
            print(f"Error: {result.stderr}")
            return False
    except subprocess.TimeoutExpired:
        print(f"⏰ {description} - TIMEOUT")
        return False
    except Exception as e:
        print(f"🚫 {description} - ERROR: {e}")
        return False

def main():
    """Main validation function"""
    print("🎯 Starting Container-focused Architecture Build Validation")
    print("=" * 70)
    
    # Check if we're in the right directory
    if not Path("docker-compose.yml").exists():
        print("❌ docker-compose.yml not found. Please run from project root.")
        sys.exit(1)
    
    # List of containers to test (start with core ones first)
    containers = [
        "d2-analysis",
        "mcp-coordinator", 
        "analysis-engine",
        "api-gateway"
    ]
    
    build_results = {}
    
    for container in containers:
        success = run_command(
            f"docker-compose build --no-cache {container}",
            f"Building {container} container"
        )
        build_results[container] = success
    
    # Summary
    print("\n" + "=" * 70)
    print("📋 Build Results Summary:")
    print("=" * 70)
    
    successful = 0
    failed = 0
    
    for container, success in build_results.items():
        status = "✅ SUCCESS" if success else "❌ FAILED"
        print(f"{container:20} | {status}")
        if success:
            successful += 1
        else:
            failed += 1
    
    print(f"\nTotal: {len(containers)} containers")
    print(f"✅ Successful: {successful}")
    print(f"❌ Failed: {failed}")
    
    if failed == 0:
        print("\n🎉 All containers built successfully!")
        print("✨ Container-focused architecture validation complete!")
        return True
    else:
        print(f"\n⚠️  {failed} container(s) failed to build.")
        print("🔧 Please check the error messages above and fix any issues.")
        return False

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
