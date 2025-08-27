#!/usr/bin/env python3
"""
Quick Start Script for PD2 MCP Analysis Platform
"""

import os
import sys
import subprocess
import time
from pathlib import Path

def print_banner():
    print("""
🎮 Project Diablo 2 MCP Analysis Platform
==========================================
""")

def check_requirements():
    """Check system requirements"""
    print("🔍 Checking system requirements...")
    
    # Check Docker
    try:
        result = subprocess.run(['docker', '--version'], capture_output=True, text=True, check=True)
        print(f"✅ Docker: {result.stdout.strip()}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ Docker not found. Please install Docker first.")
        return False
    
    # Check Docker Compose
    try:
        result = subprocess.run(['docker-compose', '--version'], capture_output=True, text=True, check=True)
        print(f"✅ Docker Compose: {result.stdout.strip()}")
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("❌ Docker Compose not found. Please install Docker Compose first.")
        return False
    
    return True

def check_game_files():
    """Check if game files exist"""
    print("\n🎯 Checking game files...")
    
    game_exe = Path("data/game_files/pd2/ProjectD2/Game.exe")
    if game_exe.exists():
        print("✅ Game.exe found")
        return True
    else:
        print("❌ Game.exe not found")
        print("   Please copy your Project Diablo 2 files to data/game_files/pd2/")
        print("   See INSTALL.md for detailed instructions")
        return False

def setup_environment():
    """Setup environment file"""
    print("\n⚙️ Setting up environment...")
    
    env_file = Path(".env")
    env_example = Path(".env.example")
    
    if not env_file.exists() and env_example.exists():
        subprocess.run(['cp', str(env_example), str(env_file)], check=True)
        print("✅ Environment file created")
    elif env_file.exists():
        print("✅ Environment file exists")
    else:
        # Create basic env file
        with open(env_file, 'w') as f:
            f.write("SESSION_ID=quickstart_session\n")
            f.write("AUTO_START_GAME=true\n")
            f.write("DEBUG=false\n")
        print("✅ Basic environment file created")

def build_platform():
    """Build the platform"""
    print("\n🔨 Building platform...")
    
    try:
        subprocess.run(['make', 'build'], check=True)
        print("✅ Platform built successfully")
        return True
    except subprocess.CalledProcessError:
        print("❌ Build failed")
        return False
    except FileNotFoundError:
        # Try docker-compose directly if make is not available
        try:
            subprocess.run(['docker-compose', 'build'], check=True)
            print("✅ Platform built successfully (using docker-compose)")
            return True
        except subprocess.CalledProcessError:
            print("❌ Build failed")
            return False

def start_platform():
    """Start the platform"""
    print("\n🚀 Starting platform...")
    
    try:
        subprocess.run(['make', 'dev'], check=True)
        print("✅ Platform started successfully")
        return True
    except subprocess.CalledProcessError:
        print("❌ Failed to start platform")
        return False
    except FileNotFoundError:
        # Try docker-compose directly
        try:
            subprocess.run(['docker-compose', '-f', 'docker-compose.yml', '-f', 'docker-compose.dev.yml', 'up', '-d'], check=True)
            print("✅ Platform started successfully (using docker-compose)")
            return True
        except subprocess.CalledProcessError:
            print("❌ Failed to start platform")
            return False

def wait_for_services():
    """Wait for services to be ready"""
    print("\n⏳ Waiting for services to start...")
    
    services = [
        ("D2 Analysis", "http://localhost:3000/health"),
        ("MCP Coordinator", "http://localhost:8000/health"),
        ("Dgraph", "http://localhost:8081/health")
    ]
    
    import requests
    
    for service, url in services:
        max_attempts = 30
        for attempt in range(max_attempts):
            try:
                response = requests.get(url, timeout=5)
                if response.status_code == 200:
                    print(f"✅ {service} is ready")
                    break
            except requests.RequestException:
                pass
            
            if attempt < max_attempts - 1:
                print(f"   Waiting for {service}... ({attempt + 1}/{max_attempts})")
                time.sleep(2)
        else:
            print(f"⚠️  {service} may not be ready yet")

def show_access_info():
    """Show access information"""
    print("\n🌐 Platform Access Information:")
    print("================================")
    print("VNC (Game View):     vnc://localhost:5900")
    print("Web Dashboard:       http://localhost:80")
    print("MCP Coordinator:     http://localhost:8000")
    print("Dgraph UI:           http://localhost:8081")
    print("Jupyter Notebooks:   http://localhost:8888")
    print("\n📊 Health Check:     http://localhost:3000/health")

def run_demo_analysis():
    """Ask if user wants to run demo analysis"""
    print("\n🧪 Demo Analysis Available")
    response = input("Would you like to run a demo analysis? (y/n): ").lower().strip()
    
    if response == 'y':
        print("\n🚀 Starting demo analysis...")
        demo_script = Path("examples/advanced_analysis/comprehensive_analysis.py")
        
        if demo_script.exists():
            try:
                subprocess.run([sys.executable, str(demo_script)], check=True)
                print("✅ Demo analysis completed")
            except subprocess.CalledProcessError:
                print("❌ Demo analysis failed")
                print("You can run it manually later with:")
                print(f"python {demo_script}")
        else:
            print(f"❌ Demo script not found at {demo_script}")

def main():
    """Main startup sequence"""
    print_banner()
    
    # Check if we're in the right directory
    if not Path("docker-compose.yml").exists():
        print("❌ Please run this script from the project root directory")
        print("   (The directory containing docker-compose.yml)")
        return 1
    
    # Check system requirements
    if not check_requirements():
        return 1
    
    # Check game files
    game_files_ok = check_game_files()
    if not game_files_ok:
        response = input("\nContinue anyway? (Demo mode without game) (y/n): ").lower().strip()
        if response != 'y':
            print("Please setup game files and run again.")
            return 1
        print("Continuing in demo mode...")
    
    # Setup environment
    setup_environment()
    
    # Build platform
    if not build_platform():
        return 1
    
    # Start platform
    if not start_platform():
        return 1
    
    # Wait for services
    wait_for_services()
    
    # Show access info
    show_access_info()
    
    # Offer demo analysis
    if game_files_ok:
        run_demo_analysis()
    
    print("\n🎉 Startup complete!")
    print("📚 See README.md for usage examples")
    print("🆘 For help: https://github.com/your-repo/issues")
    print("\n💡 To stop the platform: make clean")
    
    return 0

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n🛑 Startup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)
