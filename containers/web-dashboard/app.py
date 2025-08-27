#!/usr/bin/env python3
"""
Web Dashboard for MCP-Orchestrated D2 Analysis Platform
"""

from flask import Flask, render_template, jsonify, request, send_from_directory
import json
import time
import requests
from datetime import datetime
import os

app = Flask(__name__)

class DashboardAPI:
    def __init__(self):
        self.mcp_coordinator_url = os.getenv('MCP_COORDINATOR_URL', 'http://mcp-coordinator:8000')
        self.d2_analysis_url = os.getenv('D2_ANALYSIS_URL', 'http://d2-analysis:8765')
        
    def get_system_status(self):
        """Get overall system status"""
        try:
            response = requests.get(f"{self.mcp_coordinator_url}/health", timeout=5)
            if response.status_code == 200:
                return {"status": "healthy", "data": response.json()}
        except:
            pass
        return {"status": "unhealthy", "data": {}}
    
    def get_d2_status(self):
        """Get D2 analysis status"""
        try:
            response = requests.get(f"{self.d2_analysis_url}/health", timeout=5)
            if response.status_code == 200:
                return {"status": "healthy", "data": response.json()}
        except:
            pass
        return {"status": "unhealthy", "data": {}}
    
    def get_session_info(self):
        """Get current session information"""
        return {
            "session_id": "demo_session",
            "started_at": datetime.now().isoformat(),
            "character_name": "TestCharacter",
            "analysis_goals": ["security", "performance"]
        }

dashboard_api = DashboardAPI()

@app.route('/')
def index():
    """Main dashboard page"""
    return render_template('dashboard.html')

@app.route('/api/status')
def api_status():
    """API endpoint for system status"""
    return jsonify({
        "timestamp": time.time(),
        "system": dashboard_api.get_system_status(),
        "d2_analysis": dashboard_api.get_d2_status(),
        "session": dashboard_api.get_session_info()
    })

@app.route('/api/character')
def api_character():
    """API endpoint for character data"""
    # Mock character data for demo
    return jsonify({
        "name": "TestCharacter",
        "level": 85,
        "class": "Sorceress",
        "experience": 1234567890,
        "life": {"current": 1250, "max": 1250},
        "mana": {"current": 890, "max": 890},
        "stats": {
            "strength": 156,
            "dexterity": 187,
            "vitality": 245,
            "energy": 298
        }
    })

@app.route('/api/network')
def api_network():
    """API endpoint for network analysis data"""
    return jsonify({
        "packets_captured": 15432,
        "d2_packets": 8765,
        "protocol_violations": 3,
        "recent_activity": [
            {"timestamp": time.time() - 30, "type": "game_data", "size": 128},
            {"timestamp": time.time() - 15, "type": "battlenet", "size": 64},
            {"timestamp": time.time() - 5, "type": "game_data", "size": 256}
        ]
    })

@app.route('/api/security')
def api_security():
    """API endpoint for security events"""
    return jsonify({
        "total_events": 12,
        "critical_events": 1,
        "recent_events": [
            {
                "timestamp": time.time() - 300,
                "severity": "medium",
                "type": "unusual_packet_pattern",
                "description": "Detected repetitive packet pattern"
            },
            {
                "timestamp": time.time() - 600,
                "severity": "low",
                "type": "memory_access",
                "description": "Unusual memory access pattern detected"
            }
        ]
    })

@app.route('/api/screenshot', methods=['POST'])
def capture_screenshot():
    """Trigger screenshot capture"""
    try:
        description = request.json.get('description', 'Manual screenshot from dashboard') if request.is_json else 'Manual screenshot from dashboard'
        
        # Method 1: Try via MCP coordinator (preferred)
        try:
            response = requests.post(
                f"{dashboard_api.mcp_coordinator_url}/api/screenshot",
                json={"description": description},
                timeout=10
            )
            if response.status_code == 200:
                result = response.json()
                return jsonify({
                    "success": True,
                    "filename": result.get("filename"),
                    "timestamp": result.get("timestamp"),
                    "message": "Screenshot captured via MCP coordinator"
                })
        except requests.RequestException:
            pass  # Fall through to alternative method
        
        # Method 2: Create a trigger file that d2-analysis can monitor
        trigger_timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        trigger_filename = f"screenshot_request_{trigger_timestamp}.txt"
        expected_screenshot = f"dashboard_screenshot_{trigger_timestamp}.png"
        
        try:
            # Create a trigger file in the shared data directory
            trigger_path = f"/app/data/screenshot_requests/{trigger_filename}"
            os.makedirs("/app/data/screenshot_requests", exist_ok=True)
            
            with open(trigger_path, 'w') as f:
                json.dump({
                    "description": description,
                    "timestamp": datetime.now().isoformat(),
                    "expected_filename": expected_screenshot,
                    "source": "web_dashboard"
                }, f)
            
            # Wait a moment for processing
            import time
            time.sleep(2)
            
            # Check if screenshot was created
            screenshot_path = f"/app/data/screenshots/{expected_screenshot}"
            if os.path.exists(screenshot_path):
                return jsonify({
                    "success": True,
                    "filename": expected_screenshot,
                    "timestamp": datetime.now().isoformat(),
                    "message": "Screenshot captured via file trigger"
                })
            else:
                # Provide helpful instructions
                return jsonify({
                    "success": False,
                    "error": "Screenshot trigger created but capture not confirmed",
                    "instructions": {
                        "manual_method_1": "Run: docker exec d2-analysis bash -c \"DISPLAY=:1 scrot /screenshots/manual_$(date +%Y%m%d_%H%M%S).png\"",
                        "manual_method_2": "Use VNC hotkeys: Print Screen, Ctrl+Alt+S, or Windows+S in the VNC session",
                        "vnc_access": "http://localhost:5901",
                        "trigger_file_created": trigger_filename
                    }
                }), 202  # Accepted but not completed
                
        except Exception as file_error:
            return jsonify({
                "success": False,
                "error": f"Could not create screenshot trigger: {str(file_error)}",
                "alternatives": {
                    "vnc_hotkeys": "Use Print Screen, Ctrl+Alt+S, or Windows+S in VNC session at http://localhost:5901",
                    "manual_command": "docker exec d2-analysis bash -c \"DISPLAY=:1 scrot /screenshots/manual_$(date +%Y%m%d_%H%M%S).png\""
                }
            }), 500
                
    except Exception as e:
        return jsonify({
            "success": False,
            "error": f"Screenshot API error: {str(e)}",
            "workarounds": {
                "vnc_session": "Access http://localhost:5901 and use Print Screen or Ctrl+Alt+S",
                "direct_command": "Run: docker exec d2-analysis bash -c \"DISPLAY=:1 scrot /screenshots/manual_$(date +%Y%m%d_%H%M%S).png\""
            }
        }), 500

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({"status": "healthy", "service": "web-dashboard"})

if __name__ == '__main__':
    port = int(os.getenv('PORT', 80))
    app.run(host='0.0.0.0', port=port, debug=True)
