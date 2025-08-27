"""
Frida Dynamic Analysis Server
Advanced runtime analysis and instrumentation service
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import uvicorn
import structlog
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any

from dynamic_analyzer import FridaDynamicAnalyzer

logger = structlog.get_logger()

app = FastAPI(
    title="Frida Dynamic Analysis Server",
    version="1.0.0",
    description="Advanced runtime analysis and instrumentation using Frida"
)

# Global analyzer instance
frida_analyzer = None

class AttachRequest(BaseModel):
    process_identifier: str  # PID or process name
    
class HookRequest(BaseModel):
    session_id: str
    api_patterns: List[str]

class TraceRequest(BaseModel):
    session_id: str
    function_address: str

class MemoryScanRequest(BaseModel):
    session_id: str
    pattern: str
    scan_type: str = "bytes"  # bytes, string, value

@app.on_event("startup")
async def startup_event():
    """Initialize Frida analyzer"""
    global frida_analyzer
    try:
        frida_analyzer = FridaDynamicAnalyzer()
        logger.info("Frida analyzer initialized successfully")
    except Exception as e:
        logger.error("Failed to initialize Frida analyzer", error=str(e))
        raise

@app.get("/")
async def root():
    return {
        "service": "Frida Dynamic Analysis Server",
        "version": "1.0.0",
        "status": "running",
        "capabilities": [
            "Process attachment and instrumentation",
            "API call hooking and monitoring",
            "Function call tracing",
            "Memory scanning and analysis",
            "Runtime code modification",
            "Dynamic control flow analysis",
            "Real-time data collection"
        ],
        "supported_platforms": ["Windows", "Linux", "macOS"],
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "frida-analysis",
        "analyzer_ready": frida_analyzer is not None,
        "active_sessions": len(frida_analyzer.active_sessions) if frida_analyzer else 0,
        "timestamp": datetime.now().isoformat()
    }

@app.post("/attach")
async def attach_to_process(request: AttachRequest):
    """Attach Frida to a running process"""
    if not frida_analyzer:
        raise HTTPException(status_code=500, detail="Frida analyzer not initialized")
    
    result = await frida_analyzer.attach_to_process(request.process_identifier)
    
    if result.get("success"):
        return result
    else:
        raise HTTPException(status_code=400, detail=result.get("error", "Attachment failed"))

@app.post("/hook/api")
async def hook_api_calls(request: HookRequest):
    """Hook API calls for monitoring"""
    if not frida_analyzer:
        raise HTTPException(status_code=500, detail="Frida analyzer not initialized")
    
    result = await frida_analyzer.hook_api_calls(request.session_id, request.api_patterns)
    
    if result.get("success"):
        return result
    else:
        raise HTTPException(status_code=400, detail=result.get("error", "API hooking failed"))

@app.post("/trace/function")
async def trace_function_calls(request: TraceRequest):
    """Trace calls to specific function"""
    if not frida_analyzer:
        raise HTTPException(status_code=500, detail="Frida analyzer not initialized")
    
    result = await frida_analyzer.trace_function_calls(request.session_id, request.function_address)
    
    if result.get("success"):
        return result
    else:
        raise HTTPException(status_code=400, detail=result.get("error", "Function tracing failed"))

@app.post("/memory/scan")
async def scan_memory(request: MemoryScanRequest):
    """Scan process memory for patterns"""
    if not frida_analyzer:
        raise HTTPException(status_code=500, detail="Frida analyzer not initialized")
    
    result = await frida_analyzer.memory_scan(request.session_id, request.pattern, request.scan_type)
    
    if result.get("success"):
        return result
    else:
        raise HTTPException(status_code=400, detail=result.get("error", "Memory scan failed"))

@app.get("/session/{session_id}/data")
async def get_session_data(session_id: str):
    """Get collected analysis data for session"""
    if not frida_analyzer:
        raise HTTPException(status_code=500, detail="Frida analyzer not initialized")
    
    result = await frida_analyzer.get_analysis_data(session_id)
    
    if "error" in result:
        raise HTTPException(status_code=404, detail=result["error"])
    
    return result

@app.post("/session/{session_id}/detach")
async def detach_session(session_id: str):
    """Detach from process and cleanup session"""
    if not frida_analyzer:
        raise HTTPException(status_code=500, detail="Frida analyzer not initialized")
    
    result = await frida_analyzer.detach_session(session_id)
    
    if result.get("success"):
        return result
    else:
        raise HTTPException(status_code=400, detail=result.get("error", "Detach failed"))

@app.get("/sessions")
async def list_sessions():
    """List all active analysis sessions"""
    if not frida_analyzer:
        raise HTTPException(status_code=500, detail="Frida analyzer not initialized")
    
    return {
        "active_sessions": frida_analyzer.get_active_sessions(),
        "total_sessions": len(frida_analyzer.active_sessions)
    }

@app.get("/processes")
async def list_processes():
    """List running processes that can be analyzed"""
    try:
        import psutil
        processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'exe', 'create_time']):
            try:
                proc_info = proc.info
                # Filter out system processes and those we can't access
                if (proc_info['name'] and 
                    not proc_info['name'].startswith('System') and
                    proc_info['exe']):
                    
                    processes.append({
                        "pid": proc_info['pid'],
                        "name": proc_info['name'],
                        "exe": proc_info['exe'],
                        "create_time": datetime.fromtimestamp(proc_info['create_time']).isoformat(),
                        "attachable": True  # Could add more sophisticated checking
                    })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # Sort by name and limit results
        processes.sort(key=lambda x: x['name'].lower())
        
        return {
            "processes": processes[:50],  # Limit to 50 processes
            "total_found": len(processes),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error("Failed to list processes", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/capabilities")
async def get_capabilities():
    """Get detailed analysis capabilities"""
    return {
        "instrumentation": [
            "Function hooking and interception",
            "API call monitoring",
            "Return value modification",
            "Argument inspection and modification",
            "Stack trace collection"
        ],
        "memory_analysis": [
            "Memory pattern scanning",
            "Heap analysis",
            "Memory allocation tracking",
            "Buffer overflow detection",
            "Memory leak detection"
        ],
        "code_analysis": [
            "Dynamic control flow analysis",
            "Code coverage collection",
            "Runtime function discovery",
            "Dynamic symbol resolution"
        ],
        "data_collection": [
            "API call logs",
            "Function execution traces",
            "Memory access patterns",
            "Network activity correlation",
            "File system interactions"
        ],
        "supported_targets": [
            "Native executables (PE/ELF)",
            "Managed applications (.NET/Java)",
            "Scripted applications (Python/Node.js)",
            "Mobile applications (Android/iOS)"
        ]
    }

@app.post("/analyze/game")
async def analyze_game_process(data: Dict[str, Any]):
    """Specialized analysis for game processes"""
    if not frida_analyzer:
        raise HTTPException(status_code=500, detail="Frida analyzer not initialized")
    
    process_name = data.get("process_name", "Game.exe")
    
    try:
        # Attach to game process
        attach_result = await frida_analyzer.attach_to_process(process_name)
        if not attach_result.get("success"):
            return {"error": f"Failed to attach to {process_name}: {attach_result.get('error')}"}
        
        session_id = attach_result["session_id"]
        
        # Set up game-specific hooks
        game_apis = [
            "kernel32.dll!VirtualAlloc",
            "kernel32.dll!VirtualProtect", 
            "kernel32.dll!CreateFileA",
            "kernel32.dll!ReadFile",
            "kernel32.dll!WriteFile",
            "user32.dll!GetAsyncKeyState",
            "wininet.dll!InternetOpenA",
            "ws2_32.dll!send",
            "ws2_32.dll!recv"
        ]
        
        hook_result = await frida_analyzer.hook_api_calls(session_id, game_apis)
        
        return {
            "success": True,
            "session_id": session_id,
            "process_name": process_name,
            "hooks_created": hook_result.get("hooks_created", []),
            "message": f"Game analysis started for {process_name}",
            "recommended_duration": "5-10 minutes for comprehensive analysis"
        }
        
    except Exception as e:
        logger.error("Game analysis setup failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/status")
async def get_server_status():
    """Get comprehensive server status"""
    if not frida_analyzer:
        return {"error": "Analyzer not initialized"}
    
    return {
        "status": "running",
        "analyzer_initialized": True,
        "active_sessions": len(frida_analyzer.active_sessions),
        "active_hooks": len(frida_analyzer.active_hooks),
        "total_data_points": sum(
            sum(len(data) for data in session.get("data_collected", {}).values()) 
            for session in frida_analyzer.active_sessions.values()
        ),
        "uptime": "running",  # Could track actual uptime
        "timestamp": datetime.now().isoformat()
    }

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8003)