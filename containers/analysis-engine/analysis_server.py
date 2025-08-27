#!/usr/bin/env python3
"""
Analysis Engine Server for MCP-Orchestrated D2 Analysis Platform
Advanced binary analysis with disassembly, CFG generation, and security analysis
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import uvicorn
import structlog
import os
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any
import uuid

# Import our enhanced binary analyzer
from tools.static.binary_analyzer import BinaryAnalyzer

logger = structlog.get_logger()

app = FastAPI(
    title="Advanced Analysis Engine", 
    version="2.0.0",
    description="Comprehensive binary analysis with disassembly and security assessment"
)

# Global analyzer instance
binary_analyzer = None
active_analyses = {}

class AnalysisRequest(BaseModel):
    binary_path: str
    analysis_depth: str = "detailed"  # basic, detailed, comprehensive
    include_disassembly: bool = True
    include_strings: bool = True
    include_security_analysis: bool = True

class AnalysisStatus(BaseModel):
    analysis_id: str
    status: str  # queued, processing, completed, failed
    progress: float
    start_time: str
    completion_time: Optional[str] = None
    error_message: Optional[str] = None

@app.on_event("startup")
async def startup_event():
    """Initialize the binary analyzer on startup"""
    global binary_analyzer
    try:
        binary_analyzer = BinaryAnalyzer()
        logger.info("Binary analyzer initialized successfully")
    except Exception as e:
        logger.error("Failed to initialize binary analyzer", error=str(e))
        raise

@app.get("/")
async def root():
    return {
        "service": "Advanced Analysis Engine",
        "version": "2.0.0",
        "status": "running",
        "capabilities": [
            "PE/ELF binary analysis",
            "x86/x64 disassembly",
            "Control flow graph generation",
            "String extraction",
            "Import/export analysis",
            "Security vulnerability assessment",
            "YARA pattern matching",
            "Packer detection"
        ],
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "analysis-engine",
        "analyzer_ready": binary_analyzer is not None,
        "active_analyses": len(active_analyses),
        "timestamp": datetime.now().isoformat()
    }

@app.post("/analyze/binary")
async def analyze_binary_file(request: AnalysisRequest, background_tasks: BackgroundTasks):
    """
    Analyze a binary file with comprehensive static analysis
    
    Returns analysis ID for tracking progress
    """
    if not binary_analyzer:
        raise HTTPException(status_code=500, detail="Binary analyzer not initialized")
        
    if not os.path.exists(request.binary_path):
        raise HTTPException(status_code=404, detail=f"Binary file not found: {request.binary_path}")
    
    # Create analysis task
    analysis_id = str(uuid.uuid4())
    active_analyses[analysis_id] = AnalysisStatus(
        analysis_id=analysis_id,
        status="queued",
        progress=0.0,
        start_time=datetime.now().isoformat()
    )
    
    # Start background analysis
    background_tasks.add_task(
        perform_binary_analysis,
        analysis_id,
        request.binary_path,
        request.analysis_depth
    )
    
    return {
        "analysis_id": analysis_id,
        "status": "queued",
        "message": "Binary analysis started",
        "check_status_url": f"/analyze/status/{analysis_id}"
    }

@app.get("/analyze/status/{analysis_id}")
async def get_analysis_status(analysis_id: str):
    """Get status of ongoing analysis"""
    if analysis_id not in active_analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    return active_analyses[analysis_id].dict()

@app.get("/analyze/result/{analysis_id}")
async def get_analysis_result(analysis_id: str):
    """Get completed analysis results"""
    if analysis_id not in active_analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    status = active_analyses[analysis_id]
    if status.status != "completed":
        raise HTTPException(status_code=400, detail=f"Analysis not completed. Status: {status.status}")
    
    # Load results from storage (in real implementation)
    # For now, return status info
    return {
        "analysis_id": analysis_id,
        "status": status.status,
        "completion_time": status.completion_time,
        "results_available": True,
        "message": "Use /analyze/report/{analysis_id} for detailed results"
    }

@app.get("/analyze/report/{analysis_id}")
async def get_analysis_report(analysis_id: str):
    """Get human-readable analysis report"""
    if analysis_id not in active_analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    status = active_analyses[analysis_id]
    if status.status != "completed":
        raise HTTPException(status_code=400, detail="Analysis not completed")
    
    # In real implementation, load stored results
    return {
        "analysis_id": analysis_id,
        "report": "Analysis report would be generated here",
        "format": "text"
    }

@app.post("/analyze/pe")
async def analyze_pe_file(data: Dict[str, Any]):
    """Quick PE file analysis"""
    if "binary_path" not in data:
        raise HTTPException(status_code=400, detail="binary_path required")
    
    try:
        result = await binary_analyzer.analyze_binary(
            data["binary_path"], 
            analysis_depth="basic"
        )
        return result
    except Exception as e:
        logger.error("PE analysis failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/disassemble")
async def disassemble_binary(data: Dict[str, Any]):
    """Disassemble binary code sections"""
    if "binary_path" not in data:
        raise HTTPException(status_code=400, detail="binary_path required")
    
    try:
        result = await binary_analyzer.analyze_binary(
            data["binary_path"], 
            analysis_depth="comprehensive"
        )
        
        return {
            "disassembly": result.get("disassembly", {}),
            "control_flow": result.get("control_flow", {}),
            "binary_format": result.get("binary_format", "Unknown")
        }
    except Exception as e:
        logger.error("Disassembly failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/security/analyze")
async def security_analysis(data: Dict[str, Any]):
    """Perform security-focused analysis"""
    if "binary_path" not in data:
        raise HTTPException(status_code=400, detail="binary_path required")
    
    try:
        result = await binary_analyzer.analyze_binary(
            data["binary_path"], 
            analysis_depth="comprehensive"
        )
        
        return {
            "security_analysis": result.get("security_analysis", {}),
            "patterns": result.get("patterns", []),
            "risk_assessment": {
                "risk_score": result.get("security_analysis", {}).get("risk_score", 0),
                "recommendations": []
            }
        }
    except Exception as e:
        logger.error("Security analysis failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/tools/available")
async def list_available_tools():
    """List available analysis tools"""
    return {
        "static_analysis": [
            "PE/ELF parser",
            "Capstone disassembler",
            "Control flow graph generator",
            "String extractor",
            "YARA pattern matcher"
        ],
        "security_analysis": [
            "ASLR/DEP detection",
            "Suspicious API detection",
            "Packer detection",
            "Anti-debug detection",
            "Risk scoring"
        ],
        "formats_supported": ["PE", "ELF", "Mach-O"],
        "architectures": ["x86", "x64", "ARM", "ARM64"]
    }

@app.get("/status")
async def get_engine_status():
    """Get analysis engine status"""
    return {
        "status": "running",
        "analyzer_initialized": binary_analyzer is not None,
        "active_analyses": len(active_analyses),
        "uptime": "running",
        "memory_usage": "unknown",  # Could add actual memory tracking
        "analyses_completed": len([a for a in active_analyses.values() if a.status == "completed"]),
        "timestamp": datetime.now().isoformat()
    }

async def perform_binary_analysis(analysis_id: str, binary_path: str, analysis_depth: str):
    """Background task to perform binary analysis"""
    try:
        # Update status
        active_analyses[analysis_id].status = "processing"
        active_analyses[analysis_id].progress = 10.0
        
        # Perform analysis
        logger.info("Starting binary analysis", analysis_id=analysis_id, binary_path=binary_path)
        
        result = await binary_analyzer.analyze_binary(binary_path, analysis_depth)
        
        # Update progress
        active_analyses[analysis_id].progress = 90.0
        
        # Generate report
        if "error" not in result:
            report = await binary_analyzer.generate_analysis_report(result)
            
            # In real implementation, store results to disk/database
            logger.info("Analysis completed", analysis_id=analysis_id)
            
            active_analyses[analysis_id].status = "completed"
            active_analyses[analysis_id].progress = 100.0
            active_analyses[analysis_id].completion_time = datetime.now().isoformat()
        else:
            active_analyses[analysis_id].status = "failed"
            active_analyses[analysis_id].error_message = result["error"]
            
    except Exception as e:
        logger.error("Analysis failed", analysis_id=analysis_id, error=str(e))
        active_analyses[analysis_id].status = "failed"
        active_analyses[analysis_id].error_message = str(e)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)
