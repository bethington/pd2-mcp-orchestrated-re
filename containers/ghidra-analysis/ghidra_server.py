"""
Ghidra MCP Server for Advanced Decompilation and Analysis
Provides comprehensive binary analysis through Ghidra headless mode
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

# Import the headless analyzer
from headless_analyzer import GhidraHeadlessAnalyzer

logger = structlog.get_logger()

app = FastAPI(
    title="Ghidra Analysis Server",
    version="1.0.0", 
    description="Advanced decompilation and binary analysis using Ghidra"
)

# Global analyzer instance
ghidra_analyzer = None
active_analyses = {}

class GhidraAnalysisRequest(BaseModel):
    binary_path: str
    analysis_type: str = "comprehensive"  # basic, detailed, comprehensive
    include_decompilation: bool = True
    include_strings: bool = True
    function_address: Optional[str] = None  # For single function analysis

class AnalysisStatus(BaseModel):
    analysis_id: str
    status: str  # queued, processing, completed, failed
    progress: float
    start_time: str
    completion_time: Optional[str] = None
    error_message: Optional[str] = None

@app.on_event("startup")
async def startup_event():
    """Initialize Ghidra analyzer"""
    global ghidra_analyzer
    try:
        ghidra_analyzer = GhidraHeadlessAnalyzer()
        logger.info("Ghidra analyzer initialized successfully")
    except Exception as e:
        logger.error("Failed to initialize Ghidra analyzer", error=str(e))
        raise

@app.get("/")
async def root():
    return {
        "service": "Ghidra Analysis Server",
        "version": "1.0.0",
        "status": "running",
        "capabilities": [
            "Comprehensive binary decompilation",
            "Function analysis and signature detection",
            "String extraction and analysis", 
            "Import/export table analysis",
            "Data type reconstruction",
            "Cross-reference analysis",
            "Control flow graph generation",
            "Symbol table analysis"
        ],
        "supported_formats": ghidra_analyzer.get_supported_formats() if ghidra_analyzer else [],
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "ghidra-analysis",
        "analyzer_ready": ghidra_analyzer is not None,
        "active_analyses": len(active_analyses),
        "timestamp": datetime.now().isoformat()
    }

@app.post("/analyze/binary")
async def analyze_binary(request: GhidraAnalysisRequest, background_tasks: BackgroundTasks):
    """Start comprehensive Ghidra analysis"""
    if not ghidra_analyzer:
        raise HTTPException(status_code=500, detail="Ghidra analyzer not initialized")
        
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
        perform_ghidra_analysis,
        analysis_id,
        request.binary_path,
        request.analysis_type
    )
    
    return {
        "analysis_id": analysis_id,
        "status": "queued",
        "message": "Ghidra analysis started",
        "estimated_duration": "5-15 minutes depending on binary size",
        "check_status_url": f"/analyze/status/{analysis_id}"
    }

@app.post("/decompile/function")
async def decompile_function(data: Dict[str, Any]):
    """Decompile a specific function"""
    if not ghidra_analyzer:
        raise HTTPException(status_code=500, detail="Ghidra analyzer not initialized")
        
    required_fields = ["binary_path", "function_address"]
    for field in required_fields:
        if field not in data:
            raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
    
    try:
        result = await ghidra_analyzer.decompile_function(
            data["binary_path"],
            data["function_address"]
        )
        return result
    except Exception as e:
        logger.error("Function decompilation failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/strings")
async def analyze_strings(data: Dict[str, Any]):
    """Extract and analyze strings using Ghidra"""
    if not ghidra_analyzer:
        raise HTTPException(status_code=500, detail="Ghidra analyzer not initialized")
        
    if "binary_path" not in data:
        raise HTTPException(status_code=400, detail="binary_path required")
    
    try:
        result = await ghidra_analyzer.analyze_strings(data["binary_path"])
        return result
    except Exception as e:
        logger.error("String analysis failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/analyze/status/{analysis_id}")
async def get_analysis_status(analysis_id: str):
    """Get status of ongoing Ghidra analysis"""
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
    
    # Load results from storage
    return {
        "analysis_id": analysis_id,
        "status": status.status,
        "completion_time": status.completion_time,
        "results_available": True,
        "message": "Results available for download"
    }

@app.get("/formats")
async def supported_formats():
    """Get supported binary formats"""
    if not ghidra_analyzer:
        return {"error": "Analyzer not initialized"}
        
    return {
        "supported_formats": ghidra_analyzer.get_supported_formats(),
        "recommended_formats": ["PE", "ELF", "Mach-O"],
        "notes": "Ghidra supports most common binary formats"
    }

@app.post("/cleanup")
async def cleanup_projects(max_age_hours: int = 24):
    """Clean up old Ghidra projects"""
    if not ghidra_analyzer:
        raise HTTPException(status_code=500, detail="Analyzer not initialized")
    
    try:
        ghidra_analyzer.cleanup_old_projects(max_age_hours)
        return {"message": f"Cleaned up projects older than {max_age_hours} hours"}
    except Exception as e:
        logger.error("Cleanup failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/status")
async def get_server_status():
    """Get Ghidra server status"""
    return {
        "status": "running",
        "analyzer_initialized": ghidra_analyzer is not None,
        "active_analyses": len(active_analyses),
        "analyses_completed": len([a for a in active_analyses.values() if a.status == "completed"]),
        "analyses_failed": len([a for a in active_analyses.values() if a.status == "failed"]),
        "timestamp": datetime.now().isoformat()
    }

async def perform_ghidra_analysis(analysis_id: str, binary_path: str, analysis_type: str):
    """Background task for Ghidra analysis"""
    try:
        # Update status
        active_analyses[analysis_id].status = "processing"
        active_analyses[analysis_id].progress = 10.0
        
        logger.info("Starting Ghidra analysis", 
                   analysis_id=analysis_id, 
                   binary_path=binary_path, 
                   analysis_type=analysis_type)
        
        # Perform analysis
        result = await ghidra_analyzer.analyze_binary(binary_path, analysis_type)
        
        # Update progress
        active_analyses[analysis_id].progress = 90.0
        
        if "error" not in result:
            logger.info("Ghidra analysis completed", analysis_id=analysis_id)
            
            active_analyses[analysis_id].status = "completed"
            active_analyses[analysis_id].progress = 100.0
            active_analyses[analysis_id].completion_time = datetime.now().isoformat()
            
            # Store results (in production, save to database/filesystem)
            
        else:
            active_analyses[analysis_id].status = "failed"
            active_analyses[analysis_id].error_message = result["error"]
            logger.error("Ghidra analysis failed", 
                        analysis_id=analysis_id, 
                        error=result["error"])
            
    except Exception as e:
        logger.error("Ghidra analysis exception", analysis_id=analysis_id, error=str(e))
        active_analyses[analysis_id].status = "failed"
        active_analyses[analysis_id].error_message = str(e)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002)