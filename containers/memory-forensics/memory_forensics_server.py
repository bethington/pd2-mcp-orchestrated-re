"""
Memory Forensics Server
Advanced memory analysis and forensics service
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks, UploadFile, File
from pydantic import BaseModel
import uvicorn
import structlog
import asyncio
import os
import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any

from advanced_memory_analyzer import AdvancedMemoryAnalyzer

logger = structlog.get_logger()

app = FastAPI(
    title="Advanced Memory Forensics Server",
    version="1.0.0",
    description="Comprehensive memory analysis and forensics platform"
)

# Global analyzer instance
memory_analyzer = None
active_analyses = {}

class MemoryDumpRequest(BaseModel):
    pid: int
    dump_name: Optional[str] = None
    include_analysis: bool = True

class DumpAnalysisRequest(BaseModel):
    dump_path: str
    analysis_depth: str = "comprehensive"  # basic, detailed, comprehensive

class AnalysisStatus(BaseModel):
    analysis_id: str
    status: str  # queued, processing, completed, failed
    progress: float
    start_time: str
    completion_time: Optional[str] = None
    error_message: Optional[str] = None

@app.on_event("startup")
async def startup_event():
    """Initialize memory analyzer"""
    global memory_analyzer
    try:
        memory_analyzer = AdvancedMemoryAnalyzer()
        logger.info("Memory forensics analyzer initialized successfully")
    except Exception as e:
        logger.error("Failed to initialize memory analyzer", error=str(e))
        raise

@app.get("/")
async def root():
    return {
        "service": "Advanced Memory Forensics Server",
        "version": "1.0.0",
        "status": "running",
        "capabilities": [
            "Full process memory dumping",
            "Memory dump analysis and forensics",
            "Heap structure analysis and corruption detection",
            "Data structure recovery from memory",
            "Memory pattern recognition and classification",
            "Entropy analysis and anomaly detection",
            "Memory corruption and exploit detection",
            "Live memory monitoring and analysis"
        ],
        "supported_platforms": ["Linux", "Windows (limited)"],
        "analysis_engines": [
            "Advanced pattern matching",
            "Structure template matching",
            "Heap metadata analysis",
            "Corruption detection algorithms",
            "Statistical entropy analysis"
        ],
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "memory-forensics",
        "analyzer_ready": memory_analyzer is not None,
        "active_analyses": len(active_analyses),
        "disk_space_available": self._get_disk_space(),
        "timestamp": datetime.now().isoformat()
    }

def _get_disk_space():
    """Get available disk space for dumps"""
    try:
        import shutil
        total, used, free = shutil.disk_usage("/app/dumps")
        return {
            "total_gb": total / (1024**3),
            "free_gb": free / (1024**3),
            "used_gb": used / (1024**3),
            "free_percentage": (free / total) * 100
        }
    except Exception:
        return {"error": "Unable to determine disk space"}

@app.post("/dump/create")
async def create_memory_dump(request: MemoryDumpRequest, background_tasks: BackgroundTasks):
    """Create full memory dump of process"""
    if not memory_analyzer:
        raise HTTPException(status_code=500, detail="Memory analyzer not initialized")
    
    # Generate dump filename
    dump_name = request.dump_name or f"memory_dump_{request.pid}_{int(datetime.now().timestamp())}"
    dump_path = f"/app/dumps/{dump_name}.dump"
    
    # Create analysis task
    analysis_id = str(uuid.uuid4())
    active_analyses[analysis_id] = AnalysisStatus(
        analysis_id=analysis_id,
        status="queued",
        progress=0.0,
        start_time=datetime.now().isoformat()
    )
    
    # Start background dump creation
    background_tasks.add_task(
        perform_memory_dump,
        analysis_id,
        request.pid,
        dump_path,
        request.include_analysis
    )
    
    return {
        "analysis_id": analysis_id,
        "status": "queued",
        "pid": request.pid,
        "dump_path": dump_path,
        "message": "Memory dump creation started",
        "estimated_duration": "5-30 minutes depending on process size",
        "check_status_url": f"/dump/status/{analysis_id}"
    }

@app.post("/analyze/dump")
async def analyze_existing_dump(request: DumpAnalysisRequest, background_tasks: BackgroundTasks):
    """Analyze existing memory dump file"""
    if not memory_analyzer:
        raise HTTPException(status_code=500, detail="Memory analyzer not initialized")
    
    if not os.path.exists(request.dump_path):
        raise HTTPException(status_code=404, detail=f"Dump file not found: {request.dump_path}")
    
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
        perform_dump_analysis,
        analysis_id,
        request.dump_path,
        request.analysis_depth
    )
    
    return {
        "analysis_id": analysis_id,
        "status": "queued",
        "dump_path": request.dump_path,
        "analysis_depth": request.analysis_depth,
        "message": "Memory dump analysis started",
        "check_status_url": f"/dump/status/{analysis_id}"
    }

@app.post("/analyze/upload")
async def analyze_uploaded_dump(
    file: UploadFile = File(...),
    analysis_depth: str = "comprehensive",
    background_tasks: BackgroundTasks = None
):
    """Analyze uploaded memory dump file"""
    if not memory_analyzer:
        raise HTTPException(status_code=500, detail="Memory analyzer not initialized")
    
    # Save uploaded file
    upload_id = str(uuid.uuid4())
    dump_path = f"/app/dumps/upload_{upload_id}_{file.filename}"
    
    try:
        with open(dump_path, "wb") as buffer:
            content = await file.read()
            buffer.write(content)
            
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
            perform_dump_analysis,
            analysis_id,
            dump_path,
            analysis_depth
        )
        
        return {
            "analysis_id": analysis_id,
            "status": "queued",
            "uploaded_file": file.filename,
            "dump_path": dump_path,
            "file_size": len(content),
            "message": "Uploaded dump analysis started",
            "check_status_url": f"/dump/status/{analysis_id}"
        }
        
    except Exception as e:
        logger.error("Failed to process uploaded dump", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/dump/status/{analysis_id}")
async def get_dump_status(analysis_id: str):
    """Get status of memory dump/analysis operation"""
    if analysis_id not in active_analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    return active_analyses[analysis_id].dict()

@app.get("/dump/result/{analysis_id}")
async def get_dump_result(analysis_id: str):
    """Get completed dump analysis results"""
    if analysis_id not in active_analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    status = active_analyses[analysis_id]
    if status.status != "completed":
        raise HTTPException(status_code=400, detail=f"Analysis not completed. Status: {status.status}")
    
    # Load results from storage
    result_path = f"/app/reports/{analysis_id}_results.json"
    if os.path.exists(result_path):
        import json
        with open(result_path, 'r') as f:
            results = json.load(f)
        return results
    else:
        return {
            "analysis_id": analysis_id,
            "status": status.status,
            "completion_time": status.completion_time,
            "message": "Results processing completed but detailed results not available"
        }

@app.get("/patterns/known")
async def get_known_patterns():
    """Get list of known memory patterns for detection"""
    if not memory_analyzer:
        raise HTTPException(status_code=500, detail="Memory analyzer not initialized")
    
    return {
        "binary_signatures": list(memory_analyzer.known_patterns.keys()),
        "structure_templates": list(memory_analyzer.structure_templates.keys()),
        "corruption_patterns": [
            "buffer_overflow",
            "use_after_free", 
            "heap_spray",
            "stack_smash",
            "double_free",
            "heap_overflow"
        ],
        "game_specific_patterns": [
            "d2_character",
            "d2_inventory_item",
            "d2_save_structure"
        ]
    }

@app.post("/patterns/add")
async def add_custom_pattern(data: Dict[str, Any]):
    """Add custom pattern for detection"""
    if not memory_analyzer:
        raise HTTPException(status_code=500, detail="Memory analyzer not initialized")
    
    required_fields = ["pattern_name", "pattern_bytes"]
    for field in required_fields:
        if field not in data:
            raise HTTPException(status_code=400, detail=f"Missing required field: {field}")
    
    try:
        pattern_name = data["pattern_name"]
        pattern_bytes = bytes.fromhex(data["pattern_bytes"])
        
        memory_analyzer.known_patterns[pattern_name] = pattern_bytes
        
        return {
            "success": True,
            "pattern_name": pattern_name,
            "pattern_size": len(pattern_bytes),
            "message": f"Pattern '{pattern_name}' added successfully"
        }
        
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid pattern data: {str(e)}")

@app.get("/dumps/list")
async def list_available_dumps():
    """List available memory dumps"""
    dumps = []
    dumps_dir = "/app/dumps"
    
    try:
        if os.path.exists(dumps_dir):
            for filename in os.listdir(dumps_dir):
                if filename.endswith('.dump'):
                    filepath = os.path.join(dumps_dir, filename)
                    stat = os.stat(filepath)
                    
                    dumps.append({
                        "filename": filename,
                        "filepath": filepath,
                        "size_bytes": stat.st_size,
                        "size_mb": stat.st_size / (1024 * 1024),
                        "created_time": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                        "modified_time": datetime.fromtimestamp(stat.st_mtime).isoformat()
                    })
    except Exception as e:
        logger.error("Failed to list dumps", error=str(e))
    
    return {
        "dumps": sorted(dumps, key=lambda x: x["created_time"], reverse=True),
        "total_dumps": len(dumps),
        "total_size_mb": sum(d["size_mb"] for d in dumps)
    }

@app.delete("/dumps/{filename}")
async def delete_dump(filename: str):
    """Delete memory dump file"""
    dump_path = f"/app/dumps/{filename}"
    
    if not os.path.exists(dump_path):
        raise HTTPException(status_code=404, detail="Dump file not found")
    
    try:
        file_size = os.path.getsize(dump_path)
        os.remove(dump_path)
        
        return {
            "success": True,
            "filename": filename,
            "size_freed_mb": file_size / (1024 * 1024),
            "message": f"Dump file '{filename}' deleted successfully"
        }
        
    except Exception as e:
        logger.error("Failed to delete dump", filename=filename, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/capabilities/detailed")
async def get_detailed_capabilities():
    """Get comprehensive capabilities information"""
    return {
        "memory_dumping": {
            "methods": ["GDB core dump", "/proc/mem reading", "ptrace-based"],
            "platforms": ["Linux (full support)", "Windows (limited)"],
            "dump_formats": ["Raw memory", "Core dump", "Custom format"],
            "max_process_size": "Limited by available disk space"
        },
        "analysis_capabilities": {
            "pattern_recognition": "50+ built-in patterns, custom patterns supported",
            "structure_detection": "Template-based matching with confidence scoring",
            "heap_analysis": "Chunk analysis, fragmentation detection, corruption indicators",
            "entropy_analysis": "Shannon entropy, anomaly detection, encryption identification",
            "corruption_detection": "Buffer overflow, use-after-free, heap spray detection"
        },
        "forensics_features": {
            "timeline_reconstruction": "Memory allocation timelines",
            "artifact_recovery": "File fragments, network data, encryption keys",
            "malware_detection": "Signature-based and heuristic analysis",
            "exploit_analysis": "Shellcode detection, ROP chain identification"
        },
        "performance_characteristics": {
            "dump_speed": "50-200 MB/s depending on method",
            "analysis_speed": "10-50 MB/s for comprehensive analysis",
            "memory_usage": "2-4x dump size for comprehensive analysis",
            "concurrent_analyses": "Limited by available RAM and CPU"
        }
    }

@app.get("/statistics")
async def get_server_statistics():
    """Get server performance and usage statistics"""
    return {
        "service_status": {
            "uptime": "running",  # Could track actual uptime
            "analyzer_ready": memory_analyzer is not None,
            "active_analyses": len(active_analyses),
            "completed_analyses": len([a for a in active_analyses.values() if a.status == "completed"]),
            "failed_analyses": len([a for a in active_analyses.values() if a.status == "failed"])
        },
        "storage_usage": _get_disk_space(),
        "analysis_statistics": {
            "total_patterns_available": len(memory_analyzer.known_patterns) if memory_analyzer else 0,
            "structure_templates_loaded": len(memory_analyzer.structure_templates) if memory_analyzer else 0
        },
        "timestamp": datetime.now().isoformat()
    }

async def perform_memory_dump(analysis_id: str, pid: int, dump_path: str, include_analysis: bool):
    """Background task to create memory dump"""
    try:
        # Update status
        active_analyses[analysis_id].status = "processing"
        active_analyses[analysis_id].progress = 10.0
        
        logger.info("Starting memory dump", analysis_id=analysis_id, pid=pid)
        
        # Create memory dump
        dump_result = await memory_analyzer.create_full_memory_dump(pid, dump_path)
        
        active_analyses[analysis_id].progress = 50.0
        
        if dump_result.get("success"):
            # Optionally perform immediate analysis
            if include_analysis:
                logger.info("Starting dump analysis", analysis_id=analysis_id)
                
                analysis_result = await memory_analyzer.analyze_memory_dump(dump_path)
                active_analyses[analysis_id].progress = 90.0
                
                # Save results
                result_path = f"/app/reports/{analysis_id}_results.json"
                import json
                with open(result_path, 'w') as f:
                    json.dump({
                        "dump_result": dump_result,
                        "analysis_result": analysis_result
                    }, f, indent=2, default=str)
            
            active_analyses[analysis_id].status = "completed"
            active_analyses[analysis_id].progress = 100.0
            active_analyses[analysis_id].completion_time = datetime.now().isoformat()
            
            logger.info("Memory dump completed", analysis_id=analysis_id, dump_path=dump_path)
            
        else:
            active_analyses[analysis_id].status = "failed"
            active_analyses[analysis_id].error_message = dump_result.get("error", "Unknown error")
            
    except Exception as e:
        logger.error("Memory dump failed", analysis_id=analysis_id, error=str(e))
        active_analyses[analysis_id].status = "failed"
        active_analyses[analysis_id].error_message = str(e)

async def perform_dump_analysis(analysis_id: str, dump_path: str, analysis_depth: str):
    """Background task to analyze memory dump"""
    try:
        # Update status
        active_analyses[analysis_id].status = "processing"
        active_analyses[analysis_id].progress = 10.0
        
        logger.info("Starting dump analysis", analysis_id=analysis_id, dump_path=dump_path)
        
        # Analyze dump
        analysis_result = await memory_analyzer.analyze_memory_dump(dump_path)
        
        active_analyses[analysis_id].progress = 90.0
        
        if "error" not in analysis_result:
            # Save results
            result_path = f"/app/reports/{analysis_id}_results.json"
            import json
            with open(result_path, 'w') as f:
                json.dump(analysis_result, f, indent=2, default=str)
            
            active_analyses[analysis_id].status = "completed"
            active_analyses[analysis_id].progress = 100.0
            active_analyses[analysis_id].completion_time = datetime.now().isoformat()
            
            logger.info("Dump analysis completed", analysis_id=analysis_id)
            
        else:
            active_analyses[analysis_id].status = "failed"
            active_analyses[analysis_id].error_message = analysis_result["error"]
            
    except Exception as e:
        logger.error("Dump analysis failed", analysis_id=analysis_id, error=str(e))
        active_analyses[analysis_id].status = "failed"
        active_analyses[analysis_id].error_message = str(e)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8004)