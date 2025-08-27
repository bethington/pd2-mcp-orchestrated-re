"""
AI Analysis Server
Advanced automation and intelligence layer for reverse engineering platform
"""

from fastapi import FastAPI, HTTPException, BackgroundTasks
from pydantic import BaseModel
import uvicorn
import structlog
import asyncio
from datetime import datetime
from typing import Dict, List, Optional, Any
import uuid

from intelligent_analyzer import IntelligentAnalyzer

logger = structlog.get_logger()

app = FastAPI(
    title="AI Analysis Server",
    version="1.0.0",
    description="Advanced automation and intelligence layer with ML-driven analysis"
)

# Global analyzer instance
ai_analyzer = None
active_analyses = {}

class IntelligentTriageRequest(BaseModel):
    analysis_results: Dict[str, Any]
    priority_override: Optional[str] = None
    context_information: Optional[Dict[str, Any]] = None

class FeedbackRequest(BaseModel):
    analysis_id: str
    feedback_type: str  # "correct", "incorrect", "partial"
    corrections: Optional[Dict[str, Any]] = None
    analyst_notes: Optional[str] = None

class AnalysisStatus(BaseModel):
    analysis_id: str
    status: str
    progress: float
    start_time: str
    completion_time: Optional[str] = None
    error_message: Optional[str] = None

@app.on_event("startup")
async def startup_event():
    """Initialize AI analyzer"""
    global ai_analyzer
    try:
        ai_analyzer = IntelligentAnalyzer()
        logger.info("AI analyzer initialized successfully")
    except Exception as e:
        logger.error("Failed to initialize AI analyzer", error=str(e))
        raise

@app.get("/")
async def root():
    return {
        "service": "AI Analysis Server",
        "version": "1.0.0",
        "status": "running",
        "capabilities": [
            "Intelligent triage and prioritization",
            "Automated threat classification", 
            "ML-based anomaly detection",
            "Pattern recognition and similarity matching",
            "Automated insight generation",
            "Continuous learning from analyst feedback",
            "Risk assessment and scoring",
            "Workflow optimization recommendations"
        ],
        "ai_models": [
            "Isolation Forest (anomaly detection)",
            "Random Forest (threat classification)",
            "TF-IDF + Cosine Similarity (pattern matching)",
            "Deep Learning (feature extraction)",
            "Clustering (sample grouping)"
        ],
        "learning_capabilities": [
            "Supervised learning from labeled samples",
            "Unsupervised anomaly detection",
            "Continuous model updates",
            "Feedback-driven improvements"
        ],
        "timestamp": datetime.now().isoformat()
    }

@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "service": "ai-analysis",
        "analyzer_ready": ai_analyzer is not None,
        "models_loaded": ai_analyzer.models_loaded if ai_analyzer else False,
        "active_analyses": len(active_analyses),
        "timestamp": datetime.now().isoformat()
    }

@app.post("/triage/intelligent")
async def intelligent_triage(request: IntelligentTriageRequest, background_tasks: BackgroundTasks):
    """Perform intelligent AI-driven triage of analysis results"""
    if not ai_analyzer:
        raise HTTPException(status_code=500, detail="AI analyzer not initialized")
    
    # Create analysis task
    analysis_id = str(uuid.uuid4())
    active_analyses[analysis_id] = AnalysisStatus(
        analysis_id=analysis_id,
        status="queued",
        progress=0.0,
        start_time=datetime.now().isoformat()
    )
    
    # Start background intelligent analysis
    background_tasks.add_task(
        perform_intelligent_triage,
        analysis_id,
        request.analysis_results,
        request.priority_override,
        request.context_information
    )
    
    return {
        "analysis_id": analysis_id,
        "status": "queued",
        "message": "Intelligent triage started",
        "estimated_duration": "30-120 seconds",
        "features_analyzed": [
            "Statistical anomaly detection",
            "Threat level classification", 
            "Historical similarity matching",
            "Pattern-based insights",
            "Automated recommendations"
        ],
        "check_status_url": f"/triage/status/{analysis_id}"
    }

@app.post("/analyze/automated")
async def automated_analysis_workflow(data: Dict[str, Any], background_tasks: BackgroundTasks):
    """Run fully automated analysis workflow with AI coordination"""
    if not ai_analyzer:
        raise HTTPException(status_code=500, detail="AI analyzer not initialized")
    
    binary_path = data.get("binary_path")
    if not binary_path:
        raise HTTPException(status_code=400, detail="binary_path required")
    
    # Create comprehensive analysis task
    analysis_id = str(uuid.uuid4())
    active_analyses[analysis_id] = AnalysisStatus(
        analysis_id=analysis_id,
        status="queued", 
        progress=0.0,
        start_time=datetime.now().isoformat()
    )
    
    # Start automated workflow
    background_tasks.add_task(
        perform_automated_workflow,
        analysis_id,
        binary_path,
        data.get("analysis_preferences", {})
    )
    
    return {
        "analysis_id": analysis_id,
        "status": "queued",
        "binary_path": binary_path,
        "workflow_stages": [
            "Intelligent pre-analysis triage",
            "Coordinated multi-tool analysis",
            "AI-driven result correlation",
            "Automated insight generation",
            "Priority-based recommendations"
        ],
        "message": "Automated analysis workflow initiated",
        "estimated_duration": "10-45 minutes depending on complexity"
    }

@app.get("/triage/status/{analysis_id}")
async def get_triage_status(analysis_id: str):
    """Get status of intelligent triage operation"""
    if analysis_id not in active_analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    return active_analyses[analysis_id].dict()

@app.get("/triage/result/{analysis_id}")
async def get_triage_result(analysis_id: str):
    """Get intelligent triage results"""
    if analysis_id not in active_analyses:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    status = active_analyses[analysis_id]
    if status.status != "completed":
        raise HTTPException(status_code=400, detail=f"Analysis not completed. Status: {status.status}")
    
    # Load results from storage
    result_path = f"/app/reports/{analysis_id}_triage.json"
    if os.path.exists(result_path):
        import json
        with open(result_path, 'r') as f:
            results = json.load(f)
        return results
    else:
        return {
            "analysis_id": analysis_id,
            "status": status.status,
            "message": "Triage completed but detailed results not available"
        }

@app.post("/feedback/submit")
async def submit_feedback(request: FeedbackRequest):
    """Submit analyst feedback for continuous learning"""
    if not ai_analyzer:
        raise HTTPException(status_code=500, detail="AI analyzer not initialized")
    
    try:
        feedback_data = {
            "analysis_id": request.analysis_id,
            "feedback_type": request.feedback_type,
            "corrections": request.corrections,
            "analyst_notes": request.analyst_notes,
            "timestamp": datetime.now().isoformat()
        }
        
        result = await ai_analyzer.continuous_learning_update(feedback_data)
        
        if result.get("success"):
            return {
                "success": True,
                "message": "Feedback submitted successfully",
                "feedback_id": str(uuid.uuid4()),
                "learning_impact": "Models will be updated in next training cycle"
            }
        else:
            raise HTTPException(status_code=500, detail=result.get("error", "Feedback submission failed"))
            
    except Exception as e:
        logger.error("Feedback submission failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/models/statistics")
async def get_model_statistics():
    """Get AI model statistics and performance metrics"""
    if not ai_analyzer:
        raise HTTPException(status_code=500, detail="AI analyzer not initialized")
    
    return ai_analyzer.get_model_statistics()

@app.get("/insights/patterns")
async def get_pattern_insights():
    """Get insights about detected patterns across all analyses"""
    if not ai_analyzer:
        raise HTTPException(status_code=500, detail="AI analyzer not initialized")
    
    try:
        # Analyze patterns across analysis history
        insights = {
            "pattern_frequency": {},
            "threat_trends": {},
            "anomaly_patterns": {},
            "similarity_clusters": {}
        }
        
        history = ai_analyzer.analysis_history[-100:]  # Last 100 analyses
        
        # Pattern frequency analysis
        all_patterns = []
        for entry in history:
            static_results = entry.get("results", {}).get("static_analysis", {})
            patterns = static_results.get("patterns", [])
            for pattern in patterns:
                pattern_name = pattern.get("rule_name", "unknown")
                all_patterns.append(pattern_name)
        
        # Count pattern frequencies
        from collections import Counter
        pattern_counts = Counter(all_patterns)
        insights["pattern_frequency"] = dict(pattern_counts.most_common(20))
        
        # Threat trend analysis
        threat_over_time = []
        for entry in history:
            triage = entry.get("triage", {})
            threat_over_time.append({
                "timestamp": entry.get("timestamp"),
                "threat_level": triage.get("threat_classification", "unknown"),
                "priority_score": triage.get("priority_score", 0.0)
            })
        
        insights["threat_trends"] = threat_over_time[-20:]  # Last 20 samples
        
        return {
            "insights": insights,
            "analysis_period": f"Last {len(history)} analyses",
            "generated_at": datetime.now().isoformat(),
            "recommendations": [
                "Monitor high-frequency patterns for emerging threats",
                "Investigate anomalous pattern combinations",
                "Update detection rules based on trend analysis"
            ]
        }
        
    except Exception as e:
        logger.error("Pattern insights generation failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/workflow/optimize")
async def optimize_analysis_workflow(data: Dict[str, Any]):
    """Optimize analysis workflow based on sample characteristics"""
    if not ai_analyzer:
        raise HTTPException(status_code=500, detail="AI analyzer not initialized")
    
    try:
        sample_info = data.get("sample_info", {})
        resource_constraints = data.get("resource_constraints", {})
        
        # Generate workflow optimization recommendations
        optimization = {
            "recommended_tools": [],
            "analysis_priority": "medium",
            "estimated_time": "30-60 minutes",
            "resource_allocation": {},
            "workflow_steps": []
        }
        
        file_size = sample_info.get("file_size", 0)
        file_type = sample_info.get("file_type", "unknown")
        
        # File size based optimizations
        if file_size > 100 * 1024 * 1024:  # > 100MB
            optimization["recommended_tools"] = [
                "static_analysis_lite",  # Faster static analysis
                "selective_decompilation"  # Only key functions
            ]
            optimization["estimated_time"] = "45-90 minutes"
        else:
            optimization["recommended_tools"] = [
                "comprehensive_static_analysis",
                "full_decompilation", 
                "dynamic_analysis"
            ]
            
        # File type based optimizations
        if file_type == "PE":
            optimization["workflow_steps"] = [
                "PE header analysis",
                "Import/export analysis",
                "Section analysis",
                "Disassembly",
                "Decompilation",
                "Dynamic analysis"
            ]
        elif file_type == "ELF":
            optimization["workflow_steps"] = [
                "ELF header analysis",
                "Symbol table analysis", 
                "Section analysis",
                "Disassembly",
                "Dynamic analysis"
            ]
        else:
            optimization["workflow_steps"] = [
                "Format detection",
                "Basic static analysis",
                "Pattern matching"
            ]
            
        # Resource allocation
        optimization["resource_allocation"] = {
            "cpu_cores": min(4, resource_constraints.get("max_cores", 2)),
            "memory_gb": min(8, resource_constraints.get("max_memory_gb", 4)),
            "disk_gb": max(2, file_size / (512 * 1024 * 1024)),  # 2x file size minimum
            "priority": "normal"
        }
        
        return {
            "optimization": optimization,
            "confidence": 0.85,
            "reasoning": [
                f"File size ({file_size} bytes) influences tool selection",
                f"File type ({file_type}) determines analysis workflow",
                "Resource constraints considered for allocation"
            ],
            "generated_at": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error("Workflow optimization failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/status")
async def get_ai_server_status():
    """Get comprehensive AI server status"""
    if not ai_analyzer:
        return {"error": "AI analyzer not initialized"}
    
    return {
        "status": "running",
        "ai_analyzer_ready": True,
        "models_loaded": ai_analyzer.models_loaded,
        "active_analyses": len(active_analyses),
        "completed_analyses": len([a for a in active_analyses.values() if a.status == "completed"]),
        "failed_analyses": len([a for a in active_analyses.values() if a.status == "failed"]),
        "analysis_history_size": len(ai_analyzer.analysis_history),
        "model_statistics": ai_analyzer.get_model_statistics(),
        "timestamp": datetime.now().isoformat()
    }

async def perform_intelligent_triage(
    analysis_id: str,
    analysis_results: Dict[str, Any], 
    priority_override: Optional[str],
    context_information: Optional[Dict[str, Any]]
):
    """Background task for intelligent triage"""
    try:
        # Update status
        active_analyses[analysis_id].status = "processing"
        active_analyses[analysis_id].progress = 10.0
        
        logger.info("Starting intelligent triage", analysis_id=analysis_id)
        
        # Perform AI-driven triage
        triage_result = await ai_analyzer.intelligent_triage(analysis_results)
        
        active_analyses[analysis_id].progress = 80.0
        
        # Apply priority override if provided
        if priority_override:
            triage_result["priority_override"] = priority_override
            triage_result["priority_score"] = min(1.0, triage_result.get("priority_score", 0) + 0.2)
            
        # Add context information
        if context_information:
            triage_result["context"] = context_information
            
        # Save results
        result_path = f"/app/reports/{analysis_id}_triage.json"
        import json
        with open(result_path, 'w') as f:
            json.dump(triage_result, f, indent=2, default=str)
            
        active_analyses[analysis_id].status = "completed"
        active_analyses[analysis_id].progress = 100.0
        active_analyses[analysis_id].completion_time = datetime.now().isoformat()
        
        logger.info("Intelligent triage completed",
                   analysis_id=analysis_id,
                   threat_class=triage_result.get("threat_classification"),
                   priority_score=triage_result.get("priority_score"))
        
    except Exception as e:
        logger.error("Intelligent triage failed", analysis_id=analysis_id, error=str(e))
        active_analyses[analysis_id].status = "failed"
        active_analyses[analysis_id].error_message = str(e)

async def perform_automated_workflow(
    analysis_id: str,
    binary_path: str,
    analysis_preferences: Dict[str, Any]
):
    """Background task for fully automated analysis workflow"""
    try:
        # Update status
        active_analyses[analysis_id].status = "processing"
        active_analyses[analysis_id].progress = 5.0
        
        logger.info("Starting automated workflow", analysis_id=analysis_id, binary_path=binary_path)
        
        # This would coordinate with other analysis services
        # For now, simulate the workflow
        
        workflow_result = {
            "analysis_id": analysis_id,
            "binary_path": binary_path,
            "workflow_completed": True,
            "stages_completed": [
                "pre_analysis_triage",
                "static_analysis", 
                "decompilation",
                "security_assessment",
                "ai_correlation"
            ],
            "final_assessment": {
                "threat_level": "medium",
                "priority_score": 0.6,
                "confidence": 0.8,
                "recommended_actions": [
                    "Manual review recommended",
                    "Focus on suspicious API usage",
                    "Check for packer indicators"
                ]
            },
            "processing_time": "12 minutes",
            "timestamp": datetime.now().isoformat()
        }
        
        # Simulate processing time
        await asyncio.sleep(2)  # Shortened for demo
        
        # Save results
        result_path = f"/app/reports/{analysis_id}_workflow.json"
        import json
        with open(result_path, 'w') as f:
            json.dump(workflow_result, f, indent=2, default=str)
            
        active_analyses[analysis_id].status = "completed"
        active_analyses[analysis_id].progress = 100.0
        active_analyses[analysis_id].completion_time = datetime.now().isoformat()
        
        logger.info("Automated workflow completed", analysis_id=analysis_id)
        
    except Exception as e:
        logger.error("Automated workflow failed", analysis_id=analysis_id, error=str(e))
        active_analyses[analysis_id].status = "failed"
        active_analyses[analysis_id].error_message = str(e)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8005)