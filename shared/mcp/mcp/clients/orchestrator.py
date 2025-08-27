"""
Main MCP orchestration logic for coordinating analysis tools
"""

import asyncio
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass
from enum import Enum
import structlog
from datetime import datetime

from .mcp_client import MCPClient, MCPClientPool
from ..core.session_manager import SessionManager
from ..core.event_bus import EventBus
from ..core.security import SecurityManager, SecurityLevel

logger = structlog.get_logger()

class AnalysisPhase(Enum):
    """Analysis phases for orchestration"""
    INITIALIZATION = "initialization"
    STATIC_ANALYSIS = "static_analysis"
    DYNAMIC_ANALYSIS = "dynamic_analysis"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    CORRELATION = "correlation"
    REPORTING = "reporting"
    COMPLETED = "completed"

@dataclass
class AnalysisTask:
    """Represents an analysis task"""
    task_id: str
    phase: AnalysisPhase
    tool_name: str
    arguments: Dict[str, Any]
    dependencies: List[str]
    priority: int
    timeout: int
    retry_count: int
    max_retries: int

class AnalysisOrchestrator:
    """Orchestrates analysis across multiple MCP servers"""
    
    def __init__(self, session_manager: SessionManager, event_bus: EventBus, security_manager: SecurityManager):
        self.session_manager = session_manager
        self.event_bus = event_bus
        self.security_manager = security_manager
        self.client_pool = MCPClientPool()
        
        # Analysis state
        self.active_analyses = {}
        self.task_queue = asyncio.Queue()
        self.completed_tasks = {}
        self.failed_tasks = {}
        
        # Orchestration config
        self.max_concurrent_tasks = 5
        self.default_timeout = 300  # 5 minutes
        self.task_workers = []
        
        # Initialize servers
        self._initialize_default_servers()
        
    def _initialize_default_servers(self):
        """Initialize default MCP server connections"""
        default_servers = [
            ("d2_analysis", "http://localhost:8765", True),
            ("ghidra", "http://localhost:8766", False),
            ("windbg", "http://localhost:8767", False),
            ("network", "http://localhost:8768", False),
            ("dgraph", "http://localhost:8769", False)
        ]
        
        for server_id, url, is_default in default_servers:
            self.client_pool.add_client(server_id, url, is_default)
    
    async def start(self):
        """Start the orchestration service"""
        logger.info("Starting analysis orchestrator...")
        
        try:
            # Connect to all MCP servers
            await self.client_pool.connect_all()
            
            # Start task workers
            for i in range(self.max_concurrent_tasks):
                worker = asyncio.create_task(self._task_worker(f"worker_{i}"))
                self.task_workers.append(worker)
            
            # Subscribe to events
            await self.event_bus.subscribe("analysis_request", self._handle_analysis_request)
            await self.event_bus.subscribe("tool_result", self._handle_tool_result)
            await self.event_bus.subscribe("session_ended", self._handle_session_ended)
            
            logger.info("Analysis orchestrator started successfully")
            
        except Exception as e:
            logger.error(f"Failed to start orchestrator: {e}")
            raise
    
    async def stop(self):
        """Stop the orchestration service"""
        logger.info("Stopping analysis orchestrator...")
        
        # Cancel all worker tasks
        for worker in self.task_workers:
            worker.cancel()
        
        # Wait for workers to finish
        await asyncio.gather(*self.task_workers, return_exceptions=True)
        
        # Disconnect from servers
        await self.client_pool.disconnect_all()
        
        logger.info("Analysis orchestrator stopped")
    
    async def submit_analysis_request(self, session_id: str, analysis_config: Dict[str, Any]) -> str:
        """Submit a new analysis request"""
        # Create analysis plan
        analysis_id = f"analysis_{session_id}_{int(datetime.now().timestamp())}"
        
        # Get security context
        security_context = self.security_manager.active_contexts.get(session_id)
        if not security_context:
            security_context = self.security_manager.create_security_context(session_id)
        
        # Create analysis plan
        analysis_plan = await self._create_analysis_plan(analysis_id, session_id, analysis_config)
        
        self.active_analyses[analysis_id] = {
            "session_id": session_id,
            "config": analysis_config,
            "plan": analysis_plan,
            "status": "queued",
            "start_time": datetime.now(),
            "current_phase": AnalysisPhase.INITIALIZATION,
            "results": {},
            "security_context": security_context
        }
        
        # Queue initial tasks
        await self._queue_phase_tasks(analysis_id, AnalysisPhase.INITIALIZATION)
        
        # Publish event
        await self.event_bus.publish("analysis_started", {
            "analysis_id": analysis_id,
            "session_id": session_id,
            "config": analysis_config
        })
        
        logger.info(f"Analysis request submitted: {analysis_id}")
        return analysis_id
    
    async def get_analysis_status(self, analysis_id: str) -> Dict[str, Any]:
        """Get the status of an analysis"""
        if analysis_id not in self.active_analyses:
            return {"error": "Analysis not found"}
        
        analysis = self.active_analyses[analysis_id]
        
        # Calculate progress
        total_tasks = len(analysis["plan"])
        completed_tasks = len([t for t in analysis["plan"] if t.task_id in self.completed_tasks])
        progress = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
        
        return {
            "analysis_id": analysis_id,
            "status": analysis["status"],
            "current_phase": analysis["current_phase"].value,
            "progress_percent": progress,
            "start_time": analysis["start_time"].isoformat(),
            "completed_tasks": completed_tasks,
            "total_tasks": total_tasks,
            "results_preview": self._get_results_preview(analysis_id)
        }
    
    async def cancel_analysis(self, analysis_id: str) -> bool:
        """Cancel a running analysis"""
        if analysis_id not in self.active_analyses:
            return False
        
        analysis = self.active_analyses[analysis_id]
        analysis["status"] = "cancelled"
        
        # Cancel pending tasks
        # Note: This is a simplified implementation
        logger.info(f"Analysis cancelled: {analysis_id}")
        
        await self.event_bus.publish("analysis_cancelled", {
            "analysis_id": analysis_id
        })
        
        return True
    
    async def _create_analysis_plan(self, analysis_id: str, session_id: str, config: Dict[str, Any]) -> List[AnalysisTask]:
        """Create an analysis execution plan"""
        tasks = []
        task_counter = 0
        
        # Analysis goals determine the phases to execute
        goals = config.get("analysis_goals", ["general"])
        
        # Phase 1: Initialization
        tasks.append(AnalysisTask(
            task_id=f"{analysis_id}_task_{task_counter}",
            phase=AnalysisPhase.INITIALIZATION,
            tool_name="initialize_analysis_session",
            arguments={"session_id": session_id, "config": config},
            dependencies=[],
            priority=1,
            timeout=60,
            retry_count=0,
            max_retries=2
        ))
        task_counter += 1
        
        # Phase 2: Static Analysis (if applicable)
        if "static" in goals or "comprehensive" in goals:
            tasks.append(AnalysisTask(
                task_id=f"{analysis_id}_task_{task_counter}",
                phase=AnalysisPhase.STATIC_ANALYSIS,
                tool_name="analyze_binary_structure",
                arguments={"binary_path": config.get("binary_path", "")},
                dependencies=[tasks[0].task_id],
                priority=2,
                timeout=600,
                retry_count=0,
                max_retries=1
            ))
            task_counter += 1
        
        # Phase 3: Dynamic Analysis
        if "dynamic" in goals or "comprehensive" in goals or "security" in goals:
            tasks.append(AnalysisTask(
                task_id=f"{analysis_id}_task_{task_counter}",
                phase=AnalysisPhase.DYNAMIC_ANALYSIS,
                tool_name="start_dynamic_monitoring",
                arguments={"session_id": session_id},
                dependencies=[tasks[0].task_id],
                priority=2,
                timeout=self.default_timeout,
                retry_count=0,
                max_retries=2
            ))
            task_counter += 1
            
            # Memory analysis
            tasks.append(AnalysisTask(
                task_id=f"{analysis_id}_task_{task_counter}",
                phase=AnalysisPhase.DYNAMIC_ANALYSIS,
                tool_name="analyze_memory_structures",
                arguments={"session_id": session_id, "depth": "comprehensive"},
                dependencies=[tasks[-1].task_id],
                priority=3,
                timeout=300,
                retry_count=0,
                max_retries=1
            ))
            task_counter += 1
        
        # Phase 4: Behavioral Analysis
        if "behavioral" in goals or "cheat_detection" in goals or "comprehensive" in goals:
            tasks.append(AnalysisTask(
                task_id=f"{analysis_id}_task_{task_counter}",
                phase=AnalysisPhase.BEHAVIORAL_ANALYSIS,
                tool_name="analyze_behavior_patterns",
                arguments={"session_id": session_id},
                dependencies=[t.task_id for t in tasks if t.phase == AnalysisPhase.DYNAMIC_ANALYSIS],
                priority=4,
                timeout=600,
                retry_count=0,
                max_retries=1
            ))
            task_counter += 1
        
        # Phase 5: Network Analysis
        if "network" in goals or "security" in goals or "comprehensive" in goals:
            tasks.append(AnalysisTask(
                task_id=f"{analysis_id}_task_{task_counter}",
                phase=AnalysisPhase.DYNAMIC_ANALYSIS,
                tool_name="analyze_network_traffic",
                arguments={"session_id": session_id},
                dependencies=[tasks[0].task_id],
                priority=3,
                timeout=300,
                retry_count=0,
                max_retries=1
            ))
            task_counter += 1
        
        # Phase 6: Correlation
        correlation_deps = [t.task_id for t in tasks if t.phase != AnalysisPhase.INITIALIZATION]
        if correlation_deps:
            tasks.append(AnalysisTask(
                task_id=f"{analysis_id}_task_{task_counter}",
                phase=AnalysisPhase.CORRELATION,
                tool_name="correlate_analysis_results",
                arguments={"session_id": session_id, "analysis_id": analysis_id},
                dependencies=correlation_deps,
                priority=5,
                timeout=300,
                retry_count=0,
                max_retries=1
            ))
            task_counter += 1
        
        # Phase 7: Reporting
        tasks.append(AnalysisTask(
            task_id=f"{analysis_id}_task_{task_counter}",
            phase=AnalysisPhase.REPORTING,
            tool_name="generate_analysis_report",
            arguments={
                "session_id": session_id,
                "analysis_id": analysis_id,
                "report_type": config.get("report_type", "comprehensive")
            },
            dependencies=[t.task_id for t in tasks if t.phase == AnalysisPhase.CORRELATION] or [tasks[-1].task_id],
            priority=6,
            timeout=120,
            retry_count=0,
            max_retries=2
        ))
        
        return tasks
    
    async def _queue_phase_tasks(self, analysis_id: str, phase: AnalysisPhase):
        """Queue tasks for a specific analysis phase"""
        analysis = self.active_analyses[analysis_id]
        phase_tasks = [t for t in analysis["plan"] if t.phase == phase]
        
        for task in phase_tasks:
            # Check if dependencies are satisfied
            if self._are_dependencies_satisfied(task.dependencies):
                await self.task_queue.put((analysis_id, task))
                logger.debug(f"Queued task {task.task_id} for phase {phase.value}")
    
    def _are_dependencies_satisfied(self, dependencies: List[str]) -> bool:
        """Check if all task dependencies are satisfied"""
        return all(dep in self.completed_tasks for dep in dependencies)
    
    async def _task_worker(self, worker_id: str):
        """Worker coroutine for executing analysis tasks"""
        logger.info(f"Task worker {worker_id} started")
        
        try:
            while True:
                # Get next task from queue
                analysis_id, task = await self.task_queue.get()
                
                try:
                    await self._execute_task(analysis_id, task)
                except Exception as e:
                    logger.error(f"Task execution failed: {task.task_id}: {e}")
                    await self._handle_task_failure(analysis_id, task, str(e))
                finally:
                    self.task_queue.task_done()
                    
        except asyncio.CancelledError:
            logger.info(f"Task worker {worker_id} cancelled")
        except Exception as e:
            logger.error(f"Task worker {worker_id} error: {e}")
    
    async def _execute_task(self, analysis_id: str, task: AnalysisTask):
        """Execute a single analysis task"""
        analysis = self.active_analyses[analysis_id]
        
        if analysis["status"] == "cancelled":
            return
        
        logger.info(f"Executing task: {task.task_id} ({task.tool_name})")
        
        # Determine which MCP client to use based on tool
        client_id = self._get_client_for_tool(task.tool_name)
        client = self.client_pool.get_client(client_id)
        
        try:
            # Execute the tool
            start_time = datetime.now()
            result = await asyncio.wait_for(
                client.call_tool(task.tool_name, task.arguments),
                timeout=task.timeout
            )
            
            execution_time = (datetime.now() - start_time).total_seconds()
            
            # Store result
            self.completed_tasks[task.task_id] = {
                "task": task,
                "result": result,
                "execution_time": execution_time,
                "timestamp": datetime.now()
            }
            
            # Update analysis results
            analysis["results"][task.task_id] = result
            
            logger.info(f"Task completed: {task.task_id} ({execution_time:.2f}s)")
            
            # Check if we can queue next phase tasks
            await self._check_phase_completion(analysis_id)
            
        except asyncio.TimeoutError:
            raise Exception(f"Task timed out after {task.timeout} seconds")
        except Exception as e:
            raise Exception(f"Task execution failed: {str(e)}")
    
    async def _handle_task_failure(self, analysis_id: str, task: AnalysisTask, error_message: str):
        """Handle task execution failure"""
        task.retry_count += 1
        
        if task.retry_count <= task.max_retries:
            logger.warning(f"Retrying task {task.task_id} (attempt {task.retry_count}/{task.max_retries})")
            await self.task_queue.put((analysis_id, task))
        else:
            logger.error(f"Task failed permanently: {task.task_id}: {error_message}")
            
            self.failed_tasks[task.task_id] = {
                "task": task,
                "error": error_message,
                "timestamp": datetime.now()
            }
            
            # Check if analysis should be aborted
            await self._check_analysis_failure(analysis_id)
    
    async def _check_phase_completion(self, analysis_id: str):
        """Check if current phase is complete and advance to next phase"""
        analysis = self.active_analyses[analysis_id]
        current_phase = analysis["current_phase"]
        
        # Get tasks for current phase
        phase_tasks = [t for t in analysis["plan"] if t.phase == current_phase]
        completed_phase_tasks = [t for t in phase_tasks if t.task_id in self.completed_tasks]
        
        # Check if phase is complete
        if len(completed_phase_tasks) == len(phase_tasks):
            # Advance to next phase
            next_phase = self._get_next_phase(current_phase)
            
            if next_phase:
                analysis["current_phase"] = next_phase
                await self._queue_phase_tasks(analysis_id, next_phase)
                logger.info(f"Analysis {analysis_id} advanced to phase: {next_phase.value}")
            else:
                # Analysis is complete
                analysis["status"] = "completed"
                analysis["end_time"] = datetime.now()
                
                await self.event_bus.publish("analysis_completed", {
                    "analysis_id": analysis_id,
                    "session_id": analysis["session_id"],
                    "results": analysis["results"]
                })
                
                logger.info(f"Analysis completed: {analysis_id}")
    
    async def _check_analysis_failure(self, analysis_id: str):
        """Check if analysis should be failed due to critical task failures"""
        analysis = self.active_analyses[analysis_id]
        
        # Count critical failures
        critical_failures = 0
        for task_id, failure in self.failed_tasks.items():
            if task_id.startswith(analysis_id) and failure["task"].priority <= 2:
                critical_failures += 1
        
        # Fail analysis if too many critical tasks failed
        if critical_failures >= 2:
            analysis["status"] = "failed"
            analysis["end_time"] = datetime.now()
            
            await self.event_bus.publish("analysis_failed", {
                "analysis_id": analysis_id,
                "session_id": analysis["session_id"],
                "reason": "Too many critical task failures"
            })
            
            logger.error(f"Analysis failed: {analysis_id}")
    
    def _get_next_phase(self, current_phase: AnalysisPhase) -> Optional[AnalysisPhase]:
        """Get the next analysis phase"""
        phase_order = [
            AnalysisPhase.INITIALIZATION,
            AnalysisPhase.STATIC_ANALYSIS,
            AnalysisPhase.DYNAMIC_ANALYSIS,
            AnalysisPhase.BEHAVIORAL_ANALYSIS,
            AnalysisPhase.CORRELATION,
            AnalysisPhase.REPORTING,
            AnalysisPhase.COMPLETED
        ]
        
        try:
            current_index = phase_order.index(current_phase)
            if current_index < len(phase_order) - 1:
                return phase_order[current_index + 1]
        except ValueError:
            pass
        
        return None
    
    def _get_client_for_tool(self, tool_name: str) -> str:
        """Determine which MCP client should handle a tool"""
        tool_mapping = {
            "initialize_analysis_session": "d2_analysis",
            "start_dynamic_monitoring": "d2_analysis",
            "analyze_memory_structures": "d2_analysis",
            "analyze_behavior_patterns": "d2_analysis",
            "analyze_binary_structure": "ghidra",
            "analyze_network_traffic": "network",
            "correlate_analysis_results": "dgraph",
            "generate_analysis_report": "d2_analysis"
        }
        
        return tool_mapping.get(tool_name, "d2_analysis")
    
    def _get_results_preview(self, analysis_id: str) -> Dict[str, Any]:
        """Get a preview of analysis results"""
        analysis = self.active_analyses[analysis_id]
        
        preview = {
            "phases_completed": [],
            "key_findings": [],
            "security_events": [],
            "performance_metrics": {}
        }
        
        # Extract key information from completed tasks
        for task_id, result_data in analysis["results"].items():
            task = next((t for t in analysis["plan"] if t.task_id == task_id), None)
            if not task:
                continue
            
            if task.phase not in preview["phases_completed"]:
                preview["phases_completed"].append(task.phase.value)
            
            # Extract findings based on task type
            result = result_data
            if isinstance(result, list) and result:
                if "security" in task.tool_name.lower():
                    preview["security_events"].extend(result[:3])  # Top 3
                elif "behavior" in task.tool_name.lower():
                    preview["key_findings"].extend(result[:3])  # Top 3
        
        return preview
    
    async def _handle_analysis_request(self, event_data: Dict[str, Any]):
        """Handle analysis request events"""
        session_id = event_data.get("session_id")
        analysis_config = event_data.get("config", {})
        
        if session_id:
            await self.submit_analysis_request(session_id, analysis_config)
    
    async def _handle_tool_result(self, event_data: Dict[str, Any]):
        """Handle tool result events"""
        # Process intermediate tool results if needed
        pass
    
    async def _handle_session_ended(self, event_data: Dict[str, Any]):
        """Handle session end events"""
        session_id = event_data.get("session_id")
        
        # Cancel any active analyses for this session
        to_cancel = []
        for analysis_id, analysis in self.active_analyses.items():
            if analysis["session_id"] == session_id:
                to_cancel.append(analysis_id)
        
        for analysis_id in to_cancel:
            await self.cancel_analysis(analysis_id)
