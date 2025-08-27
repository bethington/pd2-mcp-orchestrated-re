"""
Frida Dynamic Analysis Engine
Advanced runtime analysis and instrumentation using Frida
"""

import frida
import psutil
import threading
import time
import json
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
import structlog

logger = structlog.get_logger()

class FridaDynamicAnalyzer:
    """Dynamic analysis using Frida instrumentation"""
    
    def __init__(self):
        self.active_sessions = {}
        self.active_hooks = {}
        self.analysis_data = {}
        
        logger.info("Frida dynamic analyzer initialized")
        
    async def attach_to_process(self, process_identifier: str) -> Dict[str, Any]:
        """
        Attach Frida to a running process
        
        Args:
            process_identifier: PID or process name
        """
        try:
            # Try to parse as PID first
            try:
                pid = int(process_identifier)
                process = frida.attach(pid)
                process_name = psutil.Process(pid).name()
            except ValueError:
                # Try as process name
                process = frida.attach(process_identifier)
                pid = process.get_parameters()['pid'] if hasattr(process, 'get_parameters') else 'unknown'
                process_name = process_identifier
                
            session_id = f"session_{pid}_{int(time.time())}"
            
            self.active_sessions[session_id] = {
                "process": process,
                "pid": pid,
                "process_name": process_name,
                "start_time": datetime.now().isoformat(),
                "hooks": [],
                "data_collected": {}
            }
            
            logger.info("Attached to process", 
                       session_id=session_id, 
                       pid=pid, 
                       process_name=process_name)
            
            return {
                "success": True,
                "session_id": session_id,
                "pid": pid,
                "process_name": process_name,
                "message": f"Successfully attached to {process_name} (PID: {pid})"
            }
            
        except Exception as e:
            logger.error("Failed to attach to process", 
                        process_identifier=process_identifier, 
                        error=str(e))
            return {
                "success": False,
                "error": str(e)
            }
    
    async def hook_api_calls(self, session_id: str, api_patterns: List[str]) -> Dict[str, Any]:
        """
        Hook API calls matching the specified patterns
        
        Args:
            session_id: Active Frida session ID
            api_patterns: List of API patterns to hook (e.g., ["kernel32.dll!VirtualAlloc"])
        """
        if session_id not in self.active_sessions:
            return {"error": f"Session {session_id} not found"}
            
        session = self.active_sessions[session_id]
        process = session["process"]
        
        try:
            hooks_created = []
            
            for pattern in api_patterns:
                hook_id = f"hook_{pattern}_{int(time.time())}"
                
                # Create Frida script for API hooking
                script_code = self._generate_api_hook_script(pattern, hook_id)
                
                script = process.create_script(script_code)
                script.on('message', lambda message, data: self._handle_hook_message(session_id, hook_id, message, data))
                script.load()
                
                self.active_hooks[hook_id] = {
                    "session_id": session_id,
                    "pattern": pattern,
                    "script": script,
                    "created_time": datetime.now().isoformat(),
                    "call_count": 0
                }
                
                session["hooks"].append(hook_id)
                hooks_created.append({
                    "hook_id": hook_id,
                    "pattern": pattern
                })
                
            logger.info("API hooks created", 
                       session_id=session_id, 
                       hooks_count=len(hooks_created))
            
            return {
                "success": True,
                "hooks_created": hooks_created,
                "total_hooks": len(session["hooks"])
            }
            
        except Exception as e:
            logger.error("Failed to create API hooks", 
                        session_id=session_id, 
                        error=str(e))
            return {"error": str(e)}
    
    async def trace_function_calls(self, session_id: str, function_address: str) -> Dict[str, Any]:
        """
        Trace calls to a specific function
        
        Args:
            session_id: Active Frida session ID
            function_address: Address of function to trace (e.g., "0x10001000")
        """
        if session_id not in self.active_sessions:
            return {"error": f"Session {session_id} not found"}
            
        session = self.active_sessions[session_id]
        process = session["process"]
        
        try:
            hook_id = f"trace_{function_address}_{int(time.time())}"
            
            # Create function tracing script
            script_code = self._generate_function_trace_script(function_address, hook_id)
            
            script = process.create_script(script_code)
            script.on('message', lambda message, data: self._handle_trace_message(session_id, hook_id, message, data))
            script.load()
            
            self.active_hooks[hook_id] = {
                "session_id": session_id,
                "type": "function_trace",
                "function_address": function_address,
                "script": script,
                "created_time": datetime.now().isoformat(),
                "call_count": 0
            }
            
            session["hooks"].append(hook_id)
            
            logger.info("Function tracing started", 
                       session_id=session_id, 
                       function_address=function_address)
            
            return {
                "success": True,
                "hook_id": hook_id,
                "function_address": function_address,
                "message": f"Tracing function at {function_address}"
            }
            
        except Exception as e:
            logger.error("Failed to start function tracing", 
                        session_id=session_id, 
                        error=str(e))
            return {"error": str(e)}
    
    async def memory_scan(self, session_id: str, pattern: str, scan_type: str = "bytes") -> Dict[str, Any]:
        """
        Scan process memory for patterns
        
        Args:
            session_id: Active Frida session ID  
            pattern: Pattern to search for
            scan_type: Type of scan ('bytes', 'string', 'value')
        """
        if session_id not in self.active_sessions:
            return {"error": f"Session {session_id} not found"}
            
        session = self.active_sessions[session_id]
        process = session["process"]
        
        try:
            scan_id = f"scan_{int(time.time())}"
            
            # Create memory scanning script
            script_code = self._generate_memory_scan_script(pattern, scan_type, scan_id)
            
            script = process.create_script(script_code)
            scan_results = []
            
            def handle_scan_result(message, data):
                if message['type'] == 'send' and 'scan_result' in message['payload']:
                    scan_results.append(message['payload']['scan_result'])
            
            script.on('message', handle_scan_result)
            script.load()
            
            # Wait for scan to complete (with timeout)
            timeout = 30  # 30 seconds
            start_time = time.time()
            
            while time.time() - start_time < timeout:
                time.sleep(0.5)
                if len(scan_results) > 0 or (time.time() - start_time) > 10:
                    break
                    
            script.unload()
            
            logger.info("Memory scan completed", 
                       session_id=session_id, 
                       pattern=pattern, 
                       results_count=len(scan_results))
            
            return {
                "success": True,
                "scan_id": scan_id,
                "pattern": pattern,
                "scan_type": scan_type,
                "results": scan_results[:100],  # Limit results
                "total_matches": len(scan_results)
            }
            
        except Exception as e:
            logger.error("Memory scan failed", 
                        session_id=session_id, 
                        error=str(e))
            return {"error": str(e)}
    
    async def get_analysis_data(self, session_id: str) -> Dict[str, Any]:
        """Get collected analysis data for session"""
        if session_id not in self.active_sessions:
            return {"error": f"Session {session_id} not found"}
            
        session = self.active_sessions[session_id]
        
        # Compile analysis data
        analysis_summary = {
            "session_info": {
                "session_id": session_id,
                "pid": session["pid"],
                "process_name": session["process_name"],
                "start_time": session["start_time"],
                "duration_seconds": (datetime.now() - datetime.fromisoformat(session["start_time"])).total_seconds()
            },
            "hooks_active": len(session["hooks"]),
            "data_collected": session.get("data_collected", {}),
            "statistics": {
                "api_calls_intercepted": sum(self.active_hooks[hook_id]["call_count"] 
                                           for hook_id in session["hooks"] 
                                           if hook_id in self.active_hooks),
                "hooks_created": len(session["hooks"])
            }
        }
        
        return analysis_summary
    
    async def detach_session(self, session_id: str) -> Dict[str, Any]:
        """Detach from process and cleanup session"""
        if session_id not in self.active_sessions:
            return {"error": f"Session {session_id} not found"}
            
        session = self.active_sessions[session_id]
        
        try:
            # Clean up hooks
            for hook_id in session["hooks"]:
                if hook_id in self.active_hooks:
                    try:
                        self.active_hooks[hook_id]["script"].unload()
                        del self.active_hooks[hook_id]
                    except:
                        pass  # Hook may already be cleaned up
            
            # Detach from process
            session["process"].detach()
            
            # Remove session
            del self.active_sessions[session_id]
            
            logger.info("Session detached", session_id=session_id)
            
            return {
                "success": True,
                "message": f"Session {session_id} detached successfully"
            }
            
        except Exception as e:
            logger.error("Failed to detach session", 
                        session_id=session_id, 
                        error=str(e))
            return {"error": str(e)}
    
    def _generate_api_hook_script(self, pattern: str, hook_id: str) -> str:
        """Generate Frida script for API hooking"""
        # Parse pattern (e.g., "kernel32.dll!VirtualAlloc")
        if '!' in pattern:
            module_name, function_name = pattern.split('!', 1)
        else:
            module_name = None
            function_name = pattern
            
        script = f'''
        var hookId = "{hook_id}";
        var functionName = "{function_name}";
        var moduleName = "{module_name}";
        
        try {{
            var targetFunction;
            
            if (moduleName && moduleName !== "None") {{
                var module = Process.getModuleByName(moduleName);
                targetFunction = module.getExportByName(functionName);
            }} else {{
                targetFunction = Module.findExportByName(null, functionName);
            }}
            
            if (targetFunction) {{
                Interceptor.attach(targetFunction, {{
                    onEnter: function(args) {{
                        send({{
                            type: "api_call",
                            hook_id: hookId,
                            function: functionName,
                            module: moduleName,
                            timestamp: Date.now(),
                            args: Array.from(args).slice(0, 4).map(arg => ptr(arg).toString()),
                            thread_id: this.threadId
                        }});
                    }},
                    onLeave: function(retval) {{
                        send({{
                            type: "api_return",
                            hook_id: hookId,
                            function: functionName,
                            return_value: ptr(retval).toString(),
                            timestamp: Date.now(),
                            thread_id: this.threadId
                        }});
                    }}
                }});
                
                send({{ type: "hook_success", hook_id: hookId, function: functionName }});
            }} else {{
                send({{ type: "hook_error", hook_id: hookId, error: "Function not found" }});
            }}
        }} catch (e) {{
            send({{ type: "hook_error", hook_id: hookId, error: e.toString() }});
        }}
        '''
        
        return script
    
    def _generate_function_trace_script(self, function_address: str, hook_id: str) -> str:
        """Generate Frida script for function tracing"""
        script = f'''
        var hookId = "{hook_id}";
        var functionAddress = ptr("{function_address}");
        
        try {{
            Interceptor.attach(functionAddress, {{
                onEnter: function(args) {{
                    send({{
                        type: "function_enter",
                        hook_id: hookId,
                        address: "{function_address}",
                        timestamp: Date.now(),
                        args: Array.from(args).slice(0, 6).map(arg => ptr(arg).toString()),
                        thread_id: this.threadId,
                        stack_trace: Thread.backtrace(this.context, Backtracer.ACCURATE).slice(0, 10).map(DebugSymbol.fromAddress)
                    }});
                }},
                onLeave: function(retval) {{
                    send({{
                        type: "function_leave", 
                        hook_id: hookId,
                        address: "{function_address}",
                        return_value: ptr(retval).toString(),
                        timestamp: Date.now(),
                        thread_id: this.threadId
                    }});
                }}
            }});
            
            send({{ type: "trace_success", hook_id: hookId, address: "{function_address}" }});
        }} catch (e) {{
            send({{ type: "trace_error", hook_id: hookId, error: e.toString() }});
        }}
        '''
        
        return script
    
    def _generate_memory_scan_script(self, pattern: str, scan_type: str, scan_id: str) -> str:
        """Generate Frida script for memory scanning"""
        if scan_type == "string":
            search_pattern = f'"{pattern}"'
        elif scan_type == "bytes":
            search_pattern = f'"{pattern}"'
        else:
            search_pattern = f'"{pattern}"'
            
        script = f'''
        var scanId = "{scan_id}";
        var pattern = {search_pattern};
        var scanType = "{scan_type}";
        
        try {{
            var matches = [];
            var ranges = Process.enumerateRanges("r--");
            
            ranges.forEach(function(range) {{
                if (range.size > 0x1000 && range.size < 0x10000000) {{ // Reasonable size limits
                    try {{
                        var results = Memory.scanSync(range.base, range.size, pattern);
                        results.forEach(function(result) {{
                            matches.push({{
                                address: result.address.toString(),
                                size: result.size || pattern.length,
                                range_base: range.base.toString(),
                                range_size: range.size
                            }});
                        }});
                    }} catch (e) {{
                        // Skip ranges that can't be scanned
                    }}
                }}
            }});
            
            send({{ 
                type: "send",
                payload: {{
                    scan_result: {{
                        scan_id: scanId,
                        pattern: pattern,
                        scan_type: scanType,
                        matches: matches.slice(0, 50), // Limit results
                        total_matches: matches.length
                    }}
                }}
            }});
        }} catch (e) {{
            send({{ type: "scan_error", scan_id: scanId, error: e.toString() }});
        }}
        '''
        
        return script
    
    def _handle_hook_message(self, session_id: str, hook_id: str, message: Dict, data: Any):
        """Handle messages from API hooks"""
        if hook_id in self.active_hooks:
            self.active_hooks[hook_id]["call_count"] += 1
            
        # Store message data
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            if "api_calls" not in session["data_collected"]:
                session["data_collected"]["api_calls"] = []
            
            session["data_collected"]["api_calls"].append({
                "hook_id": hook_id,
                "message": message,
                "timestamp": datetime.now().isoformat()
            })
            
            # Limit stored data to prevent memory issues
            if len(session["data_collected"]["api_calls"]) > 1000:
                session["data_collected"]["api_calls"] = session["data_collected"]["api_calls"][-500:]
    
    def _handle_trace_message(self, session_id: str, hook_id: str, message: Dict, data: Any):
        """Handle messages from function traces"""
        if hook_id in self.active_hooks:
            self.active_hooks[hook_id]["call_count"] += 1
            
        # Store trace data
        if session_id in self.active_sessions:
            session = self.active_sessions[session_id]
            if "function_traces" not in session["data_collected"]:
                session["data_collected"]["function_traces"] = []
                
            session["data_collected"]["function_traces"].append({
                "hook_id": hook_id,
                "message": message,
                "timestamp": datetime.now().isoformat()
            })
            
            # Limit stored data
            if len(session["data_collected"]["function_traces"]) > 500:
                session["data_collected"]["function_traces"] = session["data_collected"]["function_traces"][-250:]
    
    def get_active_sessions(self) -> Dict[str, Any]:
        """Get list of active analysis sessions"""
        sessions = {}
        for session_id, session in self.active_sessions.items():
            sessions[session_id] = {
                "pid": session["pid"],
                "process_name": session["process_name"],
                "start_time": session["start_time"],
                "hooks_count": len(session["hooks"]),
                "data_points": sum(len(data) for data in session.get("data_collected", {}).values())
            }
        return sessions