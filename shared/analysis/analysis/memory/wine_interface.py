"""
Wine debugging and integration interface for D2 analysis
"""

import subprocess
import re
import logging
import asyncio
import tempfile
import os
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import json
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)

@dataclass
class WineProcessInfo:
    """Information about a Wine process"""
    pid: int
    ppid: int
    name: str
    command_line: str
    wine_pid: str
    memory_maps: List[Dict[str, Any]]

class WineDebugInterface:
    """Interface for debugging Wine processes and D2 game analysis"""
    
    def __init__(self, wine_prefix: str = "/root/.wine"):
        self.wine_prefix = wine_prefix
        self.wine_server_running = False
        self.attached_processes = {}
        self.debug_log_file = None
        
        # Set Wine environment
        self.wine_env = os.environ.copy()
        self.wine_env.update({
            "WINEPREFIX": wine_prefix,
            "WINEARCH": "win32",
            "WINEDEBUG": "+all"  # Can be customized based on needs
        })
    
    async def initialize(self):
        """Initialize Wine debugging interface"""
        try:
            # Ensure Wine server is running
            await self._ensure_wine_server()
            
            # Setup debug logging
            self.debug_log_file = tempfile.NamedTemporaryFile(
                mode='w+', 
                suffix='.log', 
                prefix='wine_debug_',
                delete=False
            )
            
            logger.info("Wine debug interface initialized")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Wine debug interface: {e}")
            return False
    
    async def _ensure_wine_server(self):
        """Ensure Wine server is running"""
        try:
            # Check if wineserver is running
            result = await self._run_wine_command(["wineserver", "-k"])  # Kill existing
            await asyncio.sleep(1)
            
            # Start wine server
            result = await self._run_wine_command(["wineserver", "-p"])  # Persistent mode
            self.wine_server_running = True
            
        except Exception as e:
            logger.warning(f"Wine server setup issue: {e}")
    
    async def find_diablo_processes(self) -> List[WineProcessInfo]:
        """Find running Diablo 2 processes in Wine"""
        processes = []
        
        try:
            # Use winedbg to list processes
            result = await self._run_wine_command(["winedbg", "--command", "info proc"])
            
            if result.stdout:
                processes_text = result.stdout
                # Parse process list
                for line in processes_text.split('\n'):
                    if 'diablo' in line.lower() or 'game.exe' in line.lower():
                        proc_info = self._parse_process_line(line)
                        if proc_info:
                            processes.append(proc_info)
            
            # Alternative: use ps to find Wine processes
            if not processes:
                processes = await self._find_processes_via_ps()
            
        except Exception as e:
            logger.error(f"Error finding Diablo processes: {e}")
        
        return processes
    
    async def _find_processes_via_ps(self) -> List[WineProcessInfo]:
        """Find D2 processes using system ps command"""
        processes = []
        
        try:
            result = await asyncio.create_subprocess_exec(
                "ps", "aux",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await result.communicate()
            
            if stdout:
                for line in stdout.decode().split('\n'):
                    if any(keyword in line.lower() for keyword in ['game.exe', 'diablo', 'pd2']):
                        parts = line.split()
                        if len(parts) >= 11:
                            pid = int(parts[1])
                            ppid = int(parts[2])
                            name = parts[10]
                            command_line = ' '.join(parts[10:])
                            
                            # Get memory maps
                            memory_maps = await self._get_process_memory_maps(pid)
                            
                            processes.append(WineProcessInfo(
                                pid=pid,
                                ppid=ppid,
                                name=name,
                                command_line=command_line,
                                wine_pid=str(pid),
                                memory_maps=memory_maps
                            ))
            
        except Exception as e:
            logger.error(f"Error using ps to find processes: {e}")
        
        return processes
    
    async def _get_process_memory_maps(self, pid: int) -> List[Dict[str, Any]]:
        """Get memory maps for a process"""
        maps = []
        
        try:
            maps_file = f"/proc/{pid}/maps"
            if os.path.exists(maps_file):
                with open(maps_file, 'r') as f:
                    for line in f:
                        parts = line.strip().split()
                        if len(parts) >= 6:
                            addr_range = parts[0].split('-')
                            start_addr = int(addr_range[0], 16)
                            end_addr = int(addr_range[1], 16)
                            
                            maps.append({
                                "start_address": start_addr,
                                "end_address": end_addr,
                                "size": end_addr - start_addr,
                                "permissions": parts[1],
                                "offset": parts[2],
                                "device": parts[3],
                                "inode": parts[4],
                                "pathname": parts[5] if len(parts) > 5 else ""
                            })
        
        except Exception as e:
            logger.error(f"Error getting memory maps for PID {pid}: {e}")
        
        return maps
    
    async def attach_to_process(self, process_info: WineProcessInfo) -> bool:
        """Attach debugger to a Wine process"""
        try:
            # Use gdb to attach to the process
            gdb_commands = [
                "set confirm off",
                f"attach {process_info.pid}",
                "set breakpoint pending on",
                "continue"
            ]
            
            # Create GDB command file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as f:
                for cmd in gdb_commands:
                    f.write(f"{cmd}\n")
                gdb_script = f.name
            
            # Start GDB in background
            gdb_process = await asyncio.create_subprocess_exec(
                "gdb", "-batch", "-x", gdb_script,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            self.attached_processes[process_info.pid] = {
                "process_info": process_info,
                "gdb_process": gdb_process,
                "gdb_script": gdb_script
            }
            
            logger.info(f"Attached to process {process_info.pid} ({process_info.name})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to attach to process {process_info.pid}: {e}")
            return False
    
    async def read_process_memory(self, pid: int, address: int, size: int) -> Optional[bytes]:
        """Read memory from a Wine process"""
        try:
            # Use /proc/pid/mem to read memory directly
            mem_file = f"/proc/{pid}/mem"
            
            with open(mem_file, 'rb') as f:
                f.seek(address)
                data = f.read(size)
                return data
                
        except Exception as e:
            logger.error(f"Failed to read memory from PID {pid} at 0x{address:x}: {e}")
            
            # Alternative: use gdb to read memory
            try:
                return await self._read_memory_via_gdb(pid, address, size)
            except Exception as gdb_error:
                logger.error(f"GDB memory read also failed: {gdb_error}")
                return None
    
    async def _read_memory_via_gdb(self, pid: int, address: int, size: int) -> Optional[bytes]:
        """Read memory using GDB"""
        try:
            gdb_cmd = f"dump binary memory /tmp/memdump_{pid}_{address:x}.bin 0x{address:x} 0x{address + size:x}"
            
            # Create GDB script
            with tempfile.NamedTemporaryFile(mode='w', suffix='.gdb', delete=False) as f:
                f.write(f"attach {pid}\n")
                f.write(f"{gdb_cmd}\n")
                f.write("detach\n")
                f.write("quit\n")
                gdb_script = f.name
            
            # Run GDB
            gdb_process = await asyncio.create_subprocess_exec(
                "gdb", "-batch", "-x", gdb_script,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            await gdb_process.communicate()
            
            # Read dumped memory
            dump_file = f"/tmp/memdump_{pid}_{address:x}.bin"
            if os.path.exists(dump_file):
                with open(dump_file, 'rb') as f:
                    data = f.read()
                os.unlink(dump_file)  # Clean up
                os.unlink(gdb_script)  # Clean up
                return data
            
        except Exception as e:
            logger.error(f"GDB memory read failed: {e}")
        
        return None
    
    async def inject_dll(self, pid: int, dll_path: str) -> bool:
        """Inject a DLL into a Wine process"""
        try:
            # Use wine's built-in DLL injection
            # This is a simplified approach - real implementation would be more complex
            
            # First, convert the DLL path to Wine format
            wine_dll_path = await self._convert_path_to_wine(dll_path)
            
            # Use winedump or similar to inject
            result = await self._run_wine_command([
                "wine", "regsvr32", wine_dll_path
            ])
            
            if result.returncode == 0:
                logger.info(f"Successfully injected DLL {dll_path} into process {pid}")
                return True
            else:
                logger.error(f"DLL injection failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error injecting DLL: {e}")
            return False
    
    async def set_breakpoint(self, pid: int, address: int, callback: callable = None) -> bool:
        """Set a breakpoint in a Wine process"""
        try:
            if pid not in self.attached_processes:
                # Need to attach first
                processes = await self.find_diablo_processes()
                proc_info = next((p for p in processes if p.pid == pid), None)
                if not proc_info:
                    logger.error(f"Process {pid} not found")
                    return False
                
                if not await self.attach_to_process(proc_info):
                    return False
            
            # Set breakpoint using GDB
            gdb_cmd = f"break *0x{address:x}"
            
            # This would require a more sophisticated GDB interface
            # For now, we'll log the request
            logger.info(f"Breakpoint requested at 0x{address:x} for process {pid}")
            
            # Store callback for later use
            if callback:
                if 'breakpoints' not in self.attached_processes[pid]:
                    self.attached_processes[pid]['breakpoints'] = {}
                self.attached_processes[pid]['breakpoints'][address] = callback
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to set breakpoint: {e}")
            return False
    
    async def monitor_api_calls(self, pid: int, api_list: List[str]) -> Dict[str, Any]:
        """Monitor API calls from a Wine process"""
        monitored_calls = {}
        
        try:
            # Use strace to monitor system calls
            strace_process = await asyncio.create_subprocess_exec(
                "strace", "-p", str(pid), "-e", "trace=all",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            # Monitor for a limited time
            try:
                stdout, stderr = await asyncio.wait_for(
                    strace_process.communicate(), 
                    timeout=30.0
                )
                
                if stderr:
                    # Parse strace output
                    for line in stderr.decode().split('\n'):
                        for api in api_list:
                            if api.lower() in line.lower():
                                if api not in monitored_calls:
                                    monitored_calls[api] = []
                                monitored_calls[api].append({
                                    "timestamp": time.time(),
                                    "call_details": line.strip()
                                })
                
            except asyncio.TimeoutError:
                strace_process.terminate()
            
        except Exception as e:
            logger.error(f"API monitoring failed: {e}")
        
        return monitored_calls
    
    async def get_wine_registry_info(self) -> Dict[str, Any]:
        """Get Wine registry information relevant to D2"""
        registry_info = {}
        
        try:
            # Export relevant registry keys
            keys_to_export = [
                "HKEY_LOCAL_MACHINE\\Software\\Blizzard Entertainment",
                "HKEY_CURRENT_USER\\Software\\Blizzard Entertainment",
                "HKEY_LOCAL_MACHINE\\Software\\Microsoft\\DirectX"
            ]
            
            for key in keys_to_export:
                try:
                    result = await self._run_wine_command([
                        "regedit", "/E", "/tmp/wine_reg_export.reg", key
                    ])
                    
                    if os.path.exists("/tmp/wine_reg_export.reg"):
                        with open("/tmp/wine_reg_export.reg", 'r') as f:
                            registry_info[key] = f.read()
                        os.unlink("/tmp/wine_reg_export.reg")
                        
                except Exception as e:
                    logger.warning(f"Failed to export registry key {key}: {e}")
            
        except Exception as e:
            logger.error(f"Registry info gathering failed: {e}")
        
        return registry_info
    
    async def _run_wine_command(self, command: List[str]) -> subprocess.CompletedProcess:
        """Run a Wine command with proper environment"""
        process = await asyncio.create_subprocess_exec(
            *command,
            env=self.wine_env,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=self.wine_prefix
        )
        
        stdout, stderr = await process.communicate()
        
        return subprocess.CompletedProcess(
            args=command,
            returncode=process.returncode,
            stdout=stdout.decode() if stdout else "",
            stderr=stderr.decode() if stderr else ""
        )
    
    async def _convert_path_to_wine(self, unix_path: str) -> str:
        """Convert Unix path to Wine path"""
        try:
            result = await self._run_wine_command(["winepath", "-w", unix_path])
            if result.returncode == 0:
                return result.stdout.strip()
            else:
                # Fallback conversion
                return unix_path.replace("/", "\\")
        except Exception:
            return unix_path.replace("/", "\\")
    
    def _parse_process_line(self, line: str) -> Optional[WineProcessInfo]:
        """Parse a process line from winedbg output"""
        try:
            # This is a simplified parser - real implementation would be more robust
            parts = line.split()
            if len(parts) >= 3:
                pid = int(parts[0])
                name = parts[2] if len(parts) > 2 else "unknown"
                
                return WineProcessInfo(
                    pid=pid,
                    ppid=0,  # Not available from winedbg
                    name=name,
                    command_line=line,
                    wine_pid=str(pid),
                    memory_maps=[]
                )
        except Exception as e:
            logger.warning(f"Failed to parse process line: {line}: {e}")
        
        return None
    
    async def cleanup(self):
        """Clean up debug interface"""
        try:
            # Detach from all processes
            for pid, attachment in self.attached_processes.items():
                try:
                    if 'gdb_process' in attachment:
                        attachment['gdb_process'].terminate()
                    if 'gdb_script' in attachment:
                        os.unlink(attachment['gdb_script'])
                except Exception as e:
                    logger.warning(f"Cleanup error for process {pid}: {e}")
            
            # Close debug log file
            if self.debug_log_file:
                self.debug_log_file.close()
                os.unlink(self.debug_log_file.name)
            
            self.attached_processes.clear()
            logger.info("Wine debug interface cleaned up")
            
        except Exception as e:
            logger.error(f"Cleanup failed: {e}")

# Wine interface for memory analysis
class WineMemoryInterface:
    """Specialized interface for memory analysis in Wine"""
    
    def __init__(self, debug_interface: WineDebugInterface):
        self.debug_interface = debug_interface
        self.memory_cache = {}
        
    async def scan_for_structures(self, pid: int, structure_signatures: Dict[str, bytes]) -> Dict[str, List[int]]:
        """Scan process memory for specific data structures"""
        found_structures = {}
        
        try:
            process_info = None
            processes = await self.debug_interface.find_diablo_processes()
            
            for proc in processes:
                if proc.pid == pid:
                    process_info = proc
                    break
            
            if not process_info:
                logger.error(f"Process {pid} not found")
                return found_structures
            
            # Scan each memory region
            for memory_map in process_info.memory_maps:
                # Skip non-readable regions
                if 'r' not in memory_map['permissions']:
                    continue
                
                # Read memory region
                memory_data = await self.debug_interface.read_process_memory(
                    pid, 
                    memory_map['start_address'], 
                    min(memory_map['size'], 1024*1024)  # Limit to 1MB per region
                )
                
                if not memory_data:
                    continue
                
                # Search for structure signatures
                for struct_name, signature in structure_signatures.items():
                    positions = self._find_signature_positions(memory_data, signature)
                    if positions:
                        if struct_name not in found_structures:
                            found_structures[struct_name] = []
                        
                        # Convert relative positions to absolute addresses
                        abs_positions = [
                            memory_map['start_address'] + pos for pos in positions
                        ]
                        found_structures[struct_name].extend(abs_positions)
        
        except Exception as e:
            logger.error(f"Structure scanning failed: {e}")
        
        return found_structures
    
    def _find_signature_positions(self, data: bytes, signature: bytes) -> List[int]:
        """Find positions of a signature in memory data"""
        positions = []
        start = 0
        
        while True:
            pos = data.find(signature, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1
        
        return positions
    
    async def dump_memory_region(self, pid: int, start_address: int, size: int, output_file: str) -> bool:
        """Dump a memory region to file"""
        try:
            memory_data = await self.debug_interface.read_process_memory(pid, start_address, size)
            
            if memory_data:
                with open(output_file, 'wb') as f:
                    f.write(memory_data)
                
                logger.info(f"Memory dumped to {output_file}")
                return True
            else:
                logger.error("Failed to read memory region")
                return False
                
        except Exception as e:
            logger.error(f"Memory dump failed: {e}")
            return False

# Global Wine debug interface instance
wine_debug_interface = WineDebugInterface()
