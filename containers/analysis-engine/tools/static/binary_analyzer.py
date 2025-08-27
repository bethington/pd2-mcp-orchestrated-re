"""
Advanced Binary Analysis Engine
Comprehensive static analysis with disassembly, CFG generation, and pattern detection
"""

import os
import hashlib
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import structlog
from datetime import datetime

# Binary analysis libraries
import capstone
import pefile
import lief
from elftools.elf.elffile import ELFFile
import yara
import networkx as nx

logger = structlog.get_logger()

class BinaryAnalyzer:
    """Advanced binary analysis with disassembly and structural analysis"""
    
    def __init__(self):
        self.capstone_engines = {
            'x86': capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32),
            'x64': capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64),
            'arm': capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
            'arm64': capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM)
        }
        
        # Enable detailed instruction information
        for engine in self.capstone_engines.values():
            engine.detail = True
            
        self.yara_rules = None
        self._load_yara_rules()
        
        logger.info("Binary analyzer initialized")
        
    def _load_yara_rules(self):
        """Load YARA rules for pattern detection"""
        try:
            # Basic malware and packer detection rules
            rules_content = '''
            rule Windows_PE_File {
                meta:
                    description = "Detects Windows PE files"
                strings:
                    $pe_header = {4D 5A}
                condition:
                    $pe_header at 0
            }
            
            rule UPX_Packer {
                meta:
                    description = "Detects UPX packed executables"
                strings:
                    $upx1 = "UPX!"
                    $upx2 = "UPX0"
                    $upx3 = "UPX1"
                condition:
                    any of them
            }
            
            rule Suspicious_API_Calls {
                meta:
                    description = "Detects suspicious API imports"
                strings:
                    $api1 = "VirtualAlloc"
                    $api2 = "WriteProcessMemory"
                    $api3 = "CreateRemoteThread"
                    $api4 = "SetWindowsHookEx"
                condition:
                    2 of them
            }
            
            rule Anti_Debug_Techniques {
                meta:
                    description = "Common anti-debugging techniques"
                strings:
                    $isdbg1 = "IsDebuggerPresent"
                    $isdbg2 = "CheckRemoteDebuggerPresent"
                    $timing = "QueryPerformanceCounter"
                condition:
                    any of them
            }
            '''
            
            self.yara_rules = yara.compile(source=rules_content)
            logger.info("YARA rules loaded successfully")
            
        except Exception as e:
            logger.warning("Failed to load YARA rules", error=str(e))
            
    async def analyze_binary(self, binary_path: str, analysis_depth: str = "detailed") -> Dict[str, Any]:
        """
        Comprehensive binary analysis
        
        Args:
            binary_path: Path to binary file
            analysis_depth: 'basic', 'detailed', or 'comprehensive'
            
        Returns:
            Complete analysis results
        """
        if not os.path.exists(binary_path):
            return {"error": f"Binary file not found: {binary_path}"}
            
        try:
            binary_data = self._read_binary(binary_path)
            file_info = self._get_file_info(binary_path, binary_data)
            
            analysis_result = {
                "file_info": file_info,
                "timestamp": datetime.now().isoformat(),
                "analysis_depth": analysis_depth,
                "binary_format": None,
                "disassembly": {},
                "control_flow": {},
                "strings": [],
                "imports": [],
                "exports": [],
                "sections": [],
                "security_analysis": {},
                "patterns": []
            }
            
            # Determine binary format
            binary_format = self._detect_binary_format(binary_data)
            analysis_result["binary_format"] = binary_format
            
            if binary_format == "PE":
                pe_analysis = await self._analyze_pe_file(binary_path, binary_data)
                analysis_result.update(pe_analysis)
                
            elif binary_format == "ELF":
                elf_analysis = await self._analyze_elf_file(binary_path, binary_data)
                analysis_result.update(elf_analysis)
                
            # Common analysis for all formats
            if analysis_depth in ["detailed", "comprehensive"]:
                analysis_result["strings"] = self._extract_strings(binary_data)
                analysis_result["patterns"] = await self._detect_patterns(binary_data)
                
            if analysis_depth == "comprehensive":
                disasm_result = await self._comprehensive_disassembly(binary_data, binary_format)
                analysis_result["disassembly"] = disasm_result["disassembly"]
                analysis_result["control_flow"] = disasm_result["control_flow"]
                analysis_result["security_analysis"] = await self._security_analysis(binary_data, analysis_result)
                
            return analysis_result
            
        except Exception as e:
            logger.error("Binary analysis failed", binary_path=binary_path, error=str(e))
            return {"error": str(e)}
            
    def _read_binary(self, binary_path: str) -> bytes:
        """Read binary file data"""
        with open(binary_path, 'rb') as f:
            return f.read()
            
    def _get_file_info(self, binary_path: str, binary_data: bytes) -> Dict[str, Any]:
        """Extract basic file information"""
        file_stat = os.stat(binary_path)
        
        return {
            "filename": os.path.basename(binary_path),
            "file_path": binary_path,
            "file_size": len(binary_data),
            "creation_time": datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
            "modification_time": datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
            "md5": hashlib.md5(binary_data).hexdigest(),
            "sha1": hashlib.sha1(binary_data).hexdigest(),
            "sha256": hashlib.sha256(binary_data).hexdigest()
        }
        
    def _detect_binary_format(self, binary_data: bytes) -> str:
        """Detect binary format (PE, ELF, etc.)"""
        if binary_data.startswith(b'MZ'):
            return "PE"
        elif binary_data.startswith(b'\x7fELF'):
            return "ELF"
        elif binary_data.startswith(b'\xfe\xed\xfa\xce') or binary_data.startswith(b'\xce\xfa\xed\xfe'):
            return "Mach-O"
        else:
            return "Unknown"
            
    async def _analyze_pe_file(self, binary_path: str, binary_data: bytes) -> Dict[str, Any]:
        """Analyze Windows PE file"""
        try:
            pe = pefile.PE(data=binary_data)
            
            # Basic PE information
            pe_info = {
                "machine_type": hex(pe.FILE_HEADER.Machine),
                "timestamp": datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).isoformat(),
                "number_of_sections": pe.FILE_HEADER.NumberOfSections,
                "entry_point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                "image_base": hex(pe.OPTIONAL_HEADER.ImageBase),
                "subsystem": pe.OPTIONAL_HEADER.Subsystem,
                "dll_characteristics": hex(pe.OPTIONAL_HEADER.DllCharacteristics)
            }
            
            # Extract sections
            sections = []
            for section in pe.sections:
                sections.append({
                    "name": section.Name.decode('utf-8', errors='ignore').rstrip('\x00'),
                    "virtual_address": hex(section.VirtualAddress),
                    "virtual_size": section.Misc_VirtualSize,
                    "raw_size": section.SizeOfRawData,
                    "characteristics": hex(section.Characteristics),
                    "entropy": section.get_entropy()
                })
                
            # Extract imports
            imports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_imports = []
                    for imp in entry.imports:
                        if imp.name:
                            dll_imports.append({
                                "name": imp.name.decode('utf-8', errors='ignore'),
                                "address": hex(imp.address) if imp.address else None
                            })
                    imports.append({
                        "dll": entry.dll.decode('utf-8', errors='ignore'),
                        "functions": dll_imports
                    })
                    
            # Extract exports
            exports = []
            if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    exports.append({
                        "name": exp.name.decode('utf-8', errors='ignore') if exp.name else f"Ordinal_{exp.ordinal}",
                        "address": hex(exp.address),
                        "ordinal": exp.ordinal
                    })
                    
            return {
                "pe_info": pe_info,
                "sections": sections,
                "imports": imports,
                "exports": exports
            }
            
        except Exception as e:
            logger.error("PE analysis failed", error=str(e))
            return {"pe_analysis_error": str(e)}
            
    async def _analyze_elf_file(self, binary_path: str, binary_data: bytes) -> Dict[str, Any]:
        """Analyze ELF file"""
        try:
            with open(binary_path, 'rb') as f:
                elf = ELFFile(f)
                
                # Basic ELF information
                elf_info = {
                    "class": elf.header.e_ident.EI_CLASS,
                    "data": elf.header.e_ident.EI_DATA,
                    "machine": elf.header.e_machine,
                    "type": elf.header.e_type,
                    "entry_point": hex(elf.header.e_entry),
                    "program_header_offset": elf.header.e_phoff,
                    "section_header_offset": elf.header.e_shoff
                }
                
                # Extract sections
                sections = []
                for i, section in enumerate(elf.iter_sections()):
                    sections.append({
                        "index": i,
                        "name": section.name,
                        "type": section.header.sh_type,
                        "address": hex(section.header.sh_addr),
                        "size": section.header.sh_size,
                        "flags": hex(section.header.sh_flags)
                    })
                    
                return {
                    "elf_info": elf_info,
                    "sections": sections
                }
                
        except Exception as e:
            logger.error("ELF analysis failed", error=str(e))
            return {"elf_analysis_error": str(e)}
            
    def _extract_strings(self, binary_data: bytes, min_length: int = 4) -> List[Dict[str, Any]]:
        """Extract readable strings from binary"""
        strings = []
        current_string = ""
        offset = 0
        
        for i, byte in enumerate(binary_data):
            if 32 <= byte <= 126:  # Printable ASCII
                current_string += chr(byte)
            else:
                if len(current_string) >= min_length:
                    strings.append({
                        "string": current_string,
                        "offset": hex(offset),
                        "length": len(current_string),
                        "type": "ascii"
                    })
                current_string = ""
                offset = i + 1
                
        # Don't return too many strings to avoid overwhelming output
        return strings[:100] if len(strings) > 100 else strings
        
    async def _detect_patterns(self, binary_data: bytes) -> List[Dict[str, Any]]:
        """Detect patterns using YARA rules"""
        patterns = []
        
        if self.yara_rules:
            try:
                matches = self.yara_rules.match(data=binary_data)
                for match in matches:
                    patterns.append({
                        "rule_name": match.rule,
                        "description": match.meta.get("description", ""),
                        "matches": len(match.strings),
                        "tags": match.tags
                    })
            except Exception as e:
                logger.warning("YARA pattern detection failed", error=str(e))
                
        return patterns
        
    async def _comprehensive_disassembly(self, binary_data: bytes, binary_format: str) -> Dict[str, Any]:
        """Perform comprehensive disassembly and CFG generation"""
        try:
            # Determine architecture
            arch = self._determine_architecture(binary_data, binary_format)
            if arch not in self.capstone_engines:
                return {"error": f"Unsupported architecture: {arch}"}
                
            cs = self.capstone_engines[arch]
            
            # Find code sections to disassemble
            code_sections = self._find_code_sections(binary_data, binary_format)
            
            disassembly_results = {}
            cfg_data = {}
            
            for section_name, section_data, base_addr in code_sections:
                instructions = []
                basic_blocks = []
                
                # Disassemble section
                for insn in cs.disasm(section_data, base_addr):
                    instructions.append({
                        "address": hex(insn.address),
                        "mnemonic": insn.mnemonic,
                        "operands": insn.op_str,
                        "bytes": insn.bytes.hex(),
                        "size": insn.size
                    })
                    
                # Generate control flow graph
                cfg = self._generate_cfg(instructions)
                
                disassembly_results[section_name] = {
                    "instruction_count": len(instructions),
                    "instructions": instructions[:50],  # Limit output size
                    "basic_blocks": len(cfg.nodes()),
                    "edges": len(cfg.edges())
                }
                
                cfg_data[section_name] = {
                    "nodes": list(cfg.nodes()),
                    "edges": list(cfg.edges()),
                    "entry_points": self._find_entry_points(cfg)
                }
                
            return {
                "disassembly": disassembly_results,
                "control_flow": cfg_data
            }
            
        except Exception as e:
            logger.error("Disassembly failed", error=str(e))
            return {"disassembly_error": str(e)}
            
    def _determine_architecture(self, binary_data: bytes, binary_format: str) -> str:
        """Determine binary architecture"""
        if binary_format == "PE":
            try:
                pe = pefile.PE(data=binary_data)
                machine = pe.FILE_HEADER.Machine
                if machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_I386']:
                    return 'x86'
                elif machine == pefile.MACHINE_TYPE['IMAGE_FILE_MACHINE_AMD64']:
                    return 'x64'
            except:
                pass
        return 'x86'  # Default fallback
        
    def _find_code_sections(self, binary_data: bytes, binary_format: str) -> List[Tuple[str, bytes, int]]:
        """Find executable code sections"""
        code_sections = []
        
        if binary_format == "PE":
            try:
                pe = pefile.PE(data=binary_data)
                for section in pe.sections:
                    if section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_CNT_CODE']:
                        section_name = section.Name.decode('utf-8', errors='ignore').rstrip('\x00')
                        section_data = section.get_data()
                        base_addr = pe.OPTIONAL_HEADER.ImageBase + section.VirtualAddress
                        code_sections.append((section_name, section_data, base_addr))
            except:
                # Fallback: assume entire file is code
                code_sections.append(("unknown", binary_data[:1024], 0x400000))
                
        return code_sections
        
    def _generate_cfg(self, instructions: List[Dict[str, Any]]) -> nx.DiGraph:
        """Generate control flow graph from instructions"""
        cfg = nx.DiGraph()
        
        # Basic CFG generation - identify basic blocks
        current_block = []
        block_id = 0
        
        for insn in instructions:
            current_block.append(insn)
            
            # Check if instruction ends a basic block
            if (insn["mnemonic"] in ["jmp", "je", "jne", "jz", "jnz", "call", "ret"] or
                len(current_block) > 20):  # Limit block size
                
                if current_block:
                    cfg.add_node(block_id, instructions=current_block)
                    if block_id > 0:
                        cfg.add_edge(block_id - 1, block_id)
                    block_id += 1
                    current_block = []
                    
        return cfg
        
    def _find_entry_points(self, cfg: nx.DiGraph) -> List[int]:
        """Find entry points in control flow graph"""
        entry_points = []
        for node in cfg.nodes():
            if cfg.in_degree(node) == 0:
                entry_points.append(node)
        return entry_points
        
    async def _security_analysis(self, binary_data: bytes, analysis_result: Dict[str, Any]) -> Dict[str, Any]:
        """Perform security-focused analysis"""
        security_findings = {
            "aslr_enabled": False,
            "dep_enabled": False,
            "stack_canary": False,
            "suspicious_apis": [],
            "packer_detected": False,
            "anti_debug": False,
            "risk_score": 0
        }
        
        # Check for security mitigations in PE files
        if "pe_info" in analysis_result:
            dll_chars = int(analysis_result["pe_info"]["dll_characteristics"], 16)
            security_findings["aslr_enabled"] = bool(dll_chars & 0x0040)  # DYNAMIC_BASE
            security_findings["dep_enabled"] = bool(dll_chars & 0x0100)   # NX_COMPAT
            
        # Check for suspicious imports
        if "imports" in analysis_result:
            suspicious_apis = ["VirtualAlloc", "WriteProcessMemory", "CreateRemoteThread", 
                             "SetWindowsHookEx", "GetProcAddress", "LoadLibrary"]
            
            for import_dll in analysis_result["imports"]:
                for func in import_dll["functions"]:
                    if func["name"] in suspicious_apis:
                        security_findings["suspicious_apis"].append({
                            "dll": import_dll["dll"],
                            "function": func["name"]
                        })
                        
        # Check patterns for packers and anti-debug
        if "patterns" in analysis_result:
            for pattern in analysis_result["patterns"]:
                if "Packer" in pattern["rule_name"]:
                    security_findings["packer_detected"] = True
                if "Anti_Debug" in pattern["rule_name"]:
                    security_findings["anti_debug"] = True
                    
        # Calculate risk score
        risk_score = 0
        if not security_findings["aslr_enabled"]: risk_score += 2
        if not security_findings["dep_enabled"]: risk_score += 2
        if len(security_findings["suspicious_apis"]) > 3: risk_score += 3
        if security_findings["packer_detected"]: risk_score += 2
        if security_findings["anti_debug"]: risk_score += 3
        
        security_findings["risk_score"] = risk_score
        
        return security_findings

    async def generate_analysis_report(self, analysis_result: Dict[str, Any]) -> str:
        """Generate human-readable analysis report"""
        report_lines = []
        report_lines.append("=== BINARY ANALYSIS REPORT ===")
        report_lines.append(f"Timestamp: {analysis_result.get('timestamp', 'Unknown')}")
        report_lines.append("")
        
        # File information
        if "file_info" in analysis_result:
            file_info = analysis_result["file_info"]
            report_lines.append("FILE INFORMATION:")
            report_lines.append(f"  Filename: {file_info.get('filename', 'Unknown')}")
            report_lines.append(f"  Size: {file_info.get('file_size', 0):,} bytes")
            report_lines.append(f"  SHA256: {file_info.get('sha256', 'Unknown')}")
            report_lines.append("")
            
        # Binary format
        report_lines.append(f"Binary Format: {analysis_result.get('binary_format', 'Unknown')}")
        report_lines.append("")
        
        # Security analysis
        if "security_analysis" in analysis_result:
            sec = analysis_result["security_analysis"]
            report_lines.append("SECURITY ANALYSIS:")
            report_lines.append(f"  ASLR Enabled: {sec.get('aslr_enabled', False)}")
            report_lines.append(f"  DEP Enabled: {sec.get('dep_enabled', False)}")
            report_lines.append(f"  Risk Score: {sec.get('risk_score', 0)}/10")
            
            if sec.get("suspicious_apis"):
                report_lines.append("  Suspicious APIs:")
                for api in sec["suspicious_apis"][:5]:  # Limit to 5
                    report_lines.append(f"    - {api['dll']}!{api['function']}")
            report_lines.append("")
            
        # Patterns detected
        if "patterns" in analysis_result and analysis_result["patterns"]:
            report_lines.append("PATTERNS DETECTED:")
            for pattern in analysis_result["patterns"][:5]:  # Limit to 5
                report_lines.append(f"  - {pattern['rule_name']}: {pattern['description']}")
            report_lines.append("")
            
        # Disassembly summary
        if "disassembly" in analysis_result:
            report_lines.append("DISASSEMBLY SUMMARY:")
            for section, disasm in analysis_result["disassembly"].items():
                report_lines.append(f"  {section}: {disasm['instruction_count']} instructions")
            report_lines.append("")
            
        return "\n".join(report_lines)
