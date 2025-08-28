"""
Integration Tests for Analysis Pipeline
Comprehensive end-to-end testing of the reverse engineering platform
"""

import pytest
import asyncio
import requests
import json
import time
import tempfile
import hashlib
from pathlib import Path
from typing import Dict, List, Any
import docker

# Test Configuration
TEST_CONFIG = {
    "services": {
        "mcp-coordinator": "http://localhost:8000",
        "analysis-engine": "http://localhost:8001",
        "ghidra-analysis": "http://localhost:8002",
        "memory-forensics": "http://localhost:8004",
        "ai-analysis": "http://localhost:8005"
    },
    "timeout": {
        "service_startup": 120,
        "analysis_completion": 1800,  # 30 minutes
        "health_check": 30
    }
}

class AnalysisPipelineTest:
    """Comprehensive analysis pipeline testing"""
    
    def __init__(self):
        self.docker_client = docker.from_env()
        self.test_samples = {}
        self.analysis_results = {}
    
    async def setup_test_environment(self):
        """Setup test environment and verify services"""
        print("Setting up test environment...")
        
        # Create test binary samples
        await self.create_test_samples()
        
        # Verify all services are running
        await self.verify_services_health()
        
        print("Test environment setup complete")
    
    async def create_test_samples(self):
        """Create test binary samples for analysis"""
        samples_dir = Path("tests/samples")
        samples_dir.mkdir(parents=True, exist_ok=True)
        
        # Simple test binary (hello world)
        simple_binary = self.create_simple_binary()
        simple_path = samples_dir / "simple_test.exe"
        with open(simple_path, "wb") as f:
            f.write(simple_binary)
        
        self.test_samples["simple"] = {
            "path": str(simple_path),
            "type": "pe",
            "expected_functions": ["main", "printf"],
            "expected_strings": ["Hello", "World"],
            "threat_level": "benign"
        }
        
        # Packed binary simulation
        packed_binary = self.create_packed_binary()
        packed_path = samples_dir / "packed_test.exe"
        with open(packed_path, "wb") as f:
            f.write(packed_binary)
        
        self.test_samples["packed"] = {
            "path": str(packed_path),
            "type": "pe",
            "expected_properties": ["high_entropy", "packer_signatures"],
            "threat_level": "suspicious"
        }
        
        print(f"Created {len(self.test_samples)} test samples")
    
    def create_simple_binary(self) -> bytes:
        """Create a simple test binary"""
        # Minimal PE header + "Hello World" program stub
        pe_header = bytes([
            0x4D, 0x5A,  # MZ signature
            0x90, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0x00, 0x00,
            0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00,
            0x00, 0x00, 0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD, 0x21, 0xB8, 0x01, 0x4C,
            0xCD, 0x21, 0x54, 0x68, 0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72, 0x61, 0x6D,
            0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F, 0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E,
            0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20, 0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D,
        ])
        
        # Add strings
        strings_data = b"Hello World\\x00main\\x00printf\\x00"
        
        return pe_header + strings_data + b"\\x00" * 200
    
    def create_packed_binary(self) -> bytes:
        """Create a simulated packed binary with high entropy"""
        import random
        
        # Generate high-entropy data to simulate packing
        random.seed(42)  # Deterministic for testing
        high_entropy_data = bytes([random.randint(0, 255) for _ in range(2048)])
        
        # Add minimal PE header
        pe_header = self.create_simple_binary()[:128]
        
        return pe_header + high_entropy_data
    
    async def verify_services_health(self):
        """Verify all services are healthy and responding"""
        for service_name, base_url in TEST_CONFIG["services"].items():
            health_url = f"{base_url}/health"
            
            for attempt in range(5):
                try:
                    response = requests.get(health_url, timeout=10)
                    if response.status_code == 200:
                        health_data = response.json()
                        assert health_data.get("status") == "healthy", f"{service_name} not healthy"
                        print(f"✓ {service_name} is healthy")
                        break
                    else:
                        print(f"⚠ {service_name} health check failed (attempt {attempt + 1})")
                        await asyncio.sleep(10)
                except Exception as e:
                    print(f"⚠ {service_name} connection failed: {e} (attempt {attempt + 1})")
                    await asyncio.sleep(10)
            else:
                raise Exception(f"Service {service_name} failed all health checks")
    
    async def test_static_analysis_pipeline(self):
        """Test complete static analysis pipeline"""
        print("\\nTesting static analysis pipeline...")
        
        for sample_name, sample_info in self.test_samples.items():
            print(f"  Testing sample: {sample_name}")
            
            # Submit for static analysis
            analysis_url = f"{TEST_CONFIG['services']['analysis-engine']}/analyze/static"
            
            with open(sample_info["path"], "rb") as f:
                files = {"file": f}
                data = {"analysis_depth": "comprehensive"}
                
                response = requests.post(analysis_url, files=files, data=data)
                assert response.status_code == 200, f"Static analysis submission failed: {response.text}"
                
                result = response.json()
                analysis_id = result["analysis_id"]
                
                # Wait for completion
                status = await self.wait_for_analysis_completion(
                    f"{TEST_CONFIG['services']['analysis-engine']}/analyze/status/{analysis_id}"
                )
                
                # Get results
                results_response = requests.get(
                    f"{TEST_CONFIG['services']['analysis-engine']}/analyze/result/{analysis_id}"
                )
                assert results_response.status_code == 200, "Failed to get analysis results"
                
                analysis_results = results_response.json()
                self.analysis_results[f"{sample_name}_static"] = analysis_results
                
                # Validate results
                await self.validate_static_analysis_results(analysis_results, sample_info)
                
                print(f"    ✓ Static analysis completed for {sample_name}")
    
    async def test_ghidra_decompilation(self):
        """Test Ghidra decompilation service"""
        print("\\nTesting Ghidra decompilation...")
        
        sample_info = self.test_samples["simple"]
        
        decompile_url = f"{TEST_CONFIG['services']['ghidra-analysis']}/decompile"
        
        with open(sample_info["path"], "rb") as f:
            files = {"binary": f}
            data = {"analysis_type": "comprehensive"}
            
            response = requests.post(decompile_url, files=files, data=data)
            assert response.status_code == 200, f"Decompilation failed: {response.text}"
            
            result = response.json()
            analysis_id = result["analysis_id"]
            
            # Wait for completion
            status = await self.wait_for_analysis_completion(
                f"{TEST_CONFIG['services']['ghidra-analysis']}/decompile/status/{analysis_id}"
            )
            
            # Get results
            results_response = requests.get(
                f"{TEST_CONFIG['services']['ghidra-analysis']}/decompile/result/{analysis_id}"
            )
            assert results_response.status_code == 200, "Failed to get decompilation results"
            
            decompile_results = results_response.json()
            self.analysis_results["simple_ghidra"] = decompile_results
            
            # Validate decompilation
            assert "functions" in decompile_results, "No functions found in decompilation"
            assert len(decompile_results["functions"]) > 0, "No functions decompiled"
            
            print("    ✓ Ghidra decompilation completed")
    
    async def test_ai_analysis_pipeline(self):
        """Test AI analysis and triage system"""
        print("\\nTesting AI analysis pipeline...")
        
        # Get previous analysis results to feed into AI system
        if "simple_static" in self.analysis_results:
            static_results = self.analysis_results["simple_static"]
            
            # Test intelligent triage
            triage_url = f"{TEST_CONFIG['services']['ai-analysis']}/triage/intelligent"
            triage_data = {
                "analysis_results": static_results,
                "context_information": {"source": "integration_test"}
            }
            
            response = requests.post(triage_url, json=triage_data)
            assert response.status_code == 200, f"AI triage failed: {response.text}"
            
            result = response.json()
            analysis_id = result["analysis_id"]
            
            # Wait for completion
            status = await self.wait_for_analysis_completion(
                f"{TEST_CONFIG['services']['ai-analysis']}/triage/status/{analysis_id}"
            )
            
            # Get results
            results_response = requests.get(
                f"{TEST_CONFIG['services']['ai-analysis']}/triage/result/{analysis_id}"
            )
            assert results_response.status_code == 200, "Failed to get AI triage results"
            
            ai_results = results_response.json()
            self.analysis_results["simple_ai_triage"] = ai_results
            
            # Validate AI results
            assert "threat_classification" in ai_results, "No threat classification"
            assert "priority_score" in ai_results, "No priority score"
            
            print("    ✓ AI triage completed")
    
    async def test_memory_forensics(self):
        """Test memory forensics capabilities"""
        print("\\nTesting memory forensics...")
        
        # Test pattern recognition capabilities
        patterns_url = f"{TEST_CONFIG['services']['memory-forensics']}/patterns/known"
        
        response = requests.get(patterns_url)
        assert response.status_code == 200, "Failed to get known patterns"
        
        patterns = response.json()
        assert "binary_signatures" in patterns, "No binary signatures available"
        
        print("    ✓ Memory forensics patterns verified")
    
    async def test_end_to_end_analysis(self):
        """Test complete end-to-end analysis workflow"""
        print("\\nTesting end-to-end analysis workflow...")
        
        sample_info = self.test_samples["simple"]
        
        # Submit to automated workflow
        workflow_url = f"{TEST_CONFIG['services']['ai-analysis']}/analyze/automated"
        workflow_data = {
            "binary_path": sample_info["path"],
            "analysis_preferences": {
                "depth": "comprehensive",
                "include_dynamic": True,
                "include_decompilation": True
            }
        }
        
        response = requests.post(workflow_url, json=workflow_data)
        assert response.status_code == 200, f"Automated workflow failed: {response.text}"
        
        result = response.json()
        analysis_id = result["analysis_id"]
        
        # Wait for completion (longer timeout for full workflow)
        status = await self.wait_for_analysis_completion(
            f"{TEST_CONFIG['services']['ai-analysis']}/triage/status/{analysis_id}",
            timeout=1800  # 30 minutes
        )
        
        print("    ✓ End-to-end analysis workflow completed")
    
    async def wait_for_analysis_completion(self, status_url: str, timeout: int = 600) -> Dict[str, Any]:
        """Wait for analysis to complete"""
        start_time = time.time()
        
        while time.time() - start_time < timeout:
            try:
                response = requests.get(status_url, timeout=10)
                if response.status_code == 200:
                    status = response.json()
                    
                    if status.get("status") == "completed":
                        return status
                    elif status.get("status") == "failed":
                        raise Exception(f"Analysis failed: {status.get('error_message')}")
                    
                    # Still processing
                    progress = status.get("progress", 0)
                    print(f"      Progress: {progress:.1f}%")
                    
                await asyncio.sleep(10)
                
            except Exception as e:
                print(f"      Status check error: {e}")
                await asyncio.sleep(5)
        
        raise Exception(f"Analysis timeout after {timeout} seconds")
    
    async def validate_static_analysis_results(self, results: Dict[str, Any], sample_info: Dict[str, Any]):
        """Validate static analysis results"""
        assert "file_info" in results, "Missing file information"
        assert "imports" in results, "Missing import information"
        assert "strings" in results, "Missing strings analysis"
        
        # Check expected strings for simple binary
        if sample_info.get("expected_strings"):
            found_strings = " ".join(results.get("strings", []))
            for expected_string in sample_info["expected_strings"]:
                assert expected_string in found_strings, f"Expected string '{expected_string}' not found"
    
    def generate_test_report(self) -> Dict[str, Any]:
        """Generate comprehensive test report"""
        report = {
            "test_execution": {
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
                "samples_tested": len(self.test_samples),
                "analyses_completed": len(self.analysis_results),
                "services_tested": len(TEST_CONFIG["services"])
            },
            "sample_results": {},
            "service_coverage": {
                service: "tested" for service in TEST_CONFIG["services"].keys()
            },
            "performance_metrics": {},
            "validation_results": {}
        }
        
        # Process analysis results
        for analysis_name, results in self.analysis_results.items():
            sample_name = analysis_name.split("_")[0]
            analysis_type = "_".join(analysis_name.split("_")[1:])
            
            if sample_name not in report["sample_results"]:
                report["sample_results"][sample_name] = {}
            
            report["sample_results"][sample_name][analysis_type] = {
                "completed": True,
                "result_size": len(str(results)),
                "key_findings": self.extract_key_findings(results)
            }
        
        return report
    
    def extract_key_findings(self, results: Dict[str, Any]) -> List[str]:
        """Extract key findings from analysis results"""
        findings = []
        
        if "threat_classification" in results:
            findings.append(f"Threat: {results['threat_classification']}")
        
        if "priority_score" in results:
            findings.append(f"Priority: {results['priority_score']}")
        
        if "functions" in results:
            findings.append(f"Functions: {len(results['functions'])}")
        
        if "imports" in results:
            import_count = sum(len(dll_imports) for dll_imports in results["imports"].values())
            findings.append(f"API Imports: {import_count}")
        
        return findings


# Pytest test functions
@pytest.fixture(scope="session")
async def pipeline_test():
    """Setup test pipeline"""
    test_instance = AnalysisPipelineTest()
    await test_instance.setup_test_environment()
    return test_instance

@pytest.mark.asyncio
async def test_static_analysis(pipeline_test):
    """Test static analysis pipeline"""
    await pipeline_test.test_static_analysis_pipeline()
@pytest.mark.asyncio
async def test_ghidra_decompilation(pipeline_test):
    """Test Ghidra decompilation"""
    await pipeline_test.test_ghidra_decompilation()

@pytest.mark.asyncio
async def test_ai_analysis(pipeline_test):
    """Test AI analysis pipeline"""
    await pipeline_test.test_ai_analysis_pipeline()

@pytest.mark.asyncio
async def test_memory_forensics(pipeline_test):
    """Test memory forensics"""
    await pipeline_test.test_memory_forensics()

@pytest.mark.asyncio
async def test_end_to_end_workflow(pipeline_test):
    """Test complete end-to-end workflow"""
    await pipeline_test.test_end_to_end_analysis()

def test_generate_report(pipeline_test):
    """Generate and validate test report"""
    report = pipeline_test.generate_test_report()
    
    # Save report
    with open("tests/reports/integration_test_report.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print(f"\\nTest Report Generated:")
    print(f"  Samples tested: {report['test_execution']['samples_tested']}")
    print(f"  Analyses completed: {report['test_execution']['analyses_completed']}")
    print(f"  Services tested: {report['test_execution']['services_tested']}")

if __name__ == "__main__":
    # Run integration tests directly
    async def run_tests():
        test_instance = AnalysisPipelineTest()
        await test_instance.setup_test_environment()
        
        try:
            await test_instance.test_static_analysis_pipeline()
            await test_instance.test_ghidra_decompilation()
            await test_instance.test_ai_analysis_pipeline()
            await test_instance.test_memory_forensics()
            await test_instance.test_end_to_end_analysis()
            
            report = test_instance.generate_test_report()
            print("\\n" + "="*50)
            print("INTEGRATION TESTS COMPLETED SUCCESSFULLY")
            print("="*50)
            print(json.dumps(report, indent=2))
            
        except Exception as e:
            print(f"\\nINTEGRATION TESTS FAILED: {e}")
            raise
    
    asyncio.run(run_tests())