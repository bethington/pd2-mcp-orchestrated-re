"""
Performance Benchmarks and Validation
Comprehensive performance testing and validation suite
"""

import asyncio
import time
import psutil
import docker
import requests
import json
import statistics
from typing import Dict, List, Any, Tuple
from dataclasses import dataclass
from pathlib import Path
import matplotlib.pyplot as plt
import pandas as pd

@dataclass
class BenchmarkResult:
    """Performance benchmark result"""
    operation: str
    duration_seconds: float
    memory_usage_mb: float
    cpu_usage_percent: float
    throughput_items_per_second: float
    success: bool
    error_message: str = ""

class PerformanceBenchmarkSuite:
    """Comprehensive performance benchmarking"""
    
    def __init__(self):
        self.docker_client = docker.from_env()
        self.benchmark_results = []
        self.system_metrics = {}
        self.test_samples = []
        
    async def setup_benchmark_environment(self):
        """Setup performance testing environment"""
        print("Setting up performance benchmark environment...")
        
        # Generate test samples of various sizes
        await self.generate_performance_test_samples()
        
        # Warm up services
        await self.warm_up_services()
        
        # Collect baseline system metrics
        self.collect_baseline_metrics()
        
        print("Benchmark environment setup complete")
    
    async def generate_performance_test_samples(self):
        """Generate test samples for performance testing"""
        samples_dir = Path("tests/performance_samples")
        samples_dir.mkdir(parents=True, exist_ok=True)
        
        sample_sizes = [
            ("tiny", 1024),      # 1KB
            ("small", 10240),    # 10KB
            ("medium", 102400),  # 100KB
            ("large", 1048576),  # 1MB
            ("xlarge", 10485760) # 10MB
        ]
        
        for size_name, size_bytes in sample_sizes:
            sample_path = samples_dir / f"perf_test_{size_name}.bin"
            
            # Generate pseudo-random binary data
            import random
            random.seed(42)  # Deterministic
            
            with open(sample_path, "wb") as f:
                data = bytes([random.randint(0, 255) for _ in range(size_bytes)])
                f.write(data)
            
            self.test_samples.append({
                "name": size_name,
                "path": str(sample_path),
                "size_bytes": size_bytes,
                "size_mb": size_bytes / 1024 / 1024
            })
        
        print(f"Generated {len(self.test_samples)} performance test samples")
    
    async def warm_up_services(self):
        """Warm up all services to ensure fair benchmarking"""
        services = [
            "http://localhost:8001/health",  # analysis-engine
            "http://localhost:8002/health",  # ghidra-analysis
            "http://localhost:8003/health",  # frida-analysis
            "http://localhost:8004/health",  # memory-forensics
            "http://localhost:8005/health"   # ai-analysis
        ]
        
        for service_url in services:
            try:
                for _ in range(3):  # Make 3 calls to warm up
                    requests.get(service_url, timeout=5)
                    await asyncio.sleep(0.5)
            except Exception as e:
                print(f"Warning: Could not warm up {service_url}: {e}")
    
    def collect_baseline_metrics(self):
        """Collect baseline system metrics"""
        self.system_metrics["baseline"] = {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "available_memory_gb": psutil.virtual_memory().available / 1024**3,
            "disk_usage_percent": psutil.disk_usage("/").percent,
            "network_io": psutil.net_io_counters()._asdict()
        }
    
    async def benchmark_static_analysis_performance(self):
        """Benchmark static analysis performance across sample sizes"""
        print("\\nBenchmarking static analysis performance...")
        
        results = []
        
        for sample in self.test_samples:
            print(f"  Testing {sample['name']} ({sample['size_mb']:.2f} MB)")
            
            # Monitor system resources
            start_cpu = psutil.cpu_percent()
            start_memory = psutil.virtual_memory().used / 1024**2  # MB
            
            start_time = time.time()
            
            try:
                # Submit static analysis
                with open(sample["path"], "rb") as f:
                    files = {"file": f}
                    data = {"analysis_depth": "standard"}
                    
                    response = requests.post(
                        "http://localhost:8001/analyze/static",
                        files=files,
                        data=data,
                        timeout=300
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        analysis_id = result["analysis_id"]
                        
                        # Wait for completion
                        await self.wait_for_completion(
                            f"http://localhost:8001/analyze/status/{analysis_id}"
                        )
                        
                        end_time = time.time()
                        duration = end_time - start_time
                        
                        # Calculate resource usage
                        end_cpu = psutil.cpu_percent()
                        end_memory = psutil.virtual_memory().used / 1024**2
                        
                        cpu_usage = max(0, end_cpu - start_cpu)
                        memory_delta = max(0, end_memory - start_memory)
                        throughput = sample["size_mb"] / duration if duration > 0 else 0
                        
                        benchmark_result = BenchmarkResult(
                            operation=f"static_analysis_{sample['name']}",
                            duration_seconds=duration,
                            memory_usage_mb=memory_delta,
                            cpu_usage_percent=cpu_usage,
                            throughput_items_per_second=throughput,
                            success=True
                        )
                        
                        results.append(benchmark_result)
                        self.benchmark_results.append(benchmark_result)
                        
                        print(f"    Duration: {duration:.2f}s, Throughput: {throughput:.2f} MB/s")
                        
                    else:
                        print(f"    Failed: HTTP {response.status_code}")
                        
            except Exception as e:
                print(f"    Error: {e}")
                benchmark_result = BenchmarkResult(
                    operation=f"static_analysis_{sample['name']}",
                    duration_seconds=0,
                    memory_usage_mb=0,
                    cpu_usage_percent=0,
                    throughput_items_per_second=0,
                    success=False,
                    error_message=str(e)
                )
                results.append(benchmark_result)
                self.benchmark_results.append(benchmark_result)
            
            # Cool down between tests
            await asyncio.sleep(5)
        
        return results
    
    async def benchmark_ghidra_performance(self):
        """Benchmark Ghidra decompilation performance"""
        print("\\nBenchmarking Ghidra decompilation performance...")
        
        results = []
        
        # Test with medium and large samples (Ghidra is resource intensive)
        test_samples = [s for s in self.test_samples if s["name"] in ["medium", "large"]]
        
        for sample in test_samples:
            print(f"  Testing {sample['name']} ({sample['size_mb']:.2f} MB)")
            
            start_time = time.time()
            start_memory = psutil.virtual_memory().used / 1024**2
            
            try:
                with open(sample["path"], "rb") as f:
                    files = {"binary": f}
                    data = {"analysis_type": "functions_only"}  # Faster analysis
                    
                    response = requests.post(
                        "http://localhost:8002/decompile",
                        files=files,
                        data=data,
                        timeout=600  # 10 minutes max
                    )
                    
                    if response.status_code == 200:
                        result = response.json()
                        analysis_id = result["analysis_id"]
                        
                        await self.wait_for_completion(
                            f"http://localhost:8002/decompile/status/{analysis_id}",
                            timeout=600
                        )
                        
                        duration = time.time() - start_time
                        memory_delta = psutil.virtual_memory().used / 1024**2 - start_memory
                        throughput = sample["size_mb"] / duration if duration > 0 else 0
                        
                        benchmark_result = BenchmarkResult(
                            operation=f"ghidra_decompile_{sample['name']}",
                            duration_seconds=duration,
                            memory_usage_mb=memory_delta,
                            cpu_usage_percent=psutil.cpu_percent(),
                            throughput_items_per_second=throughput,
                            success=True
                        )
                        
                        results.append(benchmark_result)
                        self.benchmark_results.append(benchmark_result)
                        
                        print(f"    Duration: {duration:.2f}s")
                        
                    else:
                        print(f"    Failed: HTTP {response.status_code}")
                        
            except Exception as e:
                print(f"    Error: {e}")
                benchmark_result = BenchmarkResult(
                    operation=f"ghidra_decompile_{sample['name']}",
                    duration_seconds=0,
                    memory_usage_mb=0,
                    cpu_usage_percent=0,
                    throughput_items_per_second=0,
                    success=False,
                    error_message=str(e)
                )
                results.append(benchmark_result)
                self.benchmark_results.append(benchmark_result)
            
            await asyncio.sleep(10)  # Longer cool down for Ghidra
        
        return results
    
    async def benchmark_ai_analysis_performance(self):
        """Benchmark AI analysis performance"""
        print("\\nBenchmarking AI analysis performance...")
        
        results = []
        
        # Test AI triage with different complexity levels
        test_data_sets = [
            {
                "name": "simple",
                "analysis_results": {
                    "file_info": {"size": 1024, "entropy": 4.5},
                    "imports": {"kernel32.dll": ["CreateFile", "ReadFile"]},
                    "strings": ["hello", "world"]
                }
            },
            {
                "name": "complex",
                "analysis_results": {
                    "file_info": {"size": 1048576, "entropy": 7.8},
                    "imports": {
                        "kernel32.dll": ["CreateFile", "WriteFile", "CreateProcess"] * 20,
                        "ws2_32.dll": ["WSAStartup", "socket", "connect"] * 10,
                        "crypt32.dll": ["CryptEncrypt", "CryptDecrypt"] * 5
                    },
                    "strings": [f"string_{i}" for i in range(100)]
                }
            }
        ]
        
        for test_data in test_data_sets:
            print(f"  Testing {test_data['name']} analysis")
            
            start_time = time.time()
            start_memory = psutil.virtual_memory().used / 1024**2
            
            try:
                triage_data = {
                    "analysis_results": test_data["analysis_results"],
                    "context_information": {"source": "performance_test"}
                }
                
                response = requests.post(
                    "http://localhost:8005/triage/intelligent",
                    json=triage_data,
                    timeout=120
                )
                
                if response.status_code == 200:
                    result = response.json()
                    analysis_id = result["analysis_id"]
                    
                    await self.wait_for_completion(
                        f"http://localhost:8005/triage/status/{analysis_id}"
                    )
                    
                    duration = time.time() - start_time
                    memory_delta = psutil.virtual_memory().used / 1024**2 - start_memory
                    
                    benchmark_result = BenchmarkResult(
                        operation=f"ai_triage_{test_data['name']}",
                        duration_seconds=duration,
                        memory_usage_mb=memory_delta,
                        cpu_usage_percent=psutil.cpu_percent(),
                        throughput_items_per_second=1.0 / duration if duration > 0 else 0,
                        success=True
                    )
                    
                    results.append(benchmark_result)
                    self.benchmark_results.append(benchmark_result)
                    
                    print(f"    Duration: {duration:.2f}s")
                    
                else:
                    print(f"    Failed: HTTP {response.status_code}")
                    
            except Exception as e:
                print(f"    Error: {e}")
            
            await asyncio.sleep(3)
        
        return results
    
    async def benchmark_concurrent_load(self):
        """Benchmark system under concurrent load"""
        print("\\nBenchmarking concurrent load performance...")
        
        concurrent_tasks = []
        num_concurrent = 3
        
        # Create concurrent static analysis tasks
        for i in range(num_concurrent):
            sample = self.test_samples[i % len(self.test_samples)]
            task = self.single_static_analysis_task(sample, f"concurrent_{i}")
            concurrent_tasks.append(task)
        
        start_time = time.time()
        start_cpu = psutil.cpu_percent()
        start_memory = psutil.virtual_memory().used / 1024**2
        
        # Execute concurrent tasks
        try:
            results = await asyncio.gather(*concurrent_tasks, return_exceptions=True)
            
            duration = time.time() - start_time
            cpu_delta = psutil.cpu_percent() - start_cpu
            memory_delta = psutil.virtual_memory().used / 1024**2 - start_memory
            
            successful_tasks = len([r for r in results if not isinstance(r, Exception)])
            
            benchmark_result = BenchmarkResult(
                operation="concurrent_load_test",
                duration_seconds=duration,
                memory_usage_mb=memory_delta,
                cpu_usage_percent=cpu_delta,
                throughput_items_per_second=successful_tasks / duration if duration > 0 else 0,
                success=successful_tasks == num_concurrent
            )
            
            self.benchmark_results.append(benchmark_result)
            
            print(f"  Completed {successful_tasks}/{num_concurrent} concurrent tasks in {duration:.2f}s")
            
        except Exception as e:
            print(f"  Concurrent load test failed: {e}")
    
    async def single_static_analysis_task(self, sample: Dict[str, Any], task_id: str):
        """Single static analysis task for concurrent testing"""
        try:
            with open(sample["path"], "rb") as f:
                files = {"file": f}
                data = {"analysis_depth": "basic"}
                
                response = requests.post(
                    "http://localhost:8001/analyze/static",
                    files=files,
                    data=data,
                    timeout=180
                )
                
                if response.status_code == 200:
                    result = response.json()
                    analysis_id = result["analysis_id"]
                    
                    await self.wait_for_completion(
                        f"http://localhost:8001/analyze/status/{analysis_id}",
                        timeout=180
                    )
                    
                    return f"Task {task_id} completed successfully"
                else:
                    return Exception(f"Task {task_id} failed: HTTP {response.status_code}")
                    
        except Exception as e:
            return e
    
    async def wait_for_completion(self, status_url: str, timeout: int = 300):
        """Wait for analysis completion"""
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
                
                await asyncio.sleep(2)
                
            except Exception as e:
                await asyncio.sleep(1)
        
        raise Exception(f"Timeout waiting for completion after {timeout} seconds")
    
    async def run_comprehensive_benchmarks(self):
        """Run all performance benchmarks"""
        print("Starting comprehensive performance benchmarks...")
        
        await self.setup_benchmark_environment()
        
        # Run individual benchmarks
        await self.benchmark_static_analysis_performance()
        await self.benchmark_ghidra_performance()
        await self.benchmark_ai_analysis_performance()
        await self.benchmark_concurrent_load()
        
        # Collect final system metrics
        self.collect_final_metrics()
        
        # Generate performance report
        report = self.generate_performance_report()
        
        # Save results
        self.save_benchmark_results(report)
        
        return report
    
    def collect_final_metrics(self):
        """Collect final system metrics"""
        self.system_metrics["final"] = {
            "cpu_percent": psutil.cpu_percent(interval=1),
            "memory_percent": psutil.virtual_memory().percent,
            "available_memory_gb": psutil.virtual_memory().available / 1024**3,
            "disk_usage_percent": psutil.disk_usage("/").percent,
            "network_io": psutil.net_io_counters()._asdict()
        }
    
    def generate_performance_report(self) -> Dict[str, Any]:
        """Generate comprehensive performance report"""
        report = {
            "benchmark_summary": {
                "total_tests": len(self.benchmark_results),
                "successful_tests": len([r for r in self.benchmark_results if r.success]),
                "failed_tests": len([r for r in self.benchmark_results if not r.success]),
                "total_duration": sum(r.duration_seconds for r in self.benchmark_results)
            },
            "performance_metrics": {},
            "system_impact": {},
            "recommendations": []
        }
        
        # Calculate performance metrics by operation type
        operation_groups = {}
        for result in self.benchmark_results:
            op_type = result.operation.split("_")[0]
            if op_type not in operation_groups:
                operation_groups[op_type] = []
            operation_groups[op_type].append(result)
        
        for op_type, results in operation_groups.items():
            if results:
                successful_results = [r for r in results if r.success]
                if successful_results:
                    durations = [r.duration_seconds for r in successful_results]
                    throughputs = [r.throughput_items_per_second for r in successful_results]
                    memory_usage = [r.memory_usage_mb for r in successful_results]
                    
                    report["performance_metrics"][op_type] = {
                        "avg_duration_seconds": statistics.mean(durations),
                        "min_duration_seconds": min(durations),
                        "max_duration_seconds": max(durations),
                        "avg_throughput": statistics.mean(throughputs) if throughputs else 0,
                        "avg_memory_usage_mb": statistics.mean(memory_usage),
                        "success_rate": len(successful_results) / len(results)
                    }
        
        # System impact analysis
        if "baseline" in self.system_metrics and "final" in self.system_metrics:
            baseline = self.system_metrics["baseline"]
            final = self.system_metrics["final"]
            
            report["system_impact"] = {
                "cpu_increase_percent": final["cpu_percent"] - baseline["cpu_percent"],
                "memory_increase_percent": final["memory_percent"] - baseline["memory_percent"],
                "memory_freed_gb": final["available_memory_gb"] - baseline["available_memory_gb"]
            }
        
        # Generate recommendations
        report["recommendations"] = self.generate_performance_recommendations(report)
        
        return report
    
    def generate_performance_recommendations(self, report: Dict[str, Any]) -> List[str]:
        """Generate performance recommendations"""
        recommendations = []
        
        # Check static analysis performance
        static_metrics = report["performance_metrics"].get("static", {})
        if static_metrics.get("avg_duration_seconds", 0) > 60:
            recommendations.append("Static analysis taking longer than expected - consider optimizing binary parsing")
        
        # Check Ghidra performance
        ghidra_metrics = report["performance_metrics"].get("ghidra", {})
        if ghidra_metrics.get("avg_duration_seconds", 0) > 300:
            recommendations.append("Ghidra decompilation is slow - consider increasing memory allocation")
        
        # Check memory usage
        system_impact = report.get("system_impact", {})
        if system_impact.get("memory_increase_percent", 0) > 50:
            recommendations.append("High memory usage detected - monitor for memory leaks")
        
        # Check success rates
        for op_type, metrics in report["performance_metrics"].items():
            if metrics.get("success_rate", 1.0) < 0.8:
                recommendations.append(f"{op_type} has low success rate - investigate failures")
        
        if not recommendations:
            recommendations.append("All performance metrics within acceptable ranges")
        
        return recommendations
    
    def save_benchmark_results(self, report: Dict[str, Any]):
        """Save benchmark results and generate visualizations"""
        results_dir = Path("tests/performance_results")
        results_dir.mkdir(parents=True, exist_ok=True)
        
        # Save JSON report
        with open(results_dir / "performance_report.json", "w") as f:
            json.dump(report, f, indent=2, default=str)
        
        # Create performance visualizations
        self.create_performance_charts(results_dir, report)
        
        print(f"\\nPerformance results saved to {results_dir}")
    
    def create_performance_charts(self, results_dir: Path, report: Dict[str, Any]):
        """Create performance visualization charts"""
        try:
            # Duration by operation type
            op_types = []
            durations = []
            
            for op_type, metrics in report["performance_metrics"].items():
                op_types.append(op_type)
                durations.append(metrics.get("avg_duration_seconds", 0))
            
            plt.figure(figsize=(10, 6))
            plt.bar(op_types, durations)
            plt.title("Average Duration by Operation Type")
            plt.xlabel("Operation Type")
            plt.ylabel("Duration (seconds)")
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(results_dir / "duration_by_operation.png")
            plt.close()
            
            # Success rate by operation
            success_rates = [metrics.get("success_rate", 0) * 100 
                           for metrics in report["performance_metrics"].values()]
            
            plt.figure(figsize=(10, 6))
            plt.bar(op_types, success_rates)
            plt.title("Success Rate by Operation Type")
            plt.xlabel("Operation Type")
            plt.ylabel("Success Rate (%)")
            plt.ylim(0, 100)
            plt.xticks(rotation=45)
            plt.tight_layout()
            plt.savefig(results_dir / "success_rate_by_operation.png")
            plt.close()
            
            print("  Performance charts generated")
            
        except Exception as e:
            print(f"  Could not generate charts: {e}")

# Main execution
if __name__ == "__main__":
    async def run_benchmarks():
        benchmark_suite = PerformanceBenchmarkSuite()
        report = await benchmark_suite.run_comprehensive_benchmarks()
        
        print("\\n" + "="*60)
        print("PERFORMANCE BENCHMARK RESULTS")
        print("="*60)
        print(f"Total Tests: {report['benchmark_summary']['total_tests']}")
        print(f"Successful: {report['benchmark_summary']['successful_tests']}")
        print(f"Failed: {report['benchmark_summary']['failed_tests']}")
        print(f"Total Duration: {report['benchmark_summary']['total_duration']:.2f}s")
        print("\\nPerformance Metrics:")
        
        for op_type, metrics in report["performance_metrics"].items():
            print(f"  {op_type.upper()}:")
            print(f"    Avg Duration: {metrics.get('avg_duration_seconds', 0):.2f}s")
            print(f"    Success Rate: {metrics.get('success_rate', 0)*100:.1f}%")
            print(f"    Avg Memory: {metrics.get('avg_memory_usage_mb', 0):.1f}MB")
        
        print("\\nRecommendations:")
        for rec in report["recommendations"]:
            print(f"  - {rec}")
    
    asyncio.run(run_benchmarks())