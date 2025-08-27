# Makefile for Reverse Engineering Platform
# Comprehensive build, test, and deployment automation

.PHONY: help build clean dev prod test test-integration test-performance health logs deploy stop restart

# Default target
.DEFAULT_GOAL := help

# Configuration
COMPOSE_FILE := docker-compose.yml
COMPOSE_DEV := docker-compose.dev.yml
COMPOSE_PROD := docker-compose.prod.yml

help: ## Show this help message
	@echo "Reverse Engineering Platform - Available Commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "Examples:"
	@echo "  make build         # Build all containers"
	@echo "  make dev           # Start development environment"
	@echo "  make test          # Run all tests"
	@echo "  make health        # Check service health"

# Build Targets
build: ## Build all containers
	@echo "Building all containers..."
	docker-compose -f $(COMPOSE_FILE) build --no-cache
	@echo "Build complete!"

build-quick: ## Quick build (use cache)
	@echo "Quick building all containers..."
	docker-compose -f $(COMPOSE_FILE) build
	@echo "Quick build complete!"

# Environment Targets
dev: ## Start development environment
	@echo "Starting development environment..."
	docker-compose -f $(COMPOSE_FILE) -f $(COMPOSE_DEV) up -d
	@echo "Development environment started!"
	@echo ""
	@echo "Services available at:"
	@echo "  Web Dashboard:     http://localhost:80"
	@echo "  MCP Coordinator:   http://localhost:8000"
	@echo "  Analysis Engine:   http://localhost:8001"
	@echo "  Ghidra Analysis:   http://localhost:8002"
	@echo "  Frida Analysis:    http://localhost:8003"
	@echo "  Memory Forensics:  http://localhost:8004"
	@echo "  AI Analysis:       http://localhost:8005"
	@echo "  VNC (Game View):   vnc://localhost:5900"
	@echo "  Dgraph UI:         http://localhost:8081"

prod: ## Start production environment
	@echo "Starting production environment..."
	docker-compose -f $(COMPOSE_FILE) -f $(COMPOSE_PROD) up -d
	@echo "Production environment started!"

stop: ## Stop all services
	@echo "Stopping all services..."
	docker-compose -f $(COMPOSE_FILE) -f $(COMPOSE_DEV) -f $(COMPOSE_PROD) down
	@echo "All services stopped!"

restart: ## Restart all services
	@echo "Restarting all services..."
	$(MAKE) stop
	sleep 5
	$(MAKE) dev
	@echo "All services restarted!"

# Testing Targets
test: ## Run all tests
	@echo "Running all tests..."
	$(MAKE) test-unit
	$(MAKE) test-integration
	@echo "All tests completed!"

test-unit: ## Run unit tests
	@echo "Running unit tests..."
	docker-compose run --rm analysis-engine python -m pytest tests/unit/ -v --tb=short
	docker-compose run --rm ai-analysis python -m pytest tests/unit/ -v --tb=short
	@echo "Unit tests completed!"

test-integration: ## Run integration tests
	@echo "Running integration tests..."
	@echo "Ensuring services are running..."
	$(MAKE) health
	python tests/integration/test_analysis_pipeline.py
	@echo "Integration tests completed!"

test-performance: ## Run performance benchmarks
	@echo "Running performance benchmarks..."
	@echo "Ensuring services are running..."
	$(MAKE) health
	python tests/validation/performance_benchmarks.py
	@echo "Performance benchmarks completed!"

# Health and Monitoring
health: ## Check service health
	@echo "Checking service health..."
	@python -c "
import requests
import sys
import time

services = {
    'MCP Coordinator': 'http://localhost:8000/health',
    'Analysis Engine': 'http://localhost:8001/health',
    'Ghidra Analysis': 'http://localhost:8002/health',
    'Frida Analysis': 'http://localhost:8003/health',
    'Memory Forensics': 'http://localhost:8004/health',
    'AI Analysis': 'http://localhost:8005/health'
}

all_healthy = True
for name, url in services.items():
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            health_data = response.json()
            status = health_data.get('status', 'unknown')
            if status == 'healthy':
                print(f'✓ {name:<20} HEALTHY')
            else:
                print(f'⚠ {name:<20} UNHEALTHY ({status})')
                all_healthy = False
        else:
            print(f'✗ {name:<20} HTTP {response.status_code}')
            all_healthy = False
    except Exception as e:
        print(f'✗ {name:<20} CONNECTION FAILED')
        all_healthy = False

if all_healthy:
    print('\\nAll services are healthy!')
    sys.exit(0)
else:
    print('\\nSome services are unhealthy!')
    sys.exit(1)
"

logs: ## Show logs from all services
	@echo "Showing logs from all services..."
	docker-compose -f $(COMPOSE_FILE) logs --tail=50 -f

logs-d2: ## Show D2 analysis logs only
	docker-compose -f $(COMPOSE_FILE) logs --tail=100 -f d2-analysis

# Cleaning Targets
clean: ## Clean up containers and volumes
	@echo "Cleaning up containers and volumes..."
	docker-compose -f $(COMPOSE_FILE) down -v --remove-orphans
	docker system prune -f
	@echo "Cleanup complete!"

clean-all: ## Deep clean (remove images too)
	@echo "Performing deep clean..."
	docker-compose -f $(COMPOSE_FILE) down -v --remove-orphans --rmi all
	docker system prune -af --volumes
	@echo "Deep clean complete!"

# Analysis Workflows
analyze-sample: ## Analyze a sample file (usage: make analyze-sample FILE=path/to/sample)
	@echo "Analyzing sample: $(FILE)"
	@python -c "
import requests

# Submit for static analysis
with open('$(FILE)', 'rb') as f:
    files = {'file': f}
    data = {'analysis_depth': 'comprehensive'}
    
    response = requests.post('http://localhost:8001/analyze/static', files=files, data=data)
    if response.status_code == 200:
        result = response.json()
        print(f'Analysis submitted: {result[\"analysis_id\"]}')
        print(f'Check status: http://localhost:8001/analyze/status/{result[\"analysis_id\"]}')
    else:
        print(f'Analysis failed: {response.status_code}')
"

# Setup and Initialization
setup: ## Initial project setup
	@echo "Setting up project..."
	mkdir -p data/{outputs,samples,binaries}
	mkdir -p data/outputs/{reports,dumps,sessions,screenshots}
	mkdir -p tests/{unit,integration,performance_results}
	mkdir -p backups
	$(MAKE) build
	@echo "Project setup complete!"
	@echo "Run 'make dev' to start the development environment"

init: ## Initialize after first setup
	@echo "Initializing platform..."
	$(MAKE) setup
	$(MAKE) dev
	@echo "Waiting for services to start..."
	sleep 30
	$(MAKE) health
	@echo "Platform initialization complete!"

# Quick Start
quickstart: ## Quick start for new users
	@echo "==================================="
	@echo "Reverse Engineering Platform"
	@echo "Quick Start Guide"
	@echo "==================================="
	@echo ""
	@echo "This will:"
	@echo "  1. Set up the project structure"
	@echo "  2. Build all containers"
	@echo "  3. Start the development environment"
	@echo "  4. Verify all services are healthy"
	@echo ""
	@echo "Continue? [y/N]"
	@read -r REPLY; \
	if [ "$$REPLY" = "y" ] || [ "$$REPLY" = "Y" ]; then \
		$(MAKE) init; \
		echo ""; \
		echo "🎉 Quick start complete!"; \
		echo ""; \
		echo "Next steps:"; \
		echo "  • Visit http://localhost:80 for the web dashboard"; \
		echo "  • Use 'make analyze-sample FILE=path/to/file' to analyze samples"; \
		echo "  • Run 'make test' to verify everything works"; \
		echo "  • Check 'make help' for more commands"; \
	else \
		echo "Quick start cancelled."; \
	fi

setup-game-files: ## Setup game files directory
	@echo "Setting up game files directory..."
	@mkdir -p data/game_files/pd2
	@echo "📁 Copy your Project Diablo 2 files to: data/game_files/pd2/"
	@echo "📁 Required structure matches your provided directory listing"

health: ## Check service health
	@echo "🔍 Checking service health..."
	@curl -f http://localhost:3000/health 2>/dev/null && echo "D2 Analysis: ✅" || echo "D2 Analysis: ❌"
	@curl -f http://localhost:8000/health 2>/dev/null && echo "MCP Coordinator: ✅" || echo "MCP Coordinator: ❌"
	@curl -f http://localhost:8081/health 2>/dev/null && echo "Dgraph: ✅" || echo "Dgraph: ❌"
	@echo "Health check complete"

quickstart: ## Quick start with guided setup (Windows/Linux compatible)
	python quickstart.py

# Windows-specific targets
build-windows: ## Build containers (Windows)
	docker-compose build

dev-windows: ## Start development environment (Windows)
	docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d
	@echo "🎮 D2 Analysis Platform Started!"
	@echo "VNC Access: http://localhost:5900"
	@echo "Web Dashboard: http://localhost:80"
	@echo "Dgraph UI: http://localhost:8081"
	@echo "MCP Coordinator: http://localhost:8000"

setup-game-files-windows: ## Setup game files directory (Windows)
	@echo "Setting up game files directory..."
	@if not exist "data\game_files\pd2" mkdir data\game_files\pd2
	@echo "📁 Copy your Project Diablo 2 files to: data\game_files\pd2\"

health-windows: ## Check service health (Windows)
	@echo "🔍 Checking service health..."
	@powershell -Command "try { Invoke-WebRequest -Uri 'http://localhost:3000/health' -UseBasicParsing -TimeoutSec 5 | Out-Null; Write-Host 'D2 Analysis: ✅' } catch { Write-Host 'D2 Analysis: ❌' }"
	@powershell -Command "try { Invoke-WebRequest -Uri 'http://localhost:8000/health' -UseBasicParsing -TimeoutSec 5 | Out-Null; Write-Host 'MCP Coordinator: ✅' } catch { Write-Host 'MCP Coordinator: ❌' }"
	@powershell -Command "try { Invoke-WebRequest -Uri 'http://localhost:8081/health' -UseBasicParsing -TimeoutSec 5 | Out-Null; Write-Host 'Dgraph: ✅' } catch { Write-Host 'Dgraph: ❌' }"
	@echo "Health check complete"
