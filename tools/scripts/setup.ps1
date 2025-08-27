# PowerShell script for Windows users
# Run with: .\setup.ps1

param(
    [Parameter(Mandatory=$false)]
    [string]$Command = "help"
)

function Show-Banner {
    Write-Host @"
🎮 Project Diablo 2 MCP Analysis Platform
==========================================
PowerShell Management Script
"@ -ForegroundColor Cyan
}

function Show-Help {
    Write-Host @"
Available commands:
  .\setup.ps1 build              - Build all containers
  .\setup.ps1 dev                - Start development environment  
  .\setup.ps1 prod               - Start production environment
  .\setup.ps1 stop               - Stop all services
  .\setup.ps1 clean              - Clean up containers and volumes
  .\setup.ps1 logs               - Show all service logs
  .\setup.ps1 logs-d2            - Show D2 analysis logs only
  .\setup.ps1 health             - Check service health
  .\setup.ps1 setup-game-files   - Create game files directory
  .\setup.ps1 quickstart         - Guided setup and startup

Examples:
  .\setup.ps1                    # Show this help
  .\setup.ps1 quickstart         # Quick start with guided setup
  .\setup.ps1 dev                # Start development environment
"@ -ForegroundColor Yellow
}

function Test-Docker {
    try {
        $null = docker --version
        $null = docker-compose --version
        return $true
    }
    catch {
        Write-Host "❌ Docker or Docker Compose not found. Please install Docker Desktop." -ForegroundColor Red
        return $false
    }
}

function Build-Containers {
    Write-Host "🔨 Building containers..." -ForegroundColor Green
    docker-compose build
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Build completed successfully" -ForegroundColor Green
    } else {
        Write-Host "❌ Build failed" -ForegroundColor Red
    }
}

function Start-Development {
    Write-Host "🚀 Starting development environment..." -ForegroundColor Green
    docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host @"
🎮 D2 Analysis Platform Started!
VNC Access: vnc://localhost:5900
Web Dashboard: http://localhost:80
Dgraph UI: http://localhost:8081
MCP Coordinator: http://localhost:8000
Jupyter Notebooks: http://localhost:8888
"@ -ForegroundColor Green
    } else {
        Write-Host "❌ Failed to start development environment" -ForegroundColor Red
    }
}

function Start-Production {
    Write-Host "🚀 Starting production environment..." -ForegroundColor Green
    docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Production environment started" -ForegroundColor Green
    } else {
        Write-Host "❌ Failed to start production environment" -ForegroundColor Red
    }
}

function Stop-Services {
    Write-Host "🛑 Stopping services..." -ForegroundColor Yellow
    docker-compose down
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Services stopped" -ForegroundColor Green
    } else {
        Write-Host "❌ Failed to stop services" -ForegroundColor Red
    }
}

function Clean-Environment {
    Write-Host "🧹 Cleaning up containers and volumes..." -ForegroundColor Yellow
    docker-compose down -v --remove-orphans
    docker system prune -f
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✅ Cleanup completed" -ForegroundColor Green
    } else {
        Write-Host "❌ Cleanup failed" -ForegroundColor Red
    }
}

function Show-Logs {
    param([string]$Service = $null)
    
    if ($Service) {
        Write-Host "📋 Showing logs for $Service..." -ForegroundColor Blue
        docker-compose logs -f $Service
    } else {
        Write-Host "📋 Showing all service logs..." -ForegroundColor Blue
        docker-compose logs -f
    }
}

function Test-Health {
    Write-Host "🔍 Checking service health..." -ForegroundColor Blue
    
    $services = @(
        @{ Name = "D2 Analysis"; Url = "http://localhost:3000/health" },
        @{ Name = "MCP Coordinator"; Url = "http://localhost:8000/health" },
        @{ Name = "Dgraph"; Url = "http://localhost:8081/health" }
    )
    
    foreach ($service in $services) {
        try {
            $response = Invoke-WebRequest -Uri $service.Url -UseBasicParsing -TimeoutSec 5
            if ($response.StatusCode -eq 200) {
                Write-Host "$($service.Name): ✅" -ForegroundColor Green
            } else {
                Write-Host "$($service.Name): ❌ (Status: $($response.StatusCode))" -ForegroundColor Red
            }
        }
        catch {
            Write-Host "$($service.Name): ❌ (Not responding)" -ForegroundColor Red
        }
    }
    
    Write-Host "Health check complete" -ForegroundColor Blue
}

function Setup-GameFilesDirectory {
    Write-Host "📁 Setting up game files directory..." -ForegroundColor Blue
    
    $gameDir = "data\game_files\pd2"
    if (!(Test-Path $gameDir)) {
        New-Item -ItemType Directory -Path $gameDir -Force | Out-Null
        Write-Host "✅ Created directory: $gameDir" -ForegroundColor Green
    } else {
        Write-Host "✅ Directory already exists: $gameDir" -ForegroundColor Green
    }
    
    Write-Host @"
📁 Copy your Project Diablo 2 files to: $gameDir\
📁 Required structure matches the listing in .github\copilot-instructions.md

Example PowerShell command:
Copy-Item -Recurse "C:\Path\To\Your\PD2\Installation\*" "$gameDir\"
"@ -ForegroundColor Yellow
}

function Start-Quickstart {
    Write-Host "🚀 Starting quickstart setup..." -ForegroundColor Green
    
    try {
        python quickstart.py
    }
    catch {
        Write-Host "❌ Failed to run quickstart script. Ensure Python is installed." -ForegroundColor Red
        Write-Host "Alternative: Run individual commands manually" -ForegroundColor Yellow
    }
}

# Main execution
Show-Banner

if (!(Test-Docker)) {
    exit 1
}

switch ($Command.ToLower()) {
    "help" { Show-Help }
    "build" { Build-Containers }
    "dev" { Start-Development }
    "prod" { Start-Production }
    "stop" { Stop-Services }
    "clean" { Clean-Environment }
    "logs" { Show-Logs }
    "logs-d2" { Show-Logs -Service "d2-analysis" }
    "health" { Test-Health }
    "setup-game-files" { Setup-GameFilesDirectory }
    "quickstart" { Start-Quickstart }
    default {
        Write-Host "❌ Unknown command: $Command" -ForegroundColor Red
        Show-Help
        exit 1
    }
}

Write-Host ""
Write-Host "For more help: .\setup.ps1 help" -ForegroundColor Cyan
