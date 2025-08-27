# PowerShell build script for MCP-Orchestrated D2 Analysis Platform
param(
    [string]$Command = "build"
)

function Show-Usage {
    Write-Host "Usage: .\build.ps1 [command]" -ForegroundColor Green
    Write-Host "Commands:" -ForegroundColor Yellow
    Write-Host "  build    - Build all containers" -ForegroundColor White
    Write-Host "  dev      - Start development environment" -ForegroundColor White  
    Write-Host "  prod     - Start production environment" -ForegroundColor White
    Write-Host "  logs     - Show logs from all services" -ForegroundColor White
    Write-Host "  health   - Check service health" -ForegroundColor White
    Write-Host "  clean    - Clean up containers and volumes" -ForegroundColor White
}

function Build-Containers {
    Write-Host "Building MCP-Orchestrated D2 Analysis Platform..." -ForegroundColor Blue
    
    & docker-compose build
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "Build completed successfully!" -ForegroundColor Green
        Write-Host ""
        Write-Host "Next steps:" -ForegroundColor Yellow
        Write-Host "  1. Copy .env.example to .env and customize if needed" -ForegroundColor White
        Write-Host "  2. Run: .\build.ps1 dev    [for development]" -ForegroundColor White
        Write-Host "  3. Run: .\build.ps1 prod   [for production]" -ForegroundColor White
        Write-Host ""
        Write-Host "Access points after deployment:" -ForegroundColor Yellow
        Write-Host "  VNC Game View: vnc://localhost:5900" -ForegroundColor White
        Write-Host "  Web Dashboard: http://localhost:80" -ForegroundColor White
        Write-Host "  MCP Coordinator: http://localhost:8000" -ForegroundColor White
        Write-Host "  Dgraph UI: http://localhost:8081" -ForegroundColor White
    } else {
        Write-Host ""
        Write-Host "Build failed with error code $LASTEXITCODE" -ForegroundColor Red
        Write-Host "Check the output above for specific errors." -ForegroundColor Red
    }
}

function Start-Dev {
    Write-Host "Starting development environment..." -ForegroundColor Blue
    & docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "Development environment started!" -ForegroundColor Green
        Write-Host "VNC Access: http://localhost:5900 (password: none)" -ForegroundColor White
        Write-Host "Web Dashboard: http://localhost:80" -ForegroundColor White
        Write-Host "Dgraph UI: http://localhost:8081" -ForegroundColor White
        Write-Host "MCP Coordinator: http://localhost:8000" -ForegroundColor White
    }
}

function Start-Prod {
    Write-Host "Starting production environment..." -ForegroundColor Blue
    & docker-compose -f docker-compose.yml -f docker-compose.prod.yml up -d
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "Production environment started!" -ForegroundColor Green
    }
}

function Show-Logs {
    Write-Host "Showing service logs..." -ForegroundColor Blue
    & docker-compose logs -f
}

function Test-Health {
    Write-Host "Checking service health..." -ForegroundColor Blue
    
    $services = @(
        @{name="D2 Analysis"; url="http://localhost:3000/health"},
        @{name="MCP Coordinator"; url="http://localhost:8000/health"},
        @{name="Dgraph"; url="http://localhost:8081/health"}
    )
    
    foreach ($service in $services) {
        try {
            $response = Invoke-WebRequest -Uri $service.url -TimeoutSec 5 -UseBasicParsing
            if ($response.StatusCode -eq 200) {
                Write-Host "$($service.name): OK" -ForegroundColor Green
            } else {
                Write-Host "$($service.name): FAIL (Status: $($response.StatusCode))" -ForegroundColor Red
            }
        } catch {
            Write-Host "$($service.name): FAIL (Not responding)" -ForegroundColor Red
        }
    }
}

function Remove-Containers {
    Write-Host "Cleaning up containers and volumes..." -ForegroundColor Blue
    & docker-compose down -v --remove-orphans
    & docker system prune -f
    Write-Host "Cleanup complete!" -ForegroundColor Green
}

# Main script logic
switch ($Command.ToLower()) {
    "build" { Build-Containers }
    "dev" { Start-Dev }
    "prod" { Start-Prod }
    "logs" { Show-Logs }
    "health" { Test-Health }
    "clean" { Remove-Containers }
    default { Show-Usage }
}
