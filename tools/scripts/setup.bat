@echo off
REM Batch script for Windows users
REM Run with: setup.bat [command]

setlocal

if "%~1"=="" goto help
if "%~1"=="help" goto help
if "%~1"=="build" goto build
if "%~1"=="dev" goto dev
if "%~1"=="stop" goto stop
if "%~1"=="clean" goto clean
if "%~1"=="health" goto health
if "%~1"=="quickstart" goto quickstart
goto unknown

:help
echo.
echo 🎮 Project Diablo 2 MCP Analysis Platform
echo ==========================================
echo Windows Batch Management Script
echo.
echo Available commands:
echo   setup.bat build              - Build all containers
echo   setup.bat dev                - Start development environment
echo   setup.bat stop               - Stop all services
echo   setup.bat clean              - Clean up containers and volumes
echo   setup.bat health             - Check service health
echo   setup.bat quickstart         - Guided setup and startup
echo.
echo Examples:
echo   setup.bat                    # Show this help
echo   setup.bat quickstart         # Quick start with guided setup
echo   setup.bat dev                # Start development environment
echo.
goto end

:build
echo 🔨 Building containers...
docker-compose build
if errorlevel 1 (
    echo ❌ Build failed
) else (
    echo ✅ Build completed successfully
)
goto end

:dev
echo 🚀 Starting development environment...
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d
if errorlevel 1 (
    echo ❌ Failed to start development environment
) else (
    echo ✅ Development environment started
    echo.
    echo 🎮 D2 Analysis Platform Started!
    echo VNC Access: vnc://localhost:5900
    echo Web Dashboard: http://localhost:80
    echo Dgraph UI: http://localhost:8081
    echo MCP Coordinator: http://localhost:8000
)
goto end

:stop
echo 🛑 Stopping services...
docker-compose down
if errorlevel 1 (
    echo ❌ Failed to stop services
) else (
    echo ✅ Services stopped
)
goto end

:clean
echo 🧹 Cleaning up containers and volumes...
docker-compose down -v --remove-orphans
docker system prune -f
if errorlevel 1 (
    echo ❌ Cleanup failed
) else (
    echo ✅ Cleanup completed
)
goto end

:health
echo 🔍 Checking service health...
powershell -Command "try { Invoke-WebRequest -Uri 'http://localhost:3000/health' -UseBasicParsing -TimeoutSec 5 | Out-Null; Write-Host 'D2 Analysis: ✅' } catch { Write-Host 'D2 Analysis: ❌' }"
powershell -Command "try { Invoke-WebRequest -Uri 'http://localhost:8000/health' -UseBasicParsing -TimeoutSec 5 | Out-Null; Write-Host 'MCP Coordinator: ✅' } catch { Write-Host 'MCP Coordinator: ❌' }"
powershell -Command "try { Invoke-WebRequest -Uri 'http://localhost:8081/health' -UseBasicParsing -TimeoutSec 5 | Out-Null; Write-Host 'Dgraph: ✅' } catch { Write-Host 'Dgraph: ❌' }"
echo Health check complete
goto end

:quickstart
echo 🚀 Starting quickstart setup...
python quickstart.py
if errorlevel 1 (
    echo ❌ Quickstart failed. Ensure Python is installed.
    echo Alternative: Run individual commands manually
)
goto end

:unknown
echo ❌ Unknown command: %~1
echo.
goto help

:end
echo.
echo For more help: setup.bat help
endlocal
