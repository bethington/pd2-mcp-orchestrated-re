@echo off
echo Building MCP-Orchestrated D2 Analysis Platform...

REM Build all containers
docker-compose build

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ✅ Build completed successfully!
    echo.
    echo Next steps:
    echo   1. Copy .env.example to .env and customize if needed
    echo   2. Run: docker-compose up -d  [for basic setup]
    echo   3. Run: docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d  [for development]
    echo.
    echo Access points after deployment:
    echo   🎮 VNC Game View: vnc://localhost:5900
    echo   🌐 Web Dashboard: http://localhost:80
    echo   🔧 MCP Coordinator: http://localhost:8000
    echo   📊 Dgraph UI: http://localhost:8081
) else (
    echo.
    echo ❌ Build failed with error code %ERRORLEVEL%
    echo Check the output above for specific errors.
)

pause
