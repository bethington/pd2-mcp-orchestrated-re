@echo off
REM Test script for import_pd2_binaries endpoint
REM This script tests the PD2 binary import functionality via REST API

echo ========================================
echo Testing import_pd2_binaries endpoint
echo ========================================

REM Set the endpoint URL
set ENDPOINT_URL=http://localhost:8002/import/pd2_binaries

REM Test data for the import request
set TEST_DATA={\"project_name\":\"pd2_test\",\"scan_directory\":\"/app/pd2/ProjectD2\",\"file_extensions\":[\".exe\",\".dll\"]}

echo Endpoint: %ENDPOINT_URL%
echo Test Data: %TEST_DATA%
echo.

echo Making curl request...
echo.

curl -X POST "%ENDPOINT_URL%" ^
     -H "Content-Type: application/json" ^
     -d "%TEST_DATA%"

echo.
echo ========================================
echo Test completed
echo ========================================

REM Pause to see results
pause
