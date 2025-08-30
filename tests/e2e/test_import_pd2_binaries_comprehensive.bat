@echo off
REM Comprehensive test script for import_pd2_binaries endpoint
REM Tests various scenarios and provides detailed output

echo ========================================
echo Comprehensive import_pd2_binaries Test
echo ========================================

REM Configuration
set ENDPOINT_URL=http://localhost:8002/import/pd2_binaries
set LOG_FILE=test_results_%DATE:~-4,4%%DATE:~-10,2%%DATE:~-7,2%_%TIME:~0,2%%TIME:~3,2%%TIME:~6,2%.log

echo Test started at %DATE% %TIME% > "%LOG_FILE%"
echo Endpoint: %ENDPOINT_URL% >> "%LOG_FILE%"
echo. >> "%LOG_FILE%"

REM Test 1: Basic import test
echo Test 1: Basic PD2 binary import
echo Test 1: Basic PD2 binary import >> "%LOG_FILE%"

set TEST_DATA1={\"project_name\":\"pd2_basic_test\",\"scan_directory\":\"/app/pd2/ProjectD2\",\"file_extensions\":[\".exe\",\".dll\"]}

echo Request Data: %TEST_DATA1% >> "%LOG_FILE%"
echo Making request... >> "%LOG_FILE%"

curl -X POST "%ENDPOINT_URL%" ^
     -H "Content-Type: application/json" ^
     -d "%TEST_DATA1%" ^
     -w "\nHTTP Status: %%{http_code}\nTotal Time: %%{time_total}s\n" >> "%LOG_FILE%" 2>&1

echo Test 1 completed
echo.

REM Test 2: Custom project name
echo Test 2: Custom project name test
echo Test 2: Custom project name test >> "%LOG_FILE%"

set TEST_DATA2={\"project_name\":\"pd2_custom_project\",\"scan_directory\":\"/app/pd2/ProjectD2\",\"file_extensions\":[\".exe\"]}

echo Request Data: %TEST_DATA2% >> "%LOG_FILE%"
echo Making request... >> "%LOG_FILE%"

curl -X POST "%ENDPOINT_URL%" ^
     -H "Content-Type: application/json" ^
     -d "%TEST_DATA2%" ^
     -w "\nHTTP Status: %%{http_code}\nTotal Time: %%{time_total}s\n" >> "%LOG_FILE%" 2>&1

echo Test 2 completed
echo.

REM Test 3: DLL only import
echo Test 3: DLL only import test
echo Test 3: DLL only import test >> "%LOG_FILE%"

set TEST_DATA3={\"project_name\":\"pd2_dll_only\",\"scan_directory\":\"/app/pd2/ProjectD2\",\"file_extensions\":[\".dll\"]}

echo Request Data: %TEST_DATA3% >> "%LOG_FILE%"
echo Making request... >> "%LOG_FILE%"

curl -X POST "%ENDPOINT_URL%" ^
     -H "Content-Type: application/json" ^
     -d "%TEST_DATA3%" ^
     -w "\nHTTP Status: %%{http_code}\nTotal Time: %%{time_total}s\n" >> "%LOG_FILE%" 2>&1

echo Test 3 completed
echo.

REM Test 4: Invalid directory test
echo Test 4: Invalid directory test
echo Test 4: Invalid directory test >> "%LOG_FILE%"

set TEST_DATA4={\"project_name\":\"pd2_invalid\",\"scan_directory\":\"/invalid/path\",\"file_extensions\":[\".exe\"]}

echo Request Data: %TEST_DATA4% >> "%LOG_FILE%"
echo Making request... >> "%LOG_FILE%"

curl -X POST "%ENDPOINT_URL%" ^
     -H "Content-Type: application/json" ^
     -d "%TEST_DATA4%" ^
     -w "\nHTTP Status: %%{http_code}\nTotal Time: %%{time_total}s\n" >> "%LOG_FILE%" 2>&1

echo Test 4 completed
echo.

REM Test 5: Health check
echo Test 5: Service health check
echo Test 5: Service health check >> "%LOG_FILE%"

curl -X GET "http://localhost:8002/" ^
     -w "\nHTTP Status: %%{http_code}\nTotal Time: %%{time_total}s\n" >> "%LOG_FILE%" 2>&1

echo Test 5 completed
echo.

REM Summary
echo ========================================
echo Test Summary
echo ========================================
echo All tests completed. Results saved to: %LOG_FILE%
echo.
echo Test scenarios:
echo 1. Basic PD2 binary import (.exe + .dll)
echo 2. Custom project name
echo 3. DLL only import
echo 4. Invalid directory (error handling)
echo 5. Service health check
echo.
echo Check the log file for detailed results and response data.
echo ========================================

REM Display log file location
echo Log file saved at: %CD%\%LOG_FILE%

pause
