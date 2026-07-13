@echo off
REM Quick MSVC build for the symbridge x64dbg plugin (no CMake needed).
REM Usage:  build.bat "C:\path\to\pluginsdk"
REM If no arg is given, falls back to the SDK path discovered during development.

setlocal
cd /d "%~dp0"
set "SDK=%~1"
if "%SDK%"=="" set "SDK=C:\Users\jjhjhjh\Downloads\snapshot_2026-05-27_12-11\pluginsdk"

set "VCVARS=C:\Program Files\Microsoft Visual Studio\18\Insiders\VC\Auxiliary\Build\vcvars64.bat"
if not exist "%VCVARS%" (
    echo [build] vcvars64.bat not found at "%VCVARS%"
    echo         Edit this file to point at your Visual Studio, or run from an
    echo         "x64 Native Tools Command Prompt" and call cl directly.
    exit /b 1
)

call "%VCVARS%"

cl /nologo /LD /EHsc /std:c++17 /O2 /DNDEBUG ^
   /I "%SDK%" /I "%SDK%\jansson" ^
   symbridge_x64dbg.cpp ^
   /link "%SDK%\x64dbg.lib" "%SDK%\x64bridge.lib" "%SDK%\jansson\jansson_x64.lib" ws2_32.lib ^
   /OUT:symbridge.dp64

if %errorlevel%==0 (
    echo.
    echo [build] OK: symbridge.dp64 created
    echo [build] Copy symbridge.dp64 into x64dbg\x64\plugins\
) else (
    echo [build] FAILED
)
endlocal
