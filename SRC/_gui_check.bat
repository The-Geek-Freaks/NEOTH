@echo off
setlocal
if "%~1"=="" (
    echo ERROR: _gui_check.bat requires a cargo subcommand and arguments. 1>&2
    echo GUI_GATE_EXIT=2
    exit /b 2
)
call "%~dp0_msvc_env.bat"
if errorlevel 1 (
    echo GUI_GATE_EXIT=1
    exit /b 1
)
if not defined CARGO_BUILD_JOBS set "CARGO_BUILD_JOBS=2"
pushd "%~dp0"
rem A caller-provided -j overrides CARGO_BUILD_JOBS; put it before any `--` separator.
cargo %*
set "NEOTH_EXIT=%ERRORLEVEL%"
popd
echo GUI_GATE_EXIT=%NEOTH_EXIT%
exit /b %NEOTH_EXIT%
