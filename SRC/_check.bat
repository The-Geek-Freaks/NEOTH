@echo off
setlocal
call "%~dp0_msvc_env.bat"
if errorlevel 1 (
    echo BUILD_EXIT=1
    exit /b 1
)
if not defined CARGO_BUILD_JOBS set "CARGO_BUILD_JOBS=2"
pushd "%~dp0"
cargo check -p neoth
set "NEOTH_EXIT=%ERRORLEVEL%"
popd
echo BUILD_EXIT=%NEOTH_EXIT%
exit /b %NEOTH_EXIT%
