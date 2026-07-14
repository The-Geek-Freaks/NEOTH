@echo off
setlocal
call "%~dp0_msvc_env.bat"
if errorlevel 1 (
    echo TEST_EXIT=1
    exit /b 1
)
if not defined CARGO_BUILD_JOBS set "CARGO_BUILD_JOBS=2"
if not defined NEOTH_TEST_THREADS if defined RUST_TEST_THREADS set "NEOTH_TEST_THREADS=%RUST_TEST_THREADS%"
if not defined NEOTH_TEST_THREADS set "NEOTH_TEST_THREADS=2"
pushd "%~dp0"
cargo test -p neoth --test %* -- --test-threads=%NEOTH_TEST_THREADS%
set "NEOTH_EXIT=%ERRORLEVEL%"
popd
echo TEST_EXIT=%NEOTH_EXIT%
exit /b %NEOTH_EXIT%
