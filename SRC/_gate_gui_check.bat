@echo off
setlocal
set "PATH=%SystemRoot%\System32;%SystemRoot%;%USERPROFILE%\.cargo\bin;%ProgramFiles%\Git\cmd"
call "%~dp0_msvc_env.bat"
if errorlevel 1 ( echo GATE_EXIT=1 & exit /b 1 )
set "CARGO_BUILD_JOBS=1"
set "CARGO_PROFILE_DEV_DEBUG=0"
pushd "%~dp0"
call "%~dp0_gui_lint.bat" --self-test
if errorlevel 1 ( popd & echo GATE_EXIT=1 & exit /b 1 )
call "%~dp0_gui_lint.bat"
if errorlevel 1 ( popd & echo GATE_EXIT=1 & exit /b 1 )
cargo fmt --check
if errorlevel 1 ( popd & echo GATE_EXIT=1 & exit /b 1 )
cargo check -p neothd-gui --tests -j1
set "E=%ERRORLEVEL%"
popd
echo GATE_EXIT=%E%
exit /b %E%
