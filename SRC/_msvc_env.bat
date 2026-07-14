@echo off
if defined VSCMD_VER if /i "%VSCMD_ARG_TGT_ARCH%"=="x64" exit /b 0

set "NEOTH_VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%NEOTH_VSWHERE%" (
    echo ERROR: Visual Studio Installer vswhere.exe was not found. 1>&2
    exit /b 1
)

set "NEOTH_VS_INSTALL="
for /f "usebackq delims=" %%I in (`"%NEOTH_VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "NEOTH_VS_INSTALL=%%I"
if not defined NEOTH_VS_INSTALL (
    echo ERROR: Visual Studio C++ x64 build tools were not found. 1>&2
    exit /b 1
)

if not exist "%NEOTH_VS_INSTALL%\VC\Auxiliary\Build\vcvars64.bat" (
    echo ERROR: vcvars64.bat was not found under "%NEOTH_VS_INSTALL%". 1>&2
    exit /b 1
)

call "%NEOTH_VS_INSTALL%\VC\Auxiliary\Build\vcvars64.bat"
if errorlevel 1 exit /b %ERRORLEVEL%

rem Some Build Tools installations initialise the Windows SDK UM libraries but
rem omit UCRT. Derive the matching SDK paths from vcvars instead of pinning a
rem machine-specific SDK version in every wrapper.
set "NEOTH_UCRT_INCLUDE=%WindowsSdkDir%Include\%WindowsSDKVersion%ucrt"
set "NEOTH_UCRT_LIB=%WindowsSdkDir%Lib\%WindowsSDKVersion%ucrt\x64"
if not exist "%NEOTH_UCRT_LIB%\ucrt.lib" (
    echo ERROR: ucrt.lib was not found for Windows SDK %WindowsSDKVersion%. 1>&2
    exit /b 1
)
set "INCLUDE=%INCLUDE%;%NEOTH_UCRT_INCLUDE%"
set "LIB=%LIB%;%NEOTH_UCRT_LIB%"
exit /b 0
