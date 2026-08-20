@echo off
setlocal DisableDelayedExpansion

set "NEOTH_GUI_LINT_PS=%~dp0_gui_lint.ps1"
if not exist "%NEOTH_GUI_LINT_PS%" (
    echo ERROR: _gui_lint.ps1 is missing next to _gui_lint.bat. 1>&2
    echo GUI_LINT_EXIT=2
    exit /b 2
)

if /i "%~1"=="--self-test" (
    if not "%~2"=="" (
        echo ERROR: _gui_lint.bat --self-test accepts no additional arguments. 1>&2
        echo GUI_LINT_EXIT=2
        exit /b 2
    )
    "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -File "%NEOTH_GUI_LINT_PS%" -SelfTest
) else (
    if not "%~1"=="" (
        echo ERROR: _gui_lint.bat accepts no arguments; use --self-test for checked-in fixtures. 1>&2
        echo GUI_LINT_EXIT=2
        exit /b 2
    )
    "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" -NoLogo -NoProfile -NonInteractive -File "%NEOTH_GUI_LINT_PS%"
)

set "NEOTH_EXIT=%ERRORLEVEL%"
echo GUI_LINT_EXIT=%NEOTH_EXIT%
exit /b %NEOTH_EXIT%
