@echo off
REM Wazuh Active Response entry point. execd on Windows can only launch
REM .exe/.cmd/.bat, so this wrapper starts yara.ps1 and lets it inherit the
REM alert JSON that execd writes to STDIN.
REM
REM -NoProfile        keeps a user profile from altering the environment.
REM -ExecutionPolicy  runs the script without signing it or relaxing the
REM                   machine policy.
REM %~dp0             resolves next to this .bat, so the pair stays together
REM                   whatever the agent install path is.
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0yara.ps1"
exit /b %errorlevel%
