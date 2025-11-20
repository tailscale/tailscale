@echo off
rem Checking for PowerShell Core using PowerShell for Windows...
powershell -NoProfile -NonInteractive -Command "& {Get-Command -Name pwsh -ErrorAction Stop}" > NUL
if ERRORLEVEL 1 (
  rem Ask the user whether they should install the dependencies. Note that this
  rem code path never runs in CI because pwsh is always explicitly installed.

  rem Time out after 5 minutes, defaulting to 'N'
  choice /c yn /t 300 /d n /m "PowerShell Core is required. Install now"
  if ERRORLEVEL 2 (
    echo Aborting due to unmet dependencies.
    exit /b 1
  )

  rem Check for a .NET Core runtime using PowerShell for Windows...
  powershell -NoProfile -NonInteractive -Command "& {if (-not (dotnet --list-runtimes | Select-String 'Microsoft\.NETCore\.App' -Quiet)) {exit 1}}" > NUL
  rem Install .NET Core if missing to provide PowerShell Core's runtime library.
  if ERRORLEVEL 1 (
    rem Time out after 5 minutes, defaulting to 'N'
    choice /c yn /t 300 /d n /m "PowerShell Core requires .NET Core for its runtime library. Install now"
    if ERRORLEVEL 2 (
      echo Aborting due to unmet dependencies.
      exit /b 1
    )

    winget install --accept-package-agreements --id Microsoft.DotNet.Runtime.8 -e --source winget
  )

  rem Now install PowerShell Core.
  winget install --accept-package-agreements --id Microsoft.PowerShell -e --source winget
  if ERRORLEVEL 0 echo Please re-run this script within a new console session to pick up PATH changes.
  rem Either way we didn't build, so return 1.
  exit /b 1
)

pwsh -NoProfile -ExecutionPolicy Bypass "%~dp0..\tool\gocross\gocross-wrapper.ps1" %*
