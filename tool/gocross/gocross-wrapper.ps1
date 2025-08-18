# Copyright (c) Tailscale Inc & AUTHORS
# SPDX-License-Identifier: BSD-3-Clause

#Requires -Version 7.4

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 3.0

if (($Env:CI -eq 'true') -and ($Env:NOPWSHDEBUG -ne 'true')) {
    Set-PSDebug -Trace 1
}

<#
  .DESCRIPTION
  Copies the script's $args variable into an array, which is easier to work with
  when preparing to start child processes.
#>
function Copy-ScriptArgs {
    $list = [System.Collections.Generic.List[string]]::new($Script:args.Count)
    foreach ($arg in $Script:args) {
        $list.Add($arg)
    }
    return $list.ToArray()
}

<#
  .DESCRIPTION
  Copies the current environment into a hashtable, which is easier to work with
  when preparing to start child processes.
#>
function Copy-Environment {
    $result = @{}
    foreach ($pair in (Get-Item -Path Env:)) {
        $result[$pair.Key] = $pair.Value
    }
    return $result
}

<#
  .DESCRIPTION
  Outputs the fully-qualified path to the repository's root directory. This
  function expects to be run from somewhere within a git repository.
  The directory containing the git executable must be somewhere in the PATH.
#>
function Get-RepoRoot {
    Get-Command -Name 'git' | Out-Null
    $repoRoot = & git rev-parse --show-toplevel
    if ($LASTEXITCODE -ne 0) {
        throw "failed obtaining repo root: git failed with code $LASTEXITCODE"
    }

    # Git outputs a path containing forward slashes. Canonicalize.
    return [System.IO.Path]::GetFullPath($repoRoot)
}

<#
  .DESCRIPTION
  Runs the provided ScriptBlock in a child scope, restoring any changes to the
  current working directory once the script block completes.
#>
function Start-ChildScope {
    param (
        [Parameter(Mandatory = $true)]
        [ScriptBlock]$ScriptBlock
    )

    $initialLocation = Get-Location
    try {
        Invoke-Command -ScriptBlock $ScriptBlock
    }
    finally {
        Set-Location -Path $initialLocation
    }
}

<#
  .SYNOPSIS
  Write-Output with timestamps prepended to each line.
#>
function Write-Log {
    param ($message)
    $timestamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    Write-Output "$timestamp - $message"
}

$bootstrapScriptBlock = {

    $repoRoot = Get-RepoRoot

    Set-Location -LiteralPath $repoRoot

    switch -Wildcard -File .\go.toolchain.rev {
        "/*" { $toolchain = $_ }
        default {
            $rev = $_
            $tsgo = Join-Path $Env:USERPROFILE '.cache' 'tsgo'
            $toolchain = Join-Path $tsgo $rev
            if (-not (Test-Path -LiteralPath "$toolchain.extracted" -PathType Leaf -ErrorAction SilentlyContinue)) {
                New-Item -Force -Path $tsgo -ItemType Directory | Out-Null
                Remove-Item -Force -Recurse -LiteralPath $toolchain -ErrorAction SilentlyContinue
                Write-Log "Downloading Go toolchain $rev"

                # Values from https://web.archive.org/web/20250227081443/https://learn.microsoft.com/en-us/dotnet/api/system.runtime.interopservices.architecture?view=net-9.0
                $cpuArch = ([System.Runtime.InteropServices.RuntimeInformation]::OSArchitecture | Out-String -NoNewline)
                # Comparison in switch is case-insensitive by default.
                switch ($cpuArch) {
                    'x86' { $goArch = '386' }
                    'x64' { $goArch = 'amd64' }
                    default { $goArch = $cpuArch }
                }

                Invoke-WebRequest -Uri "https://github.com/tailscale/go/releases/download/build-$rev/windows-$goArch.tar.gz" -OutFile "$toolchain.tar.gz"
                try {
                    New-Item -Force -Path $toolchain -ItemType Directory | Out-Null
                    Start-ChildScope -ScriptBlock {
                        Set-Location -LiteralPath $toolchain
                        tar --strip-components=1 -xf "$toolchain.tar.gz"
                        if ($LASTEXITCODE -ne 0) {
                            throw "tar failed with exit code $LASTEXITCODE"
                        }
                    }
                    $rev | Out-File -FilePath "$toolchain.extracted"
                }
                finally {
                    Remove-Item -Force "$toolchain.tar.gz" -ErrorAction Continue
                }

                # Cleanup old toolchains.
                $maxDays = 90
                $oldFiles = Get-ChildItem -Path $tsgo -Filter '*.extracted' -File -Recurse -Depth 1 | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$maxDays) }
                foreach ($file in $oldFiles) {
                    Write-Log "Cleaning up old Go toolchain $($file.Basename)"
                    Remove-Item -LiteralPath $file.FullName -Force -ErrorAction Continue
                    $dirName = Join-Path $file.DirectoryName $file.Basename -Resolve -ErrorAction Continue
                    if ($dirName -and (Test-Path -LiteralPath $dirName -PathType Container -ErrorAction Continue)) {
                        Remove-Item -LiteralPath $dirName -Recurse -Force -ErrorAction Continue
                    }
                }
            }
        }
    }

    if ($Env:TS_USE_GOCROSS -ne '1') {
        return
    }

    if (Test-Path -LiteralPath $toolchain -PathType Container -ErrorAction SilentlyContinue) {
        $goMod = Join-Path $repoRoot 'go.mod' -Resolve
        $goLine = Get-Content -LiteralPath $goMod | Select-String -Pattern '^go (.*)$' -List
        $wantGoMinor = $goLine.Matches.Groups[1].Value.split('.')[1]
        $versionFile = Join-Path $toolchain 'VERSION'
        if (Test-Path -LiteralPath $versionFile -PathType Leaf -ErrorAction SilentlyContinue) {
            try {
                $haveGoMinor = ((Get-Content -LiteralPath $versionFile -TotalCount 1).split('.')[1]) -replace 'rc.*', ''
            }
            catch {
            }
        }

        if ([string]::IsNullOrEmpty($haveGoMinor) -or ($haveGoMinor -lt $wantGoMinor)) {
            Remove-Item -Force -Recurse -LiteralPath $toolchain -ErrorAction Continue
            Remove-Item -Force -LiteralPath "$toolchain.extracted" -ErrorAction Continue
        }
    }

    $wantVer = & git rev-parse HEAD
    $gocrossOk = $false
    $gocrossPath = '.\gocross.exe'
    if (Get-Command -Name $gocrossPath -CommandType Application -ErrorAction SilentlyContinue) {
        $gotVer = & $gocrossPath gocross-version 2> $null
        if ($gotVer -eq $wantVer) {
            $gocrossOk = $true
        }
    }

    if (-not $gocrossOk) {
        $goBuildEnv = Copy-Environment
        $goBuildEnv['CGO_ENABLED'] = '0'
        # Start-Process's -Environment arg applies diffs, so instead of removing
        # these variables from $goBuildEnv, we must set them to $null to indicate
        # that they should be cleared.
        $goBuildEnv['GOOS'] = $null
        $goBuildEnv['GOARCH'] = $null
        $goBuildEnv['GO111MODULE'] = $null
        $goBuildEnv['GOROOT'] = $null

        $procExe = Join-Path $toolchain 'bin' 'go.exe' -Resolve
        $proc = Start-Process -FilePath $procExe -WorkingDirectory $repoRoot -Environment $goBuildEnv -ArgumentList 'build', '-o', $gocrossPath, "-ldflags=-X=tailscale.com/version.gitCommitStamp=$wantVer", 'tailscale.com/tool/gocross' -NoNewWindow -Wait -PassThru
        if ($proc.ExitCode -ne 0) {
            throw 'error building gocross'
        }
    }

} # bootstrapScriptBlock

Start-ChildScope -ScriptBlock $bootstrapScriptBlock

$repoRoot = Get-RepoRoot

$execEnv = Copy-Environment
# Start-Process's -Environment arg applies diffs, so instead of removing
# these variables from $execEnv, we must set them to $null to indicate
# that they should be cleared.
$execEnv['GOROOT'] = $null

$argList = Copy-ScriptArgs

if ($Env:TS_USE_GOCROSS -ne '1') {
    $revFile = Join-Path $repoRoot 'go.toolchain.rev' -Resolve
    switch -Wildcard -File $revFile {
        "/*" { $toolchain = $_ }
        default {
            $rev = $_
            $tsgo = Join-Path $Env:USERPROFILE '.cache' 'tsgo'
            $toolchain = Join-Path $tsgo $rev -Resolve
        }
    }

    $procExe = Join-Path $toolchain 'bin' 'go.exe' -Resolve
    $proc = Start-Process -FilePath $procExe -WorkingDirectory $repoRoot -Environment $execEnv -ArgumentList $argList -NoNewWindow -Wait -PassThru
    exit $proc.ExitCode
}

$procExe = Join-Path $repoRoot 'gocross.exe' -Resolve
$proc = Start-Process -FilePath $procExe -WorkingDirectory $repoRoot -Environment $execEnv -ArgumentList $argList -NoNewWindow -Wait -PassThru
exit $proc.ExitCode
