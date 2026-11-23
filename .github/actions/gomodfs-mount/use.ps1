# Copyright (c) Tailscale Inc & contributors
# SPDX-License-Identifier: BSD-3-Clause

# use.ps1 checks that the gomodfs started by start.ps1 survived into this
# step, then points GOMODCACHE and ~/.cache/tsgo at the mount for later
# steps and sets the step output success=true. It never fails the step.

$ErrorActionPreference = 'Stop'

try {
    if (-not (Get-Process gomodfs -ErrorAction SilentlyContinue) -or
        -not (Test-Path "$env:DRIVE\.gomodfs-status")) {
        Get-Content -LiteralPath $env:LOG -Tail 20 -ErrorAction SilentlyContinue
        throw 'gomodfs did not survive past the step that started it'
    }

    $cache = Join-Path $env:USERPROFILE '.cache'
    $tsgo = Join-Path $cache 'tsgo'
    New-Item -ItemType Directory -Force $cache | Out-Null
    $old = Get-Item -LiteralPath $tsgo -Force -ErrorAction SilentlyContinue
    if ($old) {
        if ($old.LinkType) {
            $old.Delete()
        } else {
            Remove-Item -LiteralPath $tsgo -Recurse -Force
        }
    }
    New-Item -ItemType SymbolicLink -Path $tsgo -Target "$env:DRIVE\tsgo-windows-amd64" | Out-Null

    "GOMODCACHE=$env:DRIVE\" >> $env:GITHUB_ENV
    "success=true" >> $env:GITHUB_OUTPUT
    "gomodfs is mounted on $env:DRIVE; GOMODCACHE and $tsgo point at it"
} catch {
    "::warning::not using gomodfs: $_"
}
