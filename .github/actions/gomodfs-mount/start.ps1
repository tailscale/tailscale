# Copyright (c) Tailscale Inc & contributors
# SPDX-License-Identifier: BSD-3-Clause

# start.ps1 installs WinFsp, gets gomodfs.exe, and starts it in the
# background, mounted on $env:DRIVE and backed by the remote store at
# $env:STORE_URL. On success it sets the step outputs started=true and
# log=<path to gomodfs's log>. It never fails the step; on any error it
# prints a warning so the job falls back to downloading modules directly.

$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$winfspURL = 'https://github.com/winfsp/winfsp/releases/download/v2.1/winfsp-2.1.25156.msi'
$winfspSHA256 = '073a70e00f77423e34bed98b86e600def93393ba5822204fac57a29324db9f7a'

$log = Join-Path $env:RUNNER_TEMP 'gomodfs.log'
"log=$log" >> $env:GITHUB_OUTPUT

function Time-Phase([string]$name, [scriptblock]$block) {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    & $block
    "${name}: $([math]::Round($sw.Elapsed.TotalSeconds, 1))s"
}

try {
    $url = $env:STORE_URL.TrimEnd('/')
    # The URL ends up on a cmd.exe command line below.
    if ($url -notmatch '^https?://[A-Za-z0-9.\-:\[\]]+$') {
        throw "unexpected gomodfs store URL format: $url"
    }

    Time-Phase 'checking gomodfs store' {
        $code = & curl.exe -sS -m 10 -o NUL -w '%{http_code}' -H 'Accept-Encoding: lz4' "$url/api/v1/modmap/golang.org/x/sync/@v/v0.10.0"
        if ($code -ne '200') {
            throw "gomodfs store at $url is not healthy: HTTP status $code"
        }
    }

    Time-Phase 'installing WinFsp' {
        $msi = Join-Path $env:RUNNER_TEMP 'winfsp.msi'
        Invoke-WebRequest -Uri $winfspURL -OutFile $msi
        $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $msi).Hash.ToLowerInvariant()
        if ($got -ne $winfspSHA256) {
            throw "WinFsp MSI has SHA-256 $got; want $winfspSHA256"
        }
        $msiLog = Join-Path $env:RUNNER_TEMP 'winfsp-install.log'
        $p = Start-Process -Wait -PassThru -FilePath msiexec.exe -ArgumentList '/i', "`"$msi`"", '/qn', '/norestart', '/l*', "`"$msiLog`""
        if ($p.ExitCode -ne 0) {
            Get-Content -LiteralPath $msiLog -Tail 30 -ErrorAction SilentlyContinue
            throw "WinFsp install failed with exit code $($p.ExitCode)"
        }
    }

    $exe = Join-Path $env:BIN_DIR 'gomodfs.exe'
    if (Test-Path -LiteralPath $exe) {
        "using cached $exe"
    } else {
        # Use the image's Go, not ./tool/go, which would download the
        # toolchain that the mount provides.
        Time-Phase 'building gomodfs' {
            if (-not (Get-Command go -ErrorAction SilentlyContinue)) {
                throw 'no go on PATH to build gomodfs with'
            }
            $tmp = Join-Path $env:RUNNER_TEMP 'gomodfs-build'
            $env:GOMODCACHE = Join-Path $tmp 'mod'
            $env:GOCACHE = Join-Path $tmp 'cache'
            $env:GOBIN = $env:BIN_DIR
            $env:GOFLAGS = '-modcacherw'
            $env:GOTOOLCHAIN = 'auto'
            $env:CGO_ENABLED = '0'
            Remove-Item Env:GOCACHEPROG -ErrorAction SilentlyContinue
            & go install "github.com/tailscale/gomodfs/cmd/gomodfs@$env:GOMODFS_VERSION"
            if ($LASTEXITCODE -ne 0) {
                throw "building gomodfs failed with exit code $LASTEXITCODE"
            }
        }
    }

    Time-Phase 'mounting gomodfs' {
        Remove-Item Env:PARENTDEATH_ADDR, Env:PARENTDEATH_SESSION -ErrorAction SilentlyContinue
        # Start gomodfs via ShellExecute (no -NoNewWindow or -Redirect*
        # flags) so it doesn't inherit this step's stdout and stderr pipes.
        # If it did, the runner would kill it when this step ends.
        $cmdArgs = "/d /s /c `"`"$exe`" --winfsp --mount=$env:DRIVE --remote-store=$url > `"$log`" 2>&1`""
        $p = Start-Process -PassThru -WindowStyle Hidden -FilePath $env:ComSpec -ArgumentList $cmdArgs
        $deadline = (Get-Date).AddSeconds(30)
        while (-not (Test-Path "$env:DRIVE\.gomodfs-status")) {
            if ($p.HasExited -or (Get-Date) -gt $deadline) {
                Get-Content -LiteralPath $log -Tail 20 -ErrorAction SilentlyContinue
                throw "mounting gomodfs on $env:DRIVE failed"
            }
            Start-Sleep -Milliseconds 100
        }
    }
    "started=true" >> $env:GITHUB_OUTPUT
} catch {
    "::warning::gomodfs setup failed: $_"
}
