<#
  go.ps1 – Tailscale Go toolchain fetching wrapper for Windows/PowerShell
  • Reads go.toolchain.rev one dir above this script
  • If the requested commit hash isn't cached, downloads and unpacks
    https://github.com/tailscale/go/releases/download/build-${REV}/${OS}-${ARCH}.tar.gz
  • Finally execs the toolchain's "go" binary, forwarding all args & exit-code
#>

param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]] $Args
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ($env:CI -eq 'true' -and $env:NODEBUG -ne 'true') {
    $VerbosePreference = 'Continue'
}

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$REV      = (Get-Content (Join-Path $repoRoot 'go.toolchain.rev') -Raw).Trim()

if ([IO.Path]::IsPathRooted($REV)) {
    $toolchain = $REV
} else {
    if (-not [string]::IsNullOrWhiteSpace($env:TSGO_CACHE_ROOT)) {
        $cacheRoot = $env:TSGO_CACHE_ROOT
    } else {
        $cacheRoot = Join-Path $env:USERPROFILE '.cache\tsgo'
    }

    $toolchain = Join-Path $cacheRoot $REV
    $marker    = "$toolchain.extracted"

    if (-not (Test-Path $marker)) {
        Write-Host "# Downloading Go toolchain $REV" -ForegroundColor Cyan
        if (Test-Path $toolchain) { Remove-Item -Recurse -Force $toolchain }

        # Removing the marker file again (even though it shouldn't still exist)
        # because the equivalent Bash script also does so (to guard against
        # concurrent cache fills?).
        # TODO(bradfitz): remove this and add some proper locking instead?
        if (Test-Path $marker   ) { Remove-Item -Force $marker    }

        New-Item -ItemType Directory -Path $cacheRoot -Force | Out-Null

        $url  = "https://github.com/tailscale/go/releases/download/build-$REV/windows-amd64.tar.gz"
        $tgz  = "$toolchain.tar.gz"
        Invoke-WebRequest -Uri $url -OutFile $tgz -UseBasicParsing -ErrorAction Stop

        New-Item -ItemType Directory -Path $toolchain -Force | Out-Null
        tar --strip-components=1 -xzf $tgz -C $toolchain
        Remove-Item $tgz
        Set-Content -Path $marker -Value $REV
    }
}

$goExe = Join-Path $toolchain 'bin\go.exe'
if (-not (Test-Path $goExe)) { throw "go executable not found at $goExe" }

& $goExe @Args
exit $LASTEXITCODE

