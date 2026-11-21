# Copyright (c) Tailscale Inc & contributors
# SPDX-License-Identifier: BSD-3-Clause

# check.ps1 fails if the gomodfs mounted by this action has exited,
# printing the tail of its log. Run it at the end of a job that used the
# action, with $env:LOG set to the action's log output and $env:JOB_STATUS
# set to job.status.

$p = Get-Process gomodfs -ErrorAction SilentlyContinue
if ($p) {
    "gomodfs is running (pid $($p.Id))"
    if ($env:JOB_STATUS -ne 'success') {
        "job failed; last lines of gomodfs's log:"
        Get-Content -LiteralPath $env:LOG -Tail 50 -ErrorAction SilentlyContinue
    }
    exit 0
}
"::error::gomodfs.exe is no longer running, so the job's Go module cache and toolchain were gone"
"last lines of gomodfs's log:"
Get-Content -LiteralPath $env:LOG -Tail 50 -ErrorAction SilentlyContinue
exit 1
