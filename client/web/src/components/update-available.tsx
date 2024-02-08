// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import React from "react"
import { VersionInfo } from "src/types"
import Button from "src/ui/button"
import Card from "src/ui/card"
import { useLocation } from "wouter"

export function UpdateAvailableNotification({
  details,
}: {
  details: VersionInfo
}) {
  const [, setLocation] = useLocation()

  return (
    <Card>
      <h2 className="mb-2">
        Update available{" "}
        {details.LatestVersion && `(v${details.LatestVersion})`}
      </h2>
      <p className="text-sm mb-1 mt-1">
        {details.LatestVersion
          ? `Version ${details.LatestVersion}`
          : "A new update"}{" "}
        is now available. <ChangelogText version={details.LatestVersion} />
      </p>
      <Button
        className="mt-3 inline-block"
        sizeVariant="small"
        onClick={() => setLocation("/update")}
      >
        Update now
      </Button>
    </Card>
  )
}

// isStableTrack takes a Tailscale version string
// of form X.Y.Z (or vX.Y.Z) and returns whether
// it is a stable release (even value of Y)
// or unstable (odd value of Y).
// eg. isStableTrack("1.48.0") === true
// eg. isStableTrack("1.49.112") === false
function isStableTrack(ver: string): boolean {
  const middle = ver.split(".")[1]
  if (middle && Number(middle) % 2 === 0) {
    return true
  }
  return false
}

export function ChangelogText({ version }: { version?: string }) {
  if (!version || !isStableTrack(version)) {
    return null
  }
  return (
    <>
      Check out the{" "}
      <a href="https://tailscale.com/changelog/" className="link">
        release notes
      </a>{" "}
      to find out what’s new!
    </>
  )
}
