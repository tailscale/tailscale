// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import React from "react"
import CheckCircleIcon from "src/assets/icons/check-circle.svg?react"
import XCircleIcon from "src/assets/icons/x-circle.svg?react"
import { ChangelogText } from "src/components/update-available"
import { UpdateState, useInstallUpdate } from "src/hooks/self-update"
import { VersionInfo } from "src/types"
import Button from "src/ui/button"
import Spinner from "src/ui/spinner"
import { useLocation } from "wouter"

/**
 * UpdatingView is rendered when the user initiates a Tailscale update, and
 * the update is in-progress, failed, or completed.
 */
export function UpdatingView({
  versionInfo,
  currentVersion,
}: {
  versionInfo?: VersionInfo
  currentVersion: string
}) {
  const [, setLocation] = useLocation()
  const { updateState, updateLog } = useInstallUpdate(
    currentVersion,
    versionInfo
  )
  return (
    <>
      <div className="flex-1 flex flex-col justify-center items-center text-center mt-56">
        {updateState === UpdateState.InProgress ? (
          <>
            <Spinner size="sm" className="text-gray-400" />
            <h1 className="text-2xl m-3">Update in progress</h1>
            <p className="text-gray-400">
              The update shouldn’t take more than a couple of minutes. Once it’s
              completed, you will be asked to log in again.
            </p>
          </>
        ) : updateState === UpdateState.Complete ? (
          <>
            <CheckCircleIcon />
            <h1 className="text-2xl m-3">Update complete!</h1>
            <p className="text-gray-400">
              You updated Tailscale
              {versionInfo && versionInfo.LatestVersion
                ? ` to ${versionInfo.LatestVersion}`
                : null}
              . <ChangelogText version={versionInfo?.LatestVersion} />
            </p>
            <Button
              className="m-3"
              sizeVariant="small"
              onClick={() => setLocation("/")}
            >
              Log in to access
            </Button>
          </>
        ) : updateState === UpdateState.UpToDate ? (
          <>
            <CheckCircleIcon />
            <h1 className="text-2xl m-3">Up to date!</h1>
            <p className="text-gray-400">
              You are already running Tailscale {currentVersion}, which is the
              newest version available.
            </p>
            <Button
              className="m-3"
              sizeVariant="small"
              onClick={() => setLocation("/")}
            >
              Return
            </Button>
          </>
        ) : (
          /* TODO(naman,sonia): Figure out the body copy and design for this view. */
          <>
            <XCircleIcon />
            <h1 className="text-2xl m-3">Update failed</h1>
            <p className="text-gray-400">
              Update
              {versionInfo && versionInfo.LatestVersion
                ? ` to ${versionInfo.LatestVersion}`
                : null}{" "}
              failed.
            </p>
            <Button
              className="m-3"
              sizeVariant="small"
              onClick={() => setLocation("/")}
            >
              Return
            </Button>
          </>
        )}
        <pre className="h-64 overflow-scroll m-3">
          <code>{updateLog}</code>
        </pre>
      </div>
    </>
  )
}
