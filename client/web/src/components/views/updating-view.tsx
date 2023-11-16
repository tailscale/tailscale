import React from "react"
import { ReactComponent as CheckCircleIcon } from "src/assets/icons/check-circle.svg"
import { ReactComponent as XCircleIcon } from "src/assets/icons/x-circle.svg"
import { ChangelogText } from "src/components/update-available"
import {
  UpdateState,
  useInstallUpdate,
  VersionInfo,
} from "src/hooks/self-update"
import Spinner from "src/ui/spinner"
import { Link } from "wouter"

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
              The update shouldn't take more than a couple of minutes. Once it's
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
            <Link className="button button-blue text-sm m-3" to="/">
              Log in to access
            </Link>
          </>
        ) : updateState === UpdateState.UpToDate ? (
          <>
            <CheckCircleIcon />
            <h1 className="text-2xl m-3">Up to date!</h1>
            <p className="text-gray-400">
              You are already running Tailscale {currentVersion}, which is the
              newest version available.
            </p>
            <Link className="button button-blue text-sm m-3" to="/">
              Return
            </Link>
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
            <Link className="button button-blue text-sm m-3" to="/">
              Return
            </Link>
          </>
        )}
        <pre className="h-64 overflow-scroll m-3">
          <code>{updateLog}</code>
        </pre>
      </div>
    </>
  )
}
