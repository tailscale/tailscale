import React from "react"
import {
  ClientVersion,
  UpdateState,
  useInstallUpdate,
} from "src/hooks/self-update"
import { ReactComponent as CheckCircleIcon } from "src/icons/check-circle.svg"
import { ReactComponent as XCircleIcon } from "src/icons/x-circle.svg"
import Spinner from "src/ui/spinner"
import { ChangelogText } from "src/ui/update-available"
import { Link } from "wouter"

/**
 * UpdatingView is rendered when the user initiates a Tailscale update, and
 * the update is in-progress, failed, or completed.
 */
export function UpdatingView({
  cv,
  current,
}: {
  cv: ClientVersion
  current: string
}) {
  const { updateState, updateLog } = useInstallUpdate(current, cv)
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
              {cv.LatestVersion ? ` to ${cv.LatestVersion}` : null}.{" "}
              <ChangelogText version={cv.LatestVersion} />
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
              You are already running Tailscale {current}, which is the newest
              version available.
            </p>
            <Link className="button button-blue text-sm m-3" to="/">
              Return
            </Link>
          </>
        ) : (
          <>
            <XCircleIcon />
            <h1 className="text-2xl m-3">Update failed</h1>
            <p className="text-gray-400">
              Update{cv.LatestVersion ? ` to ${cv.LatestVersion}` : null}{" "}
              failed. TODO(naman): what now?
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
