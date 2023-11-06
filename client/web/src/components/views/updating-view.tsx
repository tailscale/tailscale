import React from "react"
import { ReactComponent as CheckCircleIcon } from "src/icons/check-circle.svg"
import { ReactComponent as XCircleIcon } from "src/icons/x-circle.svg"
import { ReactComponent as TailscaleLogo } from "src/icons/tailscale-logo.svg"
import { ClientVersion, UpdateState } from "src/hooks/node-data"
import { ChangelogText } from "src/ui/update-available"
import Spinner from "src/ui/spinner"

/**
 * UpdatingView is rendered when the user initiates a Tailscale update, and
 * the update is in-progress, failed, or completed.
 */
export function UpdatingView({ state, cv, updateLog }: {
  state: UpdateState,
  cv: ClientVersion,
  updateLog: string,
}) {
  return (
    <>
      <div className="mx-auto">
        <TailscaleLogo />
      </div>
      <div className="flex-1 flex flex-col justify-center items-center text-center">
        {
          (state === UpdateState.InProgress) ? (
            <>
              <Spinner size="sm" className="text-gray-400" />
              <h1 className="text-2xl m-3">Update in progress</h1>
              <p className="text-gray-400">
                The update shouldn't take more than a couple of minutes.
                Once it's completed, you will be asked to log in again.
              </p>
            </>
          ) : (state === UpdateState.Complete) ? (
            <>
              <CheckCircleIcon />
              <h1 className="text-2xl m-3">Update complete!</h1>
              <p className="text-gray-400">
                You updated Tailscale{cv.LatestVersion ? ` to ${cv.LatestVersion}` : null}. <ChangelogText version={cv.LatestVersion} />
              </p>
              <button
                className="button button-blue text-sm m-3"
                onClick={() => location.reload()}
              >
                Log in to access
              </button>
            </>
          ) : (
            <>
              <XCircleIcon />
              <h1 className="text-2xl m-3">Update failed</h1>
              <p className="text-gray-400">
                Update{cv.LatestVersion ? ` to ${cv.LatestVersion}` : null} failed. TODO(naman): what now?
              </p>
              <button
                className="button button-blue text-sm m-3"
                onClick={() => location.reload()}
              >
                Return
              </button>
            </>
          )
        }
        <pre className="h-64 overflow-scroll"><code>
          { updateLog }
        </code></pre>
      </div>
    </>
  )
}