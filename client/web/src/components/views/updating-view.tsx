import React from "react"
import { ReactComponent as CheckCircleIcon } from "src/icons/check-circle.svg"
import { ReactComponent as XCircleIcon } from "src/icons/x-circle.svg"
import { ReactComponent as TailscaleLogo } from "src/icons/tailscale-logo.svg"
import { ClientVersion, UpdateState, UpdateProgress } from "src/hooks/node-data"
import { ChangelogText } from "src/ui/update-available"
import Spinner from "src/ui/spinner"
import { apiFetch } from "src/api"
import { useState, useEffect } from "react"
import { Link } from "wouter"

/**
 * UpdatingView is rendered when the user initiates a Tailscale update, and
 * the update is in-progress, failed, or completed.
 */
export function UpdatingView({ cv, current }: {
  cv: ClientVersion,
  current: string,
}) {
  const initialUpdateState =
    cv.RunningLatest ? UpdateState.UpToDate : UpdateState.Available

  const [updateState, setUpdateState] = useState<UpdateState>(initialUpdateState)

  const [updateLog, setUpdateLog] = useState<string>('')

  const appendUpdateLog = (msg: string) => {
    setUpdateLog(updateLog + msg + '\n')
  }

  useEffect(() => {
    if (updateState !== UpdateState.Available) {
      return () => {}
    }
    return installUpdate(current, setUpdateState, appendUpdateLog)
  }, [updateState])

  return (
    <>
      <div className="flex-1 flex flex-col justify-center items-center text-center">
        {
          (updateState === UpdateState.InProgress) ? (
            <>
              <Spinner size="sm" className="text-gray-400" />
              <h1 className="text-2xl m-3">Update in progress</h1>
              <p className="text-gray-400">
                The update shouldn't take more than a couple of minutes.
                Once it's completed, you will be asked to log in again.
              </p>
            </>
          ) : (updateState === UpdateState.Complete) ? (
            <>
              <CheckCircleIcon />
              <h1 className="text-2xl m-3">Update complete!</h1>
              <p className="text-gray-400">
                You updated Tailscale{cv.LatestVersion ? ` to ${cv.LatestVersion}` : null}. <ChangelogText version={cv.LatestVersion} />
              </p>
              <Link
                className="button button-blue text-sm m-3"
                to="/"
              >
                Log in to access
              </Link>
            </>
          ) : (updateState === UpdateState.UpToDate) ? (
            <>
              <CheckCircleIcon />
              <h1 className="text-2xl m-3">Up to date!</h1>
              <p className="text-gray-400">
                You are already running Tailscale {current}, which is the newest version available.
              </p>
              <Link
                className="button button-blue text-sm m-3"
                to="/"
              >
                Return
              </Link>
            </>
          ) : (
            <>
              <XCircleIcon />
              <h1 className="text-2xl m-3">Update failed</h1>
              <p className="text-gray-400">
                Update{cv.LatestVersion ? ` to ${cv.LatestVersion}` : null} failed. TODO(naman): what now?
              </p>
              <Link
                className="button button-blue text-sm m-3"
                to="/"
              >
                Return
              </Link>
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

function installUpdate(
  currentVersion: string,
  setUpdateState: (u: UpdateState) => void,
  appendUpdateLog: (msg: string) => void,
) {
  apiFetch('/update', 'POST')
    .catch(err => {
      console.log(err)
      setUpdateState(UpdateState.Failed)
    })

  setUpdateState(UpdateState.InProgress)

  let tsAwayForPolls = 0
  let updateMessagesRead = 0

  let timer = 0

  function poll() {
    apiFetch('/update/progress', 'GET')
    .then(res => res.json())
    .then((res: UpdateProgress[]) => {
      for (; updateMessagesRead < res.length; ++updateMessagesRead) {
        const up = res[updateMessagesRead]
        if (up.status === 'UpdateFailed') {
          setUpdateState(UpdateState.Failed)
          if (up.message) appendUpdateLog('ERROR: ' + up.message)
          return
        }

        if (up.status === 'UpdateFinished') {
          // if update finished and tailscaled did not go away (ie. did not restart),
          // then the version being the same might not be an error, it might just require
          // the user to restart Tailscale manually (this is required in some cases in the
          // clientupdate package).
          if (up.version === currentVersion && tsAwayForPolls > 0) {
            setUpdateState(UpdateState.Failed)
            appendUpdateLog('ERROR: Update failed, still running Tailscale ' + up.version)
            if (up.message) appendUpdateLog('ERROR: ' + up.message)
          }
          else {
            setUpdateState(UpdateState.Complete)
            if (up.message) appendUpdateLog('INFO: ' + up.message)
          }
          return
        }

        setUpdateState(UpdateState.InProgress)
        if (up.message) appendUpdateLog('INFO: ' + up.message)
      }

      timer = setTimeout(poll, 1000)
    })
    .catch(err => {
      ++tsAwayForPolls
      if (tsAwayForPolls >= 5 * 60) {
        setUpdateState(UpdateState.Failed)
        appendUpdateLog('ERROR: tailscaled went away but did not come back!')
        appendUpdateLog('ERROR: last error received:')
        appendUpdateLog(err.toString())
      }
      else {
        timer = setTimeout(poll, 1000)
      }
    })
  }

  poll()

  // useEffect cleanup function
  return () => {
    if (timer) clearTimeout(timer)
    timer = 0
  }
}