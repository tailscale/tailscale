import cx from "classnames"
import React from "react"
import LegacyClientView from "src/components/views/legacy-client-view"
import LoginClientView from "src/components/views/login-client-view"
import ReadonlyClientView from "src/components/views/readonly-client-view"
import useAuth from "src/hooks/auth"
import useNodeData, { ClientVersion, UpdateProgress } from "src/hooks/node-data"
import ManagementClientView from "./views/management-client-view"
import { ReactComponent as UpdateAvailableIcon } from "src/icons/arrow-up-circle.svg"
import { ReactComponent as CheckCircleIcon } from "src/icons/check-circle.svg"
import { ReactComponent as XCircleIcon } from "src/icons/x-circle.svg"
import { ReactComponent as TailscaleLogo } from "src/icons/tailscale-logo.svg"
import Spinner from "src/ui/spinner"
import { apiFetch } from "src/api"
import { useState } from "react"



function UpdatingView(props: {
  updating: UpdateState,
  cv: ClientVersion,
  updateLog: string,
}) {
  const { updating, cv, updateLog } = props
  return (
    <>
      <div className="mx-auto">
        <TailscaleLogo />
      </div>
      <div className="flex-1 flex flex-col justify-center items-center text-center">
        {
          (updating === UpdateState.InProgress) ? (
            <>
              <Spinner size="sm" className="text-gray-400" />
              <h1 className="text-2xl m-3">Update in progress</h1>
              <p className="text-gray-400">
                The update shouldn't take more than a couple of minutes.
                Once it's completed, you will be asked to log in again.
              </p>
            </>
          ) : (updating === UpdateState.Complete) ? (
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

enum UpdateState {
  UpToDate,
  Available,
  InProgress,
  Complete,
  Failed
}

function UpdateAvailableNotification(props: {
  details: ClientVersion,
  updating: UpdateState,
  installUpdate: () => void
}) {
  const { details, updating, installUpdate } = props

  let buttonMessage = ''
  switch (updating) {
    case UpdateState.UpToDate:
      return null
    case UpdateState.InProgress:
      buttonMessage = 'Updating Tailscale...'
      break
    case UpdateState.Failed:
      buttonMessage = 'Update failed'
      break
    case UpdateState.Complete:
      buttonMessage = 'Update complete!'
      break
    default:
      buttonMessage = 'Update Tailscale on this device'
      break
  }

  return (
    <div className="width-full flex items-start min-width-0 m-2 mt-5 bg-stone-50 p-3 rounded-md border-gray-200 border">
      <UpdateAvailableIcon
        className="flex-shrink-0 mr-2 ml-1"
        title="hello"
        width="16"
      />
      <div>
        <h5 className="font-semibold">Tailscale update available</h5>
        <p className="text-sm mb-1 mt-1">
          {details.LatestVersion ? `Version ${details.LatestVersion}` : 'A new update'} is now available. <ChangelogText version={details.LatestVersion} />
          </p>
        <button
          className="button button-blue mb-3 mt-3 text-sm"
          onClick={installUpdate}
        >
          { buttonMessage }
        </button>
      </div>
    </div>
  )
}

function isStableTrack(ver: string): boolean {
  const middle = ver.split('.')[1];
  if (middle && Number(middle) % 2 === 0) {
    return true;
  }
  return false;
}

function ChangelogText({ version }: { version?: string }) {
  if (version && isStableTrack(version)) {
    return (
      <>
        Check out the <a href="https://tailscale.com/changelog/" className="link">release notes</a> to find out what's new!
      </>
    )
  }
  return null
}

export default function App() {
  const { data, refreshData, updateNode } = useNodeData()
  const { data: auth, loading: loadingAuth, waitOnAuth } = useAuth()
  const initialUpdateState =
    (data?.ClientVersion.RunningLatest) ? UpdateState.UpToDate : UpdateState.Available

  const [updating, setUpdating] = useState<UpdateState>(initialUpdateState)

  const [updateLog, setUpdateLog] = useState<string>('')

  const appendUpdateLog = (msg: string) => {
    console.log(msg)
    setUpdateLog(updateLog + msg + '\n')
  }

  const installUpdate = () => {
    if (!data) return

    const currentVersion = data.IPNVersion

    apiFetch('/update', 'POST')
      .catch(err => {
        console.log(err)
        setUpdating(UpdateState.Failed)
      })

    setUpdating(UpdateState.InProgress)

    let tsAwayForPolls = 0
    function poll() {
      apiFetch('/update/progress', 'GET')
      .then(res => res.json())
      .then((res: UpdateProgress[]) => {
        for (const up of res) {
          console.log(up)
          if (up.status === 'UpdateFailed') {
            setUpdating(UpdateState.Failed)
            if (up.message) appendUpdateLog('ERROR: ' + up.message)
            return
          }

          if (up.status === 'UpdateFinished') {
            // if update finished and tailscaled did not go away (ie. did not restart),
            // then the version being the same might not be an error, it might just require
            // the user to restart Tailscale manually (this is required in some cases in the
            // clientupdate package).
            if (up.version === currentVersion && tsAwayForPolls > 0) {
              setUpdating(UpdateState.Failed)
              appendUpdateLog('ERROR: Update failed, still running Tailscale ' + up.version)
              if (up.message) appendUpdateLog('ERROR: ' + up.message)
            }
            else {
              setUpdating(UpdateState.Complete)
              if (up.message) appendUpdateLog('INFO: ' + up.message)
            }
            return
          }

          setUpdating(UpdateState.InProgress)
          if (up.message) appendUpdateLog('INFO: ' + up.message)
        }

        setTimeout(poll, 1000)
      })
      .catch(err => {
        ++tsAwayForPolls
        if (tsAwayForPolls >= 5 * 60) {
          setUpdating(UpdateState.Failed)
          appendUpdateLog('ERROR: tailscaled went away but did not come back!')
          appendUpdateLog('ERROR: last error received:')
          appendUpdateLog(err.toString())
        }
        else {
          setTimeout(poll, 1000)
        }
      })
    }

    poll()
  }

  const updatingViewStates = [
    UpdateState.InProgress, UpdateState.Complete, UpdateState.Failed
  ]

  return (
    <div className="flex flex-col items-center min-w-sm max-w-lg mx-auto py-14">
      {!data || loadingAuth ? (
        <div className="text-center py-14">Loading...</div> // TODO(sonia): add a loading view
      ) : data?.Status === "NeedsLogin" || data?.Status === "NoState" ? (
        // Client not on a tailnet, render login.
        <LoginClientView
          data={data}
          onLoginClick={() => updateNode({ Reauthenticate: true })}
        />
      ) : data.DebugMode === "full" && auth?.ok ? (
        // Render new client interface in management mode.
        <ManagementClientView {...data} />
      ) : data.DebugMode === "login" || data.DebugMode === "full" ? (
        // Render new client interface in readonly mode.
        <ReadonlyClientView data={data} auth={auth} waitOnAuth={waitOnAuth} />
      ) : (
        // Render legacy client interface.
        <LegacyClientView
          data={data}
          refreshData={refreshData}
          updateNode={updateNode}
        />
      )}
      {data && !loadingAuth && <Footer licensesURL={data.LicensesURL} />}
    </div>
  )
}

export function Footer(props: { licensesURL: string; className?: string }) {
  return (
    <footer
      className={cx("container max-w-lg mx-auto text-center", props.className)}
    >
      <a
        className="text-xs text-gray-500 hover:text-gray-600"
        href={props.licensesURL}
      >
        Open Source Licenses
      </a>
    </footer>
  )
}
