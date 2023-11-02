
import React from "react"
import { ClientVersion, UpdateState, UpdateProgress } from "src/hooks/node-data"
import { ReactComponent as UpdateAvailableIcon } from "src/icons/arrow-up-circle.svg"
import { apiFetch } from "src/api"

export function UpdateAvailableNotification(props: {
  currentVersion: string,
  details: ClientVersion,
  updating: UpdateState,
  setUpdating: (u: UpdateState) => void,
  appendUpdateLog: (msg: string) => void,
}) {
  const { details, updating, currentVersion, setUpdating, appendUpdateLog } = props
  
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
          onClick={() => installUpdate(currentVersion, setUpdating, appendUpdateLog)}
        >
          { buttonMessage }
        </button>
      </div>
    </div>
  )
}


function installUpdate(
  currentVersion: string,
  setUpdating: (u: UpdateState) => void,
  appendUpdateLog: (msg: string) => void,
) {
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
  
function isStableTrack(ver: string): boolean {
  const middle = ver.split('.')[1];
  if (middle && Number(middle) % 2 === 0) {
    return true;
  }
  return false;
}
  
export function ChangelogText({ version }: { version?: string }) {
  if (version && isStableTrack(version)) {
    return (
      <>
        Check out the <a href="https://tailscale.com/changelog/" className="link">release notes</a> to find out what's new!
      </>
    )
  }
  return null
}