import { useEffect, useState } from "react"
import { apiFetch } from "src/api"

// see tailcfg.ClientVersion
export type ClientVersion = {
  RunningLatest: boolean
  LatestVersion?: string
}

// see ipnstate.UpdateProgress
export type UpdateProgress = {
  status: "UpdateFinished" | "UpdateInProgress" | "UpdateFailed"
  message: string
  version: string
}

export enum UpdateState {
  UpToDate,
  Available,
  InProgress,
  Complete,
  Failed,
}

export function useInstallUpdate(currentVersion: string, cv: ClientVersion) {
  const [updateState, setUpdateState] = useState<UpdateState>(
    cv.RunningLatest ? UpdateState.UpToDate : UpdateState.Available
  )

  const [updateLog, setUpdateLog] = useState<string>("")

  const appendUpdateLog = (msg: string) => {
    setUpdateLog(updateLog + msg + "\n")
  }

  useEffect(() => {
    if (updateState !== UpdateState.Available) {
      // useEffect cleanup function
      return () => {}
    }
    apiFetch("/update", "POST").catch((err) => {
      console.log(err)
      setUpdateState(UpdateState.Failed)
    })

    setUpdateState(UpdateState.InProgress)

    let tsAwayForPolls = 0
    let updateMessagesRead = 0

    let timer = 0

    function poll() {
      apiFetch("/update/progress", "GET")
        .then((res) => res.json())
        .then((res: UpdateProgress[]) => {
          for (; updateMessagesRead < res.length; ++updateMessagesRead) {
            const up = res[updateMessagesRead]
            if (up.status === "UpdateFailed") {
              setUpdateState(UpdateState.Failed)
              if (up.message) appendUpdateLog("ERROR: " + up.message)
              return
            }

            if (up.status === "UpdateFinished") {
              // if update finished and tailscaled did not go away (ie. did not restart),
              // then the version being the same might not be an error, it might just require
              // the user to restart Tailscale manually (this is required in some cases in the
              // clientupdate package).
              if (up.version === currentVersion && tsAwayForPolls > 0) {
                setUpdateState(UpdateState.Failed)
                appendUpdateLog(
                  "ERROR: Update failed, still running Tailscale " + up.version
                )
                if (up.message) appendUpdateLog("ERROR: " + up.message)
              } else {
                setUpdateState(UpdateState.Complete)
                if (up.message) appendUpdateLog("INFO: " + up.message)
              }
              return
            }

            setUpdateState(UpdateState.InProgress)
            if (up.message) appendUpdateLog("INFO: " + up.message)
          }

          timer = setTimeout(poll, 1000)
        })
        .catch((err) => {
          ++tsAwayForPolls
          if (tsAwayForPolls >= 5 * 60) {
            setUpdateState(UpdateState.Failed)
            appendUpdateLog(
              "ERROR: tailscaled went away but did not come back!"
            )
            appendUpdateLog("ERROR: last error received:")
            appendUpdateLog(err.toString())
          } else {
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
  }, [updateState])

  return { updateState, updateLog }
}
