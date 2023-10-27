import React from "react"
import { Footer, Header, IP, State } from "src/components/legacy"
import useAuth, { AuthResponse } from "src/hooks/auth"
import useNodeData, { NodeData, ClientVersion } from "src/hooks/node-data"
import { ReactComponent as ConnectedDeviceIcon } from "src/icons/connected-device.svg"
import { ReactComponent as TailscaleIcon } from "src/icons/tailscale-icon.svg"
import { ReactComponent as TailscaleLogo } from "src/icons/tailscale-logo.svg"
import { ReactComponent as UpdateAvailableIcon } from "src/icons/arrow-up-circle.svg"
import { ReactComponent as CheckCircleIcon } from "src/icons/check-circle.svg"
import { ReactComponent as XCircleIcon } from "src/icons/x-circle.svg"
import Spinner from "src/ui/spinner"
import { apiFetch } from "src/api"
import { useState } from "react"

export default function App() {
  // TODO(sonia): use isPosting value from useNodeData
  // to fill loading states.
  const { data, refreshData, updateNode } = useNodeData()

  const initialUpdateState =
    (data?.ClientVersion.RunningLatest) ? UpdateState.UpToDate : UpdateState.Available

  const [updating, setUpdating] = useState<UpdateState>(initialUpdateState)

  if (!data) {
    // TODO(sonia): add a loading view
    return <div className="text-center py-14">Loading...</div>
  }

  const needsLogin = data?.Status === "NeedsLogin" || data?.Status === "NoState"

  const installUpdate = () => {
    const currentVersion = data.ClientVersion

    apiFetch('/update', 'POST')
      .then(async (res) => {
        const reader = res.body?.getReader()
        const decoder = new TextDecoder()
        if (reader) {
          while (true) {
            const { done, value } = await reader.read()
            console.log(decoder.decode(value))
            if (done) break
          }
        }
      })
      .catch(err => {
        console.log(err)
        setUpdating(UpdateState.Failed)
      })

    setUpdating(UpdateState.InProgress)

    let tsAwayForPolls = 0
    function poll() {
      apiFetch('/data', 'GET')
      .then(res => res.json())
      .then((res: NodeData) => {
        if (updating === UpdateState.Failed) return
        if (tsAwayForPolls === 0) return setTimeout(poll, 1000)
        if (
          !res.ClientVersion.RunningLatest ||
          currentVersion.LatestVersion === res.ClientVersion.LatestVersion
        ) {
          setUpdating(UpdateState.Failed)
          return
        }
        // TODO(naman): do I need to worry about unraid csrf token?

        setUpdating(UpdateState.Complete)

        setTimeout(() => {
          setUpdating(UpdateState.UpToDate)
        }, 15 * 1000)
      })
      .catch(err => {
        ++tsAwayForPolls
        if (tsAwayForPolls >= 5 * 60) {
          setUpdating(UpdateState.Failed)
        }
        else {
          setTimeout(poll, 1000)
        }
      })
    }

    poll()
  }

  return !needsLogin &&
    (data.DebugMode === "login" || data.DebugMode === "full") ? (
    <WebClient {...data} updating={updating} installUpdate={installUpdate} />
  ) : (
    // Legacy client UI
    <div className="py-14">
      <main className="container max-w-lg mx-auto mb-8 py-6 px-8 bg-white rounded-md shadow-2xl">
        <Header data={data} refreshData={refreshData} updateNode={updateNode} />
        <IP data={data} />
        <State data={data} updateNode={updateNode} />
      </main>
      <Footer licensesURL={data.LicensesURL} />
    </div>
  )
}

// TODO(naman): clean this interface up?
function WebClient(props: NodeData & {
  updating: UpdateState,
  installUpdate: () => void
}) {
  const { data: auth, loading: loadingAuth, waitOnAuth } = useAuth()
  const { updating, installUpdate } = props

  if (loadingAuth) {
    return <div className="text-center py-14">Loading...</div>
  }

  const updatingViewStates = [
    UpdateState.InProgress, UpdateState.Complete, UpdateState.Failed
  ]

  return (
    <div className="flex flex-col items-center min-w-sm max-w-lg mx-auto py-10 align-middle h-screen">
      {(updatingViewStates.includes(updating)) ? (
        <UpdatingView updating={updating} cv={props.ClientVersion} />
      ) : (props.DebugMode === "full" && auth?.ok) ? (
        <ManagementView {...props} />
      ) : (
        <ReadonlyView data={props} auth={auth} waitOnAuth={waitOnAuth} updating={updating} installUpdate={installUpdate} />
      )}
      <Footer className="mt-20" licensesURL={props.LicensesURL} />
    </div>
  )
}

function UpdatingView(props: {
  updating: UpdateState,
  cv: ClientVersion
}) {
  const { updating, cv } = props
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
      </div>
    </>
  )
}

function ReadonlyView({
  data,
  auth,
  waitOnAuth,
  updating,
  installUpdate
}: {
  data: NodeData
  auth?: AuthResponse
  waitOnAuth: () => Promise<void>
  updating: UpdateState
  installUpdate: () => void
}) {
  return (
    <>
      <div className="pb-52 mx-auto">
        <TailscaleLogo />
      </div>
      <div className="w-full p-4 bg-stone-50 rounded-3xl border border-gray-200 flex flex-col gap-4">
        <div className="flex gap-2.5">
          <ProfilePic url={data.Profile.ProfilePicURL} />
          <div className="font-medium">
            <div className="text-neutral-500 text-xs uppercase tracking-wide">
              Owned by
            </div>
            <div className="text-neutral-800 text-sm leading-tight">
              {/* TODO(sonia): support tagged node profile view more eloquently */}
              {data.Profile.LoginName}
            </div>
          </div>
        </div>
        <div className="px-5 py-4 bg-white rounded-lg border border-gray-200">
          <div className="justify-between items-center flex">
            <div className="flex gap-3">
              <ConnectedDeviceIcon />
              <div className="text-neutral-800">
                <div className="text-lg font-medium leading-[25.20px]">
                  {data.DeviceName}
                </div>
                <div className="text-sm leading-tight">{data.IP}</div>
              </div>
            </div>
            {data.DebugMode === "full" && (
              <button
                className="button button-blue ml-6"
                onClick={() => {
                  window.open(auth?.authUrl, "_blank")
                  waitOnAuth()
                }}
              >
                Access
              </button>
            )}
          </div>
          <UpdateAvailableNotification details={data.ClientVersion} updating={updating} installUpdate={installUpdate} />
        </div>
      </div>
    </>
  )
}

function ManagementView(props: NodeData) {
  return (
    <div className="px-5">
      <div className="flex justify-between mb-12">
        <TailscaleIcon />
        <div className="flex">
          <p className="mr-2">{props.Profile.LoginName}</p>
          {/* TODO(sonia): support tagged node profile view more eloquently */}
          <ProfilePic url={props.Profile.ProfilePicURL} />
        </div>
      </div>
      <p className="tracking-wide uppercase text-gray-600 pb-3">This device</p>
      <div className="-mx-5 border rounded-md px-5 py-4 bg-white">
        <div className="flex justify-between items-center text-lg">
          <div className="flex items-center">
            <ConnectedDeviceIcon />
            <p className="font-medium ml-3">{props.DeviceName}</p>
          </div>
          <p className="tracking-widest">{props.IP}</p>
        </div>
      </div>
      <p className="text-gray-500 pt-2">
        Tailscale is up and running. You can connect to this device from devices
        in your tailnet by using its name or IP address.
      </p>
      <button className="button button-blue mt-6">Advertise exit node</button>
    </div>
  )
}

function ProfilePic({ url }: { url: string }) {
  return (
    <div className="relative flex-shrink-0 w-8 h-8 rounded-full overflow-hidden">
      {url ? (
        <div
          className="w-8 h-8 flex pointer-events-none rounded-full bg-gray-200"
          style={{
            backgroundImage: `url(${url})`,
            backgroundSize: "cover",
          }}
        />
      ) : (
        <div className="w-8 h-8 flex pointer-events-none rounded-full border border-gray-400 border-dashed" />
      )}
    </div>
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
