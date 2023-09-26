import React from "react"
import { Footer, Header, IP, State } from "src/components/legacy"
import useNodeData, { NodeData } from "src/hooks/node-data"
import { ReactComponent as ConnectedDeviceIcon } from "src/icons/connected-device.svg"
import { ReactComponent as TailscaleIcon } from "src/icons/tailscale-icon.svg"
import { ReactComponent as TailscaleLogo } from "src/icons/tailscale-logo.svg"

export default function App() {
  // TODO(sonia): use isPosting value from useNodeData
  // to fill loading states.
  const { data, refreshData, updateNode } = useNodeData()

  if (!data) {
    // TODO(sonia): add a loading view
    return <div className="text-center py-14">Loading...</div>
  }

  const needsLogin = data?.Status === "NeedsLogin" || data?.Status === "NoState"

  return !needsLogin &&
    (data.DebugMode === "login" || data.DebugMode === "full") ? (
    <div className="flex flex-col items-center min-w-sm max-w-lg mx-auto py-10">
      {data.DebugMode === "login" ? (
        <LoginView {...data} />
      ) : (
        <ManageView {...data} />
      )}
      <Footer className="mt-20" licensesURL={data.LicensesURL} />
    </div>
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

function LoginView(props: NodeData) {
  return (
    <>
      <div className="pb-52 mx-auto">
        <TailscaleLogo />
      </div>
      <div className="w-full p-4 bg-stone-50 rounded-3xl border border-gray-200 flex flex-col gap-4">
        <div className="flex gap-2.5">
          <ProfilePic url={props.Profile.ProfilePicURL} />
          <div className="font-medium">
            <div className="text-neutral-500 text-xs uppercase tracking-wide">
              Owned by
            </div>
            <div className="text-neutral-800 text-sm leading-tight">
              {/* TODO(sonia): support tagged node profile view more eloquently */}
              {props.Profile.LoginName}
            </div>
          </div>
        </div>
        <div className="px-5 py-4 bg-white rounded-lg border border-gray-200 justify-between items-center flex">
          <div className="flex gap-3">
            <ConnectedDeviceIcon />
            <div className="text-neutral-800">
              <div className="text-lg font-medium leading-[25.20px]">
                {props.DeviceName}
              </div>
              <div className="text-sm leading-tight">{props.IP}</div>
            </div>
          </div>
          <button className="button button-blue ml-6">Access</button>
        </div>
      </div>
    </>
  )
}

function ManageView(props: NodeData) {
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
