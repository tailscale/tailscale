import React from "react"
import { NodeData } from "src/hooks/node-data"
import { ReactComponent as ConnectedDeviceIcon } from "src/icons/connected-device.svg"
import { ReactComponent as TailscaleIcon } from "src/icons/tailscale-icon.svg"
import ProfilePic from "src/ui/profile-pic"

export default function ManagementClientView(props: NodeData) {
  return (
    <div className="px-5 mb-12">
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
