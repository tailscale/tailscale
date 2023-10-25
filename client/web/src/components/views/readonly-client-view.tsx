import React from "react"
import { AuthResponse } from "src/hooks/auth"
import { NodeData } from "src/hooks/node-data"
import { ReactComponent as ConnectedDeviceIcon } from "src/icons/connected-device.svg"
import { ReactComponent as TailscaleLogo } from "src/icons/tailscale-logo.svg"
import ProfilePic from "src/ui/profile-pic"

/**
 * ReadonlyClientView is rendered when the web interface is either
 *
 * 1. being viewed by a user not allowed to manage the node
 *    (e.g. user does not own the node)
 *
 * 2. or the user is allowed to manage the node but does not
 *    yet have a valid browser session.
 */
export default function ReadonlyClientView({
  data,
  auth,
  waitOnAuth,
}: {
  data: NodeData
  auth?: AuthResponse
  waitOnAuth: () => Promise<void>
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
              Managed by
            </div>
            <div className="text-neutral-800 text-sm leading-tight">
              {/* TODO(sonia): support tagged node profile view more eloquently */}
              {data.Profile.LoginName}
            </div>
          </div>
        </div>
        <div className="px-5 py-4 bg-white rounded-lg border border-gray-200 justify-between items-center flex">
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
      </div>
    </>
  )
}
