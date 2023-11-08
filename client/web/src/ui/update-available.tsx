
import React from "react"
import { ClientVersion, UpdateState } from "src/hooks/node-data"
import { ReactComponent as UpdateAvailableIcon } from "src/icons/arrow-up-circle.svg"
import { Link } from "wouter"

export function UpdateAvailableNotification(props: {
  currentVersion: string,
  details: ClientVersion,
}) {
  const { details, currentVersion } = props
  
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
        <Link
          className="button button-blue mb-3 mt-3 text-sm"
          to="/update"
        >
          Update Tailscale on this device
        </Link>
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