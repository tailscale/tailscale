
import React from "react"
import { ClientVersion } from "src/hooks/node-data"
import { Link } from "wouter"

export function UpdateAvailableNotification(props: {
  details: ClientVersion,
}) {
  const { details } = props
  
  return (
    <div className="card">
      <h2 className="mb-2">Update available {details.LatestVersion ? `(v${details.LatestVersion})` : null}</h2>
      <p className="text-sm mb-1 mt-1">
        {details.LatestVersion ? `Version ${details.LatestVersion}` : 'A new update'} is now available. <ChangelogText version={details.LatestVersion} />
      </p>
      <Link
        className="button button-blue mt-3 text-sm inline-block"
        to="/update"
      >
        Update now
      </Link>
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