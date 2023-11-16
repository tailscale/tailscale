import cx from "classnames"
import React, { useCallback, useEffect, useState } from "react"
import { ReactComponent as ChevronDown } from "src/assets/icons/chevron-down.svg"
import { ReactComponent as Eye } from "src/assets/icons/eye.svg"
import { ReactComponent as User } from "src/assets/icons/user.svg"
import { AuthResponse, AuthType } from "src/hooks/auth"
import { NodeData } from "src/hooks/node-data"
import Popover from "src/ui/popover"
import ProfilePic from "src/ui/profile-pic"

export default function LoginToggle({
  node,
  auth,
  newSession,
}: {
  node: NodeData
  auth: AuthResponse
  newSession: () => Promise<void>
}) {
  const [open, setOpen] = useState<boolean>(false)

  return (
    <Popover
      className="p-3 bg-white rounded-lg shadow flex flex-col gap-2 max-w-[317px]"
      content={
        <LoginPopoverContent node={node} auth={auth} newSession={newSession} />
      }
      side="bottom"
      align="end"
      open={open}
      onOpenChange={setOpen}
      asChild
    >
      {!auth.canManageNode ? (
        <button
          className={cx(
            "pl-3 py-1 bg-zinc-800 rounded-full flex justify-start items-center",
            { "pr-1": auth.viewerIdentity, "pr-3": !auth.viewerIdentity }
          )}
          onClick={() => setOpen(!open)}
        >
          <Eye />
          <div className="text-white leading-snug ml-2 mr-1">Viewing</div>
          <ChevronDown className="stroke-white w-[15px] h-[15px]" />
          {auth.viewerIdentity && (
            <ProfilePic
              className="ml-2"
              size="medium"
              url={auth.viewerIdentity.profilePicUrl}
            />
          )}
        </button>
      ) : (
        <div
          className={cx(
            "w-[34px] h-[34px] p-1 rounded-full items-center inline-flex",
            {
              "bg-transparent": !open,
              "bg-neutral-300": open,
            }
          )}
        >
          <button onClick={() => setOpen(!open)}>
            <ProfilePic
              size="medium"
              url={auth.viewerIdentity?.profilePicUrl}
            />
          </button>
        </div>
      )}
    </Popover>
  )
}

function LoginPopoverContent({
  node,
  auth,
  newSession,
}: {
  node: NodeData
  auth: AuthResponse
  newSession: () => Promise<void>
}) {
  /**
   * canConnectOverTS indicates whether the current viewer
   * is able to hit the node's web client that's being served
   * at http://${node.IP}:5252. If false, this means that the
   * viewer must connect to the correct tailnet before being
   * able to sign in.
   */
  const [canConnectOverTS, setCanConnectOverTS] = useState<boolean>(false)
  const [isRunningCheck, setIsRunningCheck] = useState<boolean>(false)

  const checkTSConnection = useCallback(() => {
    if (auth.viewerIdentity) {
      setCanConnectOverTS(true) // already connected over ts
      return
    }
    // Otherwise, test connection to the ts IP.
    if (isRunningCheck) {
      return // already checking
    }
    setIsRunningCheck(true)
    fetch(`http://${node.IP}:5252/ok`, { mode: "no-cors" })
      .then(() => {
        setIsRunningCheck(false)
        setCanConnectOverTS(true)
      })
      .catch(() => setIsRunningCheck(false))
  }, [
    auth.viewerIdentity,
    isRunningCheck,
    setCanConnectOverTS,
    setIsRunningCheck,
  ])

  /**
   * Checking connection for first time on page load.
   *
   * While not connected, we check again whenever the mouse
   * enters the popover component, to pick up on the user
   * leaving to turn on Tailscale then returning to the view.
   * See `onMouseEnter` on the div below.
   */
  useEffect(() => checkTSConnection(), [])

  const handleSignInClick = useCallback(() => {
    if (auth.viewerIdentity) {
      newSession()
    } else {
      // Must be connected over Tailscale to log in.
      // If not already connected, reroute to the Tailscale IP
      // before sending user through check mode.
      window.location.href = `http://${node.IP}:5252/?check=now`
    }
  }, [node.IP, auth.viewerIdentity, newSession])

  return (
    <div onMouseEnter={!canConnectOverTS ? checkTSConnection : undefined}>
      <div className="text-black text-sm font-medium leading-tight mb-1">
        {!auth.canManageNode ? "Viewing" : "Managing"}
        {auth.viewerIdentity && ` as ${auth.viewerIdentity.loginName}`}
      </div>
      {!auth.canManageNode &&
        (!auth.viewerIdentity || auth.authNeeded == AuthType.tailscale ? (
          <>
            <p className="text-neutral-500 text-xs">
              {auth.viewerIdentity ? (
                <>
                  To make changes, sign in to confirm your identity. This extra
                  step helps us keep your device secure.
                </>
              ) : (
                <>
                  You can see most of this device's details. To make changes,
                  you need to sign in.
                </>
              )}
            </p>
            <button
              className={cx(
                "w-full px-3 py-2 bg-indigo-500 rounded shadow text-center text-white text-sm font-medium mt-2",
                {
                  "mb-2": auth.viewerIdentity,
                  "cursor-not-allowed": !canConnectOverTS,
                }
              )}
              onClick={handleSignInClick}
              // TODO: add some helper info when disabled
              // due to needing to connect to TS
              disabled={!canConnectOverTS}
            >
              {auth.viewerIdentity ? "Sign in to confirm identity" : "Sign in"}
            </button>
          </>
        ) : (
          <p className="text-neutral-500 text-xs">
            You don’t have permission to make changes to this device, but you
            can view most of its details.
          </p>
        ))}
      {auth.viewerIdentity && (
        <>
          <hr className="my-2" />
          <div className="flex items-center">
            <User className="flex-shrink-0" />
            <p className="text-neutral-500 text-xs ml-2">
              We recognize you because you are accessing this page from{" "}
              <span className="font-medium">
                {auth.viewerIdentity.nodeName || auth.viewerIdentity.nodeIP}
              </span>
            </p>
          </div>
        </>
      )}
    </div>
  )
}
