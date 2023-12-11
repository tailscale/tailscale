// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import cx from "classnames"
import React, { useCallback, useEffect, useState } from "react"
import { ReactComponent as ChevronDown } from "src/assets/icons/chevron-down.svg"
import { ReactComponent as Eye } from "src/assets/icons/eye.svg"
import { ReactComponent as User } from "src/assets/icons/user.svg"
import { AuthResponse, AuthType } from "src/hooks/auth"
import { NodeData } from "src/types"
import Button from "src/ui/button"
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
            "pl-3 py-1 bg-gray-700 rounded-full flex justify-start items-center h-[34px]",
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
            "w-[34px] h-[34px] p-1 rounded-full justify-center items-center inline-flex hover:bg-gray-300",
            {
              "bg-transparent": !open,
              "bg-gray-300": open,
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
    fetch(`http://${node.IPv4}:5252/ok`, { mode: "no-cors" })
      .then(() => {
        setIsRunningCheck(false)
        setCanConnectOverTS(true)
      })
      .catch(() => setIsRunningCheck(false))
  }, [auth.viewerIdentity, isRunningCheck, node.IPv4])

  /**
   * Checking connection for first time on page load.
   *
   * While not connected, we check again whenever the mouse
   * enters the popover component, to pick up on the user
   * leaving to turn on Tailscale then returning to the view.
   * See `onMouseEnter` on the div below.
   */
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => checkTSConnection(), [])

  const handleSignInClick = useCallback(() => {
    if (auth.viewerIdentity) {
      if (window.self !== window.top) {
        // if we're inside an iframe, start session in new window
        let url = new URL(window.location.href)
        url.searchParams.set("check", "now")
        window.open(url, "_blank")
      } else {
        newSession()
      }
    } else {
      // Must be connected over Tailscale to log in.
      // Send user to Tailscale IP and start check mode
      const manageURL = `http://${node.IPv4}:5252/?check=now`
      if (window.self !== window.top) {
        // if we're inside an iframe, open management client in new window
        window.open(manageURL, "_blank")
      } else {
        window.location.href = manageURL
      }
    }
  }, [node.IPv4, auth.viewerIdentity, newSession])

  return (
    <div onMouseEnter={!canConnectOverTS ? checkTSConnection : undefined}>
      <div className="text-black text-sm font-medium leading-tight mb-1">
        {!auth.canManageNode ? "Viewing" : "Managing"}
        {auth.viewerIdentity && ` as ${auth.viewerIdentity.loginName}`}
      </div>
      {!auth.canManageNode && (
        <>
          {!auth.viewerIdentity ? (
            // User is not connected over Tailscale.
            // These states are only possible on the login client.
            <>
              {!canConnectOverTS ? (
                <>
                  <p className="text-gray-500 text-xs">
                    {!node.ACLAllowsAnyIncomingTraffic ? (
                      // Tailnet ACLs don't allow access.
                      <>
                        The current tailnet policy file does not allow
                        connecting to this device.
                      </>
                    ) : (
                      // ACLs allow access, but user can't connect.
                      <>
                        Cannot access this device's Tailscale IP. Make sure you
                        are connected to your tailnet, and that your policy file
                        allows access.
                      </>
                    )}{" "}
                    <a
                      href="https://tailscale.com/s/web-client-connection"
                      className="text-blue-700"
                      target="_blank"
                      rel="noreferrer"
                    >
                      Learn more &rarr;
                    </a>
                  </p>
                </>
              ) : (
                // User can connect to Tailcale IP; sign in when ready.
                <>
                  <p className="text-gray-500 text-xs">
                    You can see most of this device's details. To make changes,
                    you need to sign in.
                  </p>
                  <SignInButton auth={auth} onClick={handleSignInClick} />
                </>
              )}
            </>
          ) : auth.authNeeded === AuthType.tailscale ? (
            // User is connected over Tailscale, but needs to complete check mode.
            <>
              <p className="text-gray-500 text-xs">
                To make changes, sign in to confirm your identity. This extra
                step helps us keep your device secure.
              </p>
              <SignInButton auth={auth} onClick={handleSignInClick} />
            </>
          ) : (
            // User is connected over tailscale, but doesn't have permission to manage.
            <p className="text-gray-500 text-xs">
              You don’t have permission to make changes to this device, but you
              can view most of its details.
            </p>
          )}
        </>
      )}
      {auth.viewerIdentity && (
        <>
          <hr className="my-2" />
          <div className="flex items-center">
            <User className="flex-shrink-0" />
            <p className="text-gray-500 text-xs ml-2">
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

function SignInButton({
  auth,
  onClick,
}: {
  auth: AuthResponse
  onClick: () => void
}) {
  return (
    <Button
      className={cx("text-center w-full mt-2", {
        "mb-2": auth.viewerIdentity,
      })}
      intent="primary"
      sizeVariant="small"
      onClick={onClick}
    >
      {auth.viewerIdentity ? "Sign in to confirm identity" : "Sign in"}
    </Button>
  )
}
