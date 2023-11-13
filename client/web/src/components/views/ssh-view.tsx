import React from "react"
import { PrefsUpdate } from "src/hooks/node-data"
import Toggle from "src/ui/toggle"

export default function SSHView({
  readonly,
  runningSSH,
  updatePrefs,
}: {
  readonly: boolean
  runningSSH: boolean
  updatePrefs: (p: PrefsUpdate) => Promise<void>
}) {
  return (
    <>
      <h1 className="mb-1">Tailscale SSH server</h1>
      <p className="description mb-10">
        Run a Tailscale SSH server on this device and allow other devices in
        your tailnet to SSH into it.{" "}
        <a
          href="https://tailscale.com/kb/1193/tailscale-ssh/"
          className="text-indigo-700"
          target="_blank"
        >
          Learn more &rarr;
        </a>
      </p>
      <div className="-mx-5 px-4 py-3 bg-white rounded-lg border border-gray-200 flex gap-2.5 mb-3">
        <Toggle
          checked={runningSSH}
          onChange={() => updatePrefs({ RunSSHSet: true, RunSSH: !runningSSH })}
          disabled={readonly}
        />
        <div className="text-black text-sm font-medium leading-tight">
          Run Tailscale SSH server
        </div>
      </div>
      <p className="text-neutral-500 text-sm leading-tight">
        Remember to make sure that the{" "}
        <a
          href="https://login.tailscale.com/admin/acls/"
          className="text-indigo-700"
          target="_blank"
        >
          tailnet policy file
        </a>{" "}
        allows other devices to SSH into this device.
      </p>
    </>
  )
}
