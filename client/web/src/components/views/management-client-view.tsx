import cx from "classnames"
import React from "react"
import { NodeData } from "src/hooks/node-data"
import { ReactComponent as ArrowRight } from "src/icons/arrow-right.svg"
import { ReactComponent as ChevronDown } from "src/icons/chevron-down.svg"
import { ReactComponent as ConnectedDeviceIcon } from "src/icons/connected-device.svg"
import { Link } from "wouter"

export default function ManagementClientView(props: NodeData) {
  return (
    <div className="mb-12 w-full">
      <h2 className="mb-3">This device</h2>
      <div className="-mx-5 card mb-9">
        <div className="flex justify-between items-center text-lg mb-5">
          <div className="flex items-center">
            <ConnectedDeviceIcon />
            <div className="ml-3">
              <h1>{props.DeviceName}</h1>
              {/* TODO(sonia): display actual status */}
              <p className="text-neutral-500 text-sm">Connected</p>
            </div>
          </div>
          <p className="text-neutral-800 text-lg leading-[25.20px]">
            {props.IP}
          </p>
        </div>
        <ExitNodeSelector className="mb-5" />
        <Link
          className="text-indigo-500 font-medium leading-snug"
          to="/details"
        >
          View device details &rarr;
        </Link>
      </div>
      <h2 className="mb-3">Settings</h2>
      <SettingsCard
        link="/subnets"
        className="mb-3"
        title="Subnet router"
        body="Add devices to your tailnet without installing Tailscale on them."
      />
      <SettingsCard
        link="/ssh"
        className="mb-3"
        title="Tailscale SSH server"
        body="Run a Tailscale SSH server on this device and allow other devices in your tailnet to SSH into it."
      />
      <SettingsCard
        link="/serve"
        title="Share local content"
        body="Share local ports, services, and content to your Tailscale network or to the broader internet."
      />
    </div>
  )
}

function ExitNodeSelector({ className }: { className?: string }) {
  return (
    <div className={cx("p-1.5 rounded-md border border-gray-200", className)}>
      <div className="hover-button">
        <p className="text-neutral-500 text-xs font-medium uppercase tracking-wide mb-1">
          Exit node
        </p>
        <div className="flex items-center">
          <p className="text-neutral-800">None</p>
          <ChevronDown className="ml-[9px]" />
        </div>
      </div>
    </div>
  )
}

function SettingsCard({
  title,
  link,
  body,
  className,
}: {
  title: string
  link: string
  body: string
  className?: string
}) {
  return (
    <Link
      to={link}
      className={cx(
        "-mx-5 card flex justify-between items-center cursor-pointer",
        className
      )}
    >
      <div>
        <p className="text-neutral-800 font-medium leading-tight mb-2">
          {title}
        </p>
        <p className="text-neutral-500 text-sm leading-tight">{body}</p>
      </div>
      <div>
        <ArrowRight className="ml-3" />
      </div>
    </Link>
  )
}
