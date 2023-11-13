import cx from "classnames"
import React from "react"
import ExitNodeSelector from "src/components/exit-node-selector"
import { NodeData, NodeUpdate } from "src/hooks/node-data"
import { ReactComponent as ArrowRight } from "src/icons/arrow-right.svg"
import { ReactComponent as ConnectedDeviceIcon } from "src/icons/connected-device.svg"
import { Link } from "wouter"

export default function HomeView({
  readonly,
  node,
  updateNode,
}: {
  readonly: boolean
  node: NodeData
  updateNode: (update: NodeUpdate) => Promise<void> | undefined
}) {
  return (
    <div className="mb-12 w-full">
      <h2 className="mb-3">This device</h2>
      <div className="-mx-5 card mb-9">
        <div className="flex justify-between items-center text-lg mb-5">
          <div className="flex items-center">
            <ConnectedDeviceIcon />
            <div className="ml-3">
              <h1>{node.DeviceName}</h1>
              {/* TODO(sonia): display actual status */}
              <p className="text-neutral-500 text-sm">Connected</p>
            </div>
          </div>
          <p className="text-neutral-800 text-lg leading-[25.20px]">
            {node.IP}
          </p>
        </div>
        <ExitNodeSelector
          className="mb-5"
          node={node}
          updateNode={updateNode}
          disabled={readonly}
        />
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
