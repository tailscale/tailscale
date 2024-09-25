// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import { assertNever } from "src/utils/util"

export type NodeData = {
  Profile: UserProfile
  Status: NodeState
  DeviceName: string
  OS: string
  IPv4: string
  IPv6: string
  ID: string
  KeyExpiry: string
  KeyExpired: boolean
  UsingExitNode?: ExitNode
  AdvertisingExitNode: boolean
  AdvertisingExitNodeApproved: boolean
  AdvertisedRoutes?: SubnetRoute[]
  TUNMode: boolean
  IsSynology: boolean
  DSMVersion: number
  IsUnraid: boolean
  UnraidToken: string
  IPNVersion: string
  ClientVersion?: VersionInfo
  URLPrefix: string
  DomainName: string
  TailnetName: string
  IsTagged: boolean
  Tags: string[]
  RunningSSHServer: boolean
  ControlAdminURL: string
  LicensesURL: string
  Features: { [key in Feature]: boolean } // value is true if given feature is available on this client
  ACLAllowsAnyIncomingTraffic: boolean
}

export type NodeState =
  | "NoState"
  | "NeedsLogin"
  | "NeedsMachineAuth"
  | "Stopped"
  | "Starting"
  | "Running"

export type UserProfile = {
  LoginName: string
  DisplayName: string
  ProfilePicURL: string
}

export type SubnetRoute = {
  Route: string
  Approved: boolean
}

export type ExitNode = {
  ID: string
  Name: string
  Location?: ExitNodeLocation
  Online?: boolean
}

export type ExitNodeLocation = {
  Country: string
  CountryCode: CountryCode
  City: string
  CityCode: CityCode
  Priority: number
}

export type CountryCode = string
export type CityCode = string

export type ExitNodeGroup = {
  id: string
  name?: string
  nodes: ExitNode[]
}

export type Feature =
  | "advertise-exit-node"
  | "advertise-routes"
  | "use-exit-node"
  | "ssh"
  | "serve"
  | "funnel"
  | "auto-update"

export const featureLongName = (f: Feature) => {
  switch (f) {
    case "advertise-exit-node":
      return "Advertising as an exit node"
    case "advertise-routes":
      return "Advertising subnet routes"
    case "use-exit-node":
      return "Using an exit node"
    case "ssh":
      return "Running a Tailscale SSH server"
    case "serve":
      return "Sharing local content"
    case "funnel":
      return "Sharing local content over the internet"
    case "auto-update":
      return "Auto updating client versions"
    default:
      assertNever(f)
  }
}

/**
 * VersionInfo type is deserialized from tailcfg.ClientVersion,
 * so it should not include fields not included in that type.
 */
export type VersionInfo = {
  RunningLatest: boolean
  LatestVersion?: string
}

export type ServeData = {
  target: Target
  destination: Destination
  shareType: ShareType
  isForeground?: boolean // only populated for "GET"
  isEdit?: boolean // only populated for "PATCH"
}

export type Target = {
  type: TargetType
  value: string
}

export type Destination = {
  protocol: DestinationProtocol
  port: DestinationPort
  path: string
}

export type TargetType = "plainText" | "localHttpPort"
export type DestinationProtocol =
  | "https"
  | "http"
  | "tcp"
  | "tls-terminated-tcp"
export type DestinationPort = 443 | 8443 | 10000
export type ShareType = "serve" | "funnel"
