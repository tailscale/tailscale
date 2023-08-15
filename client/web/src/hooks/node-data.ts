export type UserProfile = {
  LoginName: string
  DisplayName: string
  ProfilePicURL: string
}

export type NodeData = {
  Profile: UserProfile
  Status: string
  DeviceName: string
  IP: string
  AdvertiseExitNode: boolean
  AdvertiseRoutes: string
  LicensesURL: string
  TUNMode: boolean
  IsSynology: boolean
  DSMVersion: number
  IsUnraid: boolean
  UnraidToken: string
  IPNVersion: string
}

// testData is static set of nodedata used during development.
// This can be removed once we have a real node data API.
const testData: NodeData = {
  Profile: {
    LoginName: "amelie",
    DisplayName: "Amelie Pangolin",
    ProfilePicURL: "https://login.tailscale.com/logo192.png",
  },
  Status: "Running",
  DeviceName: "amelies-laptop",
  IP: "100.1.2.3",
  AdvertiseExitNode: false,
  AdvertiseRoutes: "",
  LicensesURL: "https://tailscale.com/licenses/tailscale",
  TUNMode: false,
  IsSynology: true,
  DSMVersion: 7,
  IsUnraid: false,
  UnraidToken: "",
  IPNVersion: "0.1.0",
}

// useNodeData returns basic data about the current node.
export default function useNodeData() {
  return testData
}
