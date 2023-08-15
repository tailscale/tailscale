import { useEffect, useState } from "react"

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

export type UserProfile = {
  LoginName: string
  DisplayName: string
  ProfilePicURL: string
}

// useNodeData returns basic data about the current node.
export default function useNodeData() {
  const [data, setData] = useState<NodeData>()

  useEffect(() => {
    fetch("/api/data")
      .then((response) => response.json())
      .then((json) => setData(json))
      .catch((error) => console.error(error))
  }, [])

  return data
}
