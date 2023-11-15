import { useEffect, useMemo, useState } from "react"
import { apiFetch } from "src/api"

export type ExitNode = {
  ID: string
  Name: string
  Location?: ExitNodeLocation
}

type ExitNodeLocation = {
  Country: string
  CountryCode: CountryCode
  City: string
  CityCode: CityCode
  Priority: number
}

type CountryCode = string
type CityCode = string

export type ExitNodeGroup = {
  id: string
  name?: string
  nodes: ExitNode[]
}

export default function useExitNodes(tailnetName: string, filter?: string) {
  const [data, setData] = useState<ExitNode[]>([])

  useEffect(() => {
    apiFetch("/exit-nodes", "GET")
      .then((r) => r.json())
      .then((r) => setData(r))
      .catch((err) => {
        alert("Failed operation: " + err.message)
      })
  }, [])

  const { tailnetNodesSorted, locationNodesMap } = useMemo(() => {
    // First going through exit nodes and splitting them into two groups:
    // 1. tailnetNodes: exit nodes advertised by tailnet's own nodes
    // 2. locationNodes: exit nodes advertised by non-tailnet Mullvad nodes
    let tailnetNodes: ExitNode[] = []
    const locationNodes = new Map<CountryCode, Map<CityCode, ExitNode[]>>()

    data?.forEach((n) => {
      const loc = n.Location
      if (!loc) {
        // 2023-11-15: Currently, if the node doesn't have
        // location information, it is owned by the tailnet.
        // Only Mullvad exit nodes have locations filled.
        tailnetNodes.push({
          ...n,
          Name: trimDNSSuffix(n.Name, tailnetName),
        })
        return
      }
      const countryNodes =
        locationNodes.get(loc.CountryCode) || new Map<CityCode, ExitNode[]>()
      const cityNodes = countryNodes.get(loc.CityCode) || []
      countryNodes.set(loc.CityCode, [...cityNodes, n])
      locationNodes.set(loc.CountryCode, countryNodes)
    })

    return {
      tailnetNodesSorted: tailnetNodes.sort(compareByName),
      locationNodesMap: locationNodes,
    }
  }, [data, tailnetName])

  const mullvadNodesSorted = useMemo(() => {
    const nodes: ExitNode[] = []

    // addBestMatchNode adds the node with the "higest priority"
    // match from a list of exit node `options` to `nodes`.
    const addBestMatchNode = (
      options: ExitNode[],
      name: (l: ExitNodeLocation) => string
    ) => {
      const bestNode = highestPriorityNode(options)
      if (!bestNode || !bestNode.Location) {
        return // not possible, doing this for type safety
      }
      nodes.push({
        ID: bestNode.ID,
        Name: name(bestNode.Location),
        Location: bestNode.Location,
      })
    }

    if (!Boolean(filter)) {
      // When nothing is searched, only show a single best-matching
      // exit node per-country.
      //
      // There's too many location-based nodes to display all of them.
      locationNodesMap.forEach(
        // add one node per country
        (countryNodes) =>
          addBestMatchNode(flattenMap(countryNodes), (l) => l.Country)
      )
    } else {
      // Otherwise, show the best match on a city-level,
      // with a "Country: Best Match" node at top.
      //
      // i.e. We allow for discovering cities through searching.
      locationNodesMap.forEach((countryNodes) => {
        countryNodes.forEach(
          // add one node per city
          (cityNodes) =>
            addBestMatchNode(cityNodes, (l) => `${l.Country}: ${l.City}`)
        )
        // add the "Country: Best Match" node
        addBestMatchNode(
          flattenMap(countryNodes),
          (l) => `${l.Country}: Best Match`
        )
      })
    }

    return nodes.sort(compareByName)
  }, [locationNodesMap, Boolean(filter)])

  // Ordered and filtered grouping of exit nodes.
  const exitNodeGroups = useMemo(() => {
    const filterLower = !filter ? undefined : filter.toLowerCase()

    return [
      { id: "self", nodes: filter ? [] : [noExitNode, runAsExitNode] },
      {
        id: "tailnet",
        nodes: filterLower
          ? tailnetNodesSorted.filter((n) =>
              n.Name.toLowerCase().includes(filterLower)
            )
          : tailnetNodesSorted,
      },
      {
        id: "mullvad",
        name: "Mullvad VPN",
        nodes: filterLower
          ? mullvadNodesSorted.filter((n) =>
              n.Name.toLowerCase().includes(filterLower)
            )
          : mullvadNodesSorted,
      },
    ]
  }, [tailnetNodesSorted, mullvadNodesSorted, filter])

  return { data: exitNodeGroups }
}

// highestPriorityNode finds the highest priority node for use
// (the "best match" node) from a list of exit nodes.
// Nodes with equal priorities are picked between arbitrarily.
function highestPriorityNode(nodes: ExitNode[]): ExitNode | undefined {
  return nodes.length === 0
    ? undefined
    : nodes.sort(
        (a, b) => (b.Location?.Priority || 0) - (a.Location?.Priority || 0)
      )[0]
}

// compareName compares two exit nodes alphabetically by name.
function compareByName(a: ExitNode, b: ExitNode): number {
  if (a.Location && b.Location && a.Location.Country == b.Location.Country) {
    // Always put "<Country>: Best Match" node at top of country list.
    if (a.Name.includes(": Best Match")) {
      return -1
    } else if (b.Name.includes(": Best Match")) {
      return 1
    }
  }
  return a.Name.localeCompare(b.Name)
}

function flattenMap<T, V>(m: Map<T, V[]>): V[] {
  return Array.from(m.values()).reduce((prev, curr) => [...prev, ...curr])
}

// trimDNSSuffix trims the tailnet dns name from s, leaving no
// trailing dots.
//
// trimDNSSuffix("hello.ts.net", "ts.net") = "hello"
// trimDNSSuffix("hello", "ts.net") = "hello"
export function trimDNSSuffix(s: string, tailnetDNSName: string): string {
  if (s.endsWith(".")) {
    s = s.slice(0, -1)
  }
  if (s.endsWith("." + tailnetDNSName)) {
    s = s.replace("." + tailnetDNSName, "")
  }
  return s
}

export const noExitNode: ExitNode = { ID: "NONE", Name: "None" }
export const runAsExitNode: ExitNode = {
  ID: "RUNNING",
  Name: "Run as exit node…",
}
