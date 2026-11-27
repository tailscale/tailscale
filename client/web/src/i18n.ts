// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

const en = {
  connect: "Connect",
  deviceDisconnected: "Your device is disconnected from Tailscale.",
  connectToTailscale: "Connect to Tailscale",
  deviceKeyExpired:
    "Your device’s key has expired. Reauthenticate this device by logging in again, or",
  learnMore: "learn more",
  learnMoreArrow: "Learn more →",
  reauthenticate: "Reauthenticate",
  logInHeading: "Log in",
  getStartedLoggingIn:
    "Get started by logging in to your Tailscale network. Or, learn more at",
  logInButton: "Log in",
  thisDevice: "This device",
  connected: "Connected",
  offline: "Offline",
  viewDeviceDetails: "View device details →",
  settings: "Settings",
  subnetRouter: "Subnet router",
  addDevicesWithoutInstalling:
    "Add devices to your tailnet without installing Tailscale on them.",
  routeSingular: "route",
  routePlural: "routes",
  routesPendingApproval: "{count} {routes} pending approval",
  tailscaleSSHServer: "Tailscale SSH server",
  runSSHServerDescription:
    "Run a Tailscale SSH server on this device and allow other devices in your tailnet to SSH into it.",
  running: "Running",
  backToDevice: "← Back to {device}",
  pageNotFound: "Page not found",
  viewing: "Viewing",
  managing: "Managing",
  viewingAs: "Viewing as {name}",
  managingAs: "Managing as {name}",
  recognizedBecause:
    "We recognize you because you are accessing this page from",
  readOnlyDescription: "This web interface is running in read-only mode.",
  noPermissionToChange:
    "You don’t have permission to make changes to this device, but you can view most of its details.",
  tailnetPolicyBlocksDevice:
    "The current tailnet policy file does not allow connecting to this device.",
  cannotAccessDeviceIP:
    "Cannot access this device’s Tailscale IP. Make sure you are connected to your tailnet, and that your policy file allows access.",
  canViewDetailsSignIn:
    "You can see most of this device’s details. To make changes, you need to sign in.",
  checkTailnetPolicy:
    "Make sure you are connected to your tailnet, and that your policy file allows access.",
  signInToConfirm:
    "To make changes, sign in to confirm your identity. This extra step helps us keep your device secure.",
  signInToConfirmIdentity: "Sign in to confirm identity",
  signIn: "Sign in",
  loggedOut:
    "You logged out of this device. To reconnect it you will have to re-authenticate the device from either the Tailscale app or the Tailscale command line interface.",
  exitNode: "Exit node",
  exitNodeOffline: "Exit node offline",
  runningAsExitNode: "Running as exit node",
  disable: "Disable",
  selectedExitNodeOffline:
    "The selected exit node is currently offline. Your internet traffic is blocked until you disable the exit node or select a different one.",
  pendingExitNodeApproval:
    "Pending approval to run as exit node. This device won’t be usable as an exit node until then.",
  searchExitNodes: "Search exit nodes…",
  noExitNodesMatching: "No exit nodes matching “{filter}”",
  noExitNodesAvailable: "No exit nodes available",
  shortDomain: "short domain",
  fullDomain: "full domain",
  ipv4Address: "IPv4 address",
  ipv6Address: "IPv6 address",
  seeAllAddresses: "See all addresses for this device.",
  copyAddress: "Copy {address} to your clipboard.",
  copiedAddress: "Copied {label} to clipboard",
  failedToCopyAddress: "Failed to copy {label} to clipboard",
} as const

type MessageKey = keyof typeof en

const sv: Record<MessageKey, string> = {
  connect: "Anslut",
  deviceDisconnected: "Enheten är frånkopplad från Tailscale.",
  connectToTailscale: "Anslut till Tailscale",
  deviceKeyExpired:
    "Enhetens nyckel har gått ut. Autentisera enheten på nytt genom att logga in igen, eller",
  learnMore: "läs mer",
  learnMoreArrow: "Läs mer →",
  reauthenticate: "Logga in igen",
  logInHeading: "Logga in",
  getStartedLoggingIn:
    "Kom igång genom att logga in på ditt Tailscale-nätverk. Läs mer på",
  logInButton: "Logga in",
  thisDevice: "Den här enheten",
  connected: "Ansluten",
  offline: "Frånkopplad",
  viewDeviceDetails: "Visa enhetsinformation →",
  settings: "Inställningar",
  subnetRouter: "Subnätsrouter",
  addDevicesWithoutInstalling:
    "Lägg till enheter i ditt tailnet utan att installera Tailscale på dem.",
  routeSingular: "rutt",
  routePlural: "rutter",
  routesPendingApproval: "{count} {routes} väntar på godkännande",
  tailscaleSSHServer: "Tailscale SSH-server",
  runSSHServerDescription:
    "Kör en Tailscale SSH-server på den här enheten så att andra enheter i ditt tailnet kan ansluta till den med SSH.",
  running: "Körs",
  backToDevice: "← Tillbaka till {device}",
  pageNotFound: "Sidan hittades inte",
  viewing: "Visar",
  managing: "Administrerar",
  viewingAs: "Visar som {name}",
  managingAs: "Administrerar som {name}",
  pageNotFound: "Sidan hittades inte",
  recognizedBecause: "Vi känner igen dig eftersom du öppnar sidan från",
  readOnlyDescription: "Webbgränssnittet körs i skrivskyddat läge.",
  noPermissionToChange:
    "Du har inte behörighet att ändra den här enheten, men du kan visa det mesta av informationen om den.",
  tailnetPolicyBlocksDevice:
    "Den aktuella tailnet-principen tillåter inte anslutning till den här enheten.",
  cannotAccessDeviceIP:
    "Det går inte att nå enhetens Tailscale-IP-adress. Kontrollera att du är ansluten till ditt tailnet och att principfilen tillåter åtkomst.",
  canViewDetailsSignIn:
    "Du kan visa det mesta av informationen om enheten. Logga in om du vill ändra något.",
  checkTailnetPolicy:
    "Kontrollera att du är ansluten till ditt tailnet och att principfilen tillåter åtkomst.",
  signInToConfirm:
    "Logga in och bekräfta din identitet om du vill göra ändringar. Det extra steget hjälper oss att skydda enheten.",
  signInToConfirmIdentity: "Logga in och bekräfta identiteten",
  signIn: "Logga in",
  loggedOut:
    "Du har loggat ut från den här enheten. Om du vill ansluta den igen måste du autentisera enheten på nytt i Tailscale-appen eller med Tailscale-kommandoraden.",
  exitNode: "Utgångsnod",
  exitNodeOffline: "Utgångsnoden är frånkopplad",
  runningAsExitNode: "Fungerar som utgångsnod",
  disable: "Inaktivera",
  selectedExitNodeOffline:
    "Den valda utgångsnoden är frånkopplad. Din internettrafik blockeras tills du inaktiverar utgångsnoden eller väljer en annan.",
  pendingExitNodeApproval:
    "Väntar på godkännande för att fungera som utgångsnod. Enheten kan inte användas som utgångsnod förrän den har godkänts.",
  searchExitNodes: "Sök efter utgångsnoder…",
  noExitNodesMatching: "Inga utgångsnoder matchar ”{filter}”",
  noExitNodesAvailable: "Inga utgångsnoder tillgängliga",
  shortDomain: "kort domännamn",
  fullDomain: "fullständigt domännamn",
  ipv4Address: "IPv4-adress",
  ipv6Address: "IPv6-adress",
  seeAllAddresses: "Visa alla adresser för den här enheten.",
  copyAddress: "Kopiera {address} till urklipp.",
  copiedAddress: "Kopierade {label} till urklipp",
  failedToCopyAddress: "Det gick inte att kopiera {label} till urklipp",
}

export type Locale = "en" | "sv"

export function detectLocale(preferences: readonly string[]): Locale {
  for (const preference of preferences) {
    const language = preference.toLowerCase().split(/[-_]/, 1)[0]
    if (language === "sv" || language === "en") {
      return language
    }
  }
  return "en"
}

export const locale = detectLocale(
  typeof navigator === "undefined"
    ? []
    : [...(navigator.languages ?? []), navigator.language]
)

if (typeof document !== "undefined") {
  document.documentElement.lang = locale
}

export function t(
  key: MessageKey,
  values: Record<string, string | number> = {}
): string {
  const message = (locale === "sv" ? sv : en)[key]
  return message.replace(/\{(\w+)\}/g, (placeholder, name: string) =>
    String(values[name] ?? placeholder)
  )
}
