// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import React, { createContext, useContext, useMemo } from "react"

export type Locale = "en" | "sv"

type Variables = Record<string, string | number>
type Messages = Record<string, string>

const en: Messages = {
  "app.backToDevice": "Back to {device}",
  "app.featureUnavailable": "{feature} not available on this device.",
  "app.pageNotFound": "Page not found",
  "home.connected": "Connected",
  "home.deviceDetails": "View device details",
  "home.offline": "Offline",
  "home.pendingApproval": "{count} {route} pending approval",
  "home.route": "route",
  "home.routes": "routes",
  "home.running": "Running",
  "home.settings": "Settings",
  "home.sshDescription": "Run a Tailscale SSH server on this device and allow other devices in your tailnet to SSH into it.",
  "home.subnetDescription": "Add devices to your tailnet without installing Tailscale on them.",
  "home.subnetRouter": "Subnet router",
  "home.thisDevice": "This device",
  "login.connect": "Connect",
  "login.connectToTailscale": "Connect to Tailscale",
  "login.deviceDisconnected": "Your device is disconnected from Tailscale.",
  "login.learnMore": "learn more",
  "login.logIn": "Log in",
  "login.logInToNetwork": "Get started by logging in to your Tailscale network. Or, learn more at",
  "login.reauthenticate": "Reauthenticate",
  "login.keyExpired": "Your device’s key has expired. Reauthenticate this device by logging in again, or",
}

const sv: Messages = {
  "app.backToDevice": "Tillbaka till {device}",
  "app.featureUnavailable": "{feature} är inte tillgänglig på den här enheten.",
  "app.pageNotFound": "Sidan hittades inte",
  "home.connected": "Ansluten",
  "home.deviceDetails": "Visa enhetsinformation",
  "home.offline": "Frånkopplad",
  "home.pendingApproval": "{count} {route} väntar på godkännande",
  "home.route": "rutt",
  "home.routes": "rutter",
  "home.running": "Körs",
  "home.settings": "Inställningar",
  "home.sshDescription": "Kör en Tailscale SSH-server på den här enheten och låt andra enheter i ditt tailnet ansluta till den med SSH.",
  "home.subnetDescription": "Lägg till enheter i ditt tailnet utan att installera Tailscale på dem.",
  "home.subnetRouter": "Undernätsrouter",
  "home.thisDevice": "Den här enheten",
  "login.connect": "Anslut",
  "login.connectToTailscale": "Anslut till Tailscale",
  "login.deviceDisconnected": "Din enhet är frånkopplad från Tailscale.",
  "login.learnMore": "läs mer",
  "login.logIn": "Logga in",
  "login.logInToNetwork": "Kom igång genom att logga in på ditt Tailscale-nätverk. Du kan också läsa mer på",
  "login.reauthenticate": "Autentisera igen",
  "login.keyExpired": "Enhetens nyckel har gått ut. Autentisera enheten igen genom att logga in, eller",
}

const catalogs: Record<Locale, Messages> = { en, sv }

function detectLocale(language = navigator.language): Locale {
  return language.toLowerCase().startsWith("sv") ? "sv" : "en"
}

function format(message: string, variables: Variables = {}): string {
  return message.replace(/\{(\w+)\}/g, (match, name) =>
    name in variables ? String(variables[name]) : match
  )
}

type I18n = {
  locale: Locale
  t: (key: string, variables?: Variables) => string
  plural: (count: number, singularKey: string, pluralKey: string) => string
}

const I18nContext = createContext<I18n | null>(null)

export function I18nProvider({ children }: { children: React.ReactNode }) {
  const locale = detectLocale()
  const value = useMemo<I18n>(() => ({
    locale,
    t: (key, variables) => format(catalogs[locale][key] ?? en[key] ?? key, variables),
    plural: (count, singularKey, pluralKey) =>
      catalogs[locale][count === 1 ? singularKey : pluralKey] ??
      en[count === 1 ? singularKey : pluralKey],
  }), [locale])

  return <I18nContext.Provider value={value}>{children}</I18nContext.Provider>
}

export function useI18n(): I18n {
  const i18n = useContext(I18nContext)
  if (!i18n) {
    throw new Error("useI18n must be used within I18nProvider")
  }
  return i18n
}

export { detectLocale, format }
