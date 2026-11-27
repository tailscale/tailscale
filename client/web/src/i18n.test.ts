// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import { afterEach, describe, expect, it, vi } from "vitest"
import { detectLocale } from "src/i18n"

describe("detectLocale", () => {
  it("uses the first supported language preference", () => {
    expect(detectLocale(["fr-CA", "sv-SE", "en-US"])).toBe("sv")
  })

  it("normalizes regional and case-varied tags", () => {
    expect(detectLocale(["SV_se"])).toBe("sv")
    expect(detectLocale(["EN-gb"])).toBe("en")
  })

  it("falls back to English when no supported preference is present", () => {
    expect(detectLocale(["fr-CA", "de-DE"])).toBe("en")
    expect(detectLocale([])).toBe("en")
  })
})

describe("translation lookup", () => {
  afterEach(() => {
    vi.unstubAllGlobals()
    vi.resetModules()
  })

  it("uses the Swedish locale and substitutes message values", async () => {
    vi.stubGlobal("navigator", {
      languages: ["sv-SE", "en-US"],
      language: "sv-SE",
    })
    vi.resetModules()

    const { locale, t } = await import("src/i18n")

    expect(locale).toBe("sv")
    expect(document.documentElement.lang).toBe("sv")
    expect(t("routesPendingApproval", { count: 2, routes: "rutter" })).toBe(
      "2 rutter väntar på godkännande"
    )
    expect(t("backToDevice", { device: "telefon" })).toBe(
      "← Tillbaka till telefon"
    )
  })

  it("uses English and leaves an unresolved placeholder intact", async () => {
    vi.stubGlobal("navigator", {
      languages: ["fr-FR"],
      language: "fr-FR",
    })
    vi.resetModules()

    const { locale, t } = await import("src/i18n")

    expect(locale).toBe("en")
    expect(document.documentElement.lang).toBe("en")
    expect(t("backToDevice")).toBe("← Back to {device}")
  })
})
