// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

import { describe, expect, it } from "vitest"
import { detectLocale, format } from "src/i18n"

describe("detectLocale", () => {
  it("selects Swedish for Swedish browser preferences", () => {
    expect(detectLocale("sv-SE")).toBe("sv")
  })

  it("falls back to English", () => {
    expect(detectLocale("de-DE")).toBe("en")
  })
})

describe("format", () => {
  it("interpolates named variables", () => {
    expect(format("Tillbaka till {device}", { device: "server" })).toBe(
      "Tillbaka till server"
    )
  })
})
