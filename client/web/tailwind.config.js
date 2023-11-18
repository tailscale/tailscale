const plugin = require("tailwindcss/plugin")

/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    fontFamily: {
      sans: [
        "Inter",
        "-apple-system",
        "BlinkMacSystemFont",
        "Helvetica",
        "Arial",
        "sans-serif",
      ],
      mono: [
        "SFMono-Regular",
        "SFMono Regular",
        "Consolas",
        "Liberation Mono",
        "Menlo",
        "Courier",
        "monospace",
      ],
    },
    fontWeight: {
      normal: "400",
      medium: "500",
      semibold: "600",
      bold: "700",
    },
    extend: {},
  },
  plugins: [
    plugin(function ({ addVariant }) {
      addVariant("state-open", [
        '&[data-state="open"]',
        '[data-state="open"] &',
      ])
      addVariant("state-closed", [
        '&[data-state="closed"]',
        '[data-state="closed"] &',
      ])
    }),
  ],
}
