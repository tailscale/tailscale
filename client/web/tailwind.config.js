import plugin from "tailwindcss/plugin"
import styles from "./styles.json"

const config = {
  theme: {
    screens: {
      sm: "420px",
      md: "768px",
      lg: "1024px",
    },
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
    colors: styles.colors,
    extend: {
      colors: {
        ...styles.colors,
        "bg-app": "var(--color-bg-app)",
        "bg-menu-item-hover": "var(--color-bg-menu-item-hover)",

        "border-base": "var(--color-border-base)",

        "text-base": "var(--color-text-base)",
        "text-muted": "var(--color-text-muted)",
        "text-disabled": "var(--color-text-disabled)",
        "text-primary": "var(--color-text-primary)",
        "text-warning": "var(--color-text-warning)",
        "text-danger": "var(--color-text-danger)",
      },
      borderColor: {
        DEFAULT: "var(--color-border-base)",
      },
      boxShadow: {
        dialog: "0 10px 40px rgba(0,0,0,0.12), 0 0 16px rgba(0,0,0,0.08)",
        form: "0 1px 1px rgba(0, 0, 0, 0.04)",
        soft: "0 4px 12px 0 rgba(0, 0, 0, 0.03)",
        popover:
          "0 0 0 1px rgba(136, 152, 170, 0.1), 0 15px 35px 0 rgba(49, 49, 93, 0.1), 0 5px 15px 0 rgba(0, 0, 0, 0.08)",
      },
      animation: {
        "scale-in": "scale-in 120ms cubic-bezier(0.16, 1, 0.3, 1)",
        "scale-out": "scale-out 120ms cubic-bezier(0.16, 1, 0.3, 1)",
      },
      transformOrigin: {
        "radix-hovercard": "var(--radix-hover-card-content-transform-origin)",
        "radix-popover": "var(--radix-popover-content-transform-origin)",
        "radix-tooltip": "var(--radix-tooltip-content-transform-origin)",
      },
      keyframes: {
        "scale-in": {
          "0%": {
            transform: "scale(0.94)",
            opacity: "0",
          },
          "100%": {
            transform: "scale(1)",
            opacity: "1",
          },
        },
        "scale-out": {
          "0%": {
            transform: "scale(1)",
            opacity: "1",
          },
          "100%": {
            transform: "scale(0.94)",
            opacity: "0",
          },
        },
      },
    },
  },

  plugins: [
    plugin(function ({ addVariant }) {
      addVariant("state-open", [
        "&[data-state=“open”]",
        "[data-state=“open”] &",
      ])
      addVariant("state-closed", [
        "&[data-state=“closed”]",
        "[data-state=“closed”] &",
      ])
      addVariant("state-delayed-open", [
        "&[data-state=“delayed-open”]",
        "[data-state=“delayed-open”] &",
      ])
      addVariant("state-active", ["&[data-state=“active”]"])
      addVariant("state-inactive", ["&[data-state=“inactive”]"])
    }),
  ],
  content: ["./src/**/*.html", "./src/**/*.{ts,tsx}", "./index.html"],
}

export default config
