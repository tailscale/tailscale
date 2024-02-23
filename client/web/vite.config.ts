/// <reference types="vitest" />
import { createLogger, defineConfig } from "vite"
import svgr from "vite-plugin-svgr"
import paths from "vite-tsconfig-paths"

// Use a custom logger that filters out Vite's logging of server URLs, since
// they are an attractive nuisance (we run a proxy in front of Vite, and the
// tailscale web client should be accessed through that).
// Unfortunately there's no option to disable this logging, so the best we can
// do it to ignore calls from a specific function.
const filteringLogger = createLogger(undefined, { allowClearScreen: false })
const originalInfoLog = filteringLogger.info
filteringLogger.info = (...args) => {
  if (new Error("ignored").stack?.includes("printServerUrls")) {
    return
  }
  originalInfoLog.apply(filteringLogger, args)
}

// https://vitejs.dev/config/
export default defineConfig({
  base: "./",
  plugins: [
    paths(),
    svgr(),
  ],
  build: {
    outDir: "build",
    sourcemap: false,
  },
  esbuild: {
    logOverride: {
      // Silence a warning about `this` being undefined in ESM when at the
      // top-level. The way JSX is transpiled causes this to happen, but it
      // isn't a problem.
      // See: https://github.com/vitejs/vite/issues/8644
      "this-is-undefined-in-esm": "silent",
    },
  },
  server: {
    // This needs to be 127.0.0.1 instead of localhost, because of how our
    // Go proxy connects to it.
    host: "127.0.0.1",
    // If you change the port, be sure to update the proxy in assets.go too.
    port: 4000,
  },
  test: {
    exclude: ["**/node_modules/**", "**/dist/**"],
    testTimeout: 20000,
    environment: "jsdom",
    deps: {
      inline: ["date-fns", /\.wasm\?url$/],
    },
  },
  clearScreen: false,
  customLogger: filteringLogger,
})
