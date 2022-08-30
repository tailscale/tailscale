import { Terminal } from "xterm"
import { FitAddon } from "xterm-addon-fit"

export type SSHSessionDef = {
  username: string
  hostname: string
}

export function runSSHSession(
  termContainerNode: HTMLDivElement,
  def: SSHSessionDef,
  ipn: IPN,
  onDone: () => void
) {
  const term = new Terminal({
    cursorBlink: true,
  })
  const fitAddon = new FitAddon()
  term.loadAddon(fitAddon)
  term.open(termContainerNode)
  fitAddon.fit()

  let onDataHook: ((data: string) => void) | undefined
  term.onData((e) => {
    onDataHook?.(e)
  })

  term.focus()

  let resizeObserver: ResizeObserver | undefined
  let handleBeforeUnload: ((e: BeforeUnloadEvent) => void) | undefined

  const sshSession = ipn.ssh(def.hostname + "2", def.username, {
    writeFn(input) {
      term.write(input)
    },
    writeErrorFn(err) {
      console.error(err)
      term.write(err)
    },
    setReadFn(hook) {
      onDataHook = hook
    },
    rows: term.rows,
    cols: term.cols,
    onDone() {
      resizeObserver?.disconnect()
      term.dispose()
      if (handleBeforeUnload) {
        window.removeEventListener("beforeunload", handleBeforeUnload)
      }
      onDone()
    },
  })

  // Make terminal and SSH session track the size of the containing DOM node.
  resizeObserver = new ResizeObserver(() => fitAddon.fit())
  resizeObserver.observe(termContainerNode)
  term.onResize(({ rows, cols }) => sshSession.resize(rows, cols))

  // Close the session if the user closes the window without an explicit
  // exit.
  handleBeforeUnload = () => sshSession.close()
  window.addEventListener("beforeunload", handleBeforeUnload)
}
