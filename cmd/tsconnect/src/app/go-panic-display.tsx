// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

export function GoPanicDisplay({
  error,
  dismiss,
}: {
  error: string
  dismiss: () => void
}) {
  return (
    <div
      class="rounded bg-red-500 p-2 absolute top-2 right-2 text-white font-bold text-right cursor-pointer"
      onClick={dismiss}
    >
      Tailscale has encountered an error.
      <div class="text-sm font-normal">Click to reload</div>
    </div>
  )
}
