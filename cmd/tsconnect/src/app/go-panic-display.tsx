// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

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
