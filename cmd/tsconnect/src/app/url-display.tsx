// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

import { useState } from "preact/hooks"
import * as qrcode from "qrcode"

export function URLDisplay({ url }: { url: string }) {
  const [dataURL, setDataURL] = useState("")
  qrcode.toDataURL(url, { width: 512 }, (err, dataURL) => {
    if (err) {
      console.error("Error generating QR code", err)
    } else {
      setDataURL(dataURL)
    }
  })

  return (
    <div class="flex flex-col items-center justify-items-center">
      <a href={url} class="link" target="_blank">
        <img
          src={dataURL}
          class="mx-auto"
          width="256"
          height="256"
          alt="QR Code of URL"
        />
        {url}
      </a>
    </div>
  )
}
