// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

let csrfToken: string
let synoToken: string | undefined // required for synology API requests
let unraidCsrfToken: string | undefined // required for unraid POST requests (#8062)

// apiFetch wraps the standard JS fetch function with csrf header
// management and param additions specific to the web client.
//
// apiFetch adds the `api` prefix to the request URL,
// so endpoint should be provided without the `api` prefix
// (i.e. provide `/data` rather than `api/data`).
export function apiFetch<T>(
  endpoint: string,
  init?: RequestInit | undefined
): Promise<T> {
  const urlParams = new URLSearchParams(window.location.search)
  const nextParams = new URLSearchParams()
  if (synoToken) {
    nextParams.set("SynoToken", synoToken)
  } else {
    const token = urlParams.get("SynoToken")
    if (token) {
      nextParams.set("SynoToken", token)
    }
  }
  const search = nextParams.toString()
  const url = `api${endpoint}${search ? `?${search}` : ""}`

  var contentType: string
  if (unraidCsrfToken && init?.method === "POST") {
    const params = new URLSearchParams()
    params.append("csrf_token", unraidCsrfToken)
    if (init.body) {
      params.append("ts_data", init.body.toString())
    }
    init.body = params.toString()
    contentType = "application/x-www-form-urlencoded;charset=UTF-8"
  } else {
    contentType = "application/json"
  }

  return fetch(url, {
    ...init,
    headers: {
      Accept: "application/json",
      "Content-Type": contentType,
      "X-CSRF-Token": csrfToken,
    },
  })
    .then((r) => {
      updateCsrfToken(r)
      if (!r.ok) {
        return r.text().then((err) => {
          throw new Error(err)
        })
      }
      return r
    })
    .then((r) => r.json())
    .then((r) => {
      // TODO: MAYBE SET USING TOKEN HEADER
      if (r.IsUnraid && r.UnraidToken) {
        setUnraidCsrfToken(r.UnraidToken)
      }
      return r
    })
}

function updateCsrfToken(r: Response) {
  const tok = r.headers.get("X-CSRF-Token")
  if (tok) {
    csrfToken = tok
  }
}

export function setSynoToken(token?: string) {
  synoToken = token
}

export function setUnraidCsrfToken(token?: string) {
  unraidCsrfToken = token
}

/**
 * Some fetch wrappers.
 */

export async function getAuthSessionNew(): Promise<void> {
  const d = await apiFetch<{ authUrl: string }>("/auth/session/new", {
    method: "GET",
  })
  if (d.authUrl) {
    window.open(d.authUrl, "_blank")
    await apiFetch("/auth/session/wait", { method: "GET" })
  }
  // todo: still need catch for these, not using swr
}

type PatchLocalPrefsData = {
  RunSSHSet?: boolean
  RunSSH?: boolean
}

export async function patchLocalPrefs(p: PatchLocalPrefsData): Promise<void> {
  return apiFetch("/local/v0/prefs", {
    method: "PATCH",
    body: JSON.stringify(p), // todo: annoying to do this for all...
  })
  // .then(onComplete)
  // .catch((err) => {
  //   onComplete()
  //   alert("Failed to update prefs")
  //   throw err
  // })
}
