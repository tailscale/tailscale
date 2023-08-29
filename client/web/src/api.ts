let csrfToken: string

// apiFetch wraps the standard JS fetch function with csrf header
// management and param additions specific to the web client.
//
// apiFetch adds the `api` prefix to the request URL,
// so endpoint should be provided without the `api` prefix
// (i.e. provide `/data` rather than `api/data`).
export function apiFetch(
  endpoint: string,
  init?: RequestInit | undefined,
  addURLParams?: Record<string, string>
): Promise<Response> {
  const urlParams = new URLSearchParams(window.location.search)
  const nextParams = new URLSearchParams(addURLParams)
  const token = urlParams.get("SynoToken")
  if (token) {
    nextParams.set("SynoToken", token)
  }
  const search = nextParams.toString()
  const url = `api${endpoint}${search ? `?${search}` : ""}`

  return fetch(url, {
    ...init,
    headers: withCsrfToken(init?.headers),
  }).then((r) => {
    updateCsrfToken(r)
    if (!r.ok) {
      return r.text().then((err) => {
        throw new Error(err)
      })
    }
    return r
  })
}

function withCsrfToken(h?: HeadersInit): HeadersInit {
  return { ...h, "X-CSRF-Token": csrfToken }
}

function updateCsrfToken(r: Response) {
  const tok = r.headers.get("X-CSRF-Token")
  if (tok) {
    csrfToken = tok
  }
}
