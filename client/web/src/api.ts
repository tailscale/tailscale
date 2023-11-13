let csrfToken: string
let synoToken: string | undefined // required for synology API requests
let unraidCsrfToken: string | undefined // required for unraid POST requests (#8062)

// apiFetch wraps the standard JS fetch function with csrf header
// management and param additions specific to the web client.
//
// apiFetch adds the `api` prefix to the request URL,
// so endpoint should be provided without the `api` prefix
// (i.e. provide `/data` rather than `api/data`).
export function apiFetch(
  endpoint: string,
  method: "GET" | "POST" | "PATCH",
  body?: any,
  params?: Record<string, string>
): Promise<Response> {
  const urlParams = new URLSearchParams(window.location.search)
  const nextParams = new URLSearchParams(params)
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
  if (unraidCsrfToken && method === "POST") {
    const params = new URLSearchParams()
    params.append("csrf_token", unraidCsrfToken)
    if (body) {
      params.append("ts_data", JSON.stringify(body))
    }
    body = params.toString()
    contentType = "application/x-www-form-urlencoded;charset=UTF-8"
  } else {
    body = body ? JSON.stringify(body) : undefined
    contentType = "application/json"
  }

  return fetch(url, {
    method: method,
    headers: {
      Accept: "application/json",
      "Content-Type": contentType,
      "X-CSRF-Token": csrfToken,
    },
    body,
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
