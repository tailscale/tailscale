let csrfToken: string

// apiFetch wraps the standard JS fetch function
// with csrf header management.
export function apiFetch(
  input: RequestInfo | URL,
  init?: RequestInit | undefined
): Promise<Response> {
  return fetch(input, {
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
