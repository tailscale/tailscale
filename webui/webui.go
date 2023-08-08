// Package webui provides the Tailscale client for web.
package webui

import (
	"fmt"
	"net/http"
)

func Handle(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Hello, world")
}
