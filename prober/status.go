// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package prober

import (
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"tailscale.com/tsweb"
	"tailscale.com/util/mak"
)

//go:embed status.html
var statusFiles embed.FS
var statusTpl = template.Must(template.ParseFS(statusFiles, "status.html"))

type statusHandlerOpt func(*statusHandlerParams)
type statusHandlerParams struct {
	title string

	pageLinks  map[string]string
	probeLinks map[string]string
}

// WithTitle sets the title of the status page.
func WithTitle(title string) statusHandlerOpt {
	return func(opts *statusHandlerParams) {
		opts.title = title
	}
}

// WithPageLink adds a top-level link to the status page.
func WithPageLink(text, url string) statusHandlerOpt {
	return func(opts *statusHandlerParams) {
		mak.Set(&opts.pageLinks, text, url)
	}
}

// WithProbeLink adds a link to each probe on the status page.
// The textTpl and urlTpl are Go templates that will be rendered
// with the respective ProbeInfo struct as the data.
func WithProbeLink(textTpl, urlTpl string) statusHandlerOpt {
	return func(opts *statusHandlerParams) {
		mak.Set(&opts.probeLinks, textTpl, urlTpl)
	}
}

// StatusHandler is a handler for the probe overview HTTP endpoint.
// It shows a list of probes and their current status.
func (p *Prober) StatusHandler(opts ...statusHandlerOpt) tsweb.ReturnHandlerFunc {
	params := &statusHandlerParams{
		title: "Prober Status",
	}
	for _, opt := range opts {
		opt(params)
	}
	return func(w http.ResponseWriter, r *http.Request) error {
		type probeStatus struct {
			ProbeInfo
			TimeSinceLast time.Duration
			Links         map[string]template.URL
		}
		vars := struct {
			Title           string
			Links           map[string]template.URL
			TotalProbes     int64
			UnhealthyProbes int64
			Probes          map[string]probeStatus
		}{
			Title: params.title,
		}

		for text, url := range params.pageLinks {
			mak.Set(&vars.Links, text, template.URL(url))
		}

		for name, info := range p.ProbeInfo() {
			vars.TotalProbes++
			if !info.Result {
				vars.UnhealthyProbes++
			}
			s := probeStatus{ProbeInfo: info}
			if !info.End.IsZero() {
				s.TimeSinceLast = time.Since(info.End).Truncate(time.Second)
			}
			for textTpl, urlTpl := range params.probeLinks {
				text, err := renderTemplate(textTpl, info)
				if err != nil {
					return tsweb.Error(500, err.Error(), err)
				}
				url, err := renderTemplate(urlTpl, info)
				if err != nil {
					return tsweb.Error(500, err.Error(), err)
				}
				mak.Set(&s.Links, text, template.URL(url))
			}
			mak.Set(&vars.Probes, name, s)
		}

		if err := statusTpl.ExecuteTemplate(w, "status", vars); err != nil {
			return tsweb.HTTPError{Code: 500, Err: err, Msg: "error rendering status page"}
		}
		return nil
	}
}

// renderTemplate renders the given Go template with the provided data
// and returns the result as a string.
func renderTemplate(tpl string, data any) (string, error) {
	t, err := template.New("").Parse(tpl)
	if err != nil {
		return "", fmt.Errorf("error parsing template %q: %w", tpl, err)
	}
	var buf strings.Builder
	if err := t.ExecuteTemplate(&buf, "", data); err != nil {
		return "", fmt.Errorf("error rendering template %q with data %v: %w", tpl, data, err)
	}
	return buf.String(), nil
}
