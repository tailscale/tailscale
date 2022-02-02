// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package tsweb

import (
	"context"
	"crypto/tls"
	"errors"
	"expvar"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
	"tailscale.com/metrics"
	"tailscale.com/types/logger"
)

const defaultTimeout = 10 * time.Second

// ServerConfig is the initial configuration of a Server, for
// consumption by NewServer.
type ServerConfig struct {
	// Name is a human-readable name for the HTTP server.
	//
	// It must be valid as both a directory name and the user portion
	// of an email address, so it's best to stick to a single
	// alphanumeric word, such as "derper" or "control".
	//
	// The name is for internal use only, for things like naming cache
	// directories, identifying the source of autocert emails,
	// human-readable debug pages, ...
	Name string
	// Addr specifies the TCP address for the server to listen on, in
	// the form "host:port". If blank, ":http" is used.
	//
	// If Addr specifies port 443, TLS serving is automatically
	// configured and a second listener is set up on port 80 to handle
	// HTTP to HTTPS redirection. All other ports result in HTTP-only
	// serving.
	Addr string
	// Handler is the HTTP.Handler to invoke to handle
	// requests. Cannot be nil.
	Handler http.Handler
	// AllowedHostnames is a function that reports whether autocert is
	// allowed to obtain TLS certificates for a given client request.
	//
	// If the list of valid hostnames is static, you probably want to
	// use autocert.HostWhitelist(...).
	//
	// If nil, autocert will not allow any TLS requests, and you
	// should override Server.HTTPS.TLSConfig.GetCertificate to handle
	// TLS certificates yourself.
	AllowedHostnames autocert.HostPolicy

	// HSTSNoSubdomains is whether to tell browsers to only apply
	// strict HTTPS serving to the current domain being requested,
	// rather than the request domain and all its subdomains (the
	// default).
	HSTSNoSubdomains bool

	// RequestLog, if non-nil, receives one AccessLogRecord for every
	// completed HTTP request (unless the request handler invoked
	// SuppressLogging).
	RequestLog func(*AccessLogRecord)

	// ForceTLS is whether to configure Server for TLS serving only,
	// regardless of Addr's port number. This disables autocert (since
	// autocert can't function on non-443 ports) and HTTP serving, and
	// requires you to adjust Server.HTTPS.TLSConfig yourself.
	ForceTLS bool

	// TODO: some kind of dev mode? Alter how request logging and
	// error handling is done to be more human-friendly?
}

// Server is an HTTP+HTTPS server. Callers should get a Server by
// calling NewServer, then applying any desired customizations to the
// prefilled fields prior to calling ListenAndServe.
type Server struct {
	// Handler is the root handler for the Server.
	Handler http.Handler

	// HTTPS is the HTTPS serving component of the server.
	// When non-nil, it defaults to getting TLS certs from
	// CertManager, and enforces TLS 1.2 as the minimum protocol
	// version.
	HTTPS *http.Server
	// CertManager, if non-nil, manages TLS certificates for HTTPS.
	CertManager *autocert.Manager

	// HTTP is the HTTP serving component of the server. If HTTPS
	// serving is disabled, this is the main HTTP server. Otherwise,
	// it redirects everything to HTTPS, except for debug handlers
	// which are served directly to authorized clients.
	HTTP *http.Server

	// Debug is the handler for /debug/ on HTTP and HTTPS.
	Debug *DebugHandler

	// AlwaysHeaders are HTTP headers that are set on all requests
	// prior to invoking Handler.
	AlwaysHeaders http.Header
	// TLSHeaders are HTTP headers that are set on all TLS requests
	// prior to invoking Handler.
	TLSHeaders http.Header

	// RequestLog is where HTTP request logs are written. If nil,
	// request logging is disabled.
	RequestLog func(*AccessLogRecord)

	now func() time.Time // normally time.Now, modified for tests

	vars         metrics.Set
	httpRequests expvar.Int       // counter, completed requests
	httpActive   expvar.Int       // gauge, currently alive requests
	tlsRequests  metrics.LabelMap // counter, completed requests
	tlsActive    metrics.LabelMap // gauge, currently alive requests
	statusCode   metrics.LabelMap // status code of completed requests
	statusFamily metrics.LabelMap // like statusCode, but bucketed by 1st digit of status code
}

// NewServer returns a Server, initialized by cfg with good defaults
// for serving.
func NewServer(cfg ServerConfig) *Server {
	s := &Server{
		Handler:       cfg.Handler,
		Debug:         Debugger(http.NewServeMux()),
		AlwaysHeaders: http.Header{},
		TLSHeaders:    http.Header{},

		tlsRequests:  metrics.LabelMap{Label: "version"},
		tlsActive:    metrics.LabelMap{Label: "version"},
		statusCode:   metrics.LabelMap{Label: "code"},
		statusFamily: metrics.LabelMap{Label: "code_family"},
	}

	s.vars.Set("http_requests", &s.httpRequests)
	s.vars.Set("gauge_http_active", &s.httpActive)
	s.vars.Set("tls_request_version", &s.tlsRequests)
	s.vars.Set("gauge_tls_active_version", &s.tlsActive)
	s.vars.Set("http_status", &s.statusCode)
	s.vars.Set("http_status_family", &s.statusFamily)

	switch {
	case cfg.ForceTLS:
		s.HTTPS = &http.Server{
			Addr:         cfg.Addr,
			Handler:      s,
			ReadTimeout:  defaultTimeout,
			WriteTimeout: defaultTimeout,
			IdleTimeout:  defaultTimeout,
			TLSConfig: &tls.Config{
				NextProtos: []string{
					"h2", "http/1.1", // enable HTTP/2
				},
				MinVersion: tls.VersionTLS12,
			},
		}
		// Deliberately don't forcibly enable HSTS here, this is a
		// configuration where the caller has requested very manual
		// TLS management, we shouldn't impose HSTS.
	case IsProd443(cfg.Addr):
		s.CertManager = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache(DefaultCertDir(cfg.Name)),
			Email:      fmt.Sprintf("infra+autocert-%s@tailscale.com", cfg.Name),
			HostPolicy: cfg.AllowedHostnames,
		}
		if s.CertManager.HostPolicy == nil {
			s.CertManager.HostPolicy = func(context.Context, string) error {
				return errors.New("no TLS serving allowed")
			}
		}
		s.HTTPS = &http.Server{
			Addr:         cfg.Addr,
			Handler:      s,
			ReadTimeout:  defaultTimeout,
			WriteTimeout: defaultTimeout,
			IdleTimeout:  defaultTimeout,
			TLSConfig:    s.CertManager.TLSConfig(),
		}
		s.HTTPS.TLSConfig.MinVersion = tls.VersionTLS12
		s.HTTP = &http.Server{
			Addr:         ":80",
			Handler:      s.CertManager.HTTPHandler(Port80Handler{s}),
			ReadTimeout:  defaultTimeout,
			WriteTimeout: defaultTimeout,
			IdleTimeout:  defaultTimeout,
		}
		hstsVal := "max-age=63072000"
		if !cfg.HSTSNoSubdomains {
			hstsVal += "; includeSubDomains"
		}
		s.TLSHeaders.Set("Strict-Transport-Security", hstsVal)
	default:
		s.HTTP = &http.Server{
			Addr:         cfg.Addr,
			Handler:      s,
			ReadTimeout:  defaultTimeout,
			WriteTimeout: defaultTimeout,
			IdleTimeout:  defaultTimeout,
		}
	}
	s.AlwaysHeaders.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; form-action 'none'; base-uri 'self'; block-all-mixed-content; plugin-types 'none'")
	s.AlwaysHeaders.Set("X-Frame-Options", "DENY")
	s.AlwaysHeaders.Set("X-Content-Type-Options", "nosniff")

	return s
}

// ListenAndServe listens on the TCP network addresses s.HTTP.Addr and
// s.HTTPS.Addr (if any) and then calls Serve or ServeTLS to handle
// incoming requests.
//
// If s.HTTP.Addr is blank, ":http" is used.
// If s.HTTPS.Addr is blank, ":https" is used.
func (s *Server) ListenAndServe() error {
	errCh := make(chan error, 2)

	if s.HTTP != nil {
		go func() { errCh <- s.HTTP.ListenAndServe() }()
	}
	if s.HTTPS != nil {
		go func() { errCh <- s.HTTPS.ListenAndServeTLS("", "") }()
	}

	err := <-errCh
	if err == http.ErrServerClosed {
		return nil
	}
	return err
}

// close immediately closes all listeners and connections, except
// hijacked Conns. Returns any error returned from closing underlying
// listeners.
func (s *Server) Close() error {
	var err error
	if s.HTTP != nil {
		err = s.HTTP.Close()
	}
	if s.HTTPS != nil {
		err2 := s.HTTPS.Close()
		if err == nil {
			err = err2
		}
	}
	return err
}

// ServeHTTP wraps s.Handler and adds the following features:
//  - Initializes default values for response headers from
//    s.AlwaysHeaders and s.TLSHeaders (if the request is over TLS).
//  - Sends requests for /debug/* to s.Debug.
//  - Maintains HTTP and TLS expvar metrics.
//  - If s.RequestLog is non-nil, writes out JSON AccessLogRecord
//    structs when requests complete.
//  - Injects tailscale helpers into the request context, so that
//    helpers like Err and SuppressLogging work.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer s.httpRequests.Add(1)
	s.httpActive.Add(1)
	defer s.httpActive.Add(-1)
	if r.TLS != nil {
		label := "unknown"
		switch r.TLS.Version {
		case tls.VersionTLS10:
			label = "1.0"
		case tls.VersionTLS11:
			label = "1.1"
		case tls.VersionTLS12:
			label = "1.2"
		case tls.VersionTLS13:
			label = "1.3"
		}
		defer s.tlsRequests.Add(label, 1)
		s.tlsActive.Add(label, 1)
		defer s.tlsActive.Add(label, -1)
	}

	for k, v := range s.AlwaysHeaders {
		w.Header()[k] = v
	}
	if r.TLS != nil {
		for k, v := range s.TLSHeaders {
			w.Header()[k] = v
		}
	}

	// always throw in a loggingResponseWriter, even when not writing
	// access logs, so that we can record the response code and push
	// it to metrics.
	lw := &loggingResponseWriter{ResponseWriter: w, logf: logger.Discard}

	path := r.RequestURI
	switch {
	case path == "/debug" || strings.HasPrefix(path, "/debug/"):
		s.Debug.ServeHTTP(lw, r)
	case s.RequestLog != nil:
		s.serveAndLog(lw, r)
	default:
		s.Handler.ServeHTTP(lw, r)
	}

	s.statusCode.Add(strconv.Itoa(lw.httpCode()), 1)
	key := fmt.Sprintf("%dxx", lw.httpCode()/100)
	s.statusFamily.Add(key, 1)
}

// serveAndLog invokes s.Handler and writes an access log entry to
// s.RequestLog, which must be non-nil.
//
// s.Handler can provide a detailed error value, which is only logged
// and not sent to the client, using the Err helper.
//
// s.Handler can suppress the writing of an access log entry by using
// the SuppressLogging helper, for example to not log successful
// requests on very high-volume API endpoints.
func (s *Server) serveAndLog(lw *loggingResponseWriter, r *http.Request) {
	msg := &AccessLogRecord{
		When:       s.now(),
		RemoteAddr: r.RemoteAddr,
		Proto:      r.Proto,
		TLS:        r.TLS != nil,
		Host:       r.Host,
		Method:     r.Method,
		RequestURI: r.URL.RequestURI(),
		UserAgent:  r.UserAgent(),
		Referer:    r.Referer(),
	}

	var (
		detailedErr     error
		suppressLogging bool
	)
	ctx := context.WithValue(r.Context(), ctxRecordError, &detailedErr)
	ctx = context.WithValue(ctx, ctxSuppressLogging, &suppressLogging)
	r = r.WithContext(ctx)
	s.Handler.ServeHTTP(lw, r)

	if suppressLogging {
		return
	}

	msg.Seconds = s.now().Sub(msg.When).Seconds()
	msg.Bytes = lw.bytes
	msg.Code = lw.httpCode()
	if detailedErr != nil {
		msg.Err = detailedErr.Error()
	}

	s.RequestLog(msg)
}

var (
	// ctxRecordError is a context.WithValue key that stores a pointer
	// to an error, which http.Handlers can use to record a detailed
	// error that will be attached to the request's log entry.
	ctxRecordError = struct{}{}
	// ctxSuppressLogging is a context.WithValue key that stores a
	// pointer to a bool, which http.Handlers can set to true if they
	// want to suppress the writing of the current request's log
	// entry.
	ctxSuppressLogging = struct{}{}
)

// Err records err as a detailed internal error for r, for possible
// logging.
func Err(r *http.Request, err error) {
	if perr, ok := r.Context().Value(ctxRecordError).(*error); ok {
		*perr = err
	}
}

// SuppressLogging requests that no access log entry be written for r.
func SuppressLogging(r *http.Request) {
	if pb, ok := r.Context().Value(ctxSuppressLogging).(*bool); ok {
		*pb = true
	}
}
