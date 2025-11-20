// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

//go:build !plan9

// Package sessionrecording contains functionality for recording Kubernetes API
// server proxy 'kubectl exec/attach' sessions.
package sessionrecording

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"strings"

	"go.uber.org/zap"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/k8s-operator/sessionrecording/spdy"
	"tailscale.com/k8s-operator/sessionrecording/tsrecorder"
	"tailscale.com/k8s-operator/sessionrecording/ws"
	"tailscale.com/net/netx"
	"tailscale.com/sessionrecording"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/tstime"
	"tailscale.com/util/clientmetric"
)

const (
	SPDYProtocol      Protocol    = "SPDY"
	WSProtocol        Protocol    = "WebSocket"
	ExecSessionType   SessionType = "exec"
	AttachSessionType SessionType = "attach"
)

// Protocol is the streaming protocol of the hijacked session. Supported
// protocols are SPDY and WebSocket.
type Protocol string

// SessionType is the type of session initiated with `kubectl`
// (`exec` or `attach`)
type SessionType string

var (
	// CounterSessionRecordingsAttempted counts the number of session recording attempts.
	CounterSessionRecordingsAttempted = clientmetric.NewCounter("k8s_auth_proxy_session_recordings_attempted")

	// counterSessionRecordingsUploaded counts the number of successfully uploaded session recordings.
	counterSessionRecordingsUploaded = clientmetric.NewCounter("k8s_auth_proxy_session_recordings_uploaded")
)

func NewHijacker(opts HijackerOpts) *Hijacker {
	return &Hijacker{
		ts:                opts.TS,
		req:               opts.Req,
		who:               opts.Who,
		ResponseWriter:    opts.W,
		pod:               opts.Pod,
		ns:                opts.Namespace,
		addrs:             opts.Addrs,
		failOpen:          opts.FailOpen,
		proto:             opts.Proto,
		log:               opts.Log,
		sessionType:       opts.SessionType,
		connectToRecorder: sessionrecording.ConnectToRecorder,
	}
}

type HijackerOpts struct {
	TS          *tsnet.Server
	Req         *http.Request
	W           http.ResponseWriter
	Who         *apitype.WhoIsResponse
	Addrs       []netip.AddrPort
	Log         *zap.SugaredLogger
	Pod         string
	Namespace   string
	FailOpen    bool
	Proto       Protocol
	SessionType SessionType
}

// Hijacker implements [net/http.Hijacker] interface.
// It must be configured with an http request for a 'kubectl exec/attach' session that
// needs to be recorded. It knows how to hijack the connection and configure for
// the session contents to be sent to a tsrecorder instance.
type Hijacker struct {
	http.ResponseWriter
	ts                *tsnet.Server
	req               *http.Request
	who               *apitype.WhoIsResponse
	log               *zap.SugaredLogger
	pod               string           // pod being exec/attach-d
	ns                string           // namespace of the pod being exec/attach-d
	addrs             []netip.AddrPort // tsrecorder addresses
	failOpen          bool             // whether to fail open if recording fails
	connectToRecorder RecorderDialFn
	proto             Protocol    // streaming protocol
	sessionType       SessionType // subcommand, e.g., "exec, attach"
}

// RecorderDialFn dials the specified netip.AddrPorts that should be tsrecorder
// addresses. It tries to connect to recorder endpoints one by one, till one
// connection succeeds. In case of success, returns a list with a single
// successful recording attempt and an error channel. If the connection errors
// after having been established, an error is sent down the channel.
type RecorderDialFn func(context.Context, []netip.AddrPort, netx.DialFunc) (io.WriteCloser, []*tailcfg.SSHRecordingAttempt, <-chan error, error)

// Hijack hijacks a 'kubectl exec/attach' session and configures for the session
// contents to be sent to a recorder.
func (h *Hijacker) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h.log.Infof("recorder addrs: %v, failOpen: %v", h.addrs, h.failOpen)
	reqConn, brw, err := h.ResponseWriter.(http.Hijacker).Hijack()
	if err != nil {
		return nil, nil, fmt.Errorf("error hijacking connection: %w", err)
	}

	conn, err := h.setUpRecording(reqConn)
	if err != nil {
		return nil, nil, fmt.Errorf("error setting up session recording: %w", err)
	}
	return conn, brw, nil
}

// setupRecording attempts to connect to the recorders set via
// spdyHijacker.addrs. Returns conn from provided opts, wrapped in recording
// logic. If connecting to the recorder fails or an error is received during the
// session and spdyHijacker.failOpen is false, connection will be closed.
func (h *Hijacker) setUpRecording(conn net.Conn) (_ net.Conn, retErr error) {
	const (
		// https://docs.asciinema.org/manual/asciicast/v2/
		asciicastv2  = 2
		ttyKey       = "tty"
		commandKey   = "command"
		containerKey = "container"
	)
	var (
		wc      io.WriteCloser
		err     error
		errChan <-chan error
	)
	h.log.Infof("kubectl %s session will be recorded, recorders: %v, fail open policy: %t", h.sessionType, h.addrs, h.failOpen)
	// NOTE: (ChaosInTheCRD) we want to use a dedicated context here, rather than the context from the request,
	// otherwise the context can be cancelled by the client (kubectl) while we are still streaming to tsrecorder.
	ctx, cancel := context.WithCancel(context.Background())
	defer func() {
		if retErr != nil {
			cancel()
		}
	}()
	qp := h.req.URL.Query()
	container := strings.Join(qp[containerKey], "")
	var recorderAddr net.Addr
	trace := &httptrace.ClientTrace{
		GotConn: func(info httptrace.GotConnInfo) {
			recorderAddr = info.Conn.RemoteAddr()
		},
	}
	wc, _, errChan, err = h.connectToRecorder(httptrace.WithClientTrace(ctx, trace), h.addrs, h.ts.Dial)
	if err != nil {
		msg := fmt.Sprintf("error connecting to session recorders: %v", err)
		if h.failOpen {
			msg = msg + "; failure mode is 'fail open'; continuing session without recording."
			h.log.Warnf(msg)
			return conn, nil
		}
		msg = msg + "; failure mode is 'fail closed'; closing connection."
		if err := closeConnWithWarning(conn, msg); err != nil {
			return nil, errors.Join(errors.New(msg), err)
		}
		return nil, errors.New(msg)
	} else {
		h.log.Infof("%s session to container %q in Pod %q namespace %q will be recorded, the recording will be sent to a tsrecorder instance at %q", h.sessionType, container, h.pod, h.ns, recorderAddr)
	}

	cl := tstime.DefaultClock{}
	rec := tsrecorder.New(wc, cl, cl.Now(), h.failOpen, h.log)
	tty := strings.Join(qp[ttyKey], "")
	hasTerm := (tty == "true") // session has terminal attached
	ch := sessionrecording.CastHeader{
		Version:   asciicastv2,
		Timestamp: cl.Now().Unix(),
		Command:   strings.Join(qp[commandKey], " "),
		SrcNode:   strings.TrimSuffix(h.who.Node.Name, "."),
		SrcNodeID: h.who.Node.StableID,
		Kubernetes: &sessionrecording.Kubernetes{
			PodName:     h.pod,
			Namespace:   h.ns,
			Container:   container,
			SessionType: string(h.sessionType),
		},
	}
	if !h.who.Node.IsTagged() {
		ch.SrcNodeUser = h.who.UserProfile.LoginName
		ch.SrcNodeUserID = h.who.Node.User
	} else {
		ch.SrcNodeTags = h.who.Node.Tags
	}

	var lc net.Conn
	switch h.proto {
	case SPDYProtocol:
		lc, err = spdy.New(ctx, conn, rec, ch, hasTerm, h.log)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize spdy connection: %w", err)
		}
	case WSProtocol:
		lc, err = ws.New(ctx, conn, rec, ch, hasTerm, h.log)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize websocket connection: %w", err)
		}
	default:
		return nil, fmt.Errorf("unknown protocol: %s", h.proto)
	}

	go func() {
		defer cancel()
		var err error
		select {
		case <-ctx.Done():
			return
		case err = <-errChan:
		}
		if err == nil {
			counterSessionRecordingsUploaded.Add(1)
			h.log.Info("finished uploading the recording")
			return
		}
		msg := fmt.Sprintf("connection to the session recorder errored: %v;", err)
		if h.failOpen {
			msg += msg + "; failure mode is 'fail open'; continuing session without recording."
			h.log.Info(msg)
			return
		}
		msg += "; failure mode set to 'fail closed'; closing connection"
		h.log.Error(msg)
		// TODO (irbekrm): write a message to the client
		if err := lc.Close(); err != nil {
			h.log.Infof("error closing recorder connections: %v", err)
		}
	}()
	return lc, nil
}

func closeConnWithWarning(conn net.Conn, msg string) error {
	b := io.NopCloser(bytes.NewBuffer([]byte(msg)))
	resp := http.Response{Status: http.StatusText(http.StatusForbidden), StatusCode: http.StatusForbidden, Body: b}
	if err := resp.Write(conn); err != nil {
		return errors.Join(fmt.Errorf("error writing msg %q to conn: %v", msg, err), conn.Close())
	}
	return conn.Close()
}
