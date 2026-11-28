// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

//go:build !ios

package controlhttpserver

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp/controlhttpcommon"
	"tailscale.com/types/key"
)

// AcceptALPNTLS terminates TLS on conn using base and, if the client
// smuggled a Noise handshake initiation message in the ALPN protocol list of
// its ClientHello (see controlhttpcommon.ALPNHandshakePrefix), completes the
// ts2021 handshake directly over the TLS stream, with no HTTP layer.
//
// It returns exactly one of:
//   - a completed control connection, if the client smuggled a handshake
//   - the handshaken TLS connection, if the client didn't; the caller should
//     serve HTTP over it, including the /ts2021 upgrade handler
//   - an error, in which case conn has been closed
//
// The provided ctx bounds the TLS and Noise handshakes as in AcceptHTTP.
// earlyWrite is as in AcceptHTTP.
//
// TODO(bradfitz): with stock crypto/tls, the server's Handshake doesn't
// return until the client's Finished message arrives, so the Noise response
// goes out one round trip later than necessary. A TLS stack capable of
// 0.5-RTT writes (sending application data in the server's first flight)
// would let the Noise response ride along with the TLS ServerHello flight,
// making this path as fast as the plaintext port 80 path.
func AcceptALPNTLS(ctx context.Context, conn net.Conn, base *tls.Config, private key.MachinePrivate, earlyWrite func(protocolVersion int, w io.Writer) error) (_ *controlbase.Conn, _ *tls.Conn, retErr error) {
	defer func() {
		if retErr != nil {
			conn.Close()
		}
	}()

	var init []byte
	conf := base.Clone()
	conf.GetConfigForClient = func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
		smuggled, ok := controlhttpcommon.DecodeALPNHandshake(chi.SupportedProtos)
		if !ok {
			return nil, nil
		}
		init = smuggled
		c2 := base.Clone()
		c2.NextProtos = []string{controlhttpcommon.UpgradeHeaderValue}
		return c2, nil
	}

	tlsConn := tls.Server(conn, conf)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	if tlsConn.ConnectionState().NegotiatedProtocol != controlhttpcommon.UpgradeHeaderValue {
		return nil, tlsConn, nil
	}
	if init == nil {
		return nil, nil, errors.New("ts2021 ALPN protocol negotiated without a smuggled handshake")
	}

	// Cork writes so the Noise handshake response and any early payload
	// go out in a single TLS record.
	cwc := newWriteCorkingConn(tlsConn)

	nc, err := controlbase.Server(ctx, cwc, private, init)
	if err != nil {
		return nil, nil, fmt.Errorf("noise handshake failed: %w", err)
	}

	if earlyWrite != nil {
		if deadline, ok := ctx.Deadline(); ok {
			if err := tlsConn.SetDeadline(deadline); err != nil {
				return nil, nil, fmt.Errorf("setting conn deadline: %w", err)
			}
			defer tlsConn.SetDeadline(time.Time{})
		}
		if err := earlyWrite(nc.ProtocolVersion(), nc); err != nil {
			return nil, nil, err
		}
	}

	if err := cwc.uncork(); err != nil {
		return nil, nil, err
	}

	return nc, nil, nil
}
