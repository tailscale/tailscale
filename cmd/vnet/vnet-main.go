// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The vnet binary runs a virtual network stack in userspace for qemu instances
// to connect to and simulate various network conditions.
package main

import (
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/coder/websocket"
	"tailscale.com/tstest/natlab/vnet"
	"tailscale.com/types/logger"
	"tailscale.com/util/must"
)

var (
	listen   = flag.String("listen", "/tmp/qemu.sock", "path to listen on")
	nat      = flag.String("nat", "easy", "type of NAT to use")
	nat2     = flag.String("nat2", "hard", "type of NAT to use for second network")
	portmap  = flag.Bool("portmap", false, "enable portmapping; requires --v4")
	dgram    = flag.Bool("dgram", false, "enable datagram mode; for use with macOS Hypervisor.Framework and VZFileHandleNetworkDeviceAttachment")
	blend    = flag.Bool("blend", true, "blend reality (controlplane.tailscale.com and DERPs) into the virtual network")
	pcapFile = flag.String("pcap", "", "if non-empty, filename to write pcap")
	v4       = flag.Bool("v4", true, "enable IPv4")
	v6       = flag.Bool("v6", true, "enable IPv6")

	wsproxyListen = flag.String("wsproxy", "", "if non-empty, TCP address to run websocket server on. See https://github.com/copy/v86/blob/master/docs/networking.md#backend-url-schemes")
)

func main() {
	flag.Parse()
	if *wsproxyListen != "" {
		if err := runWSProxy(); err != nil {
			log.Fatalf("runWSProxy: %v", err)
		}
		return
	}

	if _, err := os.Stat(*listen); err == nil {
		os.Remove(*listen)
	}

	var srv net.Listener
	var err error
	var conn *net.UnixConn
	if *dgram {
		addr, err := net.ResolveUnixAddr("unixgram", *listen)
		if err != nil {
			log.Fatalf("ResolveUnixAddr: %v", err)
		}
		conn, err = net.ListenUnixgram("unixgram", addr)
		if err != nil {
			log.Fatalf("ListenUnixgram: %v", err)
		}
		defer conn.Close()
	} else {
		srv, err = net.Listen("unix", *listen)
	}
	if err != nil {
		log.Fatal(err)
	}

	var c vnet.Config
	c.SetPCAPFile(*pcapFile)
	c.SetBlendReality(*blend)

	var net1opt = []any{vnet.NAT(*nat)}
	if *v4 {
		net1opt = append(net1opt, "2.1.1.1", "192.168.1.1/24")
	}
	if *v6 {
		net1opt = append(net1opt, "2000:52::1/64")
	}

	node1 := c.AddNode(c.AddNetwork(net1opt...))
	c.AddNode(c.AddNetwork("2.2.2.2", "10.2.0.1/16", vnet.NAT(*nat2)))
	if *portmap && *v4 {
		node1.Network().AddService(vnet.NATPMP)
	}

	s, err := vnet.New(&c)
	if err != nil {
		log.Fatalf("newServer: %v", err)
	}

	if *blend {
		if err := s.PopulateDERPMapIPs(); err != nil {
			log.Printf("warning: ignoring failure to populate DERP map: %v", err)
		}
	}

	s.WriteStartingBanner(os.Stdout)
	nc := s.NodeAgentClient(node1)
	go func() {
		rp := httputil.NewSingleHostReverseProxy(must.Get(url.Parse("http://gokrazy")))
		d := rp.Director
		rp.Director = func(r *http.Request) {
			d(r)
			r.Header.Set("X-TTA-GoKrazy", "1")
		}
		rp.Transport = nc.HTTPClient.Transport
		http.ListenAndServe(":8080", rp)
	}()
	go func() {
		var last string
		getStatus := func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			st, err := nc.Status(ctx)
			if err != nil {
				log.Printf("NodeStatus: %v", err)
				return
			}
			if st.BackendState != last {
				last = st.BackendState
				log.Printf("NodeStatus: %v", logger.AsJSON(st))
			}
		}
		for {
			time.Sleep(5 * time.Second)
			//continue
			getStatus()
		}
	}()

	if conn != nil {
		s.ServeUnixConn(conn, vnet.ProtocolUnixDGRAM)
		return
	}

	for {
		c, err := srv.Accept()
		if err != nil {
			log.Printf("Accept: %v", err)
			continue
		}
		go s.ServeUnixConn(c.(*net.UnixConn), vnet.ProtocolQEMU)
	}
}

func runWSProxy() error {
	ln, err := net.Listen("tcp", *wsproxyListen)
	if err != nil {
		return err
	}
	defer ln.Close()

	log.Printf("Running wsproxy mode on %v ...", *wsproxyListen)

	var hs http.Server
	hs.Handler = http.HandlerFunc(handleWebSocket)

	return hs.Serve(ln)
}

func handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("Upgrade error: %v", err)
		return
	}
	defer conn.Close(websocket.StatusInternalError, "closing")
	log.Printf("WebSocket client connected: %s", r.RemoteAddr)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	messageType, firstData, err := conn.Read(ctx)
	if err != nil {
		log.Printf("ReadMessage first: %v", err)
		return
	}
	if messageType != websocket.MessageBinary {
		log.Printf("Ignoring non-binary message")
		return
	}
	if len(firstData) < 12 {
		log.Printf("Ignoring short message")
		return
	}
	clientMAC := vnet.MAC(firstData[6:12])

	// Set up a qemu-protocol Unix socket pair. We'll fake the qemu protocol here
	// to avoid changing the vnet package.
	td, err := os.MkdirTemp("", "vnet")
	if err != nil {
		panic(fmt.Errorf("MkdirTemp: %v", err))
	}
	defer os.RemoveAll(td)

	unixSrv := filepath.Join(td, "vnet.sock")

	srv, err := net.Listen("unix", unixSrv)
	if err != nil {
		panic(fmt.Errorf("Listen: %v", err))
	}
	defer srv.Close()

	var c vnet.Config
	c.SetBlendReality(true)

	var net1opt = []any{vnet.NAT("easy")}
	net1opt = append(net1opt, "2.1.1.1", "192.168.1.1/24")
	net1opt = append(net1opt, "2000:52::1/64")

	c.AddNode(c.AddNetwork(net1opt...), clientMAC)

	vs, err := vnet.New(&c)
	if err != nil {
		panic(fmt.Errorf("newServer: %v", err))
	}
	if err := vs.PopulateDERPMapIPs(); err != nil {
		log.Printf("warning: ignoring failure to populate DERP map: %v", err)
		return
	}

	errc := make(chan error, 1)
	fail := func(err error) {
		select {
		case errc <- err:
			log.Printf("failed: %v", err)
		case <-ctx.Done():
		}
	}

	go func() {
		c, err := srv.Accept()
		if err != nil {
			fail(err)
			return
		}
		vs.ServeUnixConn(c.(*net.UnixConn), vnet.ProtocolQEMU)
	}()

	uc, err := net.Dial("unix", unixSrv)
	if err != nil {
		panic(fmt.Errorf("Dial: %v", err))
	}
	defer uc.Close()

	var frameBuf []byte
	writeDataToUnixConn := func(data []byte) error {
		frameBuf = slices.Grow(frameBuf[:0], len(data)+4)[:len(data)+4]
		binary.BigEndian.PutUint32(frameBuf[:4], uint32(len(data)))
		copy(frameBuf[4:], data)

		_, err = uc.Write(frameBuf)
		return err
	}
	if err := writeDataToUnixConn(firstData); err != nil {
		fail(err)
		return
	}

	go func() {
		for {
			messageType, data, err := conn.Read(ctx)
			if err != nil {
				fail(fmt.Errorf("ReadMessage: %v", err))
				break
			}

			if messageType != websocket.MessageBinary {
				log.Printf("Ignoring non-binary message")
				continue
			}

			if err := writeDataToUnixConn(data); err != nil {
				fail(err)
				return
			}
		}
	}()

	go func() {
		const maxBuf = 4096
		frameBuf := make([]byte, maxBuf)
		for {
			_, err := io.ReadFull(uc, frameBuf[:4])
			if err != nil {
				fail(err)
				return
			}
			frameLen := binary.BigEndian.Uint32(frameBuf[:4])
			if frameLen > maxBuf {
				fail(fmt.Errorf("frame too large: %d", frameLen))
				return
			}
			if _, err := io.ReadFull(uc, frameBuf[:frameLen]); err != nil {
				fail(err)
				return
			}

			if err := conn.Write(ctx, websocket.MessageBinary, frameBuf[:frameLen]); err != nil {
				fail(err)
				return
			}
		}
	}()

	<-ctx.Done()
}
