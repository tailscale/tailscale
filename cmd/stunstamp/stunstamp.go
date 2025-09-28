// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The stunstamp binary measures round-trip latency with DERPs.
package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"
	"github.com/tcnksm/go-httpstat"
	"tailscale.com/net/stun"
	"tailscale.com/net/tcpinfo"
	"tailscale.com/tailcfg"
	"tailscale.com/util/backoff"
)

var (
	flagDERPMap        = flag.String("derp-map", "https://login.tailscale.com/derpmap/default", "URL to DERP map")
	flagInterval       = flag.Duration("interval", time.Minute, "interval to probe at in time.ParseDuration() format")
	flagIPv6           = flag.Bool("ipv6", false, "probe IPv6 addresses")
	flagRemoteWriteURL = flag.String("rw-url", "", "prometheus remote write URL")
	flagInstance       = flag.String("instance", "", "instance label value; defaults to hostname if unspecified")
	flagSTUNDstPorts   = flag.String("stun-dst-ports", "", "comma-separated list of STUN destination ports to monitor")
	flagHTTPSDstPorts  = flag.String("https-dst-ports", "", "comma-separated list of HTTPS destination ports to monitor")
	flagTCPDstPorts    = flag.String("tcp-dst-ports", "", "comma-separated list of TCP destination ports to monitor")
	flagICMP           = flag.Bool("icmp", false, "probe ICMP")
)

const (
	// maxTxJitter is the upper bounds for jitter introduced across probes
	maxTXJitter = time.Millisecond * 400
	// minInterval is the minimum allowed probe interval/step
	minInterval = time.Second * 10
	// txRxTimeout is the timeout value used for kernel timestamping loopback,
	// and packet receive operations
	txRxTimeout = time.Second * 2
	// maxBufferDuration is the maximum duration (maxBufferDuration /
	// *flagInterval steps worth) of buffered data that can be held in memory
	// before data loss occurs around prometheus unavailability.
	maxBufferDuration = time.Hour
)

func getDERPMap(ctx context.Context, url string) (*tailcfg.DERPMap, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("non-200 derp map resp: %d", resp.StatusCode)
	}
	dm := tailcfg.DERPMap{}
	err = json.NewDecoder(resp.Body).Decode(&dm)
	if err != nil {
		return nil, fmt.Errorf("failed to decode derp map resp: %v", err)
	}
	return &dm, nil
}

type timestampSource int

const (
	timestampSourceUserspace timestampSource = iota
	timestampSourceKernel
)

func (t timestampSource) String() string {
	switch t {
	case timestampSourceUserspace:
		return "userspace"
	case timestampSourceKernel:
		return "kernel"
	default:
		return "unknown"
	}
}

type protocol string

const (
	protocolSTUN  protocol = "stun"
	protocolICMP  protocol = "icmp"
	protocolHTTPS protocol = "https"
	protocolTCP   protocol = "tcp"
)

// resultKey contains the stable dimensions and their values for a given
// timeseries, i.e. not time and not rtt/timeout.
type resultKey struct {
	meta            nodeMeta
	timestampSource timestampSource
	connStability   connStability
	protocol        protocol
	dstPort         int
}

type result struct {
	key resultKey
	at  time.Time
	rtt *time.Duration // nil signifies failure, e.g. timeout
}

type lportsPool struct {
	sync.Mutex
	ports []int
}

func (l *lportsPool) get() int {
	l.Lock()
	defer l.Unlock()
	ret := l.ports[0]
	l.ports = append(l.ports[:0], l.ports[1:]...)
	return ret
}

func (l *lportsPool) put(i int) {
	l.Lock()
	defer l.Unlock()
	l.ports = append(l.ports, int(i))
}

var (
	lports *lportsPool
)

const (
	lportPoolSize = 16000
	lportBase     = 2048
)

func init() {
	lports = &lportsPool{
		ports: make([]int, 0, lportPoolSize),
	}
	for i := lportBase; i < lportBase+lportPoolSize; i++ {
		lports.ports = append(lports.ports, i)
	}
}

// lportForTCPConn satisfies io.ReadWriteCloser, but is really just used to pass
// around a persistent laddr for stableConn purposes. The underlying TCP
// connection is not created until measurement time as in some cases we need to
// measure dial time.
type lportForTCPConn int

func (l *lportForTCPConn) Close() error {
	if *l == 0 {
		return nil
	}
	lports.put(int(*l))
	return nil
}

func (l *lportForTCPConn) Write([]byte) (int, error) {
	return 0, errors.New("unimplemented")
}

func (l *lportForTCPConn) Read([]byte) (int, error) {
	return 0, errors.New("unimplemented")
}

func addrInUse(err error, lport *lportForTCPConn) bool {
	if errors.Is(err, syscall.EADDRINUSE) {
		old := int(*lport)
		// abandon port, don't return it to pool
		*lport = lportForTCPConn(lports.get()) // get a new port
		log.Printf("EADDRINUSE: %v old: %d new: %d", err, old, *lport)
		return true
	}
	return false
}

func tcpDial(ctx context.Context, lport *lportForTCPConn, dst netip.AddrPort) (net.Conn, error) {
	for {
		var opErr error
		dialer := &net.Dialer{
			LocalAddr: &net.TCPAddr{
				Port: int(*lport),
			},
			Control: func(network, address string, c syscall.RawConn) error {
				return c.Control(func(fd uintptr) {
					// we may restart faster than TIME_WAIT can clear
					opErr = setSOReuseAddr(fd)
				})
			},
		}
		if opErr != nil {
			panic(opErr)
		}
		tcpConn, err := dialer.DialContext(ctx, "tcp", dst.String())
		if err != nil {
			if addrInUse(err, lport) {
				continue
			}
			return nil, err
		}
		return tcpConn, nil
	}
}

type tempError struct {
	error
}

func (t tempError) Temporary() bool {
	return true
}

func measureTCPRTT(conn io.ReadWriteCloser, _ string, dst netip.AddrPort) (rtt time.Duration, err error) {
	lport, ok := conn.(*lportForTCPConn)
	if !ok {
		return 0, fmt.Errorf("unexpected conn type: %T", conn)
	}
	// Set a dial timeout < 1s (TCP_TIMEOUT_INIT on Linux) as a means to avoid
	// SYN retries, which can contribute to tcpi->rtt below. This simply limits
	// retries from the initiator, but SYN+ACK on the reverse path can also
	// time out and be retransmitted.
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond*750)
	defer cancel()
	tcpConn, err := tcpDial(ctx, lport, dst)
	if err != nil {
		return 0, tempError{err}
	}
	defer tcpConn.Close()
	// This is an unreliable method to measure TCP RTT. The Linux kernel
	// describes it as such in tcp_rtt_estimator(). We take some care in how we
	// hold tcp_info->rtt here, e.g. clamping dial timeout, but if we are to
	// actually use this elsewhere as an input to some decision it warrants a
	// deeper study and consideration for alternative methods. Its usefulness
	// here is as a point of comparison against the other methods.
	rtt, err = tcpinfo.RTT(tcpConn)
	if err != nil {
		return 0, tempError{err}
	}
	return rtt, nil
}

func measureHTTPSRTT(conn io.ReadWriteCloser, hostname string, dst netip.AddrPort) (rtt time.Duration, err error) {
	lport, ok := conn.(*lportForTCPConn)
	if !ok {
		return 0, fmt.Errorf("unexpected conn type: %T", conn)
	}
	var httpResult httpstat.Result
	// 5s mirrors net/netcheck.overallProbeTimeout used in net/netcheck.Client.measureHTTPSLatency.
	reqCtx, cancel := context.WithTimeout(httpstat.WithHTTPStat(context.Background(), &httpResult), time.Second*5)
	defer cancel()
	reqURL := "https://" + dst.String() + "/derp/latency-check"
	req, err := http.NewRequestWithContext(reqCtx, "GET", reqURL, nil)
	if err != nil {
		return 0, err
	}
	client := &http.Client{}
	// 1.5s mirrors derp/derphttp.dialnodeTimeout used in derp/derphttp.DialNode().
	dialCtx, dialCancel := context.WithTimeout(reqCtx, time.Millisecond*1500)
	defer dialCancel()
	tcpConn, err := tcpDial(dialCtx, lport, dst)
	if err != nil {
		return 0, tempError{err}
	}
	defer tcpConn.Close()
	tlsConn := tls.Client(tcpConn, &tls.Config{
		ServerName: hostname,
	})
	// Mirror client/netcheck behavior, which handshakes before handing the
	// tlsConn over to the http.Client via http.Transport
	err = tlsConn.Handshake()
	if err != nil {
		return 0, tempError{err}
	}
	tlsConnCh := make(chan net.Conn, 1)
	tlsConnCh <- tlsConn
	tr := &http.Transport{
		DialTLSContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			select {
			case tlsConn := <-tlsConnCh:
				return tlsConn, nil
			default:
				return nil, errors.New("unexpected second call of DialTLSContext")
			}
		},
	}
	client.Transport = tr
	resp, err := client.Do(req)
	if err != nil {
		return 0, tempError{err}
	}
	if resp.StatusCode/100 != 2 {
		return 0, tempError{fmt.Errorf("unexpected status code: %d", resp.StatusCode)}
	}
	defer resp.Body.Close()
	_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, 8<<10))
	if err != nil {
		return 0, tempError{err}
	}
	httpResult.End(time.Now())
	return httpResult.ServerProcessing, nil
}

func measureSTUNRTT(conn io.ReadWriteCloser, _ string, dst netip.AddrPort) (rtt time.Duration, err error) {
	uconn, ok := conn.(*net.UDPConn)
	if !ok {
		return 0, fmt.Errorf("unexpected conn type: %T", conn)
	}
	err = uconn.SetReadDeadline(time.Now().Add(txRxTimeout))
	if err != nil {
		return 0, fmt.Errorf("error setting read deadline: %w", err)
	}
	txID := stun.NewTxID()
	req := stun.Request(txID)
	txAt := time.Now()
	_, err = uconn.WriteToUDP(req, &net.UDPAddr{
		IP:   dst.Addr().AsSlice(),
		Port: int(dst.Port()),
	})
	if err != nil {
		return 0, fmt.Errorf("error writing to udp socket: %w", err)
	}
	b := make([]byte, 1460)
	for {
		n, err := uconn.Read(b)
		rxAt := time.Now()
		if err != nil {
			return 0, fmt.Errorf("error reading from udp socket: %w", err)
		}
		gotTxID, _, err := stun.ParseResponse(b[:n])
		if err != nil || gotTxID != txID {
			continue
		}
		return rxAt.Sub(txAt), nil
	}

}

func isTemporaryOrTimeoutErr(err error) bool {
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	if err, ok := err.(interface{ Temporary() bool }); ok {
		return err.Temporary()
	}
	return false
}

type nodeMeta struct {
	regionID   int
	regionCode string
	hostname   string
	addr       netip.Addr
}

type measureFn func(conn io.ReadWriteCloser, hostname string, dst netip.AddrPort) (rtt time.Duration, err error)

// nodeMetaFromDERPMap parses the provided DERP map in order to update nodeMeta
// in the provided nodeMetaByAddr. It returns a slice of nodeMeta containing
// the nodes that are no longer seen in the DERP map, but were previously held
// in nodeMetaByAddr.
func nodeMetaFromDERPMap(dm *tailcfg.DERPMap, nodeMetaByAddr map[netip.Addr]nodeMeta, ipv6 bool) (stale []nodeMeta, err error) {
	// Parse the new derp map before making any state changes in nodeMetaByAddr.
	// If parse fails we just stick with the old state.
	updated := make(map[netip.Addr]nodeMeta)
	for regionID, region := range dm.Regions {
		for _, node := range region.Nodes {
			v4, err := netip.ParseAddr(node.IPv4)
			if err != nil || !v4.Is4() {
				return nil, fmt.Errorf("invalid ipv4 addr for node in derp map: %v", node.Name)
			}
			metas := make([]nodeMeta, 0, 2)
			metas = append(metas, nodeMeta{
				regionID:   regionID,
				regionCode: region.RegionCode,
				hostname:   node.HostName,
				addr:       v4,
			})
			if ipv6 {
				v6, err := netip.ParseAddr(node.IPv6)
				if err != nil || !v6.Is6() {
					return nil, fmt.Errorf("invalid ipv6 addr for node in derp map: %v", node.Name)
				}
				metas = append(metas, metas[0])
				metas[1].addr = v6
			}
			for _, meta := range metas {
				updated[meta.addr] = meta
			}
		}
	}

	// Find nodeMeta that have changed
	for addr, updatedMeta := range updated {
		previousMeta, ok := nodeMetaByAddr[addr]
		if ok {
			if previousMeta == updatedMeta {
				continue
			}
			stale = append(stale, previousMeta)
			nodeMetaByAddr[addr] = updatedMeta
		} else {
			nodeMetaByAddr[addr] = updatedMeta
		}
	}

	// Find nodeMeta that no longer exist
	for addr, potentialStale := range nodeMetaByAddr {
		_, ok := updated[addr]
		if !ok {
			stale = append(stale, potentialStale)
		}
	}

	return stale, nil
}

type connAndMeasureFn struct {
	conn io.ReadWriteCloser
	fn   measureFn
}

// newConnAndMeasureFn returns a connAndMeasureFn or an error. It may return
// nil for both if some combination of the supplied timestampSource, protocol,
// or connStability is unsupported.
func newConnAndMeasureFn(forDst netip.Addr, source timestampSource, protocol protocol, stable connStability) (*connAndMeasureFn, error) {
	info := getProtocolSupportInfo(protocol)
	if !info.stableConn && bool(stable) {
		return nil, nil
	}
	if !info.userspaceTS && source == timestampSourceUserspace {
		return nil, nil
	}
	if !info.kernelTS && source == timestampSourceKernel {
		return nil, nil
	}
	switch protocol {
	case protocolSTUN:
		if source == timestampSourceKernel {
			conn, err := getUDPConnKernelTimestamp()
			if err != nil {
				return nil, err
			}
			return &connAndMeasureFn{
				conn: conn,
				fn:   measureSTUNRTTKernel,
			}, nil
		} else {
			conn, err := net.ListenUDP("udp", &net.UDPAddr{})
			if err != nil {
				return nil, err
			}
			return &connAndMeasureFn{
				conn: conn,
				fn:   measureSTUNRTT,
			}, nil
		}
	case protocolICMP:
		conn, err := getICMPConn(forDst, source)
		if err != nil {
			return nil, err
		}
		return &connAndMeasureFn{
			conn: conn,
			fn:   mkICMPMeasureFn(source),
		}, nil
	case protocolHTTPS:
		localPort := 0
		if stable {
			localPort = lports.get()
		}
		conn := lportForTCPConn(localPort)
		return &connAndMeasureFn{
			conn: &conn,
			fn:   measureHTTPSRTT,
		}, nil
	case protocolTCP:
		localPort := 0
		if stable {
			localPort = lports.get()
		}
		conn := lportForTCPConn(localPort)
		return &connAndMeasureFn{
			conn: &conn,
			fn:   measureTCPRTT,
		}, nil
	}
	return nil, errors.New("unknown protocol")
}

type stableConnKey struct {
	node     netip.Addr
	protocol protocol
	port     int
}

type protocolSupportInfo struct {
	kernelTS    bool
	userspaceTS bool
	stableConn  bool
}

func getConns(
	stableConns map[stableConnKey][2]*connAndMeasureFn,
	addr netip.Addr,
	protocol protocol,
	dstPort int,
) (stable, unstable [2]*connAndMeasureFn, err error) {
	key := stableConnKey{addr, protocol, dstPort}
	defer func() {
		if err != nil {
			for _, source := range []timestampSource{timestampSourceUserspace, timestampSourceKernel} {
				c := stable[source]
				if c != nil {
					c.conn.Close()
				}
				c = unstable[source]
				if c != nil {
					c.conn.Close()
				}
			}
		}
	}()

	var ok bool
	stable, ok = stableConns[key]
	if !ok {
		for _, source := range []timestampSource{timestampSourceUserspace, timestampSourceKernel} {
			var cf *connAndMeasureFn
			cf, err = newConnAndMeasureFn(addr, source, protocol, stableConn)
			if err != nil {
				return
			}
			stable[source] = cf
		}
		stableConns[key] = stable
	}

	for _, source := range []timestampSource{timestampSourceUserspace, timestampSourceKernel} {
		var cf *connAndMeasureFn
		cf, err = newConnAndMeasureFn(addr, source, protocol, unstableConn)
		if err != nil {
			return
		}
		unstable[source] = cf
	}
	return stable, unstable, nil
}

// probeNodes measures the round-trip time for the protocols and ports described
// by portsByProtocol against the DERP nodes described by nodeMetaByAddr.
// stableConns are used to recycle connections across calls to probeNodes.
// probeNodes is also responsible for trimming stableConns based on node
// lifetime in nodeMetaByAddr. It returns the results or an error if one occurs.
func probeNodes(nodeMetaByAddr map[netip.Addr]nodeMeta, stableConns map[stableConnKey][2]*connAndMeasureFn, portsByProtocol map[protocol][]int) ([]result, error) {
	wg := sync.WaitGroup{}
	results := make([]result, 0)
	resultsCh := make(chan result)
	errCh := make(chan error)
	doneCh := make(chan struct{})
	numProbes := 0
	at := time.Now()
	addrsToProbe := make(map[netip.Addr]bool)

	doProbe := func(cf *connAndMeasureFn, meta nodeMeta, source timestampSource, stable connStability, protocol protocol, dstPort int) {
		defer wg.Done()
		r := result{
			key: resultKey{
				meta:            meta,
				timestampSource: source,
				connStability:   stable,
				dstPort:         dstPort,
				protocol:        protocol,
			},
			at: at,
		}
		time.Sleep(rand.N(maxTXJitter)) // jitter across tx
		addrPort := netip.AddrPortFrom(meta.addr, uint16(dstPort))
		rtt, err := cf.fn(cf.conn, meta.hostname, addrPort)
		if err != nil {
			if isTemporaryOrTimeoutErr(err) {
				r.rtt = nil
				log.Printf("%s: temp error measuring RTT to %s(%s): %v", protocol, meta.hostname, addrPort, err)
			} else {
				select {
				case <-doneCh:
					return
				case errCh <- fmt.Errorf("%s: %v", protocol, err):
					return
				}
			}
		} else {
			r.rtt = &rtt
		}
		select {
		case <-doneCh:
		case resultsCh <- r:
		}
	}

	for _, meta := range nodeMetaByAddr {
		addrsToProbe[meta.addr] = true
		for p, ports := range portsByProtocol {
			for _, port := range ports {
				stable, unstable, err := getConns(stableConns, meta.addr, p, port)
				if err != nil {
					close(doneCh)
					wg.Wait()
					return nil, err
				}

				for i, cf := range stable {
					if cf != nil {
						wg.Add(1)
						numProbes++
						go doProbe(cf, meta, timestampSource(i), stableConn, p, port)
					}
				}

				for i, cf := range unstable {
					if cf != nil {
						wg.Add(1)
						numProbes++
						go doProbe(cf, meta, timestampSource(i), unstableConn, p, port)
					}
				}
			}
		}
	}

	// cleanup conns we no longer need
	for k, cf := range stableConns {
		if !addrsToProbe[k.node] {
			if cf[timestampSourceKernel] != nil {
				cf[timestampSourceKernel].conn.Close()
			}
			cf[timestampSourceUserspace].conn.Close()
			delete(stableConns, k)
		}
	}

	for {
		select {
		case err := <-errCh:
			close(doneCh)
			wg.Wait()
			return nil, err
		case result := <-resultsCh:
			results = append(results, result)
			if len(results) == numProbes {
				return results, nil
			}
		}
	}
}

type connStability bool

const (
	unstableConn connStability = false
	stableConn   connStability = true
)

const (
	rttMetricName      = "stunstamp_derp_rtt_ns"
	timeoutsMetricName = "stunstamp_derp_timeouts_total"
)

func timeSeriesLabels(metricName string, meta nodeMeta, instance string, source timestampSource, stability connStability, protocol protocol, dstPort int) []prompb.Label {
	addressFamily := "ipv4"
	if meta.addr.Is6() {
		addressFamily = "ipv6"
	}
	labels := make([]prompb.Label, 0)
	labels = append(labels, prompb.Label{
		Name:  "job",
		Value: "stunstamp-rw",
	})
	labels = append(labels, prompb.Label{
		Name:  "instance",
		Value: instance,
	})
	labels = append(labels, prompb.Label{
		Name:  "region_id",
		Value: fmt.Sprintf("%d", meta.regionID),
	})
	labels = append(labels, prompb.Label{
		Name:  "region_code",
		Value: meta.regionCode,
	})
	labels = append(labels, prompb.Label{
		Name:  "address_family",
		Value: addressFamily,
	})
	labels = append(labels, prompb.Label{
		Name:  "hostname",
		Value: meta.hostname,
	})
	labels = append(labels, prompb.Label{
		Name:  "protocol",
		Value: string(protocol),
	})
	labels = append(labels, prompb.Label{
		Name:  "dst_port",
		Value: strconv.Itoa(dstPort),
	})
	labels = append(labels, prompb.Label{
		Name:  "__name__",
		Value: metricName,
	})
	labels = append(labels, prompb.Label{
		Name:  "timestamp_source",
		Value: source.String(),
	})
	labels = append(labels, prompb.Label{
		Name:  "stable_conn",
		Value: fmt.Sprintf("%v", stability),
	})
	slices.SortFunc(labels, func(a, b prompb.Label) int {
		// prometheus remote-write spec requires lexicographically sorted label names
		return cmp.Compare(a.Name, b.Name)
	})
	return labels
}

const (
	// https://prometheus.io/docs/concepts/remote_write_spec/#stale-markers
	staleNaN uint64 = 0x7ff0000000000002
)

func staleMarkersFromNodeMeta(stale []nodeMeta, instance string, portsByProtocol map[protocol][]int) []prompb.TimeSeries {
	staleMarkers := make([]prompb.TimeSeries, 0)
	now := time.Now()

	for p, ports := range portsByProtocol {
		for _, port := range ports {
			for _, s := range stale {
				samples := []prompb.Sample{
					{
						Timestamp: now.UnixMilli(),
						Value:     math.Float64frombits(staleNaN),
					},
				}
				// We send stale markers for all combinations in the interest
				// of simplicity.
				for _, name := range []string{rttMetricName, timeoutsMetricName} {
					for _, source := range []timestampSource{timestampSourceUserspace, timestampSourceKernel} {
						for _, stable := range []connStability{unstableConn, stableConn} {
							staleMarkers = append(staleMarkers, prompb.TimeSeries{
								Labels:  timeSeriesLabels(name, s, instance, source, stable, p, port),
								Samples: samples,
							})
						}
					}
				}
			}
		}
	}

	return staleMarkers
}

// resultsToPromTimeSeries returns a slice of prometheus TimeSeries for the
// provided results and instance. timeouts is updated based on results, i.e.
// all result.key's are added to timeouts if they do not exist, and removed
// from timeouts if they are not present in results.
func resultsToPromTimeSeries(results []result, instance string, timeouts map[resultKey]uint64) []prompb.TimeSeries {
	all := make([]prompb.TimeSeries, 0, len(results)*2)
	seenKeys := make(map[resultKey]bool)
	for _, r := range results {
		timeoutsCount := timeouts[r.key] // a non-existent key will return a zero val
		seenKeys[r.key] = true
		rttLabels := timeSeriesLabels(rttMetricName, r.key.meta, instance, r.key.timestampSource, r.key.connStability, r.key.protocol, r.key.dstPort)
		rttSamples := make([]prompb.Sample, 1)
		rttSamples[0].Timestamp = r.at.UnixMilli()
		if r.rtt != nil {
			rttSamples[0].Value = float64(*r.rtt)
		} else {
			rttSamples[0].Value = math.NaN()
			timeoutsCount++
		}
		rttTS := prompb.TimeSeries{
			Labels:  rttLabels,
			Samples: rttSamples,
		}
		all = append(all, rttTS)
		timeouts[r.key] = timeoutsCount
		timeoutsLabels := timeSeriesLabels(timeoutsMetricName, r.key.meta, instance, r.key.timestampSource, r.key.connStability, r.key.protocol, r.key.dstPort)
		timeoutsSamples := make([]prompb.Sample, 1)
		timeoutsSamples[0].Timestamp = r.at.UnixMilli()
		timeoutsSamples[0].Value = float64(timeoutsCount)
		timeoutsTS := prompb.TimeSeries{
			Labels:  timeoutsLabels,
			Samples: timeoutsSamples,
		}
		all = append(all, timeoutsTS)
	}
	for k := range timeouts {
		if !seenKeys[k] {
			delete(timeouts, k)
		}
	}
	return all
}

type remoteWriteClient struct {
	c   *http.Client
	url string
}

type recoverableErr struct {
	error
}

func newRemoteWriteClient(url string) *remoteWriteClient {
	return &remoteWriteClient{
		c: &http.Client{
			Timeout: time.Second * 30,
		},
		url: url,
	}
}

func (r *remoteWriteClient) write(ctx context.Context, ts []prompb.TimeSeries) error {
	wr := &prompb.WriteRequest{
		Timeseries: ts,
	}
	b, err := wr.Marshal()
	if err != nil {
		return fmt.Errorf("unable to marshal write request: %w", err)
	}
	compressed := snappy.Encode(nil, b)
	req, err := http.NewRequestWithContext(ctx, "POST", r.url, bytes.NewReader(compressed))
	if err != nil {
		return fmt.Errorf("unable to create write request: %w", err)
	}
	req.Header.Add("Content-Encoding", "snappy")
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.Header.Set("User-Agent", "stunstamp")
	req.Header.Set("X-Prometheus-Remote-Write-Version", "0.1.0")
	resp, err := r.c.Do(req)
	if err != nil {
		return recoverableErr{fmt.Errorf("error performing write request: %w", err)}
	}
	if resp.StatusCode/100 != 2 {
		err = fmt.Errorf("remote server %s returned HTTP status %d", r.url, resp.StatusCode)
	}
	if resp.StatusCode/100 == 5 || resp.StatusCode == http.StatusTooManyRequests {
		return recoverableErr{err}
	}
	return err
}

func remoteWriteTimeSeries(client *remoteWriteClient, tsCh chan []prompb.TimeSeries) {
	bo := backoff.NewBackoff("remote-write", log.Printf, time.Second*30)
	// writeErr may contribute to bo's backoff schedule across tsCh read ops,
	// i.e. if an unrecoverable error occurs for client.write(ctx, A), that
	// should be accounted against bo prior to attempting to
	// client.write(ctx, B).
	var writeErr error
	for ts := range tsCh {
		for {
			bo.BackOff(context.Background(), writeErr)
			reqCtx, cancel := context.WithTimeout(context.Background(), time.Second*30)
			writeErr = client.write(reqCtx, ts)
			cancel()
			var re recoverableErr
			recoverable := errors.As(writeErr, &re)
			if writeErr != nil {
				log.Printf("remote write error(recoverable=%v): %v", recoverable, writeErr)
			}
			if !recoverable {
				// a nil err is not recoverable
				break
			}
		}
	}
}

func getPortsFromFlag(f string) ([]int, error) {
	if len(f) == 0 {
		return nil, nil
	}
	split := strings.Split(f, ",")
	slices.Sort(split)
	split = slices.Compact(split)
	ports := make([]int, 0)
	for _, portStr := range split {
		port, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return nil, err
		}
		ports = append(ports, int(port))
	}
	return ports, nil
}

func main() {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" {
		log.Fatal("unsupported platform")
	}
	flag.Parse()

	portsByProtocol := make(map[protocol][]int)
	stunPorts, err := getPortsFromFlag(*flagSTUNDstPorts)
	if err != nil {
		log.Fatalf("invalid stun-dst-ports flag value: %v", err)
	}
	if len(stunPorts) > 0 {
		portsByProtocol[protocolSTUN] = stunPorts
	}
	httpsPorts, err := getPortsFromFlag(*flagHTTPSDstPorts)
	if err != nil {
		log.Fatalf("invalid https-dst-ports flag value: %v", err)
	}
	if len(httpsPorts) > 0 {
		portsByProtocol[protocolHTTPS] = httpsPorts
	}
	tcpPorts, err := getPortsFromFlag(*flagTCPDstPorts)
	if err != nil {
		log.Fatalf("invalid tcp-dst-ports flag value: %v", err)
	}
	if len(tcpPorts) > 0 {
		portsByProtocol[protocolTCP] = tcpPorts
	}
	if *flagICMP {
		portsByProtocol[protocolICMP] = []int{0}
	}
	if len(portsByProtocol) == 0 {
		log.Fatal("nothing to probe")
	}

	if len(*flagDERPMap) < 1 {
		log.Fatal("derp-map flag is unset")
	}
	if *flagInterval < minInterval || *flagInterval > maxBufferDuration {
		log.Fatalf("interval must be >= %s and <= %s", minInterval, maxBufferDuration)
	}
	if len(*flagRemoteWriteURL) < 1 {
		log.Fatal("rw-url flag is unset")
	}
	_, err = url.Parse(*flagRemoteWriteURL)
	if err != nil {
		log.Fatalf("invalid rw-url flag value: %v", err)
	}
	if len(*flagInstance) < 1 {
		hostname, err := os.Hostname()
		if err != nil {
			log.Fatalf("failed to get hostname: %v", err)
		}
		*flagInstance = hostname
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	dmCh := make(chan *tailcfg.DERPMap)

	go func() {
		bo := backoff.NewBackoff("derp-map", log.Printf, time.Second*30)
		for {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
			dm, err := getDERPMap(ctx, *flagDERPMap)
			cancel()
			bo.BackOff(context.Background(), err)
			if err != nil {
				continue
			}
			dmCh <- dm
			return
		}
	}()

	nodeMetaByAddr := make(map[netip.Addr]nodeMeta)
	select {
	case <-sigCh:
		return
	case dm := <-dmCh:
		_, err := nodeMetaFromDERPMap(dm, nodeMetaByAddr, *flagIPv6)
		if err != nil {
			log.Fatalf("error parsing derp map on startup: %v", err)
		}
	}

	tsCh := make(chan []prompb.TimeSeries, maxBufferDuration / *flagInterval)
	remoteWriteDoneCh := make(chan struct{})
	rwc := newRemoteWriteClient(*flagRemoteWriteURL)
	go func() {
		remoteWriteTimeSeries(rwc, tsCh)
		close(remoteWriteDoneCh)
	}()

	shutdown := func() {
		close(tsCh)
		select {
		case <-time.After(time.Second * 10): // give goroutine some time to flush
		case <-remoteWriteDoneCh:
		}

		// send stale markers on shutdown
		staleMeta := make([]nodeMeta, 0, len(nodeMetaByAddr))
		for _, v := range nodeMetaByAddr {
			staleMeta = append(staleMeta, v)
		}
		staleMarkers := staleMarkersFromNodeMeta(staleMeta, *flagInstance, portsByProtocol)
		if len(staleMarkers) > 0 {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
			rwc.write(ctx, staleMarkers)
			cancel()
		}

		return
	}

	log.Println("stunstamp started")

	// Re-using sockets means we get the same 5-tuple across runs. This results
	// in a higher probability of the packets traversing the same underlay path.
	// Comparison of stable and unstable 5-tuple results can shed light on
	// differences between paths where hashing (multipathing/load balancing)
	// comes into play. The inner 2 element array index is timestampSource.
	stableConns := make(map[stableConnKey][2]*connAndMeasureFn)

	// timeouts holds counts of timeout events. Values are persisted for the
	// lifetime of the related node in the DERP map.
	timeouts := make(map[resultKey]uint64)

	derpMapTicker := time.NewTicker(time.Minute * 5)
	defer derpMapTicker.Stop()
	probeTicker := time.NewTicker(*flagInterval)
	defer probeTicker.Stop()

	for {
		select {
		case <-probeTicker.C:
			results, err := probeNodes(nodeMetaByAddr, stableConns, portsByProtocol)
			if err != nil {
				log.Printf("unrecoverable error while probing: %v", err)
				shutdown()
				return
			}
			ts := resultsToPromTimeSeries(results, *flagInstance, timeouts)
			select {
			case tsCh <- ts:
			default:
				select {
				case <-tsCh:
					log.Println("prometheus remote-write buffer full, dropped measurements")
				default:
					tsCh <- ts
				}
			}
		case dm := <-dmCh:
			staleMeta, err := nodeMetaFromDERPMap(dm, nodeMetaByAddr, *flagIPv6)
			if err != nil {
				log.Printf("error parsing DERP map, continuing with stale map: %v", err)
				continue
			}
			staleMarkers := staleMarkersFromNodeMeta(staleMeta, *flagInstance, portsByProtocol)
			if len(staleMarkers) < 1 {
				continue
			}
			select {
			case tsCh <- staleMarkers:
			default:
				select {
				case <-tsCh:
					log.Println("prometheus remote-write buffer full, dropped measurements")
				default:
					tsCh <- staleMarkers
				}
			}
		case <-derpMapTicker.C:
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
				defer cancel()
				updatedDM, err := getDERPMap(ctx, *flagDERPMap)
				if err == nil {
					dmCh <- updatedDM
				}
			}()
		case <-sigCh:
			shutdown()
			return
		}
	}
}
