// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

// The stunstamp binary measures STUN round-trip latency with DERPs.
package main

import (
	"bytes"
	"cmp"
	"context"
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
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/golang/snappy"
	"github.com/prometheus/prometheus/prompb"
	"tailscale.com/logtail/backoff"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
)

var (
	flagDERPMap        = flag.String("derp-map", "https://login.tailscale.com/derpmap/default", "URL to DERP map")
	flagInterval       = flag.Duration("interval", time.Minute, "interval to probe at in time.ParseDuration() format")
	flagIPv6           = flag.Bool("ipv6", false, "probe IPv6 addresses")
	flagRemoteWriteURL = flag.String("rw-url", "", "prometheus remote write URL")
	flagInstance       = flag.String("instance", "", "instance label value; defaults to hostname if unspecified")
	flagDstPorts       = flag.String("dst-ports", "", "comma-separated list of destination ports to monitor")
)

const (
	minInterval       = time.Second
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

// resultKey contains the stable dimensions and their values for a given
// timeseries, i.e. not time and not rtt/timeout.
type resultKey struct {
	meta            nodeMeta
	timestampSource timestampSource
	connStability   connStability
	dstPort         int
}

type result struct {
	key resultKey
	at  time.Time
	rtt *time.Duration // nil signifies failure, e.g. timeout
}

func measureRTT(conn io.ReadWriteCloser, dst *net.UDPAddr) (rtt time.Duration, err error) {
	uconn, ok := conn.(*net.UDPConn)
	if !ok {
		return 0, fmt.Errorf("unexpected conn type: %T", conn)
	}
	err = uconn.SetReadDeadline(time.Now().Add(time.Second * 2))
	if err != nil {
		return 0, fmt.Errorf("error setting read deadline: %w", err)
	}
	txID := stun.NewTxID()
	req := stun.Request(txID)
	txAt := time.Now()
	_, err = uconn.WriteToUDP(req, dst)
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

type measureFn func(conn io.ReadWriteCloser, dst *net.UDPAddr) (rtt time.Duration, err error)

// probe measures STUN round trip time for the node described by meta over
// conn against dstPort. It may return a nil duration and nil error if the
// STUN request timed out. A non-nil error indicates an unrecoverable or
// non-temporary error.
func probe(meta nodeMeta, conn io.ReadWriteCloser, fn measureFn, dstPort int) (*time.Duration, error) {
	ua := &net.UDPAddr{
		IP:   net.IP(meta.addr.AsSlice()),
		Port: dstPort,
	}

	time.Sleep(rand.N(200 * time.Millisecond)) // jitter across tx
	rtt, err := fn(conn, ua)
	if err != nil {
		if isTemporaryOrTimeoutErr(err) {
			log.Printf("temp error measuring RTT to %s(%s): %v", meta.hostname, ua.String(), err)
			return nil, nil
		}
		return nil, err
	}
	return &rtt, nil
}

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

func getStableConns(stableConns map[netip.Addr]map[int][2]io.ReadWriteCloser, addr netip.Addr, dstPort int) ([2]io.ReadWriteCloser, error) {
	conns := [2]io.ReadWriteCloser{}
	byDstPort, ok := stableConns[addr]
	if ok {
		conns, ok = byDstPort[dstPort]
		if ok {
			return conns, nil
		}
	}
	if supportsKernelTS() {
		kconn, err := getConnKernelTimestamp()
		if err != nil {
			return conns, err
		}
		conns[timestampSourceKernel] = kconn
	}
	uconn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		if supportsKernelTS() {
			conns[timestampSourceKernel].Close()
		}
		return conns, err
	}
	conns[timestampSourceUserspace] = uconn
	if byDstPort == nil {
		byDstPort = make(map[int][2]io.ReadWriteCloser)
	}
	byDstPort[dstPort] = conns
	stableConns[addr] = byDstPort
	return conns, nil
}

// probeNodes measures the round-trip time for STUN binding requests against the
// DERP nodes described by nodeMetaByAddr while using/updating stableConns for
// UDP sockets that should be recycled across runs. It returns the results or
// an error if one occurs.
func probeNodes(nodeMetaByAddr map[netip.Addr]nodeMeta, stableConns map[netip.Addr]map[int][2]io.ReadWriteCloser, dstPorts []int) ([]result, error) {
	wg := sync.WaitGroup{}
	results := make([]result, 0)
	resultsCh := make(chan result)
	errCh := make(chan error)
	doneCh := make(chan struct{})
	numProbes := 0
	at := time.Now()
	addrsToProbe := make(map[netip.Addr]bool)

	doProbe := func(conn io.ReadWriteCloser, meta nodeMeta, source timestampSource, dstPort int) {
		defer wg.Done()
		r := result{
			key: resultKey{
				meta:            meta,
				timestampSource: source,
				dstPort:         dstPort,
			},
			at: at,
		}
		if conn == nil {
			var err error
			if source == timestampSourceKernel {
				conn, err = getConnKernelTimestamp()
			} else {
				conn, err = net.ListenUDP("udp", &net.UDPAddr{})
			}
			if err != nil {
				select {
				case <-doneCh:
					return
				case errCh <- err:
					return
				}
			}
			defer conn.Close()
		} else {
			r.key.connStability = stableConn
		}
		fn := measureRTT
		if source == timestampSourceKernel {
			fn = measureRTTKernel
		}
		rtt, err := probe(meta, conn, fn, dstPort)
		if err != nil {
			select {
			case <-doneCh:
				return
			case errCh <- err:
				return
			}
		}
		r.rtt = rtt
		select {
		case <-doneCh:
		case resultsCh <- r:
		}
	}

	for _, meta := range nodeMetaByAddr {
		addrsToProbe[meta.addr] = true
		for _, port := range dstPorts {
			stable, err := getStableConns(stableConns, meta.addr, port)
			if err != nil {
				close(doneCh)
				wg.Wait()
				return nil, err
			}

			wg.Add(2)
			numProbes += 2
			go doProbe(stable[timestampSourceUserspace], meta, timestampSourceUserspace, port)
			go doProbe(nil, meta, timestampSourceUserspace, port)
			if supportsKernelTS() {
				wg.Add(2)
				numProbes += 2
				go doProbe(stable[timestampSourceKernel], meta, timestampSourceKernel, port)
				go doProbe(nil, meta, timestampSourceKernel, port)
			}
		}
	}

	// cleanup conns we no longer need
	for k, byDstPort := range stableConns {
		if !addrsToProbe[k] {
			for _, conns := range byDstPort {
				if conns[timestampSourceKernel] != nil {
					conns[timestampSourceKernel].Close()
				}
				conns[timestampSourceUserspace].Close()
				delete(stableConns, k)
			}
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
	rttMetricName      = "stunstamp_derp_stun_rtt_ns"
	timeoutsMetricName = "stunstamp_derp_stun_timeouts_total"
)

func timeSeriesLabels(metricName string, meta nodeMeta, instance string, source timestampSource, stability connStability, dstPort int) []prompb.Label {
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

func staleMarkersFromNodeMeta(stale []nodeMeta, instance string, dstPorts []int) []prompb.TimeSeries {
	staleMarkers := make([]prompb.TimeSeries, 0)
	now := time.Now()
	for _, s := range stale {
		for _, dstPort := range dstPorts {
			samples := []prompb.Sample{
				{
					Timestamp: now.UnixMilli(),
					Value:     math.Float64frombits(staleNaN),
				},
			}
			staleMarkers = append(staleMarkers, prompb.TimeSeries{
				Labels:  timeSeriesLabels(rttMetricName, s, instance, timestampSourceUserspace, unstableConn, dstPort),
				Samples: samples,
			})
			staleMarkers = append(staleMarkers, prompb.TimeSeries{
				Labels:  timeSeriesLabels(rttMetricName, s, instance, timestampSourceUserspace, stableConn, dstPort),
				Samples: samples,
			})
			staleMarkers = append(staleMarkers, prompb.TimeSeries{
				Labels:  timeSeriesLabels(timeoutsMetricName, s, instance, timestampSourceUserspace, unstableConn, dstPort),
				Samples: samples,
			})
			staleMarkers = append(staleMarkers, prompb.TimeSeries{
				Labels:  timeSeriesLabels(timeoutsMetricName, s, instance, timestampSourceUserspace, stableConn, dstPort),
				Samples: samples,
			})
			if supportsKernelTS() {
				staleMarkers = append(staleMarkers, prompb.TimeSeries{
					Labels:  timeSeriesLabels(rttMetricName, s, instance, timestampSourceKernel, unstableConn, dstPort),
					Samples: samples,
				})
				staleMarkers = append(staleMarkers, prompb.TimeSeries{
					Labels:  timeSeriesLabels(rttMetricName, s, instance, timestampSourceKernel, stableConn, dstPort),
					Samples: samples,
				})
				staleMarkers = append(staleMarkers, prompb.TimeSeries{
					Labels:  timeSeriesLabels(timeoutsMetricName, s, instance, timestampSourceKernel, unstableConn, dstPort),
					Samples: samples,
				})
				staleMarkers = append(staleMarkers, prompb.TimeSeries{
					Labels:  timeSeriesLabels(timeoutsMetricName, s, instance, timestampSourceKernel, stableConn, dstPort),
					Samples: samples,
				})
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
		rttLabels := timeSeriesLabels(rttMetricName, r.key.meta, instance, r.key.timestampSource, r.key.connStability, r.key.dstPort)
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
		timeoutsLabels := timeSeriesLabels(timeoutsMetricName, r.key.meta, instance, r.key.timestampSource, r.key.connStability, r.key.dstPort)
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

func main() {
	flag.Parse()
	if len(*flagDstPorts) == 0 {
		log.Fatal("dst-ports flag is unset")
	}
	dstPortsSplit := strings.Split(*flagDstPorts, ",")
	slices.Sort(dstPortsSplit)
	dstPortsSplit = slices.Compact(dstPortsSplit)
	dstPorts := make([]int, 0, len(dstPortsSplit))
	for _, d := range dstPortsSplit {
		i, err := strconv.ParseUint(d, 10, 16)
		if err != nil {
			log.Fatal("invalid dst-ports")
		}
		dstPorts = append(dstPorts, int(i))
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
	_, err := url.Parse(*flagRemoteWriteURL)
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
		staleMarkers := staleMarkersFromNodeMeta(staleMeta, *flagInstance, dstPorts)
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
	// comes into play.
	stableConns := make(map[netip.Addr]map[int][2]io.ReadWriteCloser)

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
			results, err := probeNodes(nodeMetaByAddr, stableConns, dstPorts)
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
			staleMarkers := staleMarkersFromNodeMeta(staleMeta, *flagInstance, dstPorts)
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
				if err != nil {
					dmCh <- updatedDM
				}
			}()
		case <-sigCh:
			shutdown()
			return
		}
	}
}
