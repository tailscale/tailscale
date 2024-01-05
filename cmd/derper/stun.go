package main

import (
	"context"
	"encoding/json"
	"expvar"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"time"

	"tailscale.com/metrics"
	"tailscale.com/net/stun"
)

var (
	stats           = new(metrics.Set)
	stunDisposition = &metrics.LabelMap{Label: "disposition"}
	stunAddrFamily  = &metrics.LabelMap{Label: "family"}
	stunReadError   = stunDisposition.Get("read_error")
	stunNotSTUN     = stunDisposition.Get("not_stun")
	stunWriteError  = stunDisposition.Get("write_error")
	stunSuccess     = stunDisposition.Get("success")

	stunIPv4 = stunAddrFamily.Get("ipv4")
	stunIPv6 = stunAddrFamily.Get("ipv6")
)

// statsEntry is the structure of the JSON output of the above stats.
type statsEntry struct {
	CounterAddrfamily struct {
		Ipv4 int64 `json:"ipv4"`
		Ipv6 int64 `json:"ipv6"`
	} `json:"counter_addrfamily"`
	CounterRequests struct {
		NotStun    int64 `json:"not_stun"`
		ReadError  int64 `json:"read_error"`
		Success    int64 `json:"success"`
		WriteError int64 `json:"write_error"`
	} `json:"counter_requests"`
}

func (e *statsEntry) Set() {
	stunIPv4.Set(e.CounterAddrfamily.Ipv4)
	stunIPv6.Set(e.CounterAddrfamily.Ipv6)
	stunNotSTUN.Set(e.CounterRequests.NotStun)
	stunReadError.Set(e.CounterRequests.ReadError)
	stunSuccess.Set(e.CounterRequests.Success)
	stunWriteError.Set(e.CounterRequests.WriteError)
}

func init() {
	stats.Set("counter_requests", stunDisposition)
	stats.Set("counter_addrfamily", stunAddrFamily)
	expvar.Publish("stun", stats)
}

// printSTUNStats prints STUN stats to w every d until ctx is done.
func printSTUNStats(ctx context.Context, w io.Writer, d time.Duration) {
	ticker := time.NewTicker(d)
	for {
		expvar.Do(func(kv expvar.KeyValue) {
			if kv.Key == "stun" {
				fmt.Fprintf(w, "%s\n", kv.Value)
			}
		})
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// readSTUNStats reads lines from r containing STUN statistics and updates matching expvar values.
func readSTUNStats(ctx context.Context, r io.Reader) {
	d := json.NewDecoder(r)
	var entry statsEntry
	for {
		if err := d.Decode(&entry); err != nil {
			return
		}
		entry.Set()
		if ctx.Err() != nil {
			return
		}
	}
}

// serveChildSTUN starts a stun server in a child process. If the process exits before context is done, serveChildSTUN will with a log entry.
func startChildSTUN(ctx context.Context) {
	cmd := exec.Command(os.Args[0], append(os.Args[1:], "-stun-only=true")...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Fatalf("stun: failed to create stdout pipe: %v", err)
	}
	cmd.Stderr = os.Stderr
	err = cmd.Start()
	if err != nil {
		log.Fatalf("stun: failed to start subprocess: %v", err)
	}
	readSTUNStats(ctx, stdout)
	cmd.Process.Kill()
	cmd.Process.Wait()
	if ctx.Err() == nil {
		log.Fatalf("stun: subprocess exited unexpectedly: %v", cmd.ProcessState)
	}
}

func serveSTUN(ctx context.Context, host string, port int) {
	pc, err := net.ListenPacket("udp", net.JoinHostPort(host, fmt.Sprint(port)))
	if err != nil {
		log.Fatalf("failed to open STUN listener: %v", err)
	}
	log.Printf("running STUN server on %v", pc.LocalAddr())
	// close the listener on shutdown in order to rbeak out of the read loop
	go func() {
		<-ctx.Done()
		pc.Close()
	}()
	serverSTUNListener(ctx, pc.(*net.UDPConn))
}

func serverSTUNListener(ctx context.Context, pc *net.UDPConn) {
	var buf [64 << 10]byte
	var (
		n   int
		ua  *net.UDPAddr
		err error
	)
	for {
		n, ua, err = pc.ReadFromUDP(buf[:])
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Printf("STUN ReadFrom: %v", err)
			time.Sleep(time.Second)
			stunReadError.Add(1)
			continue
		}
		pkt := buf[:n]
		if !stun.Is(pkt) {
			stunNotSTUN.Add(1)
			continue
		}
		txid, err := stun.ParseBindingRequest(pkt)
		if err != nil {
			stunNotSTUN.Add(1)
			continue
		}
		if ua.IP.To4() != nil {
			stunIPv4.Add(1)
		} else {
			stunIPv6.Add(1)
		}
		addr, _ := netip.AddrFromSlice(ua.IP)
		res := stun.Response(txid, netip.AddrPortFrom(addr, uint16(ua.Port)))
		_, err = pc.WriteTo(res, ua)
		if err != nil {
			stunWriteError.Add(1)
		} else {
			stunSuccess.Add(1)
		}
	}
}
