// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// The derpprobe binary probes derpers.
package main // import "tailscale.com/cmd/derper/derpprobe"

import (
	"bytes"
	"context"
	crand "crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"tailscale.com/derp"
	"tailscale.com/derp/derphttp"
	"tailscale.com/net/stun"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

var (
	derpMapURL = flag.String("derp-map", "https://login.tailscale.com/derpmap/default", "URL to DERP map (https:// or file://)")
	listen     = flag.String("listen", ":8030", "HTTP listen address")
	probeOnce  = flag.Bool("once", false, "probe once and print results, then exit; ignores the listen flag")
)

// certReissueAfter is the time after which we expect all certs to be
// reissued, at minimum.
//
// This is currently set to the date of the LetsEncrypt ALPN revocation event of Jan 2022:
// https://community.letsencrypt.org/t/questions-about-renewing-before-tls-alpn-01-revocations/170449
//
// If there's another revocation event, bump this again.
var certReissueAfter = time.Unix(1643226768, 0)

var (
	mu            sync.Mutex
	state         = map[nodePair]pairStatus{}
	lastDERPMap   *tailcfg.DERPMap
	lastDERPMapAt time.Time
	certs         = map[string]*x509.Certificate{}
)

func main() {
	flag.Parse()

	// proactively load the DERP map. Nothing terrible happens if this fails, so we ignore
	// the error. The Slack bot will print a notification that the DERP map was empty.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, _ = getDERPMap(ctx)

	if *probeOnce {
		log.Printf("Starting probe (may take up to 1m)")
		probe()
		log.Printf("Probe results:")
		st := getOverallStatus()
		for _, s := range st.good {
			log.Printf("good: %s", s)
		}
		for _, s := range st.bad {
			log.Printf("bad: %s", s)
		}
		return
	}

	go probeLoop()
	go slackLoop()
	log.Fatal(http.ListenAndServe(*listen, http.HandlerFunc(serve)))
}

func setCert(name string, cert *x509.Certificate) {
	mu.Lock()
	defer mu.Unlock()
	certs[name] = cert
}

type overallStatus struct {
	good, bad []string
}

func (st *overallStatus) addBadf(format string, a ...any) {
	st.bad = append(st.bad, fmt.Sprintf(format, a...))
}

func (st *overallStatus) addGoodf(format string, a ...any) {
	st.good = append(st.good, fmt.Sprintf(format, a...))
}

func getOverallStatus() (o overallStatus) {
	mu.Lock()
	defer mu.Unlock()
	if lastDERPMap == nil {
		o.addBadf("no DERP map")
		return
	}
	now := time.Now()
	if age := now.Sub(lastDERPMapAt); age > time.Minute {
		o.addBadf("DERPMap hasn't been successfully refreshed in %v", age.Round(time.Second))
	}

	addPairMeta := func(pair nodePair) {
		st, ok := state[pair]
		age := now.Sub(st.at).Round(time.Second)
		switch {
		case !ok:
			o.addBadf("no state for %v", pair)
		case st.err != nil:
			o.addBadf("%v: %v", pair, st.err)
		case age > 90*time.Second:
			o.addBadf("%v: update is %v old", pair, age)
		default:
			o.addGoodf("%v: %v, %v ago", pair, st.latency.Round(time.Millisecond), age)
		}
	}

	for _, reg := range sortedRegions(lastDERPMap) {
		for _, from := range reg.Nodes {
			addPairMeta(nodePair{"UDP", from.Name})
			for _, to := range reg.Nodes {
				addPairMeta(nodePair{from.Name, to.Name})
			}
		}
	}

	var subjs []string
	for k := range certs {
		subjs = append(subjs, k)
	}
	sort.Strings(subjs)

	soon := time.Now().Add(14 * 24 * time.Hour) // in 2 weeks; autocert does 30 days by default
	for _, s := range subjs {
		cert := certs[s]
		if cert.NotBefore.Before(certReissueAfter) {
			o.addBadf("cert %q needs reissuing; NotBefore=%v", s, cert.NotBefore.Format(time.RFC3339))
			continue
		}
		if cert.NotAfter.Before(soon) {
			o.addBadf("cert %q expiring soon (%v); wasn't auto-refreshed", s, cert.NotAfter.Format(time.RFC3339))
			continue
		}
		o.addGoodf("cert %q good %v - %v", s, cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))
	}

	return
}

func serve(w http.ResponseWriter, r *http.Request) {
	st := getOverallStatus()
	summary := "All good"
	if (float64(len(st.bad)) / float64(len(st.bad)+len(st.good))) > 0.25 {
		// This will generate an alert and page a human.
		// It also ends up in Slack, but as part of the alert handling pipeline not
		// because we generated a Slack notification from here.
		w.WriteHeader(500)
		summary = fmt.Sprintf("%d problems", len(st.bad))
	}

	io.WriteString(w, "<html><head><style>.bad { font-weight: bold; color: #700; }</style></head>\n")
	fmt.Fprintf(w, "<body><h1>derp probe</h1>\n%s:<ul>", summary)
	for _, s := range st.bad {
		fmt.Fprintf(w, "<li class=bad>%s</li>\n", html.EscapeString(s))
	}
	for _, s := range st.good {
		fmt.Fprintf(w, "<li>%s</li>\n", html.EscapeString(s))
	}
	io.WriteString(w, "</ul></body></html>\n")
}

func notifySlack(text string) error {
	type SlackRequestBody struct {
		Text string `json:"text"`
	}

	slackBody, err := json.Marshal(SlackRequestBody{Text: text})
	if err != nil {
		return err
	}

	webhookUrl := os.Getenv("SLACK_WEBHOOK")
	if webhookUrl == "" {
		return errors.New("No SLACK_WEBHOOK configured")
	}

	req, err := http.NewRequest("POST", webhookUrl, bytes.NewReader(slackBody))
	if err != nil {
		return err
	}
	req.Header.Add("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return errors.New(resp.Status)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		return errors.New("Non-ok response returned from Slack")
	}
	return nil
}

// We only page a human if it looks like there is a significant outage across multiple regions.
// To Slack, we report all failures great and small.
func slackLoop() {
	inBadState := false
	for {
		time.Sleep(time.Second * 30)
		st := getOverallStatus()

		if len(st.bad) > 0 && !inBadState {
			err := notifySlack(strings.Join(st.bad, "\n"))
			if err == nil {
				inBadState = true
			} else {
				log.Printf("%d problems, notify Slack failed: %v", len(st.bad), err)
			}
		}

		if len(st.bad) == 0 && inBadState {
			err := notifySlack("All DERPs recovered.")
			if err == nil {
				inBadState = false
			}
		}
	}
}

func sortedRegions(dm *tailcfg.DERPMap) []*tailcfg.DERPRegion {
	ret := make([]*tailcfg.DERPRegion, 0, len(dm.Regions))
	for _, r := range dm.Regions {
		ret = append(ret, r)
	}
	sort.Slice(ret, func(i, j int) bool { return ret[i].RegionID < ret[j].RegionID })
	return ret
}

type nodePair struct {
	from string // DERPNode.Name, or "UDP" for a STUN query to 'to'
	to   string // DERPNode.Name
}

func (p nodePair) String() string { return fmt.Sprintf("(%s→%s)", p.from, p.to) }

type pairStatus struct {
	err     error
	latency time.Duration
	at      time.Time
}

func setDERPMap(dm *tailcfg.DERPMap) {
	mu.Lock()
	defer mu.Unlock()
	lastDERPMap = dm
	lastDERPMapAt = time.Now()
}

func setState(p nodePair, latency time.Duration, err error) {
	mu.Lock()
	defer mu.Unlock()
	st := pairStatus{
		err:     err,
		latency: latency,
		at:      time.Now(),
	}
	state[p] = st
	if err != nil {
		log.Printf("%+v error: %v", p, err)
	} else {
		log.Printf("%+v: %v", p, latency.Round(time.Millisecond))
	}
}

func probeLoop() {
	ticker := time.NewTicker(15 * time.Second)
	for {
		err := probe()
		if err != nil {
			log.Printf("probe: %v", err)
		}
		<-ticker.C
	}
}

func probe() error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	dm, err := getDERPMap(ctx)
	if err != nil {
		return err
	}

	var wg sync.WaitGroup
	wg.Add(len(dm.Regions))
	for _, reg := range dm.Regions {
		reg := reg
		go func() {
			defer wg.Done()
			for _, from := range reg.Nodes {
				latency, err := probeUDP(ctx, dm, from)
				setState(nodePair{"UDP", from.Name}, latency, err)
				for _, to := range reg.Nodes {
					latency, err := probeNodePair(ctx, dm, from, to)
					setState(nodePair{from.Name, to.Name}, latency, err)
				}
			}
		}()
	}

	wg.Wait()
	return ctx.Err()
}

func probeUDP(ctx context.Context, dm *tailcfg.DERPMap, n *tailcfg.DERPNode) (latency time.Duration, err error) {
	pc, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return 0, err
	}
	defer pc.Close()
	uc := pc.(*net.UDPConn)

	tx := stun.NewTxID()
	req := stun.Request(tx)

	for _, ipStr := range []string{n.IPv4, n.IPv6} {
		if ipStr == "" {
			continue
		}
		port := n.STUNPort
		if port == -1 {
			continue
		}
		if port == 0 {
			port = 3478
		}
		for {
			ip := net.ParseIP(ipStr)
			_, err := uc.WriteToUDP(req, &net.UDPAddr{IP: ip, Port: port})
			if err != nil {
				return 0, err
			}
			buf := make([]byte, 1500)
			uc.SetReadDeadline(time.Now().Add(2 * time.Second))
			t0 := time.Now()
			n, _, err := uc.ReadFromUDP(buf)
			d := time.Since(t0)
			if err != nil {
				if ctx.Err() != nil {
					return 0, fmt.Errorf("timeout reading from %v: %v", ip, err)
				}
				if d < time.Second {
					return 0, fmt.Errorf("error reading from %v: %v", ip, err)
				}
				time.Sleep(100 * time.Millisecond)
				continue
			}
			txBack, _, err := stun.ParseResponse(buf[:n])
			if err != nil {
				return 0, fmt.Errorf("parsing STUN response from %v: %v", ip, err)
			}
			if txBack != tx {
				return 0, fmt.Errorf("read wrong tx back from %v", ip)
			}
			if latency == 0 || d < latency {
				latency = d
			}
			break
		}
	}
	return latency, nil
}

func probeNodePair(ctx context.Context, dm *tailcfg.DERPMap, from, to *tailcfg.DERPNode) (latency time.Duration, err error) {
	// The passed in context is a minute for the whole region. The
	// idea is that each node pair in the region will be done
	// serially and regularly in the future, reusing connections
	// (at least in the happy path). For now they don't reuse
	// connections and probe at most once every 15 seconds. We
	// bound the duration of a single node pair within a region
	// so one bad one can't starve others.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	fromc, err := newConn(ctx, dm, from)
	if err != nil {
		return 0, err
	}
	defer fromc.Close()
	toc, err := newConn(ctx, dm, to)
	if err != nil {
		return 0, err
	}
	defer toc.Close()

	// Wait a bit for from's node to hear about to existing on the
	// other node in the region, in the case where the two nodes
	// are different.
	if from.Name != to.Name {
		time.Sleep(100 * time.Millisecond) // pretty arbitrary
	}

	// Make a random packet
	pkt := make([]byte, 8)
	crand.Read(pkt)

	t0 := time.Now()

	// Send the random packet.
	sendc := make(chan error, 1)
	go func() {
		sendc <- fromc.Send(toc.SelfPublicKey(), pkt)
	}()
	select {
	case <-ctx.Done():
		return 0, fmt.Errorf("timeout sending via %q: %w", from.Name, ctx.Err())
	case err := <-sendc:
		if err != nil {
			return 0, fmt.Errorf("error sending via %q: %w", from.Name, err)
		}
	}

	// Receive the random packet.
	recvc := make(chan any, 1) // either derp.ReceivedPacket or error
	go func() {
		for {
			m, err := toc.Recv()
			if err != nil {
				recvc <- err
				return
			}
			switch v := m.(type) {
			case derp.ReceivedPacket:
				recvc <- v
			default:
				log.Printf("%v: ignoring Recv frame type %T", to.Name, v)
				// Loop.
			}
		}
	}()
	select {
	case <-ctx.Done():
		return 0, fmt.Errorf("timeout receiving from %q: %w", to.Name, ctx.Err())
	case v := <-recvc:
		if err, ok := v.(error); ok {
			return 0, fmt.Errorf("error receiving from %q: %w", to.Name, err)
		}
		p := v.(derp.ReceivedPacket)
		if p.Source != fromc.SelfPublicKey() {
			return 0, fmt.Errorf("got data packet from unexpected source, %v", p.Source)
		}
		if !bytes.Equal(p.Data, pkt) {
			return 0, fmt.Errorf("unexpected data packet %q", p.Data)
		}
	}
	return time.Since(t0), nil
}

func newConn(ctx context.Context, dm *tailcfg.DERPMap, n *tailcfg.DERPNode) (*derphttp.Client, error) {
	priv := key.NewNode()
	dc := derphttp.NewRegionClient(priv, log.Printf, func() *tailcfg.DERPRegion {
		rid := n.RegionID
		return &tailcfg.DERPRegion{
			RegionID:   rid,
			RegionCode: fmt.Sprintf("%s-%s", dm.Regions[rid].RegionCode, n.Name),
			RegionName: dm.Regions[rid].RegionName,
			Nodes:      []*tailcfg.DERPNode{n},
		}
	})
	dc.IsProber = true
	err := dc.Connect(ctx)
	if err != nil {
		return nil, err
	}
	cs, ok := dc.TLSConnectionState()
	if !ok {
		dc.Close()
		return nil, errors.New("no TLS state")
	}
	if len(cs.PeerCertificates) == 0 {
		dc.Close()
		return nil, errors.New("no peer certificates")
	}
	if cs.ServerName != n.HostName {
		dc.Close()
		return nil, fmt.Errorf("TLS server name %q != derp hostname %q", cs.ServerName, n.HostName)
	}
	setCert(cs.ServerName, cs.PeerCertificates[0])

	errc := make(chan error, 1)
	go func() {
		m, err := dc.Recv()
		if err != nil {
			errc <- err
			return
		}
		switch m.(type) {
		case derp.ServerInfoMessage:
			errc <- nil
		default:
			errc <- fmt.Errorf("unexpected first message type %T", errc)
		}
	}()
	select {
	case err := <-errc:
		if err != nil {
			go dc.Close()
			return nil, err
		}
	case <-ctx.Done():
		go dc.Close()
		return nil, fmt.Errorf("timeout waiting for ServerInfoMessage: %w", ctx.Err())
	}
	return dc, nil
}

var httpOrFileClient = &http.Client{Transport: httpOrFileTransport()}

func httpOrFileTransport() http.RoundTripper {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.RegisterProtocol("file", http.NewFileTransport(http.Dir("/")))
	return tr
}

func getDERPMap(ctx context.Context) (*tailcfg.DERPMap, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", *derpMapURL, nil)
	if err != nil {
		return nil, err
	}
	res, err := httpOrFileClient.Do(req)
	if err != nil {
		mu.Lock()
		defer mu.Unlock()
		if lastDERPMap != nil && time.Since(lastDERPMapAt) < 10*time.Minute {
			// Assume that control is restarting and use
			// the same one for a bit.
			return lastDERPMap, nil
		}
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("fetching %s: %s", *derpMapURL, res.Status)
	}
	dm := new(tailcfg.DERPMap)
	if err := json.NewDecoder(res.Body).Decode(dm); err != nil {
		return nil, fmt.Errorf("decoding %s JSON: %v", *derpMapURL, err)
	}
	setDERPMap(dm)
	return dm, nil
}
