package tsconsensus

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"slices"
	"strings"

	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/tsnet"
)

type status struct {
	Status    *ipnstate.Status
	RaftState string
}

type monitor struct {
	ts  *tsnet.Server
	con *Consensus
}

func (m *monitor) getStatus(ctx context.Context) (status, error) {
	lc, err := m.ts.LocalClient()
	if err != nil {
		return status{}, err
	}
	tStatus, err := lc.Status(ctx)
	if err != nil {
		return status{}, err
	}
	return status{Status: tStatus, RaftState: m.con.Raft.State().String()}, nil
}

func serveMonitor(c *Consensus, ts *tsnet.Server, listenAddr string) (*http.Server, error) {
	ln, err := ts.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	m := &monitor{con: c, ts: ts}
	mux := http.NewServeMux()
	mux.HandleFunc("/full", m.handleFullStatus)
	mux.HandleFunc("/", m.handleSummaryStatus)
	mux.HandleFunc("/netmap", m.handleNetmap)
	mux.HandleFunc("/dial", m.handleDial)
	srv := &http.Server{Handler: mux}
	go func() {
		defer ln.Close()
		err := srv.Serve(ln)
		log.Printf("MonitorHTTP stopped serving with error: %v", err)
	}()
	return srv, nil
}

func (m *monitor) handleFullStatus(w http.ResponseWriter, r *http.Request) {
	s, err := m.getStatus(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	if err := json.NewEncoder(w).Encode(s); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
}

func (m *monitor) handleSummaryStatus(w http.ResponseWriter, r *http.Request) {
	s, err := m.getStatus(r.Context())
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	lines := []string{}
	for _, p := range s.Status.Peer {
		if p.Online {
			lines = append(lines, fmt.Sprintf("%s\t\t%d\t%d\t%t", strings.Split(p.DNSName, ".")[0], p.RxBytes, p.TxBytes, p.Active))
		}
	}
	slices.Sort(lines)
	lines = append([]string{fmt.Sprintf("RaftState: %s", s.RaftState)}, lines...)
	txt := strings.Join(lines, "\n") + "\n"
	w.Write([]byte(txt))
}

func (m *monitor) handleNetmap(w http.ResponseWriter, r *http.Request) {
	var mask ipn.NotifyWatchOpt = ipn.NotifyInitialNetMap
	mask |= ipn.NotifyNoPrivateKeys
	lc, err := m.ts.LocalClient()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	watcher, err := lc.WatchIPNBus(r.Context(), mask)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer watcher.Close()

	n, err := watcher.Next()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	j, _ := json.MarshalIndent(n.NetMap, "", "\t")
	w.Write([]byte(j))
	return
}

func (m *monitor) handleDial(w http.ResponseWriter, r *http.Request) {
	fmt.Println("FRAN handle ping")
	var dialParams struct {
		Addr string
	}
	bs, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	err = json.Unmarshal(bs, &dialParams)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Println("dialing", dialParams.Addr)
	c, err := m.ts.Dial(r.Context(), "tcp", dialParams.Addr)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Println("ping success", c)
	defer c.Close()
	w.Write([]byte("ok\n"))
	return
}
