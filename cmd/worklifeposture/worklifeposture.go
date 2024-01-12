// worklifeposture enables achieving work-life balance through device posture.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
	"golang.org/x/oauth2/clientcredentials"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/syncs"
	"tailscale.com/tailcfg"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
	"tailscale.com/util/httpm"
)

func main() {
	s := &tsnet.Server{
		Hostname: "worklifeposture",
		Logf:     logger.Discard,
	}

	// maxmind.com
	db, err := geoip2.Open("GeoLite2-City.mmdb")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	writer := newAttrWriter()

	var lastProcessed syncs.Map[tailcfg.StableNodeID, time.Time]
	for {
		lc, err := s.LocalClient()
		if err != nil {
			log.Printf("error getting local client: %s", err)
			continue
		}
		st, err := lc.Status(context.Background())
		if err != nil {
			log.Printf("error calling status: %s", err)
			continue
		}

		var wg sync.WaitGroup
		sema := make(chan struct{}, 5) // limit concurrency
		for _, peer := range st.Peer {
			if last, ok := lastProcessed.Load(peer.ID); ok && time.Since(last) < 5*time.Minute {
				continue
			}
			sema <- struct{}{} // acquire a semaphore
			wg.Add(1)
			go func(peer *ipnstate.PeerStatus) {
				defer wg.Done()
				defer func() { <-sema }() // release the semaphore

				// Ping to trigger disco.
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				_, err := lc.Ping(ctx, peer.TailscaleIPs[0], tailcfg.PingPeerAPI)
				cancel()
				if err != nil {
					if !errors.Is(err, context.DeadlineExceeded) {
						log.Printf("ping %s error: %s", peer.ID, err)
					}
					return
				}

				// Look up timezone based on the public IP.
				ip := peer.CurAddr
				if ip == "" {
					log.Printf("no IP for peer %s", peer.ID)
					return
				}
				netip := net.ParseIP(ip)
				if netip == nil {
					log.Printf("cannot parse IP %q for peer %s", ip, peer.ID)
					return
				}
				res, err := db.City(netip)
				if err != nil {
					log.Printf("error looking up details for %s: %s", netip, err)
					return
				}

				// Write an attribute depending on whether it's working hours in a given timezone.
				tz, err := time.LoadLocation(res.Location.TimeZone)
				if err != nil {
					log.Printf("error loading location %s: %s", res.Location.TimeZone, err)
					return
				}
				at := time.Now().In(tz)
				value := "life"
				if shouldYouWork(at) {
					value = "work"
				}
				if err := writer.write(peer.ID, "custom:balance", value); err != nil {
					log.Printf("error writing attribute for %s: %s", peer.ID, err)
					return
				}
				lastProcessed.Store(peer.ID, time.Now())
			}(peer)
		}
		wg.Wait()
		time.Sleep(5 * time.Second)
	}
}

func shouldYouWork(at time.Time) bool {
	if at.Weekday() == time.Saturday || at.Weekday() == time.Sunday {
		return false
	}
	workingBegins := time.Date(at.Year(), at.Month(), at.Day(), 9, 0, 0, 0, at.Location())
	workingFinallyEnds := time.Date(at.Year(), at.Month(), at.Day(), 17, 0, 0, 0, at.Location())
	if at.After(workingBegins) && at.Before(workingFinallyEnds) {
		return true
	}
	return false
}

type attrWriter struct {
	client *http.Client
}

func newAttrWriter() *attrWriter {
	var oauthConfig = &clientcredentials.Config{
		ClientID:     os.Getenv("OAUTH_CLIENT_ID"),
		ClientSecret: os.Getenv("OAUTH_CLIENT_SECRET"),
		TokenURL:     "https://api.tailscale.com/api/v2/oauth/token",
	}
	return &attrWriter{client: oauthConfig.Client(context.Background())}
}

func (aw *attrWriter) write(nodeID tailcfg.StableNodeID, key, value string) error {
	url := fmt.Sprintf("https://api.tailscale.com/api/v2/device/%s/attributes/%s", nodeID, key)

	valueMap := map[string]any{"value": value}
	valueBody, err := json.Marshal(valueMap)
	if err != nil {
		return err
	}

	setReq, err := http.NewRequest(httpm.POST, url, bytes.NewReader(valueBody))
	if err != nil {
		return err
	}

	resp, err := aw.client.Do(setReq)
	if err != nil {
		return err
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("unexpected status for %s: %s", nodeID, resp.Status)
	}
	log.Printf("set %s %q=%q", nodeID, key, value)
	return nil
}
