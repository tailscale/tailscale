// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package tsconsensus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"tailscale.com/util/httpm"
)

type joinRequest struct {
	RemoteHost string
	RemoteID   string
}

type commandClient struct {
	port       uint16
	httpClient *http.Client
}

func (rac *commandClient) url(host string, path string) string {
	return fmt.Sprintf("http://%s:%d%s", host, rac.port, path)
}

const maxBodyBytes = 1024 * 1024

func readAllMaxBytes(r io.Reader) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, maxBodyBytes+1))
}

func (rac *commandClient) join(host string, jr joinRequest) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rBs, err := json.Marshal(jr)
	if err != nil {
		return err
	}
	url := rac.url(host, "/join")
	req, err := http.NewRequestWithContext(ctx, httpm.POST, url, bytes.NewReader(rBs))
	if err != nil {
		return err
	}
	resp, err := rac.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		respBs, err := readAllMaxBytes(resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf("remote responded %d: %s", resp.StatusCode, string(respBs))
	}
	return nil
}

func (rac *commandClient) executeCommand(host string, bs []byte) (CommandResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	url := rac.url(host, "/executeCommand")
	req, err := http.NewRequestWithContext(ctx, httpm.POST, url, bytes.NewReader(bs))
	if err != nil {
		return CommandResult{}, err
	}
	resp, err := rac.httpClient.Do(req)
	if err != nil {
		return CommandResult{}, err
	}
	defer resp.Body.Close()
	respBs, err := readAllMaxBytes(resp.Body)
	if err != nil {
		return CommandResult{}, err
	}
	if resp.StatusCode != 200 {
		return CommandResult{}, fmt.Errorf("remote responded %d: %s", resp.StatusCode, string(respBs))
	}
	var cr CommandResult
	if err = json.Unmarshal(respBs, &cr); err != nil {
		return CommandResult{}, err
	}
	return cr, nil
}

type authedHandler struct {
	auth    *authorization
	handler http.Handler
}

func (h authedHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := h.auth.Refresh(r.Context())
	if err != nil {
		log.Printf("error authedHandler ServeHTTP refresh auth: %v", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	a, err := addrFromServerAddress(r.RemoteAddr)
	if err != nil {
		log.Printf("error authedHandler ServeHTTP refresh auth: %v", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
	allowed := h.auth.AllowsHost(a)
	if !allowed {
		http.Error(w, "peer not allowed", http.StatusForbidden)
		return
	}
	h.handler.ServeHTTP(w, r)
}

func (c *Consensus) handleJoinHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes+1))
	var jr joinRequest
	err := decoder.Decode(&jr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	_, err = decoder.Token()
	if !errors.Is(err, io.EOF) {
		http.Error(w, "Request body must only contain a single JSON object", http.StatusBadRequest)
		return
	}
	if jr.RemoteHost == "" {
		http.Error(w, "Required: remoteAddr", http.StatusBadRequest)
		return
	}
	if jr.RemoteID == "" {
		http.Error(w, "Required: remoteID", http.StatusBadRequest)
		return
	}
	err = c.handleJoin(jr)
	if err != nil {
		log.Printf("join handler error: %v", err)
		http.Error(w, "", http.StatusInternalServerError)
		return
	}
}

func (c *Consensus) handleExecuteCommandHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	decoder := json.NewDecoder(r.Body)
	var cmd Command
	err := decoder.Decode(&cmd)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	result, err := c.executeCommandLocally(cmd)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Printf("error encoding execute command result: %v", err)
		return
	}
}

func (c *Consensus) makeCommandMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /join", c.handleJoinHTTP)
	mux.HandleFunc("POST /executeCommand", c.handleExecuteCommandHTTP)
	return mux
}

func (c *Consensus) makeCommandHandler(auth *authorization) http.Handler {
	return authedHandler{
		handler: c.makeCommandMux(),
		auth:    auth,
	}
}
