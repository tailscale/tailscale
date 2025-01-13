package tsconsensus

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

type joinRequest struct {
	RemoteHost string `json:'remoteAddr'`
	RemoteID   string `json:'remoteID'`
}

type commandClient struct {
	port       uint16
	httpClient *http.Client
}

func (rac *commandClient) Url(host string, path string) string {
	return fmt.Sprintf("http://%s:%d%s", host, rac.port, path)
}

func (rac *commandClient) Join(host string, jr joinRequest) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rBs, err := json.Marshal(jr)
	if err != nil {
		return err
	}
	url := rac.Url(host, "/join")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(rBs))
	if err != nil {
		return err
	}
	resp, err := rac.httpClient.Do(req)
	if err != nil {
		return err
	}
	respBs, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		return errors.New(fmt.Sprintf("remote responded %d: %s", resp.StatusCode, string(respBs)))
	}
	return nil
}

func (rac *commandClient) ExecuteCommand(host string, bs []byte) (CommandResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	url := rac.Url(host, "/executeCommand")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bs))
	if err != nil {
		return CommandResult{}, err
	}
	resp, err := rac.httpClient.Do(req)
	if err != nil {
		return CommandResult{}, err
	}
	respBs, err := io.ReadAll(resp.Body)
	if err != nil {
		return CommandResult{}, err
	}
	if resp.StatusCode != 200 {
		return CommandResult{}, errors.New(fmt.Sprintf("remote responded %d: %s", resp.StatusCode, string(respBs)))
	}
	var cr CommandResult
	if err = json.Unmarshal(respBs, &cr); err != nil {
		return CommandResult{}, err
	}
	return cr, nil
}

func (c *Consensus) makeCommandMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/join", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		decoder := json.NewDecoder(r.Body)
		var jr joinRequest
		err := decoder.Decode(&jr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
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
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
	mux.HandleFunc("/executeCommand", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Bad Request", http.StatusBadRequest)
			return
		}
		decoder := json.NewDecoder(r.Body)
		var cmd Command
		err := decoder.Decode(&cmd)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		result, err := c.executeCommandLocally(cmd)
		if err := json.NewEncoder(w).Encode(result); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	})
	return mux
}
