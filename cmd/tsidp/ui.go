// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package main

import (
	"bytes"
	_ "embed"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"tailscale.com/util/rands"
)

//go:embed ui-header.html
var headerHTML string

//go:embed ui-list.html
var listHTML string

//go:embed ui-edit.html
var editHTML string

//go:embed ui-style.css
var styleCSS string

var headerTmpl = template.Must(template.New("header").Parse(headerHTML))
var listTmpl = template.Must(headerTmpl.New("list").Parse(listHTML))
var editTmpl = template.Must(headerTmpl.New("edit").Parse(editHTML))

var processStart = time.Now()

func (s *idpServer) handleUI(w http.ResponseWriter, r *http.Request) {
	if isFunnelRequest(r) {
		http.Error(w, "tsidp: UI not available over Funnel", http.StatusNotFound)
		return
	}

	switch r.URL.Path {
	case "/":
		s.handleClientsList(w, r)
		return
	case "/new":
		s.handleNewClient(w, r)
		return
	case "/style.css":
		http.ServeContent(w, r, "ui-style.css", processStart, strings.NewReader(styleCSS))
		return
	}

	if strings.HasPrefix(r.URL.Path, "/edit/") {
		s.handleEditClient(w, r)
		return
	}

	http.Error(w, "tsidp: not found", http.StatusNotFound)
}

func (s *idpServer) handleClientsList(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	clients := make([]clientDisplayData, 0, len(s.funnelClients))
	for _, c := range s.funnelClients {
		clients = append(clients, clientDisplayData{
			ID:          c.ID,
			Name:        c.Name,
			RedirectURI: c.RedirectURI,
			HasSecret:   c.Secret != "",
		})
	}
	s.mu.Unlock()

	sort.Slice(clients, func(i, j int) bool {
		if clients[i].Name != clients[j].Name {
			return clients[i].Name < clients[j].Name
		}
		return clients[i].ID < clients[j].ID
	})

	var buf bytes.Buffer
	if err := listTmpl.Execute(&buf, clients); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	buf.WriteTo(w)
}

func (s *idpServer) handleNewClient(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		if err := s.renderClientForm(w, clientDisplayData{IsNew: true}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if r.Method == "POST" {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		name := strings.TrimSpace(r.FormValue("name"))
		redirectURI := strings.TrimSpace(r.FormValue("redirect_uri"))

		baseData := clientDisplayData{
			IsNew:       true,
			Name:        name,
			RedirectURI: redirectURI,
		}

		if errMsg := validateRedirectURI(redirectURI); errMsg != "" {
			s.renderFormError(w, baseData, errMsg)
			return
		}

		clientID := rands.HexString(32)
		clientSecret := rands.HexString(64)
		newClient := funnelClient{
			ID:          clientID,
			Secret:      clientSecret,
			Name:        name,
			RedirectURI: redirectURI,
		}

		s.mu.Lock()
		if s.funnelClients == nil {
			s.funnelClients = make(map[string]*funnelClient)
		}
		s.funnelClients[clientID] = &newClient
		err := s.storeFunnelClientsLocked()
		s.mu.Unlock()

		if err != nil {
			log.Printf("could not write funnel clients db: %v", err)
			s.renderFormError(w, baseData, "Failed to save client")
			return
		}

		successData := clientDisplayData{
			ID:          clientID,
			Name:        name,
			RedirectURI: redirectURI,
			Secret:      clientSecret,
			IsNew:       true,
		}
		s.renderFormSuccess(w, successData, "Client created successfully! Save the client secret - it won't be shown again.")
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *idpServer) handleEditClient(w http.ResponseWriter, r *http.Request) {
	clientID := strings.TrimPrefix(r.URL.Path, "/edit/")
	if clientID == "" {
		http.Error(w, "Client ID required", http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	client, exists := s.funnelClients[clientID]
	s.mu.Unlock()

	if !exists {
		http.Error(w, "Client not found", http.StatusNotFound)
		return
	}

	if r.Method == "GET" {
		data := createEditBaseData(client, client.Name, client.RedirectURI)
		if err := s.renderClientForm(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if r.Method == "POST" {
		action := r.FormValue("action")

		if action == "delete" {
			s.mu.Lock()
			delete(s.funnelClients, clientID)
			err := s.storeFunnelClientsLocked()
			s.mu.Unlock()

			if err != nil {
				log.Printf("could not write funnel clients db: %v", err)
				s.mu.Lock()
				s.funnelClients[clientID] = client
				s.mu.Unlock()

				baseData := createEditBaseData(client, client.Name, client.RedirectURI)
				s.renderFormError(w, baseData, "Failed to delete client. Please try again.")
				return
			}

			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		if action == "regenerate_secret" {
			newSecret := rands.HexString(64)
			s.mu.Lock()
			s.funnelClients[clientID].Secret = newSecret
			err := s.storeFunnelClientsLocked()
			s.mu.Unlock()

			baseData := createEditBaseData(client, client.Name, client.RedirectURI)
			baseData.HasSecret = true

			if err != nil {
				log.Printf("could not write funnel clients db: %v", err)
				s.renderFormError(w, baseData, "Failed to regenerate secret")
				return
			}

			baseData.Secret = newSecret
			s.renderFormSuccess(w, baseData, "New client secret generated! Save it - it won't be shown again.")
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		name := strings.TrimSpace(r.FormValue("name"))
		redirectURI := strings.TrimSpace(r.FormValue("redirect_uri"))
		baseData := createEditBaseData(client, name, redirectURI)

		if errMsg := validateRedirectURI(redirectURI); errMsg != "" {
			s.renderFormError(w, baseData, errMsg)
			return
		}

		s.mu.Lock()
		s.funnelClients[clientID].Name = name
		s.funnelClients[clientID].RedirectURI = redirectURI
		err := s.storeFunnelClientsLocked()
		s.mu.Unlock()

		if err != nil {
			log.Printf("could not write funnel clients db: %v", err)
			s.renderFormError(w, baseData, "Failed to update client")
			return
		}

		s.renderFormSuccess(w, baseData, "Client updated successfully!")
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

type clientDisplayData struct {
	ID          string
	Name        string
	RedirectURI string
	Secret      string
	HasSecret   bool
	IsNew       bool
	IsEdit      bool
	Success     string
	Error       string
}

func (s *idpServer) renderClientForm(w http.ResponseWriter, data clientDisplayData) error {
	var buf bytes.Buffer
	if err := editTmpl.Execute(&buf, data); err != nil {
		return err
	}
	if _, err := buf.WriteTo(w); err != nil {
		return err
	}
	return nil
}

func (s *idpServer) renderFormError(w http.ResponseWriter, data clientDisplayData, errorMsg string) {
	data.Error = errorMsg
	if err := s.renderClientForm(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *idpServer) renderFormSuccess(w http.ResponseWriter, data clientDisplayData, successMsg string) {
	data.Success = successMsg
	if err := s.renderClientForm(w, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func createEditBaseData(client *funnelClient, name, redirectURI string) clientDisplayData {
	return clientDisplayData{
		ID:          client.ID,
		Name:        name,
		RedirectURI: redirectURI,
		HasSecret:   client.Secret != "",
		IsEdit:      true,
	}
}

func validateRedirectURI(redirectURI string) string {
	if redirectURI == "" {
		return "Redirect URI is required"
	}

	u, err := url.Parse(redirectURI)
	if err != nil {
		return "Invalid URL format"
	}

	if u.Scheme != "http" && u.Scheme != "https" {
		return "Redirect URI must be a valid HTTP or HTTPS URL"
	}

	if u.Host == "" {
		return "Redirect URI must include a valid host"
	}

	return ""
}
