// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

// example-webrtc-server is a WebRTC signaling server that supports both
// WebSocket (for Tailscale) and HTTP REST (for standard WebRTC clients).
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

// SignalingMessage represents a WebRTC signaling message.
// This format is compatible with both Tailscale and standard WebRTC clients.
type SignalingMessage struct {
	Type string `json:"type"` // "offer", "answer", "candidate"
	From string `json:"from"` // sender's disco public key (hex)
	To   string `json:"to"`   // recipient's disco public key (hex)

	// For SDP offer/answer (raw JSON for flexibility)
	Offer     json.RawMessage `json:"offer,omitempty"`
	Answer    json.RawMessage `json:"answer,omitempty"`
	Candidate json.RawMessage `json:"candidate,omitempty"`

	// Legacy fields for HTTP REST clients
	SDP string `json:"sdp,omitempty"` // Used by non-Tailscale clients

	Timestamp time.Time `json:"timestamp"`
}

// Client represents a connected peer (WebSocket or HTTP polling)
type Client struct {
	ID       string
	Conn     *websocket.Conn // nil for HTTP clients
	LastSeen time.Time
}

// SignalingServer manages WebRTC signaling between peers
type SignalingServer struct {
	mu      sync.RWMutex
	clients map[string]*Client // Active WebSocket clients

	// Message queue for HTTP polling clients
	messages map[string][]SignalingMessage // Key: "to" peer ID

	upgrader websocket.Upgrader

	// Statistics
	stats struct {
		totalMessages  int
		wsConnections  int
		httpPolls      int
		activeOffers   int
		completedPairs int
	}
}

// NewSignalingServer creates a new signaling server
func NewSignalingServer() *SignalingServer {
	return &SignalingServer{
		clients:  make(map[string]*Client),
		messages: make(map[string][]SignalingMessage),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins (configure as needed)
			},
		},
	}
}

// RouteMessage delivers a message to the destination peer
func (s *SignalingServer) RouteMessage(msg SignalingMessage, clientIP string) error {
	msg.Timestamp = time.Now()

	s.mu.Lock()
	defer s.mu.Unlock()

	// Update stats
	s.stats.totalMessages++
	switch msg.Type {
	case "offer":
		s.stats.activeOffers++
		// Clear old messages from this sender when starting a new session
		s.clearOldMessages(msg.From, msg.To)
	case "answer":
		s.stats.completedPairs++
		if s.stats.activeOffers > 0 {
			s.stats.activeOffers--
		}
	}

	log.Printf("[%s] Routing %s from %s to %s", clientIP, msg.Type, msg.From, msg.To)

	// Try to deliver to WebSocket client first
	if client, ok := s.clients[msg.To]; ok && client.Conn != nil {
		// Send directly via WebSocket
		if err := client.Conn.WriteJSON(msg); err != nil {
			log.Printf("[%s] Failed to send to WebSocket client %s: %v", clientIP, msg.To, err)
			// Remove dead connection
			delete(s.clients, msg.To)
			// Fall through to queue message
		} else {
			log.Printf("[%s] Delivered %s to WebSocket client %s", clientIP, msg.Type, msg.To)
			return nil
		}
	}

	// Queue for HTTP polling client
	s.messages[msg.To] = append(s.messages[msg.To], msg)
	log.Printf("[%s] Queued %s for HTTP client %s", clientIP, msg.Type, msg.To)

	return nil
}

// clearOldMessages removes previous messages between two peers (used when new session starts)
func (s *SignalingServer) clearOldMessages(from, to string) {
	if msgs, ok := s.messages[to]; ok {
		filtered := make([]SignalingMessage, 0)
		for _, msg := range msgs {
			if msg.From != from {
				filtered = append(filtered, msg)
			}
		}
		if len(filtered) == 0 {
			delete(s.messages, to)
		} else {
			s.messages[to] = filtered
		}
	}
}

// GetMessages retrieves queued messages for an HTTP polling client
func (s *SignalingServer) GetMessages(peerID, clientIP string) []SignalingMessage {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.stats.httpPolls++

	messages := s.messages[peerID]
	if len(messages) == 0 {
		return nil
	}

	// Return all messages and clear the queue
	delete(s.messages, peerID)

	log.Printf("[%s] Delivering %d queued message(s) to HTTP client %s", clientIP, len(messages), peerID)
	return messages
}

// CleanupOldMessages removes stale messages and dead connections
func (s *SignalingServer) CleanupOldMessages(maxAge time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-maxAge)
	cleaned := 0

	// Clean old messages
	for peerID, messages := range s.messages {
		filtered := make([]SignalingMessage, 0, len(messages))
		for _, msg := range messages {
			if msg.Timestamp.After(cutoff) {
				filtered = append(filtered, msg)
			} else {
				cleaned++
			}
		}

		if len(filtered) == 0 {
			delete(s.messages, peerID)
		} else {
			s.messages[peerID] = filtered
		}
	}

	// Clean inactive clients
	for id, client := range s.clients {
		if time.Since(client.LastSeen) > maxAge {
			if client.Conn != nil {
				client.Conn.Close()
			}
			delete(s.clients, id)
			cleaned++
		}
	}

	if cleaned > 0 {
		log.Printf("Cleaned up %d old messages/connections", cleaned)
	}
}

// GetStats returns current server statistics
func (s *SignalingServer) GetStats() map[string]interface{} {
	s.mu.RLock()
	defer s.mu.RUnlock()

	queuedMessages := 0
	for _, msgs := range s.messages {
		queuedMessages += len(msgs)
	}

	return map[string]interface{}{
		"total_messages":    s.stats.totalMessages,
		"ws_connections":    s.stats.wsConnections,
		"http_polls":        s.stats.httpPolls,
		"active_offers":     s.stats.activeOffers,
		"completed_pairs":   s.stats.completedPairs,
		"queued_messages":   queuedMessages,
		"active_ws_clients": len(s.clients),
		"active_peer_ids":   len(s.messages),
	}
}

// WebSocket Handler (for Tailscale clients)
func (s *SignalingServer) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	var clientID string

	s.mu.Lock()
	s.stats.wsConnections++
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		s.stats.wsConnections--
		s.mu.Unlock()
	}()

	log.Printf("[%s] New WebSocket connection", r.RemoteAddr)

	// Read and route messages from this WebSocket client
	for {
		var msg SignalingMessage
		if err := conn.ReadJSON(&msg); err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				log.Printf("[%s] WebSocket error: %v", r.RemoteAddr, err)
			}
			break
		}

		// Register client on first message
		if clientID == "" {
			clientID = msg.From
			s.mu.Lock()
			s.clients[clientID] = &Client{
				ID:       clientID,
				Conn:     conn,
				LastSeen: time.Now(),
			}
			s.mu.Unlock()
			log.Printf("[%s] WebSocket client registered as %s", r.RemoteAddr, clientID)
		}

		// Update last seen
		s.mu.Lock()
		if client, ok := s.clients[clientID]; ok {
			client.LastSeen = time.Now()
		}
		s.mu.Unlock()

		// Route the message to destination
		if err := s.RouteMessage(msg, r.RemoteAddr); err != nil {
			log.Printf("[%s] Failed to route message: %v", r.RemoteAddr, err)
		}
	}

	// Cleanup on disconnect
	if clientID != "" {
		s.mu.Lock()
		delete(s.clients, clientID)
		s.mu.Unlock()
		log.Printf("[%s] WebSocket client %s disconnected", r.RemoteAddr, clientID)
	}
}

// HTTP REST Handlers (for standard WebRTC clients)

func (s *SignalingServer) handlePostSignal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var msg SignalingMessage
	if err := json.NewDecoder(r.Body).Decode(&msg); err != nil {
		http.Error(w, fmt.Sprintf("Invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	// Validate required fields
	if msg.From == "" || msg.To == "" || msg.Type == "" {
		http.Error(w, "Missing required fields: from, to, type", http.StatusBadRequest)
		return
	}

	if msg.Type != "offer" && msg.Type != "answer" && msg.Type != "candidate" {
		http.Error(w, "Invalid type, must be 'offer', 'answer', or 'candidate'", http.StatusBadRequest)
		return
	}

	// Convert legacy SDP field to Offer/Answer format for compatibility
	if msg.SDP != "" {
		sdpJSON := json.RawMessage(fmt.Sprintf(`{"type":"%s","sdp":%q}`, msg.Type, msg.SDP))
		if msg.Type == "offer" {
			msg.Offer = sdpJSON
		} else if msg.Type == "answer" {
			msg.Answer = sdpJSON
		}
	}

	if err := s.RouteMessage(msg, r.RemoteAddr); err != nil {
		http.Error(w, fmt.Sprintf("Failed to route message: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "ok",
		"message": fmt.Sprintf("Message routed to %s", msg.To),
	})
}

func (s *SignalingServer) handleGetSignal(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	to := r.URL.Query().Get("to")
	if to == "" {
		http.Error(w, "Missing required query parameter: to", http.StatusBadRequest)
		return
	}

	messages := s.GetMessages(to, r.RemoteAddr)

	w.Header().Set("Content-Type", "application/json")

	if len(messages) == 0 {
		w.WriteHeader(http.StatusNotFound)
		json.NewEncoder(w).Encode(map[string]string{
			"status":  "not_found",
			"message": fmt.Sprintf("No messages for %s", to),
		})
		return
	}

	w.WriteHeader(http.StatusOK)
	// Return first message (client should poll again for more)
	json.NewEncoder(w).Encode(messages[0])
}

func (s *SignalingServer) handleStats(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.GetStats())
}

func (s *SignalingServer) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status":  "healthy",
		"service": "webrtc-signaling-server",
		"version": "1.0.0",
	})
}

// CORS middleware
func corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusOK)
			return
		}

		next(w, r)
	}
}

// Logging middleware
func loggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next(w, r)
		log.Printf("%s %s %s %s", r.RemoteAddr, r.Method, r.URL.Path, time.Since(start))
	}
}

func main() {
	port := flag.Int("port", 8080, "Port to listen on")
	tlsCert := flag.String("cert", "", "TLS certificate file (optional, for HTTPS)")
	tlsKey := flag.String("key", "", "TLS key file (optional, for HTTPS)")
	cleanupInterval := flag.Duration("cleanup", 5*time.Minute, "Interval for cleaning up old messages")
	messageMaxAge := flag.Duration("max-age", 10*time.Minute, "Maximum age for messages before cleanup")
	flag.Parse()

	server := NewSignalingServer()

	// Start cleanup goroutine
	go func() {
		ticker := time.NewTicker(*cleanupInterval)
		defer ticker.Stop()

		for range ticker.C {
			server.CleanupOldMessages(*messageMaxAge)
		}
	}()

	// Register handlers
	// WebSocket endpoint (for Tailscale)
	http.HandleFunc("/ws", loggingMiddleware(server.handleWebSocket))

	// HTTP REST endpoints (for standard WebRTC clients)
	http.HandleFunc("/signal", corsMiddleware(loggingMiddleware(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			server.handlePostSignal(w, r)
		} else if r.Method == http.MethodGet {
			server.handleGetSignal(w, r)
		} else {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	})))

	// Monitoring endpoints
	http.HandleFunc("/stats", corsMiddleware(loggingMiddleware(server.handleStats)))
	http.HandleFunc("/health", corsMiddleware(loggingMiddleware(server.handleHealth)))

	addr := fmt.Sprintf(":%d", *port)

	log.Printf("Server starting on %s", addr)
	log.Printf("WebSocket endpoint: ws://localhost%s/ws", addr)
	log.Printf("HTTP REST endpoint: http://localhost%s/signal", addr)
	log.Printf("Cleanup interval: %v, Max message age: %v", *cleanupInterval, *messageMaxAge)
	log.Println("────────────────────────────────────────────────────────────")

	var err error
	if *tlsCert != "" && *tlsKey != "" {
		log.Printf("Starting HTTPS server with TLS...")
		err = http.ListenAndServeTLS(addr, *tlsCert, *tlsKey, nil)
	} else {
		log.Printf("Starting HTTP server (use -cert and -key for HTTPS)...")
		err = http.ListenAndServe(addr, nil)
	}

	if err != nil {
		log.Fatal(err)
	}
}
