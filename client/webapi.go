package phantomcore

import (
	"encoding/json"
	"net/http"
	"sync"

	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/rs/cors"
)

// WebAPIServer wraps the Core and exposes it via HTTP/WebSocket.
type WebAPIServer struct {
	core       *Core
	httpServer *http.Server
	clients    map[*websocket.Conn]bool
	clientsMu  sync.Mutex
	upgrader   websocket.Upgrader
}

// NewWebAPIServer creates a new WebAPI server instance.
func NewWebAPIServer(core *Core) *WebAPIServer {
	return &WebAPIServer{
		core:    core,
		clients: make(map[*websocket.Conn]bool),
		upgrader: websocket.Upgrader{
			CheckOrigin: func(r *http.Request) bool {
				return true // Allow all origins for local dev
			},
		},
	}
}

// SetCore sets the Core instance.
func (s *WebAPIServer) SetCore(core *Core) {
	s.core = core
}

// Start starts the HTTP server on the given address.
func (s *WebAPIServer) Start(addr string) error {
	r := mux.NewRouter()

	// API Endpoints
	r.HandleFunc("/api/init", s.handleInit).Methods("POST")
	r.HandleFunc("/api/contacts", s.handleGetContacts).Methods("GET")
	r.HandleFunc("/api/invite", s.handleCreateInvite).Methods("POST")
	r.HandleFunc("/api/join", s.handleJoin).Methods("POST")
	r.HandleFunc("/api/send", s.handleSendMessage).Methods("POST")
	r.HandleFunc("/api/messages", s.handleGetMessages).Methods("GET")
	r.HandleFunc("/api/events", s.handleEvents).Methods("GET")

	// CORS
	c := cors.New(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "OPTIONS"},
		AllowedHeaders:   []string{"*"},
		AllowCredentials: true,
	})

	s.httpServer = &http.Server{
		Addr:    addr,
		Handler: c.Handler(r),
	}

	// Register this server as an event handler proxy
	// Note: Core supports only one handler. We assume the main handler proxies to us
	// or we wrap the existing handler.
	// For simplicity, let's assume WebAPIServer IS the handler or part of it.
	// But Core is already initialized with a handler.
	// We need a way to hook into events.
	// Let's rely on the fact that the caller will set up a composite handler.

	return s.httpServer.ListenAndServe()
}

// Stop stops the HTTP server.
func (s *WebAPIServer) Stop() error {
	if s.httpServer != nil {
		return s.httpServer.Close()
	}
	return nil
}

// BroadcastEvent sends an event to all connected WebSockets.
func (s *WebAPIServer) BroadcastEvent(eventType string, data interface{}) {
	s.clientsMu.Lock()
	defer s.clientsMu.Unlock()

	msg := map[string]interface{}{
		"type": eventType,
		"data": data,
	}

	for client := range s.clients {
		err := client.WriteJSON(msg)
		if err != nil {
			client.Close()
			delete(s.clients, client)
		}
	}
}

// --- Handlers ---

func (s *WebAPIServer) handleInit(w http.ResponseWriter, r *http.Request) {
	// Core is likely already initialized by main.
	// This endpoint could be used to unlock if not unlocked.
	// For now, just return status.
	json.NewEncoder(w).Encode(map[string]string{"status": "ok", "message": "Core is running"})
}

func (s *WebAPIServer) handleGetContacts(w http.ResponseWriter, r *http.Request) {
	contacts, err := s.core.GetContacts()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(contacts)
}

func (s *WebAPIServer) handleCreateInvite(w http.ResponseWriter, r *http.Request) {
	var req struct {
		DisplayName string `json:"display_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	invite, err := s.core.CreateInvite(req.DisplayName)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"invite_code": invite})
}

func (s *WebAPIServer) handleJoin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		InviteCode string `json:"invite_code"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.core.ProcessInvite(req.InviteCode); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *WebAPIServer) handleSendMessage(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Hash    string `json:"hash"`
		Message string `json:"message"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if err := s.core.SendMessage(req.Hash, req.Message); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "sent"})
}

func (s *WebAPIServer) handleGetMessages(w http.ResponseWriter, r *http.Request) {
	hash := r.URL.Query().Get("hash")
	if hash == "" {
		http.Error(w, "hash parameter is required", http.StatusBadRequest)
		return
	}

	msgs, err := s.core.GetMessages(hash, 100) // Limit 100
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(msgs)
}

func (s *WebAPIServer) handleEvents(w http.ResponseWriter, r *http.Request) {
	conn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}

	s.clientsMu.Lock()
	s.clients[conn] = true
	s.clientsMu.Unlock()

	// Keep connection alive
	for {
		if _, _, err := conn.NextReader(); err != nil {
			s.clientsMu.Lock()
			delete(s.clients, conn)
			s.clientsMu.Unlock()
			conn.Close()
			break
		}
	}
}

// WebAPIEventHandler bridges Core events to WebAPI
type WebAPIEventHandler struct {
	Server *WebAPIServer
}

func (h *WebAPIEventHandler) OnMessageReceived(msg StoredMessage) {
	h.Server.BroadcastEvent("message_received", msg)
}

func (h *WebAPIEventHandler) OnContactListUpdated(contacts []ContactInfo) {
	h.Server.BroadcastEvent("contact_list_updated", contacts)
}

func (h *WebAPIEventHandler) OnSessionEstablished(peerHash string) {
	h.Server.BroadcastEvent("session_established", map[string]string{"peer_hash": peerHash})
}

func (h *WebAPIEventHandler) OnLog(level LogLevel, message string) {
	h.Server.BroadcastEvent("log", map[string]interface{}{"level": level, "message": message})
}

func (h *WebAPIEventHandler) OnConnectionStateChanged(state string, err error) {
	errMsg := ""
	if err != nil {
		errMsg = err.Error()
	}
	h.Server.BroadcastEvent("connection_state_changed", map[string]string{"state": state, "error": errMsg})
}

func (h *WebAPIEventHandler) OnShutdown(message string) {
	h.Server.BroadcastEvent("shutdown", map[string]string{"message": message})
}

func (h *WebAPIEventHandler) OnP2PStateChanged(isActive bool, peers []string) {
	h.Server.BroadcastEvent("p2p_state_changed", map[string]interface{}{"is_active": isActive, "peers": peers})
}
