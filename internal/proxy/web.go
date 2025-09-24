package proxy

import (
	"encoding/json"
	"net/http"

	"github.com/gocertmitm/internal/web"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

type Hub struct {
	clients    map[*websocket.Conn]bool
	broadcast  chan []byte
	register   chan *websocket.Conn
	unregister chan *websocket.Conn
}

func newHub() *Hub {
	return &Hub{
		broadcast:  make(chan []byte),
		register:   make(chan *websocket.Conn),
		unregister: make(chan *websocket.Conn),
		clients:    make(map[*websocket.Conn]bool),
	}
}

func (h *Hub) run() {
	for {
		select {
		case client := <-h.register:
			h.clients[client] = true
		case client := <-h.unregister:
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				client.Close()
			}
		case message := <-h.broadcast:
			for client := range h.clients {
				err := client.WriteMessage(websocket.TextMessage, message)
				if err != nil {
					client.Close()
					delete(h.clients, client)
				}
			}
		}
	}
}

func (s *Server) StartWebUI(addr string) error {
	handler, err := web.GetHandler()
	if err != nil {
		return err
	}

	http.Handle("/", handler)
	http.HandleFunc("/api/status", s.handleAPIStatus)
	http.HandleFunc("/ws", s.handleWebSocket)

	return http.ListenAndServe(addr, nil)
}

func (s *Server) handleAPIStatus(w http.ResponseWriter, r *http.Request) {
	status := struct {
		RecentDomains []string `json:"recent_domains"`
	}{
		RecentDomains: s.GetRecentDomains(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.logger.Errorf("Failed to upgrade WebSocket connection: %v", err)
		return
	}
	s.hub.register <- conn

	defer func() {
		s.hub.unregister <- conn
		conn.Close()
	}()

	for {
		// We don't need to read messages from the client, just keep the connection open
		// The client will close the connection when it's done
		if _, _, err := conn.NextReader(); err != nil {
			break
		}
	}
}