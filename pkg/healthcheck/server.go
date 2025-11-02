package healthcheck

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/fystack/mpcium/pkg/logger"
	"github.com/fystack/mpcium/pkg/mpc"
	"github.com/hashicorp/consul/api"
	"github.com/nats-io/nats.go"
)

// Server provides HTTP health check endpoints for Kubernetes probes
type Server struct {
	httpServer   *http.Server
	peerRegistry mpc.PeerRegistry
	natsConn     *nats.Conn
	consulClient *api.Client
}

// HealthResponse represents the JSON response for health check endpoints
type HealthResponse struct {
	Status    string         `json:"status"`
	Live      bool           `json:"live"`
	Ready     bool           `json:"ready"`
	Details   map[string]any `json:"details,omitempty"`
}

// NewServer creates a new health check HTTP server
func NewServer(addr string, peerRegistry mpc.PeerRegistry, natsConn *nats.Conn, consulClient *api.Client) *Server {
	s := &Server{
		peerRegistry: peerRegistry,
		natsConn:     natsConn,
		consulClient: consulClient,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/health", s.healthHandler)

	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  15 * time.Second,
	}

	return s
}

// Start begins serving health check endpoints
func (s *Server) Start() error {
	addr := s.httpServer.Addr

	// Parse host and port from address
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		// If parsing fails, just use the address as-is
		logger.Info("Starting health check server", "address", addr)
	} else {
		// Replace empty host or 0.0.0.0 with localhost for display
		if host == "" || host == "0.0.0.0" {
			host = "localhost"
		}
		endpoint := fmt.Sprintf("http://%s:%s/health", host, port)
		logger.Info("Starting health check server", "endpoint", endpoint)
	}

	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("health check server failed: %w", err)
	}
	return nil
}

// Shutdown gracefully stops the health check server
func (s *Server) Shutdown(ctx context.Context) error {
	logger.Info("Shutting down health check server")
	return s.httpServer.Shutdown(ctx)
}

// healthHandler responds to health check requests
// This endpoint checks both liveness and readiness in a single response
func (s *Server) healthHandler(w http.ResponseWriter, r *http.Request) {
	details := make(map[string]any)
	ready := true
	live := true // Service is always live if it can respond

	// Check NATS connection
	natsConnected := s.natsConn != nil && s.natsConn.IsConnected()
	details["nats_connected"] = natsConnected
	if !natsConnected {
		ready = false
	}

	// Check Consul connection
	consulConnected := false
	if s.consulClient != nil {
		if leader, err := s.consulClient.Status().Leader(); err == nil && leader != "" {
			consulConnected = true
		}
	}
	details["consul_connected"] = consulConnected
	if !consulConnected {
		ready = false
	}

	// Check peer registry readiness (includes ECDH completion)
	if s.peerRegistry != nil {
		peersReady := s.peerRegistry.ArePeersReady()
		majorityReady := s.peerRegistry.AreMajorityReady()
		readyCount := s.peerRegistry.GetReadyPeersCount()
		totalCount := s.peerRegistry.GetTotalPeersCount()

		details["peers_ready_count"] = fmt.Sprintf("%d/%d", readyCount, totalCount)
		details["all_peers_ready"] = peersReady
		details["majority_ready"] = majorityReady

		// Node is ready if majority of peers are ready (allows for some fault tolerance)
		if !majorityReady {
			ready = false
		}
	} else {
		details["peers_available"] = false
		ready = false
	}

	response := HealthResponse{
		Live:    live,
		Ready:   ready,
		Details: details,
	}

	w.Header().Set("Content-Type", "application/json")

	if ready {
		response.Status = "ready"
		w.WriteHeader(http.StatusOK)
	} else {
		response.Status = "not_ready"
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	if err := json.NewEncoder(w).Encode(response); err != nil {
		logger.Error("Failed to encode health check response", err)
	}
}
