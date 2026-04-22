package coordinator

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	coordinatorv1 "github.com/fystack/mpcium-sdk/integrations/coordinator-grpc/proto/coordinator/v1"
	"github.com/fystack/mpcium/pkg/logger"
	"google.golang.org/grpc"
)

type GRPCRuntime struct {
	addr          string
	server        *grpc.Server
	listener      net.Listener
	mu            sync.Mutex
	started       bool
	stopOnce      sync.Once
	orchestration *OrchestrationGRPCServer
}

func NewGRPCRuntime(addr string, coordination *Coordinator, pollInterval time.Duration) *GRPCRuntime {
	return &GRPCRuntime{
		addr:          strings.TrimSpace(addr),
		server:        grpc.NewServer(),
		orchestration: NewOrchestrationGRPCServer(coordination, pollInterval),
	}
}

func (r *GRPCRuntime) Start(_ context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		return nil
	}

	listener, err := net.Listen("tcp", r.addr)
	if err != nil {
		return fmt.Errorf("listen grpc: %w", err)
	}

	coordinatorv1.RegisterCoordinatorOrchestrationServer(r.server, r.orchestration)
	r.listener = listener
	r.started = true

	go func() {
		logger.Info("starting grpc orchestration runtime", "addr", r.addr)
		if serveErr := r.server.Serve(listener); serveErr != nil && !strings.Contains(strings.ToLower(serveErr.Error()), "closed network connection") {
			logger.Error("grpc runtime stopped with error", serveErr, "addr", r.addr)
		}
	}()

	return nil
}

func (r *GRPCRuntime) Stop() error {
	r.stopOnce.Do(func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if !r.started {
			return
		}
		r.server.GracefulStop()
		if r.listener != nil {
			_ = r.listener.Close()
		}
		r.started = false
	})
	return nil
}
