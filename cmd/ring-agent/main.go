// Command ring-agent is the peer agent daemon: replicate, verify,
// serve, probe (DESIGN §6). Co-tenant deployment unit; see
// internal/agent for the composition.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/selfsimilar/resiliency-ring/internal/agent"
	"github.com/selfsimilar/resiliency-ring/internal/keyfile"
)

func main() {
	member := flag.String("member", "", "this agent's member id (required)")
	registryPath := flag.String("registry", "", "path to the signed registry file (required)")
	registryPub := flag.String("registry-pub-file", "", "registry root public key file (required)")
	dataDir := flag.String("data", "", "data directory for the bundle cache (required)")
	listen := flag.String("listen", "127.0.0.1:8100", "address to serve on")
	poll := flag.Duration("poll", 30*time.Second, "bundle poll interval")
	probeIv := flag.Duration("probe", 60*time.Second, "health probe interval")
	staleness := flag.Duration("staleness", 5*time.Minute, "freshness grace window")
	verbose := flag.Bool("v", false, "debug logging")
	flag.Parse()

	if *member == "" || *registryPath == "" || *registryPub == "" || *dataDir == "" {
		flag.Usage()
		os.Exit(1)
	}

	level := slog.LevelInfo
	if *verbose {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))
	slog.SetDefault(log)

	pub, err := keyfile.LoadPublic(*registryPub)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ring-agent: %v\n", err)
		os.Exit(1)
	}

	a, err := agent.New(agent.Config{
		MemberID:      *member,
		RegistryPath:  *registryPath,
		RegistryPub:   pub,
		DataDir:       *dataDir,
		Listen:        *listen,
		PollInterval:  *poll,
		ProbeInterval: *probeIv,
		Staleness:     *staleness,
		Logger:        log,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "ring-agent: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "ring-agent: %v\n", err)
		os.Exit(1)
	}
}
