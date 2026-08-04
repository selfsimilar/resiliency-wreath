// Copyright 2026 The Resiliency Wreath Authors
// SPDX-License-Identifier: Apache-2.0

// Command wreath-agent is the peer agent daemon: replicate, verify,
// serve, probe (DESIGN §6). Co-tenant deployment unit; see
// internal/agent for the composition.
//
// Configuration: a JSON config file (-config) provides defaults; any
// flag set on the command line overrides it. See exampleConfig below.
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

	"github.com/selfsimilar/resiliency-wreath/internal/agent"
	"github.com/selfsimilar/resiliency-wreath/internal/keyfile"
)

const exampleConfig = `{
  "member_id": "example-org",
  "registry": "/etc/wreath/registry.json",
  "registry_pub_file": "/etc/wreath/root.pub",
  "data_dir": "/var/lib/wreath",
  "listen": ":8443",
  "poll": "30s",
  "probe": "60s",
  "staleness": "5m",
  "tls_domains": ["fallback.example.org"],
  "acme_email": "ops@example.org",
  "log_level": "info",
  "log_format": "text"
}`

func main() {
	cfgPath := flag.String("config", "", "JSON config file (flags override it)")
	member := flag.String("member", "", "this agent's member id")
	registryPath := flag.String("registry", "", "path to the signed registry file")
	registryPub := flag.String("registry-pub-file", "", "registry root public key file")
	dataDir := flag.String("data", "", "data directory for the bundle cache")
	listen := flag.String("listen", "", "address to serve on (default 127.0.0.1:8100)")
	poll := flag.Duration("poll", 0, "bundle poll interval (default 30s)")
	probeIv := flag.Duration("probe", 0, "health probe interval (default 60s)")
	staleness := flag.Duration("staleness", 0, "freshness grace window (default 5m)")
	logLevel := flag.String("log-level", "", "debug|info|warn|error (default info)")
	logFormat := flag.String("log-format", "", "text|json (default text)")
	printExample := flag.Bool("example-config", false, "print an example config file and exit")
	flag.Parse()

	if *printExample {
		fmt.Println(exampleConfig)
		return
	}

	cfg, err := loadConfig(*cfgPath)
	if err != nil {
		fatal(err)
	}
	// Flags set explicitly on the command line win over the file.
	overrideString(&cfg.MemberID, *member)
	overrideString(&cfg.Registry, *registryPath)
	overrideString(&cfg.RegistryPubFile, *registryPub)
	overrideString(&cfg.DataDir, *dataDir)
	overrideString(&cfg.Listen, *listen)
	overrideString(&cfg.LogLevel, *logLevel)
	overrideString(&cfg.LogFormat, *logFormat)
	pollD, err := cfg.duration("poll", *poll, 30*time.Second)
	if err != nil {
		fatal(err)
	}
	probeD, err := cfg.duration("probe", *probeIv, 60*time.Second)
	if err != nil {
		fatal(err)
	}
	staleD, err := cfg.duration("staleness", *staleness, 5*time.Minute)
	if err != nil {
		fatal(err)
	}
	if cfg.Listen == "" {
		cfg.Listen = "127.0.0.1:8100"
	}
	if cfg.MemberID == "" || cfg.Registry == "" || cfg.RegistryPubFile == "" || cfg.DataDir == "" {
		fmt.Fprintln(os.Stderr, "wreath-agent: member_id, registry, registry_pub_file, and data_dir are required (via -config or flags)")
		flag.Usage()
		os.Exit(1)
	}

	log, err := buildLogger(cfg.LogLevel, cfg.LogFormat)
	if err != nil {
		fatal(err)
	}
	slog.SetDefault(log)

	pub, err := keyfile.LoadPublic(cfg.RegistryPubFile)
	if err != nil {
		fatal(err)
	}

	var tlsProvider agent.TLSProvider
	if len(cfg.TLSDomains) > 0 {
		tlsProvider = newCertmagicTLS(cfg.TLSDomains, cfg.ACMEEmail, log)
		log.Info("tls: managing certificates", "domains", cfg.TLSDomains)
	}

	a, err := agent.New(agent.Config{
		MemberID:      cfg.MemberID,
		RegistryPath:  cfg.Registry,
		RegistryPub:   pub,
		DataDir:       cfg.DataDir,
		Listen:        cfg.Listen,
		TLS:           tlsProvider,
		PollInterval:  pollD,
		ProbeInterval: probeD,
		Staleness:     staleD,
		Logger:        log,
	})
	if err != nil {
		fatal(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil {
		fatal(err)
	}
	log.Info("wreath-agent: shut down cleanly")
}

func fatal(err error) {
	fmt.Fprintf(os.Stderr, "wreath-agent: %v\n", err)
	os.Exit(1)
}

func overrideString(dst *string, flagVal string) {
	if flagVal != "" {
		*dst = flagVal
	}
}

func buildLogger(level, format string) (*slog.Logger, error) {
	var lv slog.Level
	switch level {
	case "", "info":
		lv = slog.LevelInfo
	case "debug":
		lv = slog.LevelDebug
	case "warn":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		return nil, fmt.Errorf("unknown log level %q", level)
	}
	opts := &slog.HandlerOptions{Level: lv}
	switch format {
	case "", "text":
		return slog.New(slog.NewTextHandler(os.Stderr, opts)), nil
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stderr, opts)), nil
	default:
		return nil, fmt.Errorf("unknown log format %q", format)
	}
}
