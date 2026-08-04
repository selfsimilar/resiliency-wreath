// Copyright 2026 The Resiliency Wreath Authors
// SPDX-License-Identifier: Apache-2.0

// Command wreath-sim drives the simulated multi-member wreath: the demo and
// the protocol test bed (KICKOFF M4). Scenarios are the same code paths
// `go test ./internal/sim` asserts on; here they stream a readable
// event log.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/selfsimilar/resiliency-wreath/internal/demo"
	"github.com/selfsimilar/resiliency-wreath/internal/sim"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "list":
		for _, sc := range sim.All {
			fmt.Printf("  %-14s %s\n", sc.Name, sc.Desc)
		}
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		name := fs.String("scenario", "all", "scenario name (see 'wreath-sim list') or 'all'")
		verbose := fs.Bool("v", false, "stream agent logs too")
		fs.Parse(os.Args[2:])
		if *name == "all" {
			failed := 0
			for _, sc := range sim.All {
				fmt.Printf("=== %s — %s\n", sc.Name, sc.Desc)
				if err := sc.Run(os.Stdout, *verbose); err != nil {
					fmt.Printf("FAIL %s: %v\n\n", sc.Name, err)
					failed++
					continue
				}
				fmt.Printf("PASS %s\n\n", sc.Name)
			}
			if failed > 0 {
				fmt.Printf("%d/%d scenarios failed\n", failed, len(sim.All))
				os.Exit(1)
			}
			fmt.Printf("all %d scenarios passed\n", len(sim.All))
		} else {
			sc := sim.Find(*name)
			if sc == nil {
				fmt.Fprintf(os.Stderr, "wreath-sim: unknown scenario %q (try 'wreath-sim list')\n", *name)
				os.Exit(1)
			}
			fmt.Printf("=== %s — %s\n", sc.Name, sc.Desc)
			if err := sc.Run(os.Stdout, *verbose); err != nil {
				fmt.Printf("FAIL: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("PASS")
		}
	case "demo":
		fs := flag.NewFlagSet("demo", flag.ExitOnError)
		membersFlag := fs.String("members", "alpha,bravo,charlie", "comma-separated member IDs (2..8)")
		listen := fs.String("listen", "127.0.0.1:8100", "dashboard listen address")
		poll := fs.Duration("poll", 2*time.Second, "agent bundle-poll interval")
		probe := fs.Duration("probe", 3*time.Second, "agent health-probe interval")
		staleness := fs.Duration("staleness", 20*time.Second, "freshness tolerance")
		chaos := fs.Bool("chaos", true, "swing members dark and back automatically")
		chaosGap := fs.Duration("chaos-gap", 30*time.Second, "quiet time between automatic outages")
		chaosOutage := fs.Duration("chaos-outage", 20*time.Second, "duration of an automatic outage")
		verbose := fs.Bool("v", false, "stream agent logs too")
		fs.Parse(os.Args[2:])
		var members []string
		for _, id := range strings.Split(*membersFlag, ",") {
			if id = strings.TrimSpace(id); id != "" {
				members = append(members, id)
			}
		}
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()
		if err := demo.Run(ctx, demo.Config{
			Members:     members,
			Listen:      *listen,
			Poll:        *poll,
			Probe:       *probe,
			Staleness:   *staleness,
			Chaos:       *chaos,
			ChaosGap:    *chaosGap,
			ChaosOutage: *chaosOutage,
			Verbose:     *verbose,
		}); err != nil {
			fmt.Fprintf(os.Stderr, "wreath-sim demo: %v\n", err)
			os.Exit(1)
		}
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `wreath-sim — simulated multi-member wreath

Usage:
  wreath-sim list                     show scenarios
  wreath-sim run -scenario=<name|all> [-v]
  wreath-sim demo [-members=a,b,c] [-listen=127.0.0.1:8100] [-chaos=false]
                long-running wreath with a web dashboard
`)
}
