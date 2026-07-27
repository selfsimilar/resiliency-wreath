// Copyright 2026 The Resiliency Ring Authors
// SPDX-License-Identifier: Apache-2.0

// Command ring-sim drives the simulated multi-member ring: the demo and
// the protocol test bed (KICKOFF M4). Scenarios are the same code paths
// `go test ./internal/sim` asserts on; here they stream a readable
// event log.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/selfsimilar/resiliency-ring/internal/sim"
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
		name := fs.String("scenario", "all", "scenario name (see 'ring-sim list') or 'all'")
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
				fmt.Fprintf(os.Stderr, "ring-sim: unknown scenario %q (try 'ring-sim list')\n", *name)
				os.Exit(1)
			}
			fmt.Printf("=== %s — %s\n", sc.Name, sc.Desc)
			if err := sc.Run(os.Stdout, *verbose); err != nil {
				fmt.Printf("FAIL: %v\n", err)
				os.Exit(1)
			}
			fmt.Println("PASS")
		}
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `ring-sim — simulated multi-member ring

Usage:
  ring-sim list                     show scenarios
  ring-sim run -scenario=<name|all> [-v]
`)
}
