// Copyright 2026 The Resiliency Wreath Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// fileConfig mirrors the JSON config file. All fields optional; flags
// override. Durations are Go duration strings ("30s", "5m").
type fileConfig struct {
	MemberID        string   `json:"member_id"`
	Registry        string   `json:"registry"`
	RegistryPubFile string   `json:"registry_pub_file"`
	DataDir         string   `json:"data_dir"`
	Listen          string   `json:"listen"`
	Poll            string   `json:"poll"`
	Probe           string   `json:"probe"`
	Staleness       string   `json:"staleness"`
	TLSDomains      []string `json:"tls_domains"`
	ACMEEmail       string   `json:"acme_email"`
	LogLevel        string   `json:"log_level"`
	LogFormat       string   `json:"log_format"`
}

func loadConfig(path string) (*fileConfig, error) {
	cfg := &fileConfig{}
	if path == "" {
		return cfg, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields() // typos in config files should fail loudly
	if err := dec.Decode(cfg); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	return cfg, nil
}

// duration resolves one interval: explicit flag > config file > default.
func (c *fileConfig) duration(name string, flagVal time.Duration, def time.Duration) (time.Duration, error) {
	if flagVal > 0 {
		return flagVal, nil
	}
	var raw string
	switch name {
	case "poll":
		raw = c.Poll
	case "probe":
		raw = c.Probe
	case "staleness":
		raw = c.Staleness
	}
	if raw == "" {
		return def, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("config %s: %w", name, err)
	}
	return d, nil
}
