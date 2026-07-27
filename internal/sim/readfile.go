// Copyright 2026 The Resiliency Ring Authors
// SPDX-License-Identifier: Apache-2.0

package sim

import "os"

func readFile(p string) ([]byte, error) { return os.ReadFile(p) }
