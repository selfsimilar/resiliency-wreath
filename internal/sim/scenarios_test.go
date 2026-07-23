package sim_test

// M4 acceptance: `go test ./...` runs every scenario green. The same
// scenarios run interactively via `ring-sim run -scenario=<name>`.

import (
	"testing"

	"github.com/selfsimilar/resiliency-ring/internal/sim"
)

func TestScenarios(t *testing.T) {
	for _, sc := range sim.All {
		t.Run(sc.Name, func(t *testing.T) {
			if err := sc.Run(testWriter{t}, false); err != nil {
				t.Fatalf("%s: %v", sc.Name, err)
			}
		})
	}
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Logf("%s", p)
	return len(p), nil
}
