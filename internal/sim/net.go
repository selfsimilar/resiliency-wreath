package sim

import (
	"fmt"
	"net/http"
	"sync"
)

// PartitionTable simulates network partitions. Every simulated node
// (agents AND their origins) registers its host:port; each agent's HTTP
// client gets a Transport bound to its node name, and a request is
// dropped with a connection-style error when the two nodes are in
// different partition groups. Unknown hosts are always reachable.
//
// A partition is node-to-node (both the member's origin and its agent
// become unreachable from the other side) — that models a network
// split. A *dead origin* is a different failure (ToggleServer.SetDown)
// and can be combined with partitions freely.
type PartitionTable struct {
	mu         sync.RWMutex
	hostToNode map[string]string
	blocked    map[string]map[string]bool
}

func NewPartitionTable() *PartitionTable {
	return &PartitionTable{
		hostToNode: make(map[string]string),
		blocked:    make(map[string]map[string]bool),
	}
}

// RegisterHost maps a host:port to a node name.
func (pt *PartitionTable) RegisterHost(hostport, node string) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.hostToNode[hostport] = node
}

func (pt *PartitionTable) block(a, b string) {
	if pt.blocked[a] == nil {
		pt.blocked[a] = make(map[string]bool)
	}
	if pt.blocked[b] == nil {
		pt.blocked[b] = make(map[string]bool)
	}
	pt.blocked[a][b] = true
	pt.blocked[b][a] = true
}

// SetGroups partitions the ring into the given groups: traffic between
// different groups is blocked, traffic within a group flows. Replaces
// any previous partition.
func (pt *PartitionTable) SetGroups(groups ...[]string) {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.blocked = make(map[string]map[string]bool)
	for i := range groups {
		for j := i + 1; j < len(groups); j++ {
			for _, a := range groups[i] {
				for _, b := range groups[j] {
					pt.block(a, b)
				}
			}
		}
	}
}

// Heal removes all partitions.
func (pt *PartitionTable) Heal() {
	pt.mu.Lock()
	defer pt.mu.Unlock()
	pt.blocked = make(map[string]map[string]bool)
}

// Allowed reports whether traffic from node may reach hostport.
func (pt *PartitionTable) Allowed(from, hostport string) bool {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	to, ok := pt.hostToNode[hostport]
	if !ok {
		return true
	}
	return !pt.blocked[from][to]
}

// Transport returns a RoundTripper enforcing the table for one node.
func (pt *PartitionTable) Transport(from string) http.RoundTripper {
	return &partitionTransport{pt: pt, from: from}
}

type partitionTransport struct {
	pt   *PartitionTable
	from string
}

func (t *partitionTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.pt.Allowed(t.from, req.URL.Host) {
		return nil, fmt.Errorf("sim: partition drops %s -> %s", t.from, req.URL.Host)
	}
	return http.DefaultTransport.RoundTrip(req)
}
