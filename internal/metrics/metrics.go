// Package metrics exposes Prometheus metrics for the tunnel: invocations by
// tool/decision, tool latency, active background shells, active sessions,
// and elicitation latency.
package metrics

// Stub: full implementation replaces this file.
// Contract (frozen):
//
//	New(reg prometheus.Registerer, activeShells, activeSessions func() float64) *Metrics
//	(*Metrics).ObserveInvocation(tool, decision string, d time.Duration)
//	(*Metrics).ObserveElicitation(d time.Duration)
//	(*Metrics).Handler() http.Handler   — /metrics handler for the registry

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Metrics holds the tunnel's Prometheus instruments.
type Metrics struct{}

// New registers the tunnel metrics on reg. The gauge callbacks report live
// counts of background shells and sessions.
func New(reg prometheus.Registerer, activeShells, activeSessions func() float64) *Metrics {
	return &Metrics{}
}

func (m *Metrics) ObserveInvocation(tool, decision string, d time.Duration) {}
func (m *Metrics) ObserveElicitation(d time.Duration)                       {}
func (m *Metrics) Handler() http.Handler {
	return http.NotFoundHandler()
}
