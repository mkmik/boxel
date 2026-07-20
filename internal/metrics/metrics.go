// Package metrics exposes Prometheus metrics for the tunnel: invocations by
// tool/decision, tool latency, active background shells, active sessions,
// and elicitation latency.
package metrics

import (
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Metrics holds the tunnel's Prometheus instruments.
type Metrics struct {
	invocations  *prometheus.CounterVec
	toolDuration *prometheus.HistogramVec
	elicitation  prometheus.Histogram

	// gatherer is reg when it also implements prometheus.Gatherer (true for
	// *prometheus.Registry); Handler serves it. Nil otherwise.
	gatherer prometheus.Gatherer
}

// New registers the tunnel metrics on reg. The gauge callbacks report live
// counts of background shells and sessions.
func New(reg prometheus.Registerer, activeShells, activeSessions func() float64) *Metrics {
	m := &Metrics{
		invocations: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "boxel_invocations_total",
			Help: "Tunneled tool invocations by tool and permission decision.",
		}, []string{"tool", "decision"}),
		toolDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "boxel_tool_duration_seconds",
			Help:    "Tool invocation latency in seconds.",
			Buckets: prometheus.DefBuckets,
		}, []string{"tool"}),
		elicitation: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name: "boxel_elicitation_duration_seconds",
			Help: "Time waiting for user approval of an elicitation.",
			// Covers ~0.1s through ~5min (0.1 * 2^11 = 204.8s).
			Buckets: prometheus.ExponentialBuckets(0.1, 2, 12),
		}),
	}

	shells := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "boxel_active_shells",
		Help: "Number of active background shells.",
	}, activeShells)
	sessions := prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name: "boxel_active_sessions",
		Help: "Number of active sessions.",
	}, activeSessions)

	reg.MustRegister(m.invocations, m.toolDuration, m.elicitation, shells, sessions)

	if g, ok := reg.(prometheus.Gatherer); ok {
		m.gatherer = g
	}
	return m
}

// ObserveInvocation records one tool invocation with its permission decision
// and duration.
func (m *Metrics) ObserveInvocation(tool, decision string, d time.Duration) {
	m.invocations.WithLabelValues(tool, decision).Inc()
	m.toolDuration.WithLabelValues(tool).Observe(d.Seconds())
}

// ObserveElicitation records how long a user approval took.
func (m *Metrics) ObserveElicitation(d time.Duration) {
	m.elicitation.Observe(d.Seconds())
}

// Handler returns the /metrics handler for the registry passed to New. If
// that registry was not also a Gatherer, it falls back to the default
// Prometheus handler.
func (m *Metrics) Handler() http.Handler {
	if m.gatherer != nil {
		return promhttp.HandlerFor(m.gatherer, promhttp.HandlerOpts{})
	}
	return promhttp.Handler()
}
