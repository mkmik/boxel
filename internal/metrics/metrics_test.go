package metrics

// The task spec suggested prometheus/testutil, but that package imports
// github.com/kylelemons/godebug/diff which has no go.sum entry in this
// module (and dependency changes are out of scope for this package). These
// tests make the equivalent assertions directly against Registry.Gather().

import (
	"io"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func gather(t *testing.T, reg *prometheus.Registry) map[string]*dto.MetricFamily {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	byName := make(map[string]*dto.MetricFamily, len(mfs))
	for _, mf := range mfs {
		byName[mf.GetName()] = mf
	}
	return byName
}

// counterValue returns the value of the counter sample whose label pairs
// match want exactly, failing the test if no such sample exists.
func counterValue(t *testing.T, mf *dto.MetricFamily, want map[string]string) float64 {
	t.Helper()
	for _, m := range mf.GetMetric() {
		labels := make(map[string]string, len(m.GetLabel()))
		for _, lp := range m.GetLabel() {
			labels[lp.GetName()] = lp.GetValue()
		}
		match := len(labels) == len(want)
		for k, v := range want {
			if labels[k] != v {
				match = false
			}
		}
		if match {
			return m.GetCounter().GetValue()
		}
	}
	t.Fatalf("no %s sample with labels %v", mf.GetName(), want)
	return 0
}

func TestObserveInvocation(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg, func() float64 { return 0 }, func() float64 { return 0 })

	m.ObserveInvocation("Bash", "allow", time.Second)

	mfs := gather(t, reg)

	inv, ok := mfs["boxel_invocations_total"]
	if !ok {
		t.Fatal("boxel_invocations_total not gathered")
	}
	if got := counterValue(t, inv, map[string]string{"tool": "Bash", "decision": "allow"}); got != 1 {
		t.Errorf("boxel_invocations_total{tool=Bash,decision=allow} = %v, want 1", got)
	}
	if got := len(inv.GetMetric()); got != 1 {
		t.Errorf("invocation counter children = %d, want 1", got)
	}

	dur, ok := mfs["boxel_tool_duration_seconds"]
	if !ok {
		t.Fatal("boxel_tool_duration_seconds not gathered")
	}
	if got := len(dur.GetMetric()); got != 1 {
		t.Fatalf("tool duration children = %d, want 1", got)
	}
	h := dur.GetMetric()[0].GetHistogram()
	if h.GetSampleCount() != 1 {
		t.Errorf("tool duration sample count = %d, want 1", h.GetSampleCount())
	}
	if h.GetSampleSum() != 1.0 {
		t.Errorf("tool duration sample sum = %v, want 1.0", h.GetSampleSum())
	}
}

func TestMetricNamesRegistered(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg, func() float64 { return 0 }, func() float64 { return 0 })
	// Vec metrics only appear in Gather output once they have children.
	m.ObserveInvocation("Read", "allow", 10*time.Millisecond)
	m.ObserveElicitation(time.Second)

	mfs := gather(t, reg)
	for _, want := range []string{
		"boxel_invocations_total",
		"boxel_tool_duration_seconds",
		"boxel_active_shells",
		"boxel_active_sessions",
		"boxel_elicitation_duration_seconds",
	} {
		if _, ok := mfs[want]; !ok {
			t.Errorf("metric %q not registered", want)
		}
	}
}

func TestGaugeCallbacksReflectChanges(t *testing.T) {
	reg := prometheus.NewRegistry()
	shells := 2.0
	sessions := 5.0
	New(reg, func() float64 { return shells }, func() float64 { return sessions })

	get := func(name string) float64 {
		t.Helper()
		mf, ok := gather(t, reg)[name]
		if !ok {
			t.Fatalf("metric %q not found", name)
		}
		return mf.GetMetric()[0].GetGauge().GetValue()
	}

	if got := get("boxel_active_shells"); got != 2 {
		t.Errorf("boxel_active_shells = %v, want 2", got)
	}
	if got := get("boxel_active_sessions"); got != 5 {
		t.Errorf("boxel_active_sessions = %v, want 5", got)
	}

	shells = 7
	sessions = 1
	if got := get("boxel_active_shells"); got != 7 {
		t.Errorf("boxel_active_shells after change = %v, want 7", got)
	}
	if got := get("boxel_active_sessions"); got != 1 {
		t.Errorf("boxel_active_sessions after change = %v, want 1", got)
	}
}

func TestHandlerServesRegistry(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg, func() float64 { return 3 }, func() float64 { return 0 })
	m.ObserveInvocation("Bash", "deny", 50*time.Millisecond)

	srv := httptest.NewServer(m.Handler())
	defer srv.Close()

	resp, err := srv.Client().Get(srv.URL)
	if err != nil {
		t.Fatalf("GET /metrics: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	text := string(body)
	if !strings.Contains(text, "boxel_invocations_total") {
		t.Errorf("exposition missing boxel_invocations_total:\n%s", text)
	}
	if !strings.Contains(text, `boxel_invocations_total{decision="deny",tool="Bash"} 1`) {
		t.Errorf("exposition missing counter sample:\n%s", text)
	}
	if !strings.Contains(text, "boxel_active_shells 3") {
		t.Errorf("exposition missing gauge value:\n%s", text)
	}
}

func TestObserveElicitation(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := New(reg, func() float64 { return 0 }, func() float64 { return 0 })

	m.ObserveElicitation(2 * time.Second)

	mf, ok := gather(t, reg)["boxel_elicitation_duration_seconds"]
	if !ok {
		t.Fatal("boxel_elicitation_duration_seconds not gathered")
	}
	h := mf.GetMetric()[0].GetHistogram()
	if h.GetSampleCount() != 1 {
		t.Errorf("elicitation sample count = %d, want 1", h.GetSampleCount())
	}
	if h.GetSampleSum() != 2.0 {
		t.Errorf("elicitation sample sum = %v, want 2.0", h.GetSampleSum())
	}
	// ExponentialBuckets(0.1, 2, 12) covers ~0.1s through ~5min.
	if got := len(h.GetBucket()); got != 12 {
		t.Errorf("elicitation bucket count = %d, want 12", got)
	}
}
