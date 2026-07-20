package session

import (
	"testing"
	"time"
)

func TestGetCreatesAndReuses(t *testing.T) {
	m := NewManager("/work", 0)
	a := m.Get("s1")
	if a.ID != "s1" || a.Cwd() != "/work" {
		t.Fatalf("unexpected session: %+v", a)
	}
	if b := m.Get("s1"); b != a {
		t.Error("Get should return the same session instance for the same ID")
	}
	if m.Count() != 1 {
		t.Errorf("Count = %d, want 1", m.Count())
	}
}

func TestGetEmptyIDMapsToDefault(t *testing.T) {
	m := NewManager("/work", 0)
	if s := m.Get(""); s.ID != DefaultID {
		t.Errorf("empty ID → %q, want %q", s.ID, DefaultID)
	}
}

func TestChdirAndEnv(t *testing.T) {
	m := NewManager("/work", 0)
	s := m.Get("s")
	s.Chdir("/work/sub")
	if s.Cwd() != "/work/sub" {
		t.Errorf("Cwd = %q", s.Cwd())
	}
	s.SetEnv("FOO", "bar")
	if s.Env()["FOO"] != "bar" {
		t.Errorf("Env = %v", s.Env())
	}
	// Env returns a copy.
	s.Env()["FOO"] = "mutated"
	if s.Env()["FOO"] != "bar" {
		t.Error("Env() should return a copy")
	}
}

func TestReset(t *testing.T) {
	m := NewManager("/work", 0)
	s := m.Get("s")
	s.Chdir("/work/deep")
	s.SetEnv("X", "1")
	s2 := m.Reset("s")
	if s2 == s {
		t.Error("Reset should replace the session instance")
	}
	if s2.Cwd() != "/work" {
		t.Errorf("reset cwd = %q, want /work", s2.Cwd())
	}
	if len(s2.Env()) != 0 {
		t.Errorf("reset env not empty: %v", s2.Env())
	}
}

func TestListSorted(t *testing.T) {
	m := NewManager("/work", 0)
	m.Get("c")
	m.Get("a")
	m.Get("b")
	list := m.List()
	if len(list) != 3 || list[0].ID != "a" || list[1].ID != "b" || list[2].ID != "c" {
		t.Fatalf("List not sorted: %v", idsOf(list))
	}
}

func idsOf(ss []*Session) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.ID
	}
	return out
}

func TestGCReapsIdle(t *testing.T) {
	m := NewManager("/work", 10*time.Millisecond)
	s := m.Get("old")
	// Force the last-used timestamp into the past.
	s.mu.Lock()
	s.lastUsed = time.Now().Add(-time.Hour)
	s.mu.Unlock()
	m.gcOnce(time.Now())
	if m.Count() != 0 {
		t.Errorf("idle session not reaped; Count = %d", m.Count())
	}
}

func TestGCKeepsFresh(t *testing.T) {
	m := NewManager("/work", time.Hour)
	m.Get("fresh")
	m.gcOnce(time.Now())
	if m.Count() != 1 {
		t.Errorf("fresh session reaped; Count = %d", m.Count())
	}
}

func TestActiveShells(t *testing.T) {
	m := NewManager("/work", 0)
	m.Get("a")
	m.Get("b")
	// No background shells started, so the aggregate is zero.
	if got := m.ActiveShells(); got != 0 {
		t.Errorf("ActiveShells = %d, want 0", got)
	}
}
