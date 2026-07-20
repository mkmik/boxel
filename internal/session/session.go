// Package session manages logical tunnel sessions. A session owns a working
// directory, environment overrides, a background shell table, and a
// session-scoped permission overlay. Idle sessions are garbage-collected
// after a TTL; their background shells are killed on GC.
package session

import (
	"context"
	"sort"
	"sync"
	"time"

	"github.com/mkmik/boxel/internal/policy"
	"github.com/mkmik/boxel/internal/shellmgr"
)

// DefaultID is the session used when the client passes no session ID.
const DefaultID = "default"

// Session is a logical tunnel session.
type Session struct {
	ID string
	// Shells is the background shell table owned by this session.
	Shells *shellmgr.Table
	// Overlay accumulates session-scoped "allow always" rules.
	Overlay *policy.Overlay

	mu       sync.Mutex
	cwd      string
	env      map[string]string
	created  time.Time
	lastUsed time.Time
}

// Cwd returns the session's current working directory.
func (s *Session) Cwd() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.cwd
}

// Chdir updates the session's working directory.
func (s *Session) Chdir(dir string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.cwd = dir
}

// Env returns a copy of the session's environment overrides.
func (s *Session) Env() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]string, len(s.env))
	for k, v := range s.env {
		out[k] = v
	}
	return out
}

// SetEnv sets an environment override for subsequent Bash calls.
func (s *Session) SetEnv(key, value string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.env[key] = value
}

// Touch marks the session as recently used.
func (s *Session) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastUsed = time.Now()
}

// LastUsed returns the last-use timestamp.
func (s *Session) LastUsed() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastUsed
}

// Created returns the creation timestamp.
func (s *Session) Created() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.created
}

// Manager creates, tracks and garbage-collects sessions.
type Manager struct {
	mu         sync.Mutex
	sessions   map[string]*Session
	defaultCwd string
	ttl        time.Duration
}

// NewManager returns a manager whose sessions start in defaultCwd and are
// GC'd after ttl of inactivity (0 disables GC).
func NewManager(defaultCwd string, ttl time.Duration) *Manager {
	return &Manager{
		sessions:   make(map[string]*Session),
		defaultCwd: defaultCwd,
		ttl:        ttl,
	}
}

func (m *Manager) newSession(id string) *Session {
	now := time.Now()
	return &Session{
		ID:       id,
		Shells:   shellmgr.NewTable(),
		Overlay:  policy.NewOverlay(),
		cwd:      m.defaultCwd,
		env:      make(map[string]string),
		created:  now,
		lastUsed: now,
	}
}

// Get returns the session with the given ID, creating it if absent.
// An empty ID maps to DefaultID.
func (m *Manager) Get(id string) *Session {
	if id == "" {
		id = DefaultID
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s, ok := m.sessions[id]
	if !ok {
		s = m.newSession(id)
		m.sessions[id] = s
	}
	s.Touch()
	return s
}

// List returns all live sessions sorted by ID.
func (m *Manager) List() []*Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// Count returns the number of live sessions.
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.sessions)
}

// Reset kills the session's background shells and replaces it with a fresh
// session (same ID, default cwd, empty overlay).
func (m *Manager) Reset(id string) *Session {
	if id == "" {
		id = DefaultID
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.sessions[id]; ok {
		old.Shells.KillAll()
	}
	s := m.newSession(id)
	m.sessions[id] = s
	return s
}

// ActiveShells returns the total number of running background shells across
// all sessions (for metrics).
func (m *Manager) ActiveShells() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, s := range m.sessions {
		n += s.Shells.ActiveCount()
	}
	return n
}

// StartGC launches a goroutine that reaps idle sessions until ctx is done.
func (m *Manager) StartGC(ctx context.Context, interval time.Duration) {
	if m.ttl <= 0 {
		return
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.gcOnce(time.Now())
			}
		}
	}()
}

func (m *Manager) gcOnce(now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.sessions {
		if now.Sub(s.LastUsed()) > m.ttl {
			s.Shells.KillAll()
			delete(m.sessions, id)
		}
	}
}
