// Package store is the SQLite persistence of DutyDesk: signals, incidents,
// runs, known problems, alerts, proposals, seat state and a small key/value
// table. A Store is safe for concurrent use. Every timestamp is written as a
// UTC RFC3339 string (second precision) and read from the injected clock, so
// tests are deterministic.
package store

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	_ "modernc.org/sqlite" // pure Go driver, registered as "sqlite"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

var (
	// ErrNotFound is returned when a row addressed by its key does not exist.
	ErrNotFound = errors.New("store: not found")
	// ErrStateConflict is returned when an incident is not in one of the
	// states a transition expects (somebody else moved it first).
	ErrStateConflict = errors.New("store: incident is not in the expected state")
	// ErrDuplicateOpen is returned by CreateIncident when an open incident
	// already exists for the same project and fingerprint.
	ErrDuplicateOpen = errors.New("store: an open incident already exists for this fingerprint")
)

// Store wraps the database. Build it with Open.
type Store struct {
	db  *sql.DB
	now func() time.Time
}

// Open opens (and creates if needed) the database at path, applies the
// pending migrations and returns the store. now is the clock; nil means
// time.Now.
func Open(path string, now func() time.Time) (*Store, error) {
	if now == nil {
		now = time.Now
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	// Create the file ourselves so it is never world-readable; the WAL and
	// SHM files inherit the mode of the main database file.
	f, err := os.OpenFile(abs, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	if err := f.Close(); err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	q := url.Values{}
	q.Add("_pragma", "busy_timeout(10000)")
	q.Add("_pragma", "journal_mode(WAL)")
	q.Add("_pragma", "synchronous(NORMAL)")
	q.Add("_pragma", "foreign_keys(1)")
	// Write transactions take the write lock up front: no deadlock on a
	// read-to-write upgrade, the busy timeout does the queueing.
	q.Set("_txlock", "immediate")
	dsn := (&url.URL{Scheme: "file", Path: abs, RawQuery: q.Encode()}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: %w", err)
	}
	s := &Store{db: db, now: now}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Close closes the database.
func (s *Store) Close() error { return s.db.Close() }

// SchemaVersion returns the highest applied migration.
func (s *Store) SchemaVersion() (int, error) {
	var v int
	err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&v)
	return v, err
}

type migration struct {
	version int
	name    string
	sql     string
}

func loadMigrations() ([]migration, error) {
	names, err := fs.Glob(migrationsFS, "migrations/*.sql")
	if err != nil {
		return nil, err
	}
	var out []migration
	for _, n := range names {
		base := filepath.Base(n)
		prefix, _, ok := strings.Cut(base, "_")
		if !ok {
			return nil, fmt.Errorf("store: migration %q: want NNNN_name.sql", base)
		}
		v, err := strconv.Atoi(prefix)
		if err != nil || v <= 0 {
			return nil, fmt.Errorf("store: migration %q: bad version", base)
		}
		b, err := migrationsFS.ReadFile(n)
		if err != nil {
			return nil, err
		}
		out = append(out, migration{version: v, name: base, sql: string(b)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].version < out[j].version })
	for i := 1; i < len(out); i++ {
		if out[i].version == out[i-1].version {
			return nil, fmt.Errorf("store: duplicate migration version %d", out[i].version)
		}
	}
	return out, nil
}

func (s *Store) migrate() error {
	migs, err := loadMigrations()
	if err != nil {
		return err
	}
	if _, err := s.db.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (
		version INTEGER PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT NOT NULL)`); err != nil {
		return fmt.Errorf("store: migrations table: %w", err)
	}
	for _, m := range migs {
		err := s.tx(func(tx *sql.Tx) error {
			var n int
			if err := tx.QueryRow(`SELECT COUNT(*) FROM schema_migrations WHERE version = ?`, m.version).Scan(&n); err != nil {
				return err
			}
			if n > 0 {
				return nil
			}
			if _, err := tx.Exec(m.sql); err != nil {
				return err
			}
			_, err := tx.Exec(`INSERT INTO schema_migrations(version, name, applied_at) VALUES (?, ?, ?)`,
				m.version, m.name, fmtTime(s.now()))
			return err
		})
		if err != nil {
			return fmt.Errorf("store: migration %s: %w", m.name, err)
		}
	}
	var max int
	if err := s.db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_migrations`).Scan(&max); err != nil {
		return err
	}
	if len(migs) > 0 && max > migs[len(migs)-1].version {
		return fmt.Errorf("store: database schema %d is newer than this binary (%d)", max, migs[len(migs)-1].version)
	}
	return nil
}

// tx runs fn in a write transaction, committing when it returns nil.
func (s *Store) tx(fn func(tx *sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if err := fn(tx); err != nil {
		_ = tx.Rollback()
		return err
	}
	return tx.Commit()
}

// fmtTime renders t as UTC RFC3339; the zero time is the empty string.
func fmtTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

func parseTime(v string) time.Time {
	if v == "" {
		return time.Time{}
	}
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return time.Time{}
	}
	return t.UTC()
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// placeholders returns "?,?,?" for n values.
func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}

// ---------- seat state ----------

// SeatExhaustedUntil returns when the seat becomes usable again; the zero
// time means the seat is not marked exhausted.
func (s *Store) SeatExhaustedUntil(seat string) (time.Time, error) {
	var v string
	err := s.db.QueryRow(`SELECT exhausted_until FROM seat_state WHERE seat = ?`, seat).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	return parseTime(v), err
}

// SetSeatExhausted marks the seat unusable until the given time; the zero
// time clears the mark.
func (s *Store) SetSeatExhausted(seat string, until time.Time) error {
	_, err := s.db.Exec(`INSERT INTO seat_state(seat, exhausted_until) VALUES (?, ?)
		ON CONFLICT(seat) DO UPDATE SET exhausted_until = excluded.exhausted_until`, seat, fmtTime(until))
	return err
}

// ---------- kv ----------

// GetKV returns the value stored under key and whether it exists.
func (s *Store) GetKV(key string) (string, bool, error) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM kv WHERE key = ?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", false, nil
	}
	return v, err == nil, err
}

// SetKV stores value under key.
func (s *Store) SetKV(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO kv(key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value`, key, value)
	return err
}

// DeleteKV removes key; a missing key is not an error.
func (s *Store) DeleteKV(key string) error {
	_, err := s.db.Exec(`DELETE FROM kv WHERE key = ?`, key)
	return err
}
