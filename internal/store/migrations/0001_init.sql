-- 0001: initial schema. All times are UTC RFC3339 strings, '' = unset.

CREATE TABLE incidents (
  seq            INTEGER PRIMARY KEY,
  id             TEXT NOT NULL UNIQUE,
  project        TEXT NOT NULL,
  source         TEXT NOT NULL,
  fingerprint    TEXT NOT NULL,
  family         TEXT NOT NULL DEFAULT '',
  severity       INTEGER NOT NULL,
  summary        TEXT NOT NULL DEFAULT '',
  state          TEXT NOT NULL,
  mass           INTEGER NOT NULL DEFAULT 0,
  recurrent      INTEGER NOT NULL DEFAULT 0,
  runbook        TEXT NOT NULL DEFAULT '',
  signal_count   INTEGER NOT NULL DEFAULT 0,
  runs           INTEGER NOT NULL DEFAULT 0,
  failures       INTEGER NOT NULL DEFAULT 0,
  agent_token    TEXT NOT NULL DEFAULT '',
  ticket         TEXT NOT NULL DEFAULT '',
  recheck_at     TEXT NOT NULL DEFAULT '',
  opened_at      TEXT NOT NULL,
  updated_at     TEXT NOT NULL,
  closed_at      TEXT NOT NULL DEFAULT '',
  last_alert_at  TEXT NOT NULL DEFAULT '',
  close_reason   TEXT NOT NULL DEFAULT '',
  last_signal_at TEXT NOT NULL DEFAULT '',
  state_since    TEXT NOT NULL DEFAULT ''
);
-- At most one open incident per project + fingerprint (dedup backstop).
CREATE UNIQUE INDEX incidents_open_fp ON incidents(project, fingerprint) WHERE state <> 'resolved';
CREATE INDEX incidents_queue ON incidents(state, severity, opened_at);
CREATE INDEX incidents_family ON incidents(project, family, state, closed_at);
CREATE INDEX incidents_source ON incidents(project, source, state);

CREATE TABLE signals (
  id          INTEGER PRIMARY KEY,
  incident_id TEXT REFERENCES incidents(id),
  project     TEXT NOT NULL,
  source      TEXT NOT NULL,
  fingerprint TEXT NOT NULL,
  severity    INTEGER NOT NULL,
  summary     TEXT NOT NULL DEFAULT '',
  fields      TEXT NOT NULL DEFAULT '{}',
  at          TEXT NOT NULL
);
CREATE INDEX signals_incident ON signals(incident_id, id);

CREATE TABLE runs (
  id          INTEGER PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incidents(id),
  seat        TEXT NOT NULL DEFAULT '',
  started_at  TEXT NOT NULL,
  ended_at    TEXT NOT NULL DEFAULT '',
  status      TEXT NOT NULL DEFAULT '', -- '' while running
  verdict     TEXT NOT NULL DEFAULT '', -- JSON
  error       TEXT NOT NULL DEFAULT '',
  cost_usd    REAL NOT NULL DEFAULT 0,
  turns       INTEGER NOT NULL DEFAULT 0,
  input_tok   INTEGER NOT NULL DEFAULT 0,
  output_tok  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX runs_incident ON runs(incident_id, id);
CREATE INDEX runs_seat ON runs(seat, started_at);

CREATE TABLE actions (
  id          INTEGER PRIMARY KEY,
  incident_id TEXT NOT NULL REFERENCES incidents(id),
  run_id      INTEGER NOT NULL DEFAULT 0,
  name        TEXT NOT NULL,
  at          TEXT NOT NULL
);
CREATE INDEX actions_incident ON actions(incident_id, id);

CREATE TABLE known_problems (
  id        INTEGER PRIMARY KEY,
  project   TEXT NOT NULL,
  family    TEXT NOT NULL,
  repo      TEXT NOT NULL DEFAULT '',
  mr_url    TEXT NOT NULL DEFAULT '',
  mr_id     TEXT NOT NULL DEFAULT '',
  incident  TEXT NOT NULL DEFAULT '',
  opened_at TEXT NOT NULL,
  closed_at TEXT NOT NULL DEFAULT ''
);
CREATE INDEX known_problems_family ON known_problems(project, family, closed_at);

CREATE TABLE alerts (
  id       INTEGER PRIMARY KEY,
  kind     TEXT NOT NULL,
  project  TEXT NOT NULL DEFAULT '',
  incident TEXT NOT NULL DEFAULT '',
  title    TEXT NOT NULL DEFAULT '',
  body     TEXT NOT NULL DEFAULT '',
  url      TEXT NOT NULL DEFAULT '',
  at       TEXT NOT NULL
);
CREATE INDEX alerts_incident ON alerts(incident, kind, id);
CREATE INDEX alerts_project ON alerts(project, kind, id);

CREATE TABLE proposals (
  id         INTEGER PRIMARY KEY,
  project    TEXT NOT NULL,
  incident   TEXT NOT NULL DEFAULT '',
  kind       TEXT NOT NULL, -- improvement | missing_action
  title      TEXT NOT NULL DEFAULT '',
  mr_url     TEXT NOT NULL DEFAULT '',
  mr_id      TEXT NOT NULL DEFAULT '',
  state      TEXT NOT NULL DEFAULT 'open',
  created_at TEXT NOT NULL
);
CREATE INDEX proposals_project ON proposals(project, id);

CREATE TABLE seat_state (
  seat            TEXT PRIMARY KEY,
  exhausted_until TEXT NOT NULL DEFAULT ''
);

CREATE TABLE kv (
  key   TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
