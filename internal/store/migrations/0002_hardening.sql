-- 0002: hardening after the security review.

-- Bounds on the paths that used to bypass max_runs: green-light rounds and
-- passes lost to an exhausted seat. age_from restarts the age limit when a
-- human resumes an incident ('' = opened_at).
ALTER TABLE incidents ADD COLUMN green_lights INTEGER NOT NULL DEFAULT 0;
ALTER TABLE incidents ADD COLUMN quota_runs INTEGER NOT NULL DEFAULT 0;
ALTER TABLE incidents ADD COLUMN age_from TEXT NOT NULL DEFAULT '';

-- Every green-light ticket ever accepted on an incident. A ticket belongs to
-- one incident for ever: it can be neither presented twice nor taken over.
CREATE TABLE tickets (
  ticket      TEXT PRIMARY KEY,
  incident_id TEXT NOT NULL,
  at          TEXT NOT NULL
);
CREATE INDEX tickets_incident ON tickets(incident_id);

-- Effects the core owes after a state transition. A row is written in the
-- transaction of the transition and marked done only once the effect
-- succeeded; the daemon drains the table, also at start-up.
--   kind 'transition': what a lifecycle step owes (merge requests, known
--                      problem, alerts); payload = incident.Owed, progress =
--                      the steps already done
--   kind 'alert':      one alert or notice to deliver; payload = model.Alert
CREATE TABLE outbox (
  id         INTEGER PRIMARY KEY,
  kind       TEXT NOT NULL,
  project    TEXT NOT NULL DEFAULT '',
  incident   TEXT NOT NULL DEFAULT '',
  payload    TEXT NOT NULL DEFAULT '{}',
  progress   TEXT NOT NULL DEFAULT '',
  state      TEXT NOT NULL DEFAULT 'pending', -- pending | done | dropped
  attempts   INTEGER NOT NULL DEFAULT 0,
  next_at    TEXT NOT NULL DEFAULT '',
  last_error TEXT NOT NULL DEFAULT '',
  created_at TEXT NOT NULL,
  done_at    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX outbox_pending ON outbox(state, kind, next_at, id);
CREATE INDEX outbox_incident ON outbox(incident, kind, state);

-- Configuration proposals are de-duplicated per project + family.
ALTER TABLE proposals ADD COLUMN family TEXT NOT NULL DEFAULT '';
