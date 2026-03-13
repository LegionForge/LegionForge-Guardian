-- legionforge-guardian init.sql
-- Standalone schema for deploying Guardian without the full LegionForge framework.
--
-- When deployed ALONGSIDE LegionForge, do NOT run this file — LegionForge's own
-- migrations create these tables with the full schema including additional columns.
-- This file uses CREATE TABLE IF NOT EXISTS, so running it against a LegionForge
-- DB is safe (no-op on existing tables).
--
-- Run order: psql $GUARDIAN_DB_URL -f init.sql

CREATE TABLE IF NOT EXISTS tool_registry (
    tool_id         TEXT PRIMARY KEY,
    status          TEXT NOT NULL DEFAULT 'APPROVED'
                        CHECK (status IN ('APPROVED', 'REVOKED', 'PENDING')),
    description_hash TEXT,
    schema_hash     TEXT,
    entrypoint_hash TEXT,
    signature       TEXT,
    registered_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    approved_at     TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS tool_registry_status_idx ON tool_registry (status);

CREATE TABLE IF NOT EXISTS threat_rules (
    id          BIGSERIAL PRIMARY KEY,
    rule_id     TEXT UNIQUE NOT NULL,
    rule_type   TEXT NOT NULL,
    rule_def    JSONB NOT NULL DEFAULT '{}',
    status      TEXT NOT NULL DEFAULT 'APPROVED'
                    CHECK (status IN ('APPROVED', 'PENDING', 'REJECTED', 'EXPIRED')),
    approved_at TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS threat_rules_status_expires_idx
    ON threat_rules (status, expires_at);

CREATE TABLE IF NOT EXISTS agent_profiles (
    id           BIGSERIAL PRIMARY KEY,
    agent_id     TEXT NOT NULL,
    sequence     TEXT[] NOT NULL,
    registered_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS agent_profiles_agent_id_idx ON agent_profiles (agent_id);

CREATE TABLE IF NOT EXISTS threat_events (
    id          BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    agent_id    TEXT NOT NULL,
    run_id      TEXT NOT NULL,
    threat_type TEXT NOT NULL,
    confidence  FLOAT,
    raw_input   TEXT,
    action_taken TEXT NOT NULL,
    metadata    JSONB NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS threat_events_agent_id_idx ON threat_events (agent_id);
CREATE INDEX IF NOT EXISTS threat_events_threat_type_idx ON threat_events (threat_type);
CREATE INDEX IF NOT EXISTS threat_events_ts_idx ON threat_events (ts DESC);

CREATE TABLE IF NOT EXISTS audit_log (
    seq         BIGSERIAL PRIMARY KEY,
    ts          TIMESTAMPTZ NOT NULL DEFAULT now(),
    event_type  TEXT NOT NULL,
    agent_id    TEXT,
    payload     JSONB NOT NULL DEFAULT '{}',
    prev_hash   TEXT NOT NULL,
    row_hash    TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS audit_log_ts_idx ON audit_log (ts DESC);
CREATE INDEX IF NOT EXISTS audit_log_event_type_idx ON audit_log (event_type);

-- Canary tool: registered but should never be called by any legitimate agent.
-- A /check request for this tool_id is immediate evidence of a probing attack
-- or hallucinating model. Guardian logs a CANARY_TRIGGERED threat event.
INSERT INTO tool_registry (tool_id, status, description_hash, schema_hash, registered_at, approved_at)
VALUES (
    'guardian_canary',
    'APPROVED',
    'canary',
    'canary',
    NOW(),
    NOW()
) ON CONFLICT (tool_id) DO NOTHING;
