-- SENTINEL database schema (PostgreSQL 14+).
-- Docker Compose loads this file on first start of the database container.
-- Phase 1 uses: threat_sources, indicators, observations.
-- The remaining tables are defined now so relationships are settled; they are used in later phases.

CREATE TABLE threat_sources (
    id          BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    name        VARCHAR(64) NOT NULL UNIQUE,
    feed_url    TEXT,
    reliability DOUBLE PRECISION NOT NULL DEFAULT 0.5 CHECK (reliability BETWEEN 0 AND 1),
    enabled     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE indicators (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    indicator_type    VARCHAR(16) NOT NULL CHECK (indicator_type IN ('ip', 'domain', 'url', 'hash')),
    value             TEXT NOT NULL,
    value_hash        CHAR(64) NOT NULL,          -- sha256 of the normalized value
    first_seen        TIMESTAMPTZ NOT NULL,
    last_seen         TIMESTAMPTZ NOT NULL,
    observation_count INTEGER NOT NULL DEFAULT 0,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_indicator_type_hash UNIQUE (indicator_type, value_hash)
);
CREATE INDEX ix_indicators_indicator_type ON indicators (indicator_type);
CREATE INDEX ix_indicators_last_seen ON indicators (last_seen DESC);

CREATE TABLE observations (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    indicator_id BIGINT NOT NULL REFERENCES indicators (id) ON DELETE CASCADE,
    source_id    BIGINT NOT NULL REFERENCES threat_sources (id),
    source_ref   VARCHAR(255) NOT NULL,           -- the feed's own id; makes ingestion idempotent
    observed_at  TIMESTAMPTZ NOT NULL,
    threat_type  VARCHAR(64),
    tags         JSONB NOT NULL DEFAULT '[]',
    details      JSONB NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT uq_observation_ref UNIQUE (indicator_id, source_id, source_ref)
);
CREATE INDEX ix_observations_indicator_id ON observations (indicator_id);
CREATE INDEX ix_observations_source_time ON observations (source_id, observed_at);

-- Phase 2: scoring history and analysis output
CREATE TABLE threat_scores (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    indicator_id  BIGINT NOT NULL REFERENCES indicators (id) ON DELETE CASCADE,
    score         SMALLINT NOT NULL CHECK (score BETWEEN 0 AND 100),
    confidence    DOUBLE PRECISION CHECK (confidence BETWEEN 0 AND 1),
    factors       JSONB NOT NULL DEFAULT '{}',    -- explainability: what contributed to the score
    model_version VARCHAR(32) NOT NULL,
    scored_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_threat_scores_indicator_time ON threat_scores (indicator_id, scored_at DESC);

CREATE TABLE analysis_results (
    id           BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    indicator_id BIGINT NOT NULL REFERENCES indicators (id) ON DELETE CASCADE,
    analyzer     VARCHAR(64) NOT NULL,
    severity     VARCHAR(16) CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    finding      JSONB NOT NULL DEFAULT '{}',
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX ix_analysis_results_indicator ON analysis_results (indicator_id);

-- Phase 3/4: accounts and alerting
CREATE TABLE users (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email         VARCHAR(255) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    role          VARCHAR(16) NOT NULL DEFAULT 'viewer' CHECK (role IN ('admin', 'analyst', 'viewer')),
    is_active     BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE alerts (
    id              BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    indicator_id    BIGINT REFERENCES indicators (id) ON DELETE SET NULL,
    severity        VARCHAR(16) NOT NULL CHECK (severity IN ('info', 'low', 'medium', 'high', 'critical')),
    title           TEXT NOT NULL,
    message         TEXT,
    status          VARCHAR(16) NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'closed')),
    acknowledged_by BIGINT REFERENCES users (id),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    acknowledged_at TIMESTAMPTZ
);
CREATE INDEX ix_alerts_status_time ON alerts (status, created_at DESC);
