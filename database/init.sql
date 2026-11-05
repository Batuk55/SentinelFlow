-- SentinelFlow schema. Runs automatically on first start of the Docker Postgres container.
-- The backend also calls SQLAlchemy create_all() on startup, which is a no-op for existing tables.

CREATE TABLE IF NOT EXISTS network_events (
    id                  BIGSERIAL PRIMARY KEY,
    source_ip           VARCHAR(45)  NOT NULL,
    destination_ip      VARCHAR(45)  NOT NULL,
    source_port         INTEGER CHECK (source_port BETWEEN 0 AND 65535),
    destination_port    INTEGER      NOT NULL CHECK (destination_port BETWEEN 0 AND 65535),
    protocol            VARCHAR(10)  NOT NULL,
    event_type          VARCHAR(30)  NOT NULL,
    connection_status   VARCHAR(20)  NOT NULL,
    connection_attempts INTEGER      NOT NULL DEFAULT 1 CHECK (connection_attempts >= 1),
    event_timestamp     TIMESTAMPTZ  NOT NULL,
    created_at          TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_events_source_ip ON network_events (source_ip);
CREATE INDEX IF NOT EXISTS ix_events_timestamp ON network_events (event_timestamp);
CREATE INDEX IF NOT EXISTS ix_events_source_ts ON network_events (source_ip, event_timestamp);

CREATE TABLE IF NOT EXISTS incidents (
    id              BIGSERIAL PRIMARY KEY,
    threat_category VARCHAR(100) NOT NULL,
    detection_rule  VARCHAR(100) NOT NULL,
    source_ip       VARCHAR(45)  NOT NULL,
    severity        VARCHAR(10)  NOT NULL CHECK (severity IN ('Low','Medium','High','Critical')),
    description     TEXT         NOT NULL,
    evidence        JSONB        NOT NULL DEFAULT '{}'::jsonb,
    status          VARCHAR(20)  NOT NULL DEFAULT 'Open'
                    CHECK (status IN ('Open','Investigating','Resolved','False Positive')),
    detected_at     TIMESTAMPTZ  NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_incidents_severity ON incidents (severity);
CREATE INDEX IF NOT EXISTS ix_incidents_status ON incidents (status);
CREATE INDEX IF NOT EXISTS ix_incidents_source_rule ON incidents (source_ip, detection_rule);

CREATE TABLE IF NOT EXISTS investigation_notes (
    id          BIGSERIAL PRIMARY KEY,
    incident_id BIGINT       NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
    author      VARCHAR(100) NOT NULL DEFAULT 'analyst',
    note        TEXT         NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_notes_incident ON investigation_notes (incident_id);

CREATE TABLE IF NOT EXISTS audit_logs (
    id          BIGSERIAL PRIMARY KEY,
    incident_id BIGINT       REFERENCES incidents(id) ON DELETE SET NULL,
    action      VARCHAR(50)  NOT NULL,
    actor       VARCHAR(100) NOT NULL,
    details     JSONB        NOT NULL DEFAULT '{}'::jsonb,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS ix_audit_incident ON audit_logs (incident_id);
CREATE INDEX IF NOT EXISTS ix_audit_created ON audit_logs (created_at);

CREATE TABLE IF NOT EXISTS knowledge_documents (
    id            BIGSERIAL PRIMARY KEY,
    slug          VARCHAR(100) NOT NULL UNIQUE,
    title         VARCHAR(200) NOT NULL,
    category      VARCHAR(100) NOT NULL,
    content       TEXT         NOT NULL,
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    search_vector tsvector GENERATED ALWAYS AS (
        setweight(to_tsvector('english', coalesce(title, '')), 'A') ||
        setweight(to_tsvector('english', coalesce(category, '')), 'B') ||
        setweight(to_tsvector('english', coalesce(content, '')), 'C')
    ) STORED
);
CREATE INDEX IF NOT EXISTS ix_knowledge_search ON knowledge_documents USING GIN (search_vector);
