-- =============================================================================
-- Power BI Embedded portal — initial schema
--
-- Design notes:
--  * A user reaches a report via a role grant OR a direct user grant (union).
--  * RLS role names in Power BI are decoupled from portal role names via
--    rls_role_mappings, because the two naming schemes always drift.
--  * user_rls_attributes carries values consumed by dynamic DAX (region, etc.)
--    and is what keeps Postgres and the model's mapping table in sync.
-- =============================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;     -- case-insensitive email

-- ---------------------------------------------------------------- users ----
CREATE TABLE users (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email               CITEXT      NOT NULL UNIQUE,
    -- Argon2id hash. NULL when the user authenticates via Entra ID / SSO only.
    password_hash       TEXT,
    display_name        TEXT        NOT NULL,
    -- Entra ID object id (oid claim), set when AUTH_PROVIDER=entra.
    entra_object_id     TEXT UNIQUE,
    department          TEXT,
    -- The string handed to Power BI as identities[].username, i.e. what
    -- USERPRINCIPALNAME() returns inside the dataset's DAX. Defaults to email
    -- (see trigger below) but can be overridden when the model keys on
    -- something else (employee number, a synthetic principal, ...).
    effective_username  TEXT,
    is_active           BOOLEAN     NOT NULL DEFAULT TRUE,
    last_login_at       TIMESTAMPTZ,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now(),

    -- A user must be able to authenticate somehow.
    CONSTRAINT users_auth_method_present
        CHECK (password_hash IS NOT NULL OR entra_object_id IS NOT NULL)
);

CREATE INDEX users_active_idx     ON users (is_active) WHERE is_active;
CREATE INDEX users_department_idx ON users (department);

-- ---------------------------------------------------------------- roles ----
CREATE TABLE roles (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Portal-side role key, e.g. 'sales_manager'. Lowercase snake_case.
    name        TEXT        NOT NULL UNIQUE,
    description TEXT,
    -- Portal administrators; grants access to /api/admin/*.
    is_admin    BOOLEAN     NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT roles_name_format CHECK (name ~ '^[a-z][a-z0-9_]{1,63}$')
);

CREATE TABLE user_roles (
    user_id     UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    role_id     UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    granted_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    granted_by  UUID REFERENCES users (id) ON DELETE SET NULL,
    PRIMARY KEY (user_id, role_id)
);

CREATE INDEX user_roles_role_idx ON user_roles (role_id);

-- ------------------------------------------------------------- reports ----
CREATE TABLE reports (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    -- Display metadata (safe to send to the browser).
    name              TEXT        NOT NULL,
    slug              TEXT        NOT NULL UNIQUE,
    description       TEXT,
    category          TEXT,

    -- Power BI coordinates. Never sent to the browser except via /api/embed,
    -- and only after the authorization check passes.
    workspace_id      UUID        NOT NULL,   -- Power BI group id
    pbi_report_id     UUID        NOT NULL,
    -- Optional: resolved from the Power BI API at embed time when NULL.
    -- Storing it saves one REST round-trip per cache miss.
    pbi_dataset_id    UUID,

    -- FAIL-CLOSED FLAG. When true, embed.service refuses to mint a token if
    -- identity resolution yields zero RLS roles. Leave TRUE unless the dataset
    -- genuinely has no RLS roles defined (Power BI rejects identities then).
    rls_required      BOOLEAN     NOT NULL DEFAULT TRUE,

    -- Embed token lifetime request, capped by the AAD token's remaining life.
    token_lifetime_minutes INTEGER NOT NULL DEFAULT 60,

    is_active         BOOLEAN     NOT NULL DEFAULT TRUE,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT reports_slug_format CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
    CONSTRAINT reports_lifetime_range
        CHECK (token_lifetime_minutes BETWEEN 5 AND 60),
    -- One row per report per workspace.
    CONSTRAINT reports_pbi_unique UNIQUE (workspace_id, pbi_report_id)
);

CREATE INDEX reports_active_idx   ON reports (is_active) WHERE is_active;
CREATE INDEX reports_category_idx ON reports (category);

-- ------------------------------------------------- access grants (2 ways) --
-- (a) role-based: everyone with the role gets the report
CREATE TABLE report_role_access (
    report_id  UUID NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
    role_id    UUID NOT NULL REFERENCES roles (id)   ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (report_id, role_id)
);

CREATE INDEX report_role_access_role_idx ON report_role_access (role_id);

-- (b) direct: an exception for one person, optionally time-boxed
CREATE TABLE report_user_access (
    report_id  UUID NOT NULL REFERENCES reports (id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users (id)   ON DELETE CASCADE,
    granted_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    granted_by UUID REFERENCES users (id) ON DELETE SET NULL,
    -- NULL = permanent. Enforced in the access query, not by a constraint.
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (report_id, user_id)
);

CREATE INDEX report_user_access_user_idx ON report_user_access (user_id);

-- ------------------------------------------------------- RLS mapping ------
-- Portal role  ->  Power BI RLS role name, scoped to one dataset.
--
-- Scoped per dataset because the same portal role often maps to differently
-- named roles in different models ('sales_manager' -> 'RegionalManager' in the
-- sales model, -> 'Manager' in the finance model).
CREATE TABLE rls_role_mappings (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    role_id         UUID NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    pbi_dataset_id  UUID NOT NULL,
    -- EXACT role name as defined in Power BI Desktop → Manage roles.
    -- Case-sensitive; a mismatch silently yields an unfiltered or failed embed.
    pbi_role_name   TEXT NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),

    CONSTRAINT rls_role_mappings_unique
        UNIQUE (role_id, pbi_dataset_id, pbi_role_name)
);

CREATE INDEX rls_role_mappings_dataset_idx ON rls_role_mappings (pbi_dataset_id);

-- Per-user values consumed by dynamic DAX. These must match the model's
-- mapping table (see docs/AZURE_SETUP.md step 8) or the user sees zero rows.
CREATE TABLE user_rls_attributes (
    user_id     UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    -- e.g. 'region', 'cost_centre', 'customer_id'
    attr_key    TEXT NOT NULL,
    attr_value  TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (user_id, attr_key),

    CONSTRAINT user_rls_attributes_key_format CHECK (attr_key ~ '^[a-z][a-z0-9_]{1,63}$')
);

-- ------------------------------------------------------ refresh tokens ----
-- Rotating refresh tokens with reuse detection. Only the SHA-256 hash is
-- stored, so a database dump does not yield usable sessions.
CREATE TABLE refresh_tokens (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id      UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash   TEXT        NOT NULL UNIQUE,
    -- Groups all tokens descended from one login, so detecting reuse of any
    -- ancestor lets us revoke the entire family.
    family_id    UUID        NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    revoked_at   TIMESTAMPTZ,
    replaced_by  UUID REFERENCES refresh_tokens (id) ON DELETE SET NULL,
    user_agent   TEXT,
    ip_address   INET,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX refresh_tokens_user_idx   ON refresh_tokens (user_id);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens (family_id);
CREATE INDEX refresh_tokens_expiry_idx ON refresh_tokens (expires_at)
    WHERE revoked_at IS NULL;

-- ----------------------------------------------------------- audit log ----
-- Who saw which report, under which effective identity. Keep this: it is the
-- only record of what RLS context data was released under.
CREATE TABLE audit_log (
    id                 BIGSERIAL PRIMARY KEY,
    user_id            UUID REFERENCES users (id) ON DELETE SET NULL,
    action             TEXT NOT NULL,   -- login | login_failed | embed_token_issued | access_denied | ...
    report_id          UUID REFERENCES reports (id) ON DELETE SET NULL,
    -- Snapshot of the identity asserted to Power BI, for forensics.
    effective_username TEXT,
    rls_roles          TEXT[],
    detail             JSONB NOT NULL DEFAULT '{}'::jsonb,
    ip_address         INET,
    user_agent         TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX audit_log_user_time_idx   ON audit_log (user_id, created_at DESC);
CREATE INDEX audit_log_action_time_idx ON audit_log (action, created_at DESC);
CREATE INDEX audit_log_report_time_idx ON audit_log (report_id, created_at DESC);

-- ------------------------------------------------------------ triggers ----
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_updated_at   BEFORE UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();
CREATE TRIGGER reports_updated_at BEFORE UPDATE ON reports
    FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- Default effective_username to the email address.
CREATE OR REPLACE FUNCTION default_effective_username() RETURNS TRIGGER AS $$
BEGIN
    IF NEW.effective_username IS NULL THEN
        NEW.effective_username = NEW.email::text;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER users_default_effective_username BEFORE INSERT OR UPDATE ON users
    FOR EACH ROW EXECUTE FUNCTION default_effective_username();

-- --------------------------------------------------------------- view -----
-- Canonical "can this user see this report" resolution. Used by both the
-- report list and the embed authorization check, so the two can never diverge.
CREATE VIEW user_report_access AS
SELECT DISTINCT
    u.id            AS user_id,
    r.id            AS report_id,
    r.slug,
    r.name,
    r.description,
    r.category,
    r.workspace_id,
    r.pbi_report_id,
    r.pbi_dataset_id,
    r.rls_required,
    r.token_lifetime_minutes
FROM users u
JOIN reports r ON r.is_active
LEFT JOIN user_roles ur         ON ur.user_id = u.id
LEFT JOIN report_role_access ra ON ra.report_id = r.id AND ra.role_id = ur.role_id
LEFT JOIN report_user_access ua ON ua.report_id = r.id AND ua.user_id = u.id
                                AND (ua.expires_at IS NULL OR ua.expires_at > now())
WHERE u.is_active
  AND (ra.role_id IS NOT NULL OR ua.user_id IS NOT NULL);
