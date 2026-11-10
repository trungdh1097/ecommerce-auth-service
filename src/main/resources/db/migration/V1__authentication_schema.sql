CREATE TABLE users (
    id uuid PRIMARY KEY,
    username varchar(50) UNIQUE,
    email varchar(320) NOT NULL UNIQUE,
    password_hash text,
    email_verified boolean NOT NULL DEFAULT false,
    status varchar(32) NOT NULL CHECK (status IN ('PENDING_VERIFICATION', 'ACTIVE', 'DISABLED')),
    registration_expires_at timestamptz,
    auth_version bigint NOT NULL DEFAULT 0,
    revoked_before timestamptz,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    CHECK (status <> 'PENDING_VERIFICATION' OR registration_expires_at IS NOT NULL)
);
CREATE INDEX users_pending_expiry_idx ON users (registration_expires_at) WHERE status = 'PENDING_VERIFICATION';

CREATE TABLE external_identities (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id),
    provider varchar(32) NOT NULL,
    provider_subject varchar(255) NOT NULL,
    created_at timestamptz NOT NULL,
    updated_at timestamptz NOT NULL,
    UNIQUE (provider, provider_subject)
);

CREATE TABLE browser_contexts (
    id uuid PRIMARY KEY,
    secret_hash bytea NOT NULL UNIQUE,
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL
);

CREATE TABLE sessions (
    id uuid PRIMARY KEY,
    user_id uuid NOT NULL REFERENCES users(id),
    client_id varchar(100) NOT NULL,
    platform varchar(16) NOT NULL CHECK (platform IN ('WEB', 'ANDROID', 'IOS')),
    browser_context_id uuid REFERENCES browser_contexts(id),
    status varchar(16) NOT NULL CHECK (status IN ('ACTIVE', 'REVOKED', 'EXPIRED')),
    auth_version bigint NOT NULL,
    auth_time timestamptz NOT NULL,
    amr varchar(255) NOT NULL,
    device_label varchar(255),
    user_agent varchar(512),
    masked_ip varchar(64),
    created_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL,
    last_refresh_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    revoked_at timestamptz,
    revocation_reason varchar(100),
    CHECK ((platform = 'WEB' AND browser_context_id IS NOT NULL) OR (platform IN ('ANDROID', 'IOS') AND browser_context_id IS NULL))
);
CREATE UNIQUE INDEX sessions_one_web_user_idx ON sessions(user_id) WHERE status = 'ACTIVE' AND platform = 'WEB';
CREATE UNIQUE INDEX sessions_one_mobile_user_idx ON sessions(user_id) WHERE status = 'ACTIVE' AND platform IN ('ANDROID', 'IOS');
CREATE UNIQUE INDEX sessions_one_web_context_idx ON sessions(browser_context_id) WHERE status = 'ACTIVE' AND platform = 'WEB';
CREATE INDEX sessions_user_status_created_idx ON sessions(user_id, status, created_at, id);

CREATE TABLE refresh_tokens (
    id uuid PRIMARY KEY,
    session_id uuid NOT NULL REFERENCES sessions(id),
    family_id uuid NOT NULL,
    token_hash bytea NOT NULL UNIQUE,
    parent_id uuid REFERENCES refresh_tokens(id),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    revoked_at timestamptz
);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens(family_id);
CREATE INDEX refresh_tokens_session_idx ON refresh_tokens(session_id);

CREATE TABLE auth_challenges (
    id uuid PRIMARY KEY,
    purpose varchar(32) NOT NULL CHECK (purpose IN ('LOGIN_OTP', 'VERIFY_EMAIL', 'RESET_PASSWORD', 'GOOGLE_LOGIN', 'GOOGLE_LINK')),
    user_id uuid REFERENCES users(id),
    token_hash varchar(128) UNIQUE,
    browser_context_id uuid REFERENCES browser_contexts(id),
    binding_hash bytea,
    client_id varchar(100),
    session_id uuid REFERENCES sessions(id),
    nonce_hash bytea,
    auth_version bigint,
    generation integer NOT NULL DEFAULT 1 CHECK (generation > 0),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    expires_at timestamptz NOT NULL,
    consumed_at timestamptz,
    superseded_at timestamptz,
    created_at timestamptz NOT NULL,
    device_label varchar(100),
    user_agent varchar(256),
    masked_ip varchar(64),
    otp_mac bytea,
    last_sent_at timestamptz,
    device_id varchar(255),
    device_platform varchar(16)
);
CREATE INDEX auth_challenges_expiry_idx ON auth_challenges(expires_at);
CREATE INDEX auth_challenges_user_purpose_idx ON auth_challenges(user_id, purpose);

CREATE TABLE audit_events (
    id uuid PRIMARY KEY,
    event_type varchar(100) NOT NULL,
    user_id uuid REFERENCES users(id) ON DELETE SET NULL,
    session_correlation_hash bytea,
    result varchar(64) NOT NULL,
    trace_id varchar(100),
    metadata jsonb,
    created_at timestamptz NOT NULL
);
CREATE INDEX audit_events_created_idx ON audit_events(created_at);

CREATE TABLE notification_outbox (
    id uuid PRIMARY KEY,
    challenge_id uuid NOT NULL REFERENCES auth_challenges(id),
    purpose varchar(32) NOT NULL,
    generation integer NOT NULL,
    encrypted_payload bytea,
    key_id varchar(100) NOT NULL,
    expires_at timestamptz NOT NULL,
    status varchar(32) NOT NULL CHECK (status IN ('PENDING', 'PROCESSING', 'SENT', 'EXPIRED', 'FAILED')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL
);
CREATE INDEX notification_outbox_work_idx ON notification_outbox(status, next_attempt_at);

create table roles
(
    id          serial
        primary key,
    name        varchar(50) not null
        unique,
    description varchar(512),
    created_at  timestamp with time zone default CURRENT_TIMESTAMP
);

create table account_roles
(
    account_id uuid    not null
        constraint fk_user_roles_account
            references users
            on delete cascade,
    role_id    integer not null
        constraint fk_user_roles_role
            references roles
            on delete cascade,
    created_at timestamp with time zone default CURRENT_TIMESTAMP,
    primary key (account_id, role_id)
);

CREATE TABLE trusted_devices (
                                 id uuid PRIMARY KEY,
                                 user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                                 client_id varchar(100) NOT NULL,
                                 platform varchar(16) NOT NULL CHECK (platform IN ('WEB', 'ANDROID', 'IOS')),
                                 browser_context_id uuid REFERENCES browser_contexts(id) ON DELETE CASCADE,
                                 device_id varchar(255),
                                 secret_hash bytea,
                                 auth_version bigint NOT NULL,
                                 created_at timestamptz NOT NULL,
                                 expires_at timestamptz NOT NULL,
                                 CHECK ((platform = 'WEB' AND browser_context_id IS NOT NULL AND device_id IS NULL AND secret_hash IS NULL)
                                     OR (platform IN ('ANDROID', 'IOS') AND browser_context_id IS NULL AND device_id IS NOT NULL AND secret_hash IS NOT NULL))
);
CREATE UNIQUE INDEX trusted_devices_web_idx ON trusted_devices (user_id, client_id, browser_context_id) WHERE platform = 'WEB';
CREATE UNIQUE INDEX trusted_devices_mobile_idx ON trusted_devices (user_id, client_id, platform, device_id) WHERE platform IN ('ANDROID', 'IOS');
CREATE INDEX trusted_devices_expiry_idx ON trusted_devices (expires_at);

