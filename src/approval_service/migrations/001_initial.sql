CREATE TABLE approval_requests (
    operation_id text PRIMARY KEY,
    digest text NOT NULL,
    requester_hash text NOT NULL,
    person_id text NOT NULL,
    request_bytes bytea,
    created_at bigint NOT NULL,
    deadline bigint NOT NULL,
    outcome text NOT NULL DEFAULT 'pending' CHECK (outcome IN ('pending','approved','denied','expired','cancelled')),
    decided_at bigint,
    assertion jsonb,
    binding_ref text,
    UNIQUE (requester_hash, digest),
    CHECK (deadline > created_at),
    CHECK (outcome='pending' OR request_bytes IS NULL)
);
CREATE INDEX approval_pending_person ON approval_requests(person_id,created_at) WHERE outcome='pending';
CREATE INDEX approval_assertion_expiry ON approval_requests(deadline) WHERE assertion IS NOT NULL;
CREATE TABLE approval_audit (
    operation_id text PRIMARY KEY REFERENCES approval_requests(operation_id),
    digest text NOT NULL,
    person_id text NOT NULL,
    decided_at bigint NOT NULL,
    outcome text NOT NULL
);
CREATE TABLE approval_enrollments (
    person_id text PRIMARY KEY,
    organisation text NOT NULL,
    identity_key text NOT NULL,
    certificate text NOT NULL,
    issuer text NOT NULL,
    user_handle bytea NOT NULL UNIQUE,
    deadline bigint NOT NULL,
    state text NOT NULL CHECK (state IN ('pending','active','retired')),
    binding_ref text
);
CREATE TABLE approval_binding_versions (
    digest text PRIMARY KEY,
    person_id text NOT NULL REFERENCES approval_enrollments(person_id),
    binding jsonb NOT NULL,
    id_chain jsonb NOT NULL
);
CREATE TABLE approval_credentials (
    person_id text NOT NULL REFERENCES approval_enrollments(person_id),
    credential_id text NOT NULL,
    public_key bytea NOT NULL,
    sign_count bigint NOT NULL CHECK (sign_count>=0),
    grade text NOT NULL CHECK (grade IN ('passkey_uv','certified_hardware')),
    snapshot text,
    attestation bytea NOT NULL,
    retired boolean NOT NULL DEFAULT false,
    PRIMARY KEY(person_id,credential_id),
    UNIQUE(credential_id),
    UNIQUE(public_key)
);
CREATE TABLE approval_sessions (
    token_hash text PRIMARY KEY,
    person_id text NOT NULL REFERENCES approval_enrollments(person_id),
    identity_key text NOT NULL,
    credential_id text NOT NULL,
    csrf_hash text NOT NULL,
    deadline bigint NOT NULL,
    retired boolean NOT NULL DEFAULT false
);
CREATE TABLE approval_challenges (
    challenge_id text PRIMARY KEY,
    person_id text NOT NULL REFERENCES approval_enrollments(person_id),
    purpose text NOT NULL CHECK (purpose IN ('registration','login','approval')),
    operation_id text REFERENCES approval_requests(operation_id),
    session_hash text,
    challenge bytea NOT NULL,
    issued_at bigint NOT NULL,
    deadline bigint NOT NULL,
    consumed boolean NOT NULL DEFAULT false,
    CHECK (deadline>issued_at)
);
