-- The service has not been deployed: one initial, organisation-scoped schema.
CREATE TABLE approval_enrollments (
    organisation text NOT NULL,
    person_id text NOT NULL,
    identity_key text NOT NULL,
    certificate text NOT NULL,
    issuer text NOT NULL,
    user_handle bytea NOT NULL UNIQUE,
    deadline bigint NOT NULL,
    state text NOT NULL CHECK (state IN ('pending','active','retired')),
    binding_ref text,
    enrollment_locator text NOT NULL UNIQUE,
    intent jsonb,
    requester_hash text NOT NULL,
    browser_hash text,
    browser_deadline bigint,
    confirmation_id text,
    admission jsonb,
    PRIMARY KEY (organisation,person_id)
);
CREATE TABLE approval_binding_versions (
    digest text PRIMARY KEY,
    organisation text NOT NULL,
    person_id text NOT NULL,
    binding jsonb NOT NULL,
    id_chain jsonb NOT NULL,
    FOREIGN KEY (organisation,person_id) REFERENCES approval_enrollments(organisation,person_id)
);
CREATE TABLE approval_credentials (
    organisation text NOT NULL,
    person_id text NOT NULL,
    credential_id text NOT NULL,
    public_key bytea NOT NULL,
    sign_count bigint NOT NULL CHECK (sign_count>=0),
    grade text NOT NULL CHECK (grade IN ('passkey_uv','certified_hardware')),
    snapshot text,
    attestation bytea NOT NULL,
    retired boolean NOT NULL DEFAULT false,
    registration jsonb,
    client_extension_results jsonb,
    binding_entry jsonb NOT NULL,
    PRIMARY KEY(organisation,person_id,credential_id),
    UNIQUE(organisation,person_id,public_key),
    FOREIGN KEY (organisation,person_id) REFERENCES approval_enrollments(organisation,person_id)
);
CREATE TABLE approval_requests (
    organisation text NOT NULL,
    person_id text NOT NULL,
    operation_id text NOT NULL,
    digest text NOT NULL,
    requester_hash text NOT NULL,
    request_bytes bytea,
    admission jsonb,
    created_at bigint NOT NULL,
    deadline bigint NOT NULL,
    outcome text NOT NULL DEFAULT 'pending' CHECK (outcome IN ('pending','approved','denied','expired','cancelled')),
    decided_at bigint,
    assertion jsonb,
    binding_ref text,
    PRIMARY KEY (organisation,person_id,operation_id),
    UNIQUE (organisation,person_id,requester_hash,digest),
    CHECK (deadline > created_at),
    CHECK (outcome='pending' OR (request_bytes IS NULL AND admission IS NULL))
);
CREATE INDEX approval_pending_person ON approval_requests(organisation,person_id,created_at) WHERE outcome='pending';
CREATE INDEX approval_assertion_expiry ON approval_requests(deadline) WHERE assertion IS NOT NULL;
CREATE TABLE approval_audit (
    organisation text NOT NULL,
    person_id text NOT NULL,
    operation_id text NOT NULL,
    digest text NOT NULL,
    decided_at bigint NOT NULL,
    outcome text NOT NULL,
    PRIMARY KEY(organisation,person_id,operation_id),
    FOREIGN KEY(organisation,person_id,operation_id) REFERENCES approval_requests(organisation,person_id,operation_id)
);
CREATE TABLE approval_sessions (
    organisation text NOT NULL,
    person_id text NOT NULL,
    token_hash text NOT NULL UNIQUE,
    identity_key text NOT NULL,
    credential_id text NOT NULL,
    csrf_hash text NOT NULL,
    deadline bigint NOT NULL,
    retired boolean NOT NULL DEFAULT false,
    PRIMARY KEY(organisation,person_id,token_hash),
    FOREIGN KEY(organisation,person_id,credential_id) REFERENCES approval_credentials(organisation,person_id,credential_id)
);
CREATE TABLE approval_challenges (
    challenge_id text PRIMARY KEY,
    organisation text,
    person_id text,
    purpose text NOT NULL CHECK (purpose IN ('registration','login','approval')),
    operation_id text,
    session_hash text,
    challenge bytea NOT NULL,
    issued_at bigint NOT NULL,
    deadline bigint NOT NULL,
    consumed boolean NOT NULL DEFAULT false,
    FOREIGN KEY(organisation,person_id) REFERENCES approval_enrollments(organisation,person_id),
    FOREIGN KEY(organisation,person_id,operation_id) REFERENCES approval_requests(organisation,person_id,operation_id),
    CHECK ((organisation IS NOT NULL AND person_id IS NOT NULL) OR (organisation IS NULL AND person_id IS NULL AND purpose='login')),
    CHECK (deadline>issued_at)
);
ALTER TABLE approval_enrollments ADD CONSTRAINT enrollment_confirmation_scope
    FOREIGN KEY(organisation,person_id,confirmation_id) REFERENCES approval_requests(organisation,person_id,operation_id);
