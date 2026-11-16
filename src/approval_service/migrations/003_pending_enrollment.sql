ALTER TABLE approval_enrollments
    ADD COLUMN enrollment_locator text UNIQUE,
    ADD COLUMN intent jsonb,
    ADD COLUMN requester_hash text,
    ADD COLUMN browser_hash text,
    ADD COLUMN browser_deadline bigint,
    ADD COLUMN confirmation_id text REFERENCES approval_requests(operation_id);
ALTER TABLE approval_credentials
    ADD COLUMN registration jsonb,
    ADD COLUMN client_extension_results jsonb,
    ADD COLUMN binding_entry jsonb;
