-- Current-issuer re-signing retains the enrollment and its original history.
CREATE TABLE approval_binding_refresh_audit (
    audit_id bigserial PRIMARY KEY,
    organisation text NOT NULL,
    person_id text NOT NULL,
    actor_key text NOT NULL,
    previous_binding_ref text NOT NULL REFERENCES approval_binding_versions(digest),
    current_binding_ref text NOT NULL REFERENCES approval_binding_versions(digest),
    previous_issuer text NOT NULL,
    current_issuer text NOT NULL,
    recorded_at bigint NOT NULL CHECK (recorded_at >= 0),
    UNIQUE(organisation, person_id, previous_binding_ref, current_binding_ref)
);
CREATE FUNCTION refuse_binding_refresh_audit_mutation() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'binding refresh audit is append-only';
END;
$$;
CREATE TRIGGER binding_refresh_audit_append_only
BEFORE UPDATE OR DELETE ON approval_binding_refresh_audit
FOR EACH ROW EXECUTE FUNCTION refuse_binding_refresh_audit_mutation();
