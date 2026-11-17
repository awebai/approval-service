-- Hashes still identify an exact requester descriptor for ownership. Budgets
-- and scheduling follow the signing key, even when that descriptor changes.
ALTER TABLE approval_requests ADD COLUMN requester_key text;
UPDATE approval_requests SET requester_key=COALESCE(
    (convert_from(request_bytes,'UTF8')::jsonb #>> '{requester,key}'), requester_hash);
ALTER TABLE approval_requests ALTER COLUMN requester_key SET NOT NULL;
CREATE INDEX approval_pending_key ON approval_requests(organisation,requester_key,deadline) WHERE outcome='pending';
ALTER TABLE approval_enrollments ADD COLUMN requester_key text;
UPDATE approval_enrollments SET requester_key=intent #>> '{intent,requester,key}';
ALTER TABLE approval_enrollments ALTER COLUMN requester_key SET NOT NULL;
CREATE INDEX approval_pending_enrollment_key ON approval_enrollments(requester_key,deadline) WHERE state='pending';
-- The small outcome audit survives operational request retention.
ALTER TABLE approval_audit DROP CONSTRAINT approval_audit_organisation_person_id_operation_id_fkey;
-- Bound each periodic cleanup batch by indexed expiry/decision order.
CREATE INDEX approval_challenge_deadline ON approval_challenges(deadline);
CREATE INDEX approval_session_deadline ON approval_sessions(deadline);
CREATE INDEX approval_terminal_decided ON approval_requests(decided_at) WHERE outcome<>'pending';
