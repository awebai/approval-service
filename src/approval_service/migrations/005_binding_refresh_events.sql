-- Each installed transition is an event, including A -> B -> A -> B.
-- Migration 004's sole unique constraint incorrectly deduplicated these events.
DO $$
DECLARE
    event_pair_constraint text;
BEGIN
    SELECT conname INTO STRICT event_pair_constraint
    FROM pg_constraint
    WHERE conrelid = 'approval_binding_refresh_audit'::regclass AND contype = 'u';
    EXECUTE format('ALTER TABLE approval_binding_refresh_audit DROP CONSTRAINT %I',
                   event_pair_constraint);
END;
$$;
