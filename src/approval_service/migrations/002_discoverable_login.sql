-- A LOGIN starts without knowing a person; the credential's user handle
-- selects them only after the returned assertion has been verified.
ALTER TABLE approval_challenges ALTER COLUMN person_id DROP NOT NULL;
ALTER TABLE approval_challenges ADD CONSTRAINT approval_challenge_person_scope
    CHECK (person_id IS NOT NULL OR purpose='login');
