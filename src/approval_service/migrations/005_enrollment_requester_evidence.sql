-- Activation authenticates the original caller again, using its original public
-- certificate/chain and a new status observation, without changing the wire.
ALTER TABLE approval_enrollments ADD COLUMN admission jsonb;
