-- Raw attestation is needed only in pending registration material. The
-- separate bytea copy was never read or erased when activation cleared it.
ALTER TABLE approval_credentials DROP COLUMN attestation;

-- Registration uses the issuer's signed intent challenge, never this table.
DELETE FROM approval_challenges WHERE purpose='registration';
ALTER TABLE approval_challenges DROP CONSTRAINT approval_challenges_purpose_check;
ALTER TABLE approval_challenges ADD CONSTRAINT approval_challenges_purpose_check
    CHECK (purpose IN ('login','approval'));
