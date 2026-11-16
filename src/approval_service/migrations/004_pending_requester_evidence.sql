-- Public proofs are needed to recheck requester admission at the human decision.
-- They leave pending storage together with the act at every terminal outcome.
ALTER TABLE approval_requests ADD COLUMN admission jsonb;
