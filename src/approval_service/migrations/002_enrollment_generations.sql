-- A pending credential set never replaces the currently usable enrollment.
-- Preserve historical bindings used by bounded decision recovery.
ALTER TABLE approval_enrollments ADD COLUMN previous_locator text;
ALTER TABLE approval_enrollments ADD COLUMN evidence jsonb;
ALTER TABLE approval_binding_versions ADD COLUMN enrollment_locator text;
ALTER TABLE approval_credentials ADD COLUMN enrollment_locator text;
ALTER TABLE approval_sessions ADD COLUMN enrollment_locator text;
ALTER TABLE approval_challenges ADD COLUMN enrollment_locator text;

UPDATE approval_binding_versions v SET enrollment_locator=e.enrollment_locator
FROM approval_enrollments e WHERE e.organisation=v.organisation AND e.person_id=v.person_id;
UPDATE approval_credentials c SET enrollment_locator=e.enrollment_locator
FROM approval_enrollments e WHERE e.organisation=c.organisation AND e.person_id=c.person_id;
UPDATE approval_sessions s SET enrollment_locator=e.enrollment_locator
FROM approval_enrollments e WHERE e.organisation=s.organisation AND e.person_id=s.person_id;
UPDATE approval_challenges c SET enrollment_locator=e.enrollment_locator
FROM approval_enrollments e WHERE e.organisation=c.organisation AND e.person_id=c.person_id;

ALTER TABLE approval_binding_versions ALTER COLUMN enrollment_locator SET NOT NULL;
ALTER TABLE approval_credentials ALTER COLUMN enrollment_locator SET NOT NULL;
ALTER TABLE approval_sessions ALTER COLUMN enrollment_locator SET NOT NULL;
ALTER TABLE approval_binding_versions DROP CONSTRAINT approval_binding_versions_organisation_person_id_fkey;
ALTER TABLE approval_credentials DROP CONSTRAINT approval_credentials_organisation_person_id_fkey;
ALTER TABLE approval_sessions DROP CONSTRAINT approval_sessions_organisation_person_id_credential_id_fkey;
ALTER TABLE approval_challenges DROP CONSTRAINT approval_challenges_organisation_person_id_fkey;
ALTER TABLE approval_enrollments DROP CONSTRAINT approval_enrollments_pkey;
ALTER TABLE approval_enrollments ADD PRIMARY KEY(organisation,person_id,enrollment_locator);
CREATE UNIQUE INDEX approval_one_active_enrollment ON approval_enrollments(organisation,person_id) WHERE state='active';
CREATE UNIQUE INDEX approval_one_pending_enrollment ON approval_enrollments(organisation,person_id) WHERE state='pending';
ALTER TABLE approval_enrollments ADD FOREIGN KEY(organisation,person_id,previous_locator)
REFERENCES approval_enrollments(organisation,person_id,enrollment_locator);
ALTER TABLE approval_binding_versions ADD FOREIGN KEY(organisation,person_id,enrollment_locator)
REFERENCES approval_enrollments(organisation,person_id,enrollment_locator);
ALTER TABLE approval_credentials DROP CONSTRAINT approval_credentials_pkey;
ALTER TABLE approval_credentials DROP CONSTRAINT approval_credentials_organisation_person_id_public_key_key;
ALTER TABLE approval_credentials ADD PRIMARY KEY(organisation,person_id,enrollment_locator,credential_id);
ALTER TABLE approval_credentials ADD UNIQUE(organisation,person_id,enrollment_locator,public_key);
ALTER TABLE approval_credentials ADD FOREIGN KEY(organisation,person_id,enrollment_locator)
REFERENCES approval_enrollments(organisation,person_id,enrollment_locator);
ALTER TABLE approval_sessions ADD FOREIGN KEY(organisation,person_id,enrollment_locator,credential_id)
REFERENCES approval_credentials(organisation,person_id,enrollment_locator,credential_id);
ALTER TABLE approval_challenges ADD FOREIGN KEY(organisation,person_id,enrollment_locator)
REFERENCES approval_enrollments(organisation,person_id,enrollment_locator);
ALTER TABLE approval_challenges ADD CHECK((person_id IS NULL AND enrollment_locator IS NULL) OR (person_id IS NOT NULL AND enrollment_locator IS NOT NULL));
