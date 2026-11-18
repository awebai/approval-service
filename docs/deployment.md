# awsign deployment and metadata operation

The hosted service is **awsign**, with exact HTTPS origin `https://awsign.com`
and WebAuthn RP ID `awsign.com` (the origin's own host). Enrollment bindings pin
that origin and RP; a change requires reenrollment. The repository remains
`awebai/approval-service`. DNS, TLS and hosting are managed by the deployment operator.

The approval-service repository maintainer owns metadata pin renewal and its
correctness review. The deployment operator owns installing that reviewed pin,
retaining its private external cache, refreshing the process and responding to
expiry alerts. Neither duty belongs to the person enrolling or the issuer's
browser. A released pin is configuration, not a permanent metadata archive.

The service's enrollment composition uses `EnrollmentGrading.load` with an
explicit operator mode: `hardware` or `passkey_only`. In hardware mode, cache
location is required. Missing or expired metadata pauses hardware-attested
registration, with an explicit metadata error and non-200 enrollment-readiness status.
Unattested passkeys remain available; a failed load never silently downgrades
an attested key. Receipt-only checking and already-saved historical proofs do
not require a current metadata download.
Passkey-only mode deliberately passes no snapshot and promises passkey grade
only. It is never selected because loading failed, timed out or returned stale
data. Changing policy is an operator action, never an enrollment parameter.

`.github/workflows/metadata-pin.yml` runs daily and on manual dispatch. It fetches
FIDO's live blob and the configured CRLs, verifies their real chain, JWT, dates,
revocation and sequence under the EXISTING pinned root, then opens or updates a
pin-only PR. The approval-service maintainer reviews the latest head and lands
it. The job never merges, tags, publishes a release or deploys. It never commits
vendor data or follows a root/CRL URL discovered in the new blob. A root change,
new CRL route, rollback, verification failure or unavailable upstream stops the
job and needs the maintainer's attention. The repository owner must enable
scheduled Actions and allow its token to open PRs; otherwise this mechanism is
not running. The maintainer watches failed runs and pending pin PRs.

A pin to FIDO's live URL cannot bootstrap an empty cache after FIDO replaces that
file. Keep the exact verified artifacts in a persistent external cache; their
bytes are not placed in Git, Actions artifacts or the container image. A newly
installed machine must use a current reviewed pin, or an operator-provided copy
of the exact cached artifacts (all pins and cryptographic checks still run).
Neither option extends the original input deadlines. Before deploying a new
pin, install it with the ordinary loader, then replace/reload the service's
policy only after installation succeeds:

```sh
uv run python -m approval_service.metadata_cache \
  --manifest /etc/approval/mds-pin-v1.json \
  --cache-dir /var/lib/approval/mds-cache
```

The process uses this same loader, not a separate download implementation.
There is no download per approval. The cache directory is 0700 and files are
0600. The loader preserves the highest installed sequence; a pin update cannot
roll it back. An unsuccessful refresh leaves the previous policy in place only
until its original deadline; it does not grant a grace period or lower grade.

Operator warning begins seven days before the EARLIEST verified input deadline:
the blob's `next_update`, signer/root certificate expiry or required CRL expiry.
`EnrollmentGrading.status()` reports the deadline, seconds remaining, warning
and whether enrollment is ready. The service health composition must expose
these facts to its deployment monitor. Independently, run this command at least
hourly under the operator's existing monitor/scheduler and alert on any nonzero
exit (2 means verified but expiring; 1 means installation/check failed):

```sh
uv run python -m approval_service.metadata_cache --check \
  --manifest /etc/approval/mds-pin-v1.json \
  --cache-dir /var/lib/approval/mds-cache
```

The command re-verifies cached inputs against the host clock and emits only
metadata health. This monitor sends the operator's alert; the approval service
still sends nothing to people. Do not put a mail address or notice sender into
the service. The initial blob's next update is 2026-12-01; its CRLs can expire
earlier. The maintainer's reviewed renewal and the operator's monitored refresh
are continuing requirements, not a one-time setup or a silent downgrade path.


## Process configuration

- `AWSIGN_DATABASE_URL`: PostgreSQL connection string, supplied by the operator's
  secret mechanism. `AWSIGN_DATABASE_SCHEMA` defaults to `awsign`.
- `AWSIGN_DATABASE_POOL_MAX`: process pool ceiling, default 10; all polling and
  ceremonies share it. No synchronous per-request connection is opened.
- `AWSIGN_ORIGIN`: exact browser and signed-request origin, default
  `https://awsign.com`. `AWSIGN_RP_ID` defaults to `awsign.com`; it must be the
  origin's own lower-case ASCII host. Front this loopback process with HTTPS.
- `AWID_REGISTRY_URL`: operator-configured registry; request bodies never select
  an origin. The registry must provide public exact-certificate status reads.
- `AWSIGN_GRADING`: `hardware` by default; explicit `passkey_only` is for
  passkey-grade enrollment. `AWSIGN_MDS_CACHE` names the private persistent
  metadata cache. Loading failures pause attested enrollment, not passkeys.

Run `uv run awsign migrate`, then `uv run awsign serve --bind 127.0.0.1 --port 8030`.
Disable proxy request-body logging. The process disables access logs, serves
only local browser assets and adds a restrictive CSP, no-store responses and
secure HttpOnly SameSite cookies. Pending registration material, including raw
attestation, is kept only until activation or deletion of the pending enrollment.
Activation erases that material; no separate attestation copy is retained. Run
`awsign migrate` before starting the service to remove legacy attestation copies.
Its bounded expiry worker erases terminal act
bytes and expired assertion slots; unactivated pending enrollments expire too.
`GET /health` includes the metadata expiry warning for the operator monitor.

Receipt-only enforcers and self-hosted key holders need no Redis. This service
uses a bounded 60-second in-process public observation cache which preserves
original age. No unavailable read renews an observation. The standalone development lock selects the public post-deletion AWID SDK source
at `9bbdd365d85ad6d476663a1484fe3060bb2b9679` (`awid` subdirectory). It supplies
`get_team_certificate_status_fresh` in the normal installed environment.
**Before the server release, replace this source pin with the released
`awid-service` version.** SDK version numbers remain owned by the release.



## Enrollment link handling

The pending `/enroll#<locator>` link is a bearer capability: anyone holding it
can add a pending registration and refresh the page window. Deliver it over an
authenticated channel. The issuer's intent expires within 24 hours, cannot be
extended by opening the link, and names the exact organisation and person.
Before signing the enrollment binding, the issuer checks the number of
registrations in the material against the number the person reports making.
The link alone grants no signed-in session or active identity.

After a person's confirmation is approved, the pending credentials remain for
activation even after the intent deadline. The normal sweep removes them 30 days
after that deadline; an earlier new enrollment start replaces the expired
pending attempt. Unconfirmed attempts expire at the original deadline. Material,
confirmation, browser ceremonies and raw assertion retrieval keep their original
deadlines; the requester must save its receipt before retrieval closes.


`AWSIGN_TRUSTED_PROXY_IPS` explicitly configures which proxy peers may supply
forwarded client addresses (default `127.0.0.1,::1` for a loopback HTTPS proxy).
Set it to the actual proxy addresses when the proxy is elsewhere, and configure
that proxy to replace incoming forwarded headers. An empty setting trusts no
forwarding; behind a proxy this makes each IP budget shared by all callers
using that proxy.
`AWSIGN_REQUESTS_PER_IP_PER_MINUTE` bounds all `/v1/*` attempts per observed
client IP (default 600 per process), before body parsing, signature processing
or public reads. The existing per-requester budget still applies. Raw forwarded
headers are not used here; only the configured trusted-proxy handling can set
the observed peer. An absent peer uses one shared bounded bucket.
The authenticated requester budget is keyed by the signing key, so changing
identity or certificate selectors cannot renew it. Team-certificate selectors
are checked against the certificate before discovery. Exact-status misses and
discovered team keys are cached for at most 60 seconds; a bad signature under
a cached key causes no further registry read. These are admission limits, not
effect authority.
Load balancers and orchestrator probes use `/health`: database reachability
keeps it at 200, even if hardware metadata expires. Its body reports enrollment
state. Operator alerting uses `/health/enrollment`, which answers 503 while
hardware grading is not ready. Sign-in, approvals and unattested passkey
registration remain available during metadata expiry.

Re-enrollment uses a separate pending generation, so run `awsign migrate` before
starting the service with its initial generation-scoped schema.
Recovery requires the person's previous
identity key to sign the normal registry rotation first. No operator reset,
mail account or organisation signature substitutes for that key. When it too
is lost, revoke the old person ID and issue a new ID. Recovery evidence starts
a new creation event after an explicit break, rather than inheriting the old
evidence grade.


## Installing metadata without restarting

For hardware grading, set `AWSIGN_MDS_MANIFEST` to a persistent operator-owned
JSON pin file and `AWSIGN_MDS_CACHE` to its private artifact cache. Install a
reviewed manifest by replacing that file atomically. The process checks it once
per minute; only a successfully pinned, signed, chain/CRL-checked, non-rollback
snapshot replaces the running one. The key holder uses the same loader and
watcher with `--mds-manifest FILE --mds-cache DIR`.

A bad replacement leaves the previously verified snapshot usable only until
its original earliest expiry. The health metadata reports `reload_error`, and
the process logs reload failures and the seven-day validity warning. Once the
old snapshot expires or is missing, hardware-attested registrations refuse with
`snapshot_expired`, `snapshot_validation_expired` or `snapshot_unavailable`.
Unattested registrations still receive passkey grade; an attested key is never
silently downgraded. Sign-in and approvals continue. Metadata failures cannot
stop the watcher from installing a later verified replacement.

The blob's next-update date is not the snapshot expiry: use the earliest
verified certificate, CRL or blob deadline reported by the loader and health.
The maintainer's daily metadata-pin workflow verifies upstream changes under
the existing pinned root and opens the review request. The service maintainer
checks failed runs and pending proposals daily, reviews and lands each verified
renewal; deployment operators monitor at least hourly and install it before the earliest
reported deadline. Runtime does not adopt an unreviewed new pin or fetch vendor
data per approval. With no external manifest path, the packaged pin remains
in use until a new deployment installs its replacement.
