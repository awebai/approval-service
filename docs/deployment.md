# awsign deployment and metadata operation

The hosted service is **awsign**, with exact HTTPS origin `https://awsign.com`
and WebAuthn RP ID `awsign.com` (the origin's own host). Enrollment bindings pin
that origin and RP; a change requires reenrollment. The repository remains
`awebai/approval-service`. DNS, TLS and hosting changes are production work;
the coordinator obtains Juan's go before they happen. This document records
configuration and operating duties, not an instruction to provision production.

Build and land reviewed work on main. Nothing ships until Juan has completed
ONE walk covering the finished Cloud fixes and main programme together. No
release planning or deployment is started by these notes.

The approval-service repository maintainer owns metadata pin renewal and its
correctness review. The deployment operator owns installing that reviewed pin,
retaining its private external cache, refreshing the process and responding to
expiry alerts. Neither duty belongs to the person enrolling or the issuer's
browser. A released pin is configuration, not a permanent metadata archive.

The service's enrollment composition uses `EnrollmentGrading.load` with an
explicit operator mode: `hardware` or `passkey_only`. In hardware mode, cache
location is required and every loading error refuses startup; no exception path
passes `snapshot=None`. A running instance also refuses enrollment when its
loaded blob, signer certificate or required CRL expires. Receipt-only checking
and already-saved historical proofs do not require a current metadata download.
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
not running. The maintainer watches failed runs and pending pin PRs. Releases
remain held under the existing release instruction.

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
