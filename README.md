# awsign

Exact human approval using enrolled keys. The service holds no organisation
private keys and performs no application effects. Enforcers verify receipts
under their own rules. Implementation follows the approved architecture and
approval protocol. The hosted origin is `https://awsign.com` and its WebAuthn
RP ID is `awsign.com`. The repository remains `awebai/approval-service`.

Any origin/RP change after enrollment requires reenrollment.

Receipt verifiers take independently checked `Trust`; a binding carried in a
receipt is not its own trust anchor. Python `approval_service.trust.read_trust`
and Go `verify.ReadTrust` obtain public ID status and DNS authority through the
configured AWID SDK resolver, then use the shared chain-to-trust implementation
in that language. The plain Python client in `awid-service` 0.5.40 and later
supports exact-certificate status reads without Redis. Enforcers call these
entry points to verify the chain and public status before trusting a receipt.

The pure `derive_trust` / `DeriveTrust` entry points accept **trusted acquisition
inputs only**. Their observation records never come from a request or receipt.
They retain original acquisition age, refuse unavailable/expired status,
require the exact namespace and current person identity, and derive the
certificate and issuer key from checked public data. They grant no application
permission. Historical checks still use explicit as-of trust.

The Python and Go trust tests share real ID certificate/log signatures from the
public AWID conformance corpus. They exercise cryptography and supplied public
observation ports; they are not live registry, service or hardware tests.

The issuer is always its CURRENT key. After a namespace controller rotation or
an issuing person's key change, that issuer must sign the affected person's
binding again; bindings signed by the superseded issuer key no longer verify.
For inherited DNS authority, the child's checked namespace delegation and epochs
select its issuer; the parent's controller cannot issue the child's binding.
Human certificate parents cannot be did:key identities: a human's identity
parent must itself be human, and human IDs must be did:aw.

Go callers supplying a pure public observation must decode status with a
`json.Decoder` using `UseNumber`; ordinary float64 map decoding is refused by
the underlying ID verifier. `ReadTrust` uses the SDK's correct decoder.

The service and issuer verify the SAME registration response with
`approval_service.registration.check_registration`. The WebAuthn create
challenge is the issuer's fresh value for the exact person and pending
certificate. Before signing certified hardware in B, the issuer checks the raw
private attestation with this shared code and its own pinned metadata input;
otherwise it may sign passkey grade at most. This prevents a compromised service
from labelling software hardware or replaying another enrollment's attestation.
It cannot stop that service enrolling genuine hardware held by an attacker:
the organisation's authorization supplies the first physical-key association.
There is no second registration; the separate enrollment_confirmation get
assertion over B remains the public creation proof. Attestation certificates
remain private and are never placed in a binding or public identity sidecar.

The v1 format source permits `none`, `packed` and `fido-u2f` registration profiles.
The service and issuer refuse TPM and Apple attestation with
`attestation_profile_unsupported` because their privacy properties have yet to
be established for v1. Use an authenticator that supplies a supported profile.
A software authenticator or a claimed model identifier alone earns passkey
grade at most. Hardware qualification requires a real device ceremony.

Metadata is fetched and pinned, never distributed in this repository. The hosted
process and issuer install a snapshot through the same loader:

```sh
uv run python -m approval_service.metadata_cache --cache-dir /private/path/mds-cache
```

The [bundled manifest](src/approval_service/data/mds-pin-v1.json) pins the
published blob, root and required CRLs by SHA-256.
The cache must be outside the repository with mode 0700; artifact files are 0600.
Every installation checks the pins, root, signer, signature, CRLs, original
next-update date and the highest previously installed sequence. Network errors
and changed/expired inputs refuse installation. Updating the operator manifest
is deliberate; the loader never trusts a newly fetched root or silently follows
a changing upstream blob. The process loads metadata at startup and checks the
configured manifest for changes once a minute. Attested registration refuses
an unavailable or expired snapshot. Unattested passkeys remain available
independently of hardware metadata. Explicit passkey-only grading supplies no
snapshot and never claims certified hardware. An effective unscoped withdrawal disqualifies
the model regardless of firmware version; a certificate-scoped withdrawal
affects only that batch.

The 0.1.0 readiness baseline pins sequence 303, retrieved on 2026-11-27, with
a cutoff of 2026-12-01 at 00:00 UTC. The bundled manifest's `valid_until` is
the earliest expiry across the blob and its validation inputs. Operators must
install the reviewed replacement before that cutoff.
Ordinary tests use real signatures under a synthetic vendor trust anchor and
exercise an actual HTTPS fetch. They distribute no FIDO data. To check the real
downloaded pinned artifact as of its recorded date:

```sh
APPROVAL_MDS_CACHE=/private/path/mds-cache uv run pytest -q artifact_tests
```

That historical artifact check is not a current enrollment or physical-device
qualification. Raw cached data stays private and outside the repository.

Service enrollment uses the explicit operator policy in
`approval_service.grading.EnrollmentGrading`; hardware input loading cannot fall
back to passkey-only. The daily reviewed pin-renewal job and operator warning,
cache and refresh responsibilities are in [deployment notes](docs/deployment.md).


## Running the service

Set `AWSIGN_DATABASE_URL` to the service's PostgreSQL database, then run
`uv run awsign migrate` explicitly. `uv run awsign serve` opens one bounded
async pgdbm pool and listens on loopback port 8030 behind the configured HTTPS
origin. It never applies migrations at server startup. `/` signs in using a
discoverable enrolled key; `/enroll#<locator>` is the first enrollment page
opened from the issuer's page or command. Arrival grants no authenticated
session. Registration, confirmation of the issuer-signed binding, and observed
committed identity activation are separate steps.

The signed requester routes and their closed replies are pinned in `vectors/`.
The caller carries the issuer intent and request, polls for the result and
assembles its own receipt. Enforcers never call the approval service.
See [deployment configuration](docs/deployment.md) for settings and the public
certificate-status SDK dependency.


Pending enrollment links are bearer capabilities; follow the issuer's
[delivery and registration-count checks](docs/deployment.md#enrollment-link-handling).

## Lost approval keys

Replacing a lost enrolled key is not implemented; today a person who loses their only enrolled key is issued a new ID by the operator and enrols again, and the old ID is revoked. Enrol two keys.

The shared lifecycle checkers preserve existing `unbroken`, `assisted` and
`recreated` evidence semantics. They do not provide an issuer replacement
workflow. Old saved receipts remain historical proofs under explicit as-of
Trust; they cannot supply current approval authority.

Activation alone also accepts the exact target person's current identity key
as authenticated carrier after rotation. `carrier` names that identity in the
activation body. It does not change I, C, the original requester, polling or
assertion recovery, and grants no session. The shared seam checks the same
rule as the HTTP handler; other members and non-current keys are refused.

A person's ID can be created without awsign. Existing people enroll with an
issuer-signed `enroll_existing_person` intent naming their committed certificate,
carried by their own current identity key. The issuer and service independently
check the registration, then reuse `enrollment.confirm`. Activation v2 carries
`human_enrolled_later` under its distinct signature domain, never a creation
claim. `VerifyEnrollmentEvidence` / `verify_enrollment_evidence` authenticate the
issuer facts and optionally the original confirmation receipt without imposing
a live ceremony deadline: “can approve since T (issuer's statement), grade G”.
The time and grade remain issuer claims even with a checked proof.

Later statements are signed by the checked current namespace controller. A
receipt binding may select that controller or the person's actual-parent issuer;
both come from independently verified public Trust, not the supplied artifact.
Creation statements keep the actual-parent issuer. Live checks use current keys;
a controller change requires affected bindings/statements to be re-signed by
the new issuer. The holder has no automatic rotation/re-signing hook yet; this
is not a requirement to repeat the person's registration ceremony. Historical
verification uses explicit as-of authority inputs.

The package requires the released `awid-service>=0.5.40,<0.6` for exact-certificate
status reads. Use `uv sync --locked` to reproduce the repository's installation.
Requester routes apply an operator-configured per-IP budget before processing input.
For metadata renewal without restarting, install reviewed pins in
`AWSIGN_MDS_MANIFEST`; see [deployment](docs/deployment.md#installing-metadata-without-restarting).

Ordinary act submissions last at most 10 minutes; enrollment confirmation keeps
its separate 24-hour window. The service quotes caller identifiers as technical
data and accepts only an HTTPS origin for the enforcer. Pending budgets and
queue interleaving follow the actual signing key, rather than its descriptor.
Terminal requests are pruned after 30 days; expired sessions and challenges
are removed by cleanup, at most 30 days after their deadline.
Enrollment confirmation state, signed bindings, evidence and outcome audit are
retained; pruning cannot erase an approved confirmation needed for activation.

Issuer and service independently grade each registration. The issuer may claim
a weaker grade, and two valid hardware snapshots may differ; the service refuses
a grade beyond its own assessment. A missing or expired hardware list still
refuses attested enrollment rather than silently lowering its grade.

## Approval-page display tests

The browser tests render the actual page module in Chromium, without a service,
registry or signing fixture:

```sh
uv run --frozen --group browser playwright install chromium
uv run --frozen --group browser pytest -q browser_tests
```
