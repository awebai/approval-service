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
configured AWID SDK resolver (Python 0.5.40rc1 supports the plain client
without Redis; the service may use its cached subclass), then use the single chain-to-trust implementation
in that language. Enforcers use this path rather than extracting keys from a
receipt or writing their own chain/status interpretation.

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

The v1 registration profiles are listed in the format source. Formats whose
privacy has not been established are refused rather than silently importing
enterprise identifiers. A software authenticator or a claimed model identifier
alone earns passkey grade only; genuine hardware qualification still requires
a real device ceremony.

Metadata is fetched and pinned, never distributed in this repository. The hosted
process and issuer install a snapshot through the same loader:

```sh
uv run python -m approval_service.metadata_cache --cache-dir /private/path/mds-cache
```

`data/mds-pin-v1.json` pins the published blob, root and required CRLs by SHA256.
The cache must be outside the repository with mode 0700; artifact files are 0600.
Every installation checks the pins, root, signer, signature, CRLs, original
next-update date and the highest previously installed sequence. Network errors
and changed/expired inputs refuse installation. Updating the operator manifest
is deliberate; the loader never trusts a newly fetched root or silently follows
a changing upstream blob. Loading occurs at process startup or explicit refresh,
not per approval. `check_registration` also refuses `snapshot_expired` if an
installed snapshot expires while the process runs. Passkey-only enrollment
explicitly supplies `snapshot=None`. An effective unscoped withdrawal disqualifies
the model regardless of firmware version; a certificate-scoped withdrawal
affects only that batch.

The default pins record snapshot 301 (retrieved 2026-11-15, next update 2026-12-01);
its CRLs have their own earlier deadlines. Operators must replace the reviewed
pins and refresh before any input expires; there is no automatic downgrade.
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

## Re-enrollment and lost approval keys

A pending replacement has a fresh user handle, browser window and credential
set beside the active enrollment. It cannot sign in or approve ordinary acts.
The issuer prepares the AFTER binding, obtains the normal prior-key or helper
approval over the exact BEFORE/AFTER target, applies its own rule and nonce,
then commits the new identity key and signed evidence. Activation observes that
committed identity, checks both proofs and the service's own credential grades,
and atomically retires the old generation and its sessions. Expiring an
unfinished attempt leaves the old generation usable. Historical receipt recovery
still returns the binding originally selected at decision. An activated
generation's issuer-signed evidence is immutable on retry; a new signature by
a retired BEFORE key cannot relabel assisted history as unbroken.

When every approval key is lost, the identity key can still sign its ordinary
rotation. Recovery enrollment requires that new key to be current for the SAME
stable person ID. Its evidence says `recreated` and records a new recovery
creation event, never an unbroken continuation or an inherited old grade. An
organisation key alone cannot move an existing ID. Losing the identity key too
requires revoking that ID and creating a new one.

The `enrollment-lifecycle-v1` vectors cover the shared Python/Go activation
checks. Previous enrollment state and historical transition Trust are checked
inputs, not receipt-supplied authority. The service takes them from previously
committed binding versions. Unavailable prior E can be supplied as the
issuer-authenticated saved public statement from its requester; it does not
reconstruct it from an act archive. Recovery can explicitly record unavailable
prior history while starting a new evidence history after the break.

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
