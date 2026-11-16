# Seam vectors, version 1

The three seam corpora cover one self-custody path: the namespace controller
starts the first person's enrollment; the first person approves adding a
DISTINCT second person. Test keys and identities are synthetic and public.
The JSON schema and all domains, routes and limits live in
`src/approval_service/data/format-v1.json`; Go embeds its generated projection.
The same source bundles the closed `human.add` and limited
`enrollment.confirm` act/display definitions. R carries the actual canonical
content hash of that definition; no example hash or fetched definition is used.
`tests/test_seams.py` and `verify/seams_test.go` consume these exact files.

`requester-service-v1.json` pins the `Authorization: Awsign <base64url>` header,
its canonical signed packet and domain-prefixed preimage, canonical JSON body
hash, exact origin/POST/path/purpose and canonical key-level requester. Timestamp
age is 0 through 60 seconds inclusive; future timestamps refuse. A handler
rejects duplicate Authorization headers before this codec. Transport body JSON
may have whitespace; duplicate fields and noninteger tokens refuse before
canonicalization. Packet bytes themselves must be canonical. Replays within the
window do not extend a request: handlers deduplicate by the original digest or
issuer intent, preserve terminal decisions and one-time challenges, and enforce
original deadlines. A checked signature is not current requester admission.

`issuer-service-enrollment-v1.json` pins the exact issuer-signed intent, proposed
ID certificate and issuer challenge, pending binding, separate creation
assertion/receipt and acyclic issuer-signed human creation evidence. The intent
only produces `pending`; the issuer's shared creation-proof check validates its
own nonce/deadline and still returns pending. It consumes the nonce with its
certificate-issuance transaction. Activation also requires the independently acquired,
current COMMITTED identity Trust and matching evidence/proof. The service must
compare the credential set against its private pending registration rows. The
same shared registration verifier checks the raw create response at service and
issuer; these vectors exercise the binding/activation seam, not a hardware
registration or database enrollment. The public human creation evidence has no
raw attestation, user handle, cross-person identifier or private app receipt.
Transition/evidence-history consumers retain their separate supported-version
checks; this first-path collection does not claim to check those later paths.

`enforcer-requester-v1.json` pins the HTTP 428 `needs_human` answer carrying the
unchanged canonical R, and receipt presentation by the original requester.
The configured approval origin is checked at both exchanges. Enforcer nonce,
original bounds, current person Trust and required grade are checked, but its
rule/approver eligibility, current admitted team key and atomic effect/nonce
consumption remain the enforcer's. The service never contacts an enforcer.

`create_seam_vectors.py` refuses to overwrite a corpus. Signing-byte cases
pin both producers and readers. The fixtures supply explicit trust acquisition
ports, not live registry results, and do not qualify browser, custody or effect
execution. A locator or supplied key is never its own authority.

Published definitions are immutable by **id and version**, including display
text. `definition-hashes-v1.json` pins each published hash as a literal in both
language tests. A content change adds a new version beside the old; it never
replaces the old version. Multiple-version lookup is added when the first v2
exists. Every refusing case pins its exact error code in both languages.

The service answers are closed schemas too: submit pins the locator/state and
original D/deadline; poll pins pending, approved with a raw assertion/B/chain,
denied, cancelled, expired, and approved after assertion erasure. The latter
keeps the decision and yields `receipt_unavailable` when assembly is requested.
Cancel returns the actual terminal state, including an approval that won the
race. The requester retains canonical R and assembles C from the bundle; one
case pins those assembled bytes to the enforcer corpus's exact C. Assembly has
no current-clock check: a saved proof remains historical evidence; an enforcer
still enforces the live deadline before an effect.

Enrollment start returns issuer-challenge-bound discoverable create options.
Material returns pending raw registrations for the issuer's SAME shared
registration verifier. The material-to-B case runs `check_registration` under
explicit passkey-only policy and checks the complete returned entry against B;
it does not claim hardware. Confirm carries the original intent, B and frozen
confirmation R. Its idempotent submission/poll answer uses the decision bundle
shape, and approval of this limited proof still leaves enrollment pending until
committed identity and E are observed. Responses never contain an act archive
or imply delivery to an enforcer. The HTTP handler must compare private stored
registration grades as well as keys/IDs before accepting B.

Poll and cancel selection bodies carry the requester's original R, so the HTTP
handler derives the signing descriptor from R even after erasure at decision;
it must not re-store or log the supplied act. Material/confirm bodies carry the
original signed intent. These are transport inputs, not positive public status.
`append_service_answer_vectors.py` appends the answer cases deliberately and
refuses to overwrite them. The JSON readers check duplicate members before
map decoding, preserve named refusal codes and preserve a server error's actual
HTTP status. No service message text supplies authority.
