# Seam vectors, version 1

The three seam corpora cover one self-custody path: the namespace controller
starts the first person's enrollment; the first person approves adding a
DISTINCT second person. Test keys and identities are synthetic and public.
The JSON schema and all domains, routes and limits live in
`src/approval_service/data/format-v1.json`; Go embeds its generated projection.
The same source bundles the closed `human.add`, `human.enrollment.replace`,
`agent.root.authorize` and limited `enrollment.confirm` act/display definitions.
R carries the actual canonical
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
current COMMITTED identity Trust and matching evidence/proof.
The shared activation check verifies the signed intent and saved confirmation
as historical content: once matching committed evidence exists, neither
ceremony deadline limits activation. Fresh current Trust is still required.
Binding/confirmation and material requests remain deadline-bound; they cannot
use the activation path to renew a ceremony. The deadline vectors exercise both
the exact boundary and a later activation, plus stale/missing Trust and tampered
intent/assertion refusals.
The service must compare the credential set against its private pending
registration rows. The
same shared registration verifier checks the raw create response at service and
issuer; these vectors exercise the binding/activation seam, not a hardware
registration or database enrollment. The public human creation evidence has no
raw attestation, user handle, cross-person identifier or private app receipt.
Transition/evidence-history consumers retain their separate supported-version
checks; this first-path collection does not claim to check those later paths.

`registration-profiles-v1.json` pins the TPM and Apple profile refusal code.
The Python registration tests apply these cases to synthetic WebAuthn
registration envelopes with test certificates. The cases check the refusal
before grading. Go consumes the generated format schema for public proofs.

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

`enrollment-lifecycle-v1.json` pins ordinary, assisted and recovery replacements.
The signed intent names `previous_binding_commitment`; `replace_person_keys`
prepares a pending ordinary/assisted replacement, while active-person
`enroll_person` is recovery and requires the AFTER identity key already current
at start. Both remain pending until committed activation. E's closed
`transition` names the BEFORE subject/binding, previous E commitment, AFTER
confirmation receipt and ordinary transition receipt. Its mode is `unbroken`,
`assisted` or `recreated`. A missing previous E is explicit null only for a
recovery break; normal replacement must preserve authenticated original
creation facts. Recovery's creation field describes the NEW recovery ceremony.
It never carries the former grade forward.

Activation's `transition_receipt` is a complete public identity-act proof. The
new bundled `human.enrollment.replace@1` definition commits exact BEFORE/AFTER
certificate, identity key and B digest, person and continuity mode. The raw
assertion is checked under independently trusted historical input; the helper
is not relabelled as the target. The enforcer still checks current permission,
its own nonce/deadline and atomic application of the effect. Activation is not
that effect. `previous_evidence` optionally carries the requester's saved public
statement when prior history is unavailable; it is verified under the
known prior issuer and binding, never a supplied trust root.

The `previous.trust` and `transition_trust` entries in these vectors represent
checked historical inputs, not public wire fields. Service implementations use
committed binding generations and independently read current AFTER Trust.
The corpus also supplies the prior confirmation receipt so its construction
can be checked independently. No private attestation or application resource
is published in these identity proofs.

The three `activation-carrier-*` cases in `issuer-service-enrollment-v1.json`
keep I/C byte-for-byte unchanged and pin a valid signed HTTP envelope for each
carrier. Only the exact person/current-key descriptor, or the original
requester with current admission, can carry activation. The same person with
a non-current key and a different person's key both refuse with
`requester_mismatch`. No carrier exception applies to other enrollment routes,
polling, receipt recovery or LOGIN.

`root-agent-v1.json` pins the exact root effect and the live/historical split.
Live checks pin same-holder audience, current approver == target person, exact
revision, owned organisation teams and aw's empty-list-only rule. Replacement
returns the whole new list; empty withdraws. The consumer commits that list and
nonce atomically. Historical `{version:1,receipt:C}` is a distinct `root_proof`
profile, never a human-creation statement. All three enforcer audiences use the
same historical check. Expired effect windows do not invalidate saved proof.

RootIdentity and PersonContinuity in these cases are independently checked
SDK/lifecycle/as-of input ports, like Trust; they are NOT proof fields and this
corpus does not qualify their acquisition. Continuous root-ID key history keeps
the proof; broken history or a changed root ID refuses that evidence. Person
continuity is from the receipt's person key to the chosen as-of key. Unbroken
continuity preserves approval; assisted/recreated reports an approval predating
a break; missing history is unknown. The returned since-time names that existing
checked basis, not an independently proved time of the human's touch. The raw
assertion and issuer signature are real. Missing or invalid root evidence never
changes the caller's independent ID-chain verdict, and ordinary agent-to-agent
links need no receipt. These vectors do not claim that a holder stored a grant
or that aw issued a certificate; those consumers own their effect tests.

The root corpus also pins live refusal for another immediate person parent and
for no person parent, before a grant can be returned. For a registered root, the consumer registers
the person-to-root certificate before presentation. For a local `did:key` root,
it presents that certificate with the request and the SDK verifies it against
the person's current registered status. Both recheck the link on routine
admission. Checked input ports do not stand in for that acquisition.
`prepare-read` cases read revision 0 (first grant) and 7 (replacement) from the
enforcer-built 428's unchanged R. Replacements advance the per-enforcer
(organisation, person, root_id) grant revision once, including empty withdrawal;
idempotent retries do not advance it. aw evidence-only uses revision 0.

Team IDs are sorted, unique lowercase `name:domain`, with dot/underscore name
neighbors, 128-character name and 128-entry list boundaries. The one lexical
profile is in the act schema; both languages use SDK Parse/Build canonical
equality, without narrowing the released SDK parsers. Person/root ID and
Ed25519 root-key patterns are checked before presentation. The act schema's
local `$defs` are inside the definition hash, so changing a referenced lexical
rule changes the definition too; no global uncommitted rule can change a
published definition under its existing hash. The two malformed-byte cases
pin `invalid_encoding` for authenticator data and `presentation_invalid` for
presentation request bytes in both languages.

The local-root live/historical cases use an independently SDK-checked
RootIdentity with id=current_key and continuous_keys=[id]. The local key must
also equal R's root_id; a different root_key refuses `root_key_mismatch` in the
shared definition check. A did:key person remains `definition_invalid`.
`unsorted-and-foreign-teams` pins whole-list sortedness before per-team domain
checks in both languages; it refuses `definition_invalid`.

`later-enrollment-v1.json` pins the distinct enrolled-later statement and
activation v2; `later-lifecycle-v1.json` reuses replacement/recovery without
inventing a creation claim. `pending-person-v1.json` pins mapping-only ownership
for a pending person's own enrollment routes, including the four scope/key
refusals. `enrollment-authority-v1.json` checks binding issuers from independently
verified namespace and parent authority, never a supplied key.

`enrollment-boundaries-v1.json` covers the malformed intent-certificate boundary
for both creation and later enrollment, at both intent and activation entry
points, and the challenge/confirmation-byte refusal codes. An activation body's
schema error is `activation_invalid`; a malformed certificate inside an otherwise
valid intent is `enrollment_invalid`. No caller may rely on a panic as refusal.
