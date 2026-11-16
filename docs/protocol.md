# awsign approval protocol — approved revision 3

This protocol keeps independently checkable human approval separate from
organisation keys and application permission. Closed wire layouts, domains,
key limits and the shared Python/Go cases live in `format-v1.json` and `vectors/`.

The hosted service is **awsign** at `https://awsign.com`, with WebAuthn RP ID
`awsign.com`. The repository is `awebai/approval-service`. Moving an established
enrollment to a different origin or RP requires reenrollment; changing
configuration or redirecting does not migrate a binding.

## Read this first: five objects

1. **The act request:** the enforcer makes it for one caller and one named
   person. It fixes the act, enforcer, nonce and deadline; the caller carries it.
2. **The enrollment binding:** the person's issuer signs which approval keys
   belong to that person's current identity key, with a grade for each key.
3. **The assertion:** the person's enrolled key signs the request's challenge
   at the approval site with user verification. It contains no act text.
4. **The receipt:** the caller joins its request, the assertion, and the
   issuer-signed binding/chain returned by the service; the enforcer checks it.
5. **The identity evidence:** the issuer records creation and later changes,
   referring to receipts; it travels beside the unchanged ID chain.

Ordinary request -> assertion -> receipt -> evidence; the binding is a separate
issuer-signed input to the receipt, not a receipt's reference back to itself.
Digests name these objects; they do not replace them. Neither statement grants
an app role. The enforcer owns the rule and effect; no new registry record.

## 1. Authority

The registry continues publishing existing public identities, chains and
certificates. It neither records nor vouches for key custody or a protection
mode. The approval service obtains proof of an exact act. The enforcer owns
eligibility, requirements and the effect. A key holder, when used, owns org keys,
its signing rules and audit. The approval service holds no org signing key and
does not execute or confirm the application effect.

## 2. People, sign-in and enrollment

An enrollment belongs to exactly one canonical person ID and its current ID
certificate/key. There is no hosted-service account linking that person's IDs
across organisations, combined pending list, shared recovery account, email
address, phone number or cross-ID lookup. A person with IDs in two organisations
has two enrollments. Each gets fresh credential material and a fresh opaque
WebAuthn user handle; do not reuse a credential public key/ID or derive a handle
from a natural-person identifier across them. The service offers no account-link
or same-human discovery feature. Network timing remains an observation of the
operator; the protocol does not promise anonymous network access.

Sign-in uses an enrolled key, with UV, and nothing else. A session names that
exact person ID/enrollment/current identity key and original session deadline.
No password, emailed link, identity-key signature alone, operator reset, or
mail-based recovery can sign in. LOGIN is separate from act approval: each act
requires its own exact-request assertion with UP and UV. The pending list and
all session operations are scoped to this enrollment, including after awaits.

Initial enrollment is an organisation-authorised bootstrap ceremony, not an
alternate sign-in. The issuer's own authenticated page or command directs the
person to the named approval-service enrollment page. This first-arrival
instruction is distinct from an act-waiting notice, which never has a link.
Arriving there grants nothing: an invitation cannot sign in, approve an act,
choose another person/certificate, or activate an enrollment. The person still
checks the service origin before registering a key.

 one enrolled key is required; a second is strongly
recommended and offered in the same flow. Losing the only key uses assisted
continuity or recreation, never a weaker sign-in. Keys may have different
grades: each credential has its own grade and snapshot reference.

The service holds new credentials pending for the exact proposed person
certificate/identity key and original deadline. They become usable only when
it observes that issuer's committed public certificate and matching signed
evidence naming those credentials, presented by the issuer or person. Pending
enrollment proof-of-possession ceremonies are not ordinary signed-in sessions.
An unconfirmed pending enrollment expires at its original deadline. Once its
confirmation is approved, its pending credentials remain usable for ACTIVATION
only: browser, material, confirmation and sign-in gain no deadline extension.
A new enrollment start for that person after the deadline replaces the old
pending generation; otherwise the sweep removes it 30 days after that deadline.
Activation ends pending retention by making the enrollment active. The raw
assertion's retrieval window still ends at the original deadline; the requester
must retain the creation receipt it already obtained.
This is one-directional observation:
no issuer/service prepare/commit protocol or mutual commit acknowledgment.
For activation only, the authenticated carrier may be the intent's original
requester or an identity descriptor naming that exact person and Trust's current
identity key, signed by that key. Another member, a non-current key, or a
controller other than the original requester cannot carry activation. The
intent, confirmation request, polling and assertion recovery keep the original
requester unchanged. The carrier grants neither sign-in nor approval authority.
Section8 specifies an acyclic binding/proof construction, including bootstrap.

The identity key and the enrolled approval keys are different keys. Replacing
or withdrawing an enrolled key changes the person's identity key and evidence
epoch. Between an issuer's identity-key transition and the service observing the new binding, the service may still accept the withdrawn key; the enforcer's current-identity-key check refuses its receipts, so prompt notice to the service is not a security requirement.
Another person's approved assistance is visible assisted continuity.
Complete loss by a sole human requires organisation-authorised recreation,
visible as recreation. Neither flow authenticates as the lost enrollment, and
email recovery supplies no approval. Later enrollment cannot improve an ID's
original creation grade. Sole-human recovery keeps the same stable person ID
only when the previous identity key can sign the ordinary log rotation. Before
recovery enrollment starts, the new identity key must already be current in
the registry. The new evidence records a recovery break and a new creation by
recovery; it carries no old creation grade into that event. The original event
is not rewritten. If the identity key is also lost, the organisation revokes
the old ID and issues a new person ID: its authority cannot rotate the old ID. Details of who may assist remain the issuer/enforcer's rule.

An origin or RP migration cannot preserve a binding by redirecting, changing
configuration, accepting a related suffix, or relabelling signed evidence.
Reenroll at the new origin; issuer evidence identifies the actual new binding
and its continuity. Pin an exact HTTPS origin and RP ID, with no broad origin
allowlist. Cross-origin frames and cross-origin WebAuthn ceremonies are refused.

## 3. The requester is the caller, not the enforcer

The requester is the agent, command or person's session that wants the act.
The enforcer authenticates that caller, checks whether it may ask, builds R,
and gives it back with "this needs a human". That same caller signs submission
to the approval service, polls for the assertion, builds the receipt, and
presents it back. Enforcers never contact the approval service and need no
account, client credential, installation record or standing there. **No new
registry record is added.**

A registered requester proves one of these public relationships to the person's
**exact namespace**, never a common ancestor or shared hosted parent:

| Canonical requester descriptor in R | Public admission evidence |
| --- | --- |
| `team_member`: exact team_id, certificate_id, member did:key | Presented signed team certificate for a team whose domain equals the person's namespace; exact anonymous certificate-status read supplies team_did_key and active status; verify certificate and possession under those keys |
| `identity`: exact identity ID and current did:key | Valid public ID chain rooted at that exact namespace and current subject key/status; a chainless local key does not qualify under this route |
| `namespace_controller`: exact namespace and controller did:key | Current DNS/delegation-verified controller, with the narrowly authorised bootstrap of that exact person's ID; never controller status at an ancestor alone |

Certificate-only requesters need no ID chain and work on private teams. Use
`GET /v1/namespaces/{domain}/teams/{name}/certificates/{id}/status`, not GET team,
not a member roster, and no stored member credential at the approval service.
The response key/status plus presented certificate must match exactly; cache
by exact certificate for at most60seconds. This registry-supplied team key is
for REQUESTER ADMISSION ONLY, keeping strangers out of a pending list. It must
not become an authority check at an enforcer: those decisions use that
enforcer's admitted team key and the authenticated transition model.
Existing public source:
`docs/awid-sot.md:724-738`; `awid_service/routes/teams.py:1128-1170` at DAB.
This establishes membership, not a portable claim about private-key custody.

A global member whose ID is rooted elsewhere but whom the org admitted to a
team in this namespace qualifies by the team-certificate route. A sibling-org
member without that admission does not. A parent controller such as aweb.ai or
a customer apex never qualifies for a child's people merely through parent
control. The exact person's authorised ID issuer has only the specific
bootstrap exception, not a blanket requester exception for the child's acts.

Select ONE descriptor when the enforcer authenticates the caller; it is covered
in R and used unchanged at submission, polling and receipt presentation. No
alias, address, did:aw/did:key conversion or switch to a different certificate
may change that equality. Submission and polls prove possession of the exact
key named in that descriptor using a purpose/freshness/HTTP-bound signed
request. The service verifies both the descriptor and signer equality with R.
A peer from the right org cannot carry a request naming somebody else.
Key rotation never silently relabels an already frozen descriptor.

The requester chooses ONE person ID to ask. The enforcer lists the allowed
approvers as public person IDs when the caller does not know whom to ask,
then checks the chosen ID against its rule and builds R for that person only.
No union of possible approvers or race to claim a request. Asking another
person is a new request with its own enforcer value; never retarget the old R.
This discovery comes from the enforcer, not an enrollment/grade lookup at the
approval service. The enforcer needs no binding, credential or grade data to
build an ordinary request.

Public observations bind origin, subject and acquisition time, with at most
60seconds age at admission and decision; no grace or positive inference on
unavailable evidence. Recheck after waits before an actionable decision. A
failed refresh cannot move a request to another org. Bound submissions, polls,
queues and public lookups per requester/org; do not enumerate all people or
invalidate a shared cache. None of this adds an ordinary messaging warm path.

The service cannot verify an enforcer's private MAC. A same-org member can
submit an INVENTED request matching a bundled definition; its receipt is
worthless to the enforcer, which refuses its MAC. Issuers publish evidence
only after checking their own nonce and act. The remaining nuisance is bounded
pending-list noise, not another authority gate at the service.

### Requesters for the first two gates

| Gate | Requester carrying R and the receipt | Enforcer / public requester link |
| --- | --- | --- |
| Add a human, command | Authenticated administrator's own identity or team-member key; first-person bootstrap uses the exact namespace controller through its administrator command | Org key holder; requester ID chain, team certificate/status, or exact bootstrap controller evidence above |
| Add a human, hosted dashboard | The signed-in person's OWN namespace identity, signed by Cloud with that person's identity key | Org key holder; that person's exact-namespace ID chain/current key; key holder is never the dashboard requester |
| Secrets read-write, agent/command | The authenticated agent/member/caller that asks Secrets for the key | Secrets; the caller's presented team certificate/status or exact-namespace ID chain, not Secrets' service identity |
| Secrets read-write, hosted dashboard | The signed-in person's OWN namespace identity, signed by Cloud with that person's identity key | Secrets; the same person's exact-namespace ID chain/current key |

A browser login alone is not an identity-key signature. Cloud's web may submit
as hosted people under its identity-key custody; it cannot approve as them
without their separate enrolled-key UV. This states the accepted hosted limit,
not an in-process org-key signer or a new custody implementation. An enforcer's
own service identity/manifest cannot replace the caller descriptor. Existing
team-server records advertise a coordination URL; team-server installations
are authenticated app state, not a missing public requester delegation that
must be added (`docs/awid-sot.md:773-819`; `docs/app-registry.md:26-36`).

## 4. Complete request and byte commitment

One immutable request contains the following closed fields. Bindings are not
optional transport hints; they are in the bytes the enrolled key approves.

| Field | Meaning |
| --- | --- |
| `version`, `purpose` | New format version1; ordinary `act_approval`, or limited `enrollment_confirmation` under section8, never LOGIN or old B2 wire |
| `organisation` | Person's exact canonical namespace, not a shared delegation root |
| `approver` | ONE canonical person ID in the exact namespace ONLY; no enrollment binding digest, credential, certificate or current key. Issuer-built transition/creation details belong inside act.target |
| `requester` | ONE canonical key-level descriptor from section3, set by the enforcer from its authenticated caller and matched at all three boundaries |
| `enforcer` | Stable enforcer audience plus its key/service binding, not an arbitrary callback URL |
| `definition` | Fixed act-schema/display identifier, version and content digest |
| `act` | Complete operation, distinct target subject/certificate/key, resource, rights and expected state/revision; any proposed AFTER binding is covered here |
| `not_before`, `deadline` | Original UTC bounds, not renewable on retry |
| `nonce` | Enforcer value and its key-version selector |

In v1, trusted act definitions are bundled with the approval-service release
for add-human and Secrets read-write. There is no network definition fetch,
requester-authored HTML/prose or customer-signed definition extension in v1.
Each definition declares a closed act schema and fixed names,
consequences and technical fields. Unknown fields/definition versions refuse;
defaults are resolved before commitment, never after display. The service
does not infer application permission from the definition or substitute its
own policy for an enforcer's requirement. Any rule revision or expected state
needed by that enforcer must be part of `act`.

Proposed byte profile: reuse the B2 canonical JSON profile, with its existing
positive/negative bytes, not the hooks' different ASCII-only/no-null profile.
UTF-8, Unicode-code-point object-key order, array order unchanged, compact
separators, exact existing escaping and safe integers with magnitude at most
2^53−1. The permitted RAW number grammar is `-?(0|[1-9][0-9]*)`, with `-0`
separately refused. Reject every decimal-point or exponent token (`1.0`, `1e0`,
`1E+0` included), even when its value is an integer, BEFORE parsing normalises
it. Reject duplicate members, malformed Unicode/text and unsafe integers too.
Unicode
and explicit null are allowed only where the new schema permits them; required
fields cannot be omitted, unknown fields refuse, and null never defaults to
omission. Time fields are integer Unix seconds, no alternate textual timestamp
forms. Request body limit64KiB/depth32 and receipt limit1MiB are proposed bounds
for shared vectors; nested certificates retain their own version's validation.

Strict transport JSON is parsed/validated then canonicalised; transport
whitespace is not signed. Receipts carry
`request_bytes = canonical_json(request)` in the binary
encoding defined below. Verifiers require decoded bytes to equal their strict
canonical re-encoding, then add the prefix below exactly once. Define:

```
R = UTF8("aweb.human-approval-request/1\n") || canonical_json(request)
D = SHA256(R)
WebAuthn act challenge = D
```

These are proposed NEW domains, deliberately distinct from existing
`aweb.approval-request/1` and `aweb.approval-challenge/1`. LOGIN and enrollment
use separate versioned purpose preimages and unpredictable one-time challenges;
neither can validate as `act_approval`. Limited `enrollment_confirmation`
cannot authorise any application effect or bootstrap a normal session.
All rule/approver/definition/nonces and
enforcer fields above are covered. Do not substitute a service operation ID,
display summary, hash of a subset, or approval-service nonce for R.

The enforcer computes its nonce with a local secret and domain-separated HMAC
over the canonical request core (all fields except nonce) and secret-key version.
It keeps no issued-nonce list. The nonce-key selector is an input to the MAC,
not authority to choose another enforcer. Secret rotation may verify original
unexpired requests under retained old versions; it never extends deadlines.
Nonce construction/key-rollover vectors belong to the format review with the
enforcer owners. No approval-service secret or registry field establishes it.

## 5. User flow and decision transaction

The caller selects one allowed public person ID, obtains R from its enforcer
and saves the exact request bytes before submission. If it needs choices, the
enforcer lists the public person IDs allowed by its rule. A different chosen
person requires a new request, never a new destination for the existing R.
No caller/enforcer lookup for enrollment bindings is required. The caller
signs R's descriptor/D to
submit, then polls using the same descriptor and D. The service never sends R
or an assertion to the enforcer.

The approval service sends nothing to anyone: no mail, SMS, push, webhooks,
outbound receipt delivery or callback to requester-supplied URLs. It stores no
contact channel for a person. The requester may give a notice through its own
existing channel, containing neither a link nor any detail of the act. The
person opens their known approval-service address independently. No old mailed
handoff links or copyable terminal approval links are part of this protocol.

The enrolled-key session sees only its person ID's pending requests. A page
shows authenticated requester/org, exact fixed act, expected rights/state,
deadline and full request commitment. It loads no third-party scripts; scripts,
styles and other page assets are local, with a restrictive CSP and no framing.
No external analytics, tag manager or remote definition asset can enter the
page. Same-origin closed bodies, CSRF and exact session binding apply to
decision routes. Sign-in and the act are visibly distinct ceremonies.

The service validates the raw assertion, credential state, exact frozen R,
session, current admission and original bounds, and atomically consumes its
challenge and records one decision with the bounded raw-assertion slot in
section6. No requester connection is required to be open when the person
approves; the original deadline bounds later retrieval. After the last awaited
input and while
holding the decision lock it rechecks local session/credential validity,
deadline and terminal state. Failed/expired checks roll back the decision;
a duplicate decision cannot create a second receipt or new challenge window.
Counter verification preserves legitimate zero/zero authenticators; it is not
an unconditional strictly-increasing counter rule. Denial and unsigned expiry
create no approval proof.

Decision state is `pending -> approved | denied | expired | cancelled`.
`approved` means an exact UV assertion was accepted, not that an application
executed. Requester-only cancellation and identical submission retries are
bound to the original authenticated principal and digest. A changed request
under an existing operation locator conflicts; a retry cannot renew bounds.
The retained terminal digest/outcome prevents a terminal operation locator from
restarting. The minimal audit index binds that locator to D without storing
act detail; its exact schema is part of the retention review.

## 6. Receipt, bounded assertion recovery and retention

The caller owns R. The service holds the issuer-signed enrollment binding from
enrollment and returns that binding and its public chain with the raw assertion
to the same authenticated caller. Its full portable receipt is
canonical request_bytes plus the original raw assertion (clientDataJSON,
authenticatorData, signature and credential selector), the approver chain and
the nonrecursive issuer-signed binding B from section8. The enforcer did not
need B in advance. It verifies its issuer signature, exact requested person,
that person's CURRENT identity key and the asserting credential entry; no R
commitment to H_B is needed for ordinary acts. The caller assembles
and stores this receipt after fetching the assertion. The service responds to
authenticated polls; it never delivers anything to the enforcer or a callback.
A browser/session/locator is not evidence of approval. The service's assertion
slot contains no act fields, display text or full request bytes.

All binary fields use canonical unpadded base64url, with strict decoding and
re-encoding equality.  accept ES256/P-256, EdDSA/Ed25519 and
RS256/RSA, tagged by the trusted bound public COSE key. Require the correct
algorithm/key/signature form; a global Ed25519 length check is wrong for the
others. Reject private COSE parameters, duplicate CBOR keys/trailing objects
and unsupported algorithm/key combinations. Preserve the original raw signed
clientDataJSON/authenticator bytes without reserialising them. Credential IDs
are selectors, checked against issuer-bound credentials, not signed authority.
WebAuthn verification follows the [W3C assertion procedure](https://www.w3.org/TR/2026/REC-webauthn-3-20260825/#sctn-verifying-assertion).
Exact RSA parameter limits and cross-language vectors are format-review work.

A complete receipt commitment uses its own domain prefix and canonical receipt
envelope, never bare concatenation of variable-length proof fields. The exact
preimages for B, R/D, receipt and final evidence are separated in section8.

| Service data | While pending | After decision, before ORIGINAL deadline | At/after deadline |
| --- | --- | --- | --- |
| Full request/act/display | Private pending ceremony | Erased from live storage, queues, caches, logs and telemetry | Absent |
| Raw assertion | Verified at decision | Original clientDataJSON, authenticatorData, signature and selector beside D | Erased; no retry extends it |
| Tombstone/audit | Pending D | D, requester-binding digest, person, times/deadline, outcome and proof commitment; no act detail | Minimal audit under normal retention; no assertion |
| Full receipt | Caller will assemble it | Requester's record, never a service act/history archive | Requester's independent historical proof |
| Enrollment/attestation | Separate private lifecycle state | Separate private lifecycle state | Not a hidden app-act archive |

At decision commit, freeze an access-control commitment to the EXACT canonical
requester descriptor the service admitted for D, and its original deadline.
A poll proves possession under that descriptor's exact key and the same
submission origin/purpose/freshness discipline. Service compares its requester
commitment, D and the owned operation locator, checks the current public
requester evidence, and returns only its outcome/raw assertion. Knowing D or
being another member/person/approver is insufficient. A changed descriptor,
key, namespace, D or locator does not adopt the record. The minimal slot
supports these checks without retaining the full act or app record. It also
names the original immutable enrollment-binding version selected at decision,
so polls return that same B/chain with the same assertion. B is enrollment
state, not an act archive. A poll returns that original binding, not a later replacement. A requester may
repackage the assertion with a later current issuer-signed binding that still
lists the signing credential, under the construction rules below. Live enforcer
currency checks may refuse the saved old binding even though its historical
proof remains valid.

Recovery cases are explicit and require no second approval:

- Requester never connected when the person approved: later same-requester
  poll before deadline retrieves the assertion and its issuer-signed binding.
- Requester disconnected before decision commit: the person's decision may
  commit independently; that requester later polls the same D/locator.
- Poll response lost after commit: repeat the authenticated poll, obtaining
  identical raw assertion and binding, not another ceremony.
- Original deadline reached: erase the assertion; an approved audit can report
  `receipt_unavailable`. No effect can newly use the expired request. This
  erasure does not invalidate a requester's independently saved historical proof.

Decision and HTTP delivery are separate failure points. Atomicity is between
challenge consumption, terminal outcome and the bounded assertion slot, not
between SQL and network delivery. No live-receiver prerequisite, handoff
protocol, outbox, retained effect or full-act archive is introduced. A caller
that lost its own R cannot recover the act from the service. The enforcer must
have the actual complete receipt and its own expected request before acting;
unknown answers never justify another UUID or automatic reapproval.

Full pending acts leave live storage at the terminal decision. Backups age out
under ordinary deployment backup rotation; there is no per-row crypto-shredding
or special key-disposal protocol. Terminal person history may show digests,
time and outcome, never reconstructed act titles/resources. The issuer owns
its public identity-event proof; application callers own their private acts.

WebAuthn provides no trusted signing timestamp. Service time is audit
attribution; live enforcers enforce the original deadline using their own
clock, and record effect acceptance. Historical verification uses explicit
trust/as-of inputs, never a signature-inferred signing time.

## 7. Certified-hardware starting rule and MDS

Every accepted ceremony requires UP and UV. Certified hardware additionally
requires a verified attestation path to a model root in the pinned, dated
metadata snapshot; an applicable certification; no applicable trust-withdrawing
status; and a credential reporting single-device/non-backup eligibility, checked
again in assertions. Enterprise attestation is refused, not downgraded. Valid
UV credentials without the additional hardware evidence get `passkey_uv`;
invalid proof or missing UV is refused, never relabelled a weaker success.

Starting policy for review: require **FIDO_CERTIFIED_L1 or a stronger FIDO
Authenticator level**. L1 is the lowest modern authenticator-security level;
do not treat older functional-only FIDO_CERTIFIED, a vendor self-assertion or a
FIPS label alone as equivalent. This is a proposed minimum, not a claim of
physical tamper resistance. Interpret certification/status applicability to the
attested model/version/key; an unknown applicability cannot earn the hardware
grade. The metadata semantics come from [FIDO MDS3.1.1](https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#authenticatorstatus-enum).

Grade/snapshot belong to the selected credential, never a maximum grade over
the person's keys. The hardware grade is the issuer's signed claim, checked
by the approval service at enrollment. Public v1 verifiers authenticate that
claim and its binding to the assertion; they do not inspect private attestation.
The service/issuer's private attestation-check type is not a public verifier
result. A compromised approval service cannot label a software key as hardware or
reuse an attestation from another enrollment when the issuer performs the
independent registration check below. It can enroll genuine hardware held by
an attacker: first enrollment relies on the organisation's authorization for
which physical key belongs to the person. A certified-hardware rule refuses
software keys; UV alone never raises their grade.

The issuer supplies one fresh registration challenge for the exact person and
pending certificate. The service uses it for WebAuthn.create; service and
issuer verify the SAME raw registration response with the shared verifier.
Before signing hardware grade, the issuer independently checks format, chain,
its pinned MDS snapshot/model status, backup flags, challenge and exact site.
Without that check it signs passkey grade at most. Raw attestation stays private.
There is no second registration. The subsequent enrollment_confirmation get
assertion over B in §8.1 remains unchanged .

Snapshot input must pin the signed BLOB bytes/hash, signing trust roots,
sequence, issue/retrieval dates, `nextUpdate`, model entries and policy version.
Metadata bytes are fetched from the published URL into an external cache,
checked against the pinned hash/root, and never committed or redistributed here.
An expired supplied snapshot refuses enrollment (`snapshot_expired`), rather than
silently assigning a permanent lower grade. Effective unscoped withdrawals end
model eligibility regardless of firmware; certificate scope remains specific.

Verify before installation; reject rollback, untrusted replacement and expired
eligibility data. Do not fetch MDS during each approval. Preserve earlier
snapshots for historical verification without letting them restore current
eligibility after a trust withdrawal. The actual initial snapshot/hash and
status/refresh policy are review inputs still to select; there is no fabricated
snapshot in this document. Raw attestation remains private and scoped per
enrollment. Accept only attestation profiles whose privacy can be established;
never publish a unique device certificate or import enterprise-identifying
attestation under a different name.

The grade is an issuer-signed enrollment claim anchored to that evidence. A
public verifier authenticates the trusted issuer's claim and raw act assertion,
not the private hardware chain. A software authenticator proves only passkey
grade in the acceptance journey. No proof promises that the person understood
the act, that the page/computer displayed it honestly, or that the real service
was uncompromised.

## 8. Acyclic enrollment/evidence commitments and verifier results

The approver and the target subject are DIFFERENT fields. An agent adoption
request names the approving human in `approver` and the agent certificate/key
in `act.target`; the agent is never treated as a human approver. Creation,
adoption and key-transition proofs are complete public identity acts, separate
from private application receipts. Never redact a private receipt to make a
public proof or publish its resource names/device attestation.

### 8.1 Artifacts and exact dependency direction

Use the section4 canonical profile and binary encoding. The following NEW
preimages are proposed for the format review; each literal prefix ends in one
newline byte. Existing ID-certificate signatures/digests remain unchanged.

| Artifact | Closed content / preimage |
| --- | --- |
| Enrollment binding body `B_body` | Version, exact namespace, person ID, exact proposed/current certificate digest and identity key, origin/RP, and credential entries: selector, public key, per-credential grade, snapshot reference or null, grade-policy version. NO receipt/proof/final-sidecar digest or outcome |
| Signed binding `B` | Issuer signature over UTF8(`aweb.human-enrollment-binding/1\n`) + canonical_json(B_body); issuer comes from independently checked exact-person issuer authority |
| Binding commitment `H_B` | SHA256(UTF8(`aweb.human-enrollment-commitment/1\n`) + canonical_json(B)), including issuer selector and signature |
| Approval `R/D` | Section4 preimage: ordinary approver is person ID only. For issuer-built identity creation/transition, BEFORE/AFTER binding commitments are inside act.target. D hashes R |
| Receipt `C` | Closed version/request_bytes/raw assertion/approver chain/B envelope, NO resulting evidence sidecar or self-reference; H_C = SHA256(UTF8(`aweb.human-approval-receipt/1\n`) + canonical_json(C)) |
| Evidence `E_body` | Exact subject certificate/key/kind and issuer; person B/H_B or agent-link approving-human B reference; creation credential/grade claim and proof commitments; prior-evidence/transition commitments. No own resulting signature/digest |
| Signed sidecar `E` | Issuer signature over UTF8(`aweb.human-id-evidence/1\n`) + canonical_json(E_body); H_E = SHA256(UTF8(`aweb.human-id-evidence-commitment/1\n`) + canonical_json(E)) |

Creation/transition receipts are supplied alongside their digest references in
a bounded proof collection; the digest alone cannot establish proof validity.
Ordinary dependencies are R -> assertion -> C -> E, with B as an independent
issuer-signed input to C. For issuer-built creation/transition, B_BEFORE and/or
B_AFTER may precede R as explicit act.target commitments. E may refer to a
PREVIOUS E, never itself or a future artifact. R never commits resulting E.
Reject cyclic/inconsistent references and bounded-input exhaustion. Canonical
body and envelope definitions above have separate purposes; signatures never
cover a structure containing their own resulting signature or digest.

**Bootstrap construction:** the exact authorised issuer first prepares the
proposed person certificate/identity key. The service holds registered
credential/public-attestation inputs pending. The issuer may sign B for this
exact pending certificate and registered keys, without claiming activation or
creation approval. This pending B is authorised enrollment data, not proof of
current person membership or prior enrollment. The same person proves
possession/UV of the actual creation credential over an
`enrollment_confirmation` request naming its person ID and committing H_B
and the proposed certificate INSIDE act.target, built by that exact issuer.
It is a limited bootstrap ceremony, not ordinary LOGIN or application approval.
The issuer independently verifies that proof and its OWN nonce, commits its
person certificate, and signs E referencing B and that creation receipt. The
service observes the committed certificate plus matching E, then activates.
The shared activation verifier checks I and the saved creation proof without
their ceremony deadlines once evidence exists; it still requires fresh current
public Trust. Binding, material and confirmation remain deadline-bound.
It does not require the as-yet-unissued E or an active person status as input
to the pending ceremony. No issuer/service two-phase commit is introduced.
If org policy requires another person's consent to add a human, that is a
SEPARATE ordinary act-approval receipt by the already active human, checked
by the key holder. It cannot replace the new person's own creation ceremony
or raise the new person's creation grade. Incomplete observations expire or
remain inactive; they never acquire ordinary session/effect authority.

**Normal act:** `approver` names only the existing person ID. The service
selects its current issuer-signed B and returns B with the assertion. C carries
that B, not an E that later embeds C. The enforcer checks issuer, requested
person, current identity key and selected credential itself. E may be supplied
separately for continuity/creation checks; no bare-ID evidence lookup exists.
Another credential in B cannot lend its grade to the key that actually signed.

**Identity/enrollment transition:** the issuer builds act.target naming the
exact BEFORE certificate/person key/H_B_BEFORE and the exact AFTER certificate,
identity key/H_B_AFTER. The approver field remains one person ID. For a same-person transition, the assertion uses a key in the target's
B_BEFORE, which C carries. For assisted recovery, the approver is the helper's
person ID: the assertion and binding carried by C are the helper's current
ones, while act.target still names the recovering target's BEFORE and AFTER.
The helper must never be relabelled as the target or as unbroken continuity. B_AFTER is constructed
without its resulting
transition receipt. The issuer checks its nonce and current transition rule,
then issues E_AFTER referencing H_E_BEFORE and C_transition. Replacing or
withdrawing an enrolled key changes the person's identity key; ordinary
receipts bound to BEFORE stop being current. A same-human prior-key proof
supports unbroken continuity; assisted recovery identifies that different
human approver and is reported assisted; a known missing required approval
ends continuity. Missing historical inputs mean unknown, not proven broken.

Each credential entry in B has its OWN grade and snapshot. The grade for a
receipt is the grade of its actually selected, proven key. Two keys may be
passkey/certified-hardware: using the passkey never inherits the other key's
grade. Creation grade comes from the new person's actual creation assertion,
not the strongest currently enrolled key or the grade of an assisting human.
Later enrollment cannot upgrade how an ID was created.

### 8.2 Public v1 result: authenticated facts only

One shared Python/Go result separates statement status, proof status,
issuer-authenticated grade, whether proof binds that grade, currentness and
continuity. No unauthenticated `claimed_grade` and no public
`attestation_assessment` field: no v1 outside consumer holds private
attestation. The hardware grade is the issuer's signed claim, checked at
enrollment by the approval service. Its private verifier uses its own internal
type. Public results never say that they inspected that private chain.

ID-chain validity/responsibility, message verification and aw verify exits are
independent of every evidence outcome. No aggregate `authorized` boolean.
These exact enum/nullability proposals retain the independent checks without
promoting an unauthenticated statement or missing proof:

| Field | Values / nullability |
| --- | --- |
| `link` | Exact checked chain position, certificate digest and subject ID/key, always THIS link |
| `approving_person` | Human ID/certificate/key established by this event's proof, or null; distinct from an agent target |
| `presence` | `absent` or `present` |
| `statement.status` | `not_evaluated`, `valid`, `invalid`, `unavailable`, `unsupported` |
| `statement.reason` | `missing_statement`, `checked`, `malformed`, `signature_invalid`, `binding_mismatch`, `trust_input_unavailable`, `unsupported_version` |
| `proof.status` | Independently `not_evaluated`, `valid`, `invalid`, `unavailable`, `unsupported` |
| `proof.reason` | `missing_statement`, `statement_unverified`, `checked`, `absent_proof`, `malformed`, `signature_invalid`, `binding_mismatch`, `trust_input_unavailable`, `unsupported_version`, `unsupported_algorithm` |
| `issuer_authenticated_grade` | `passkey_uv`, `certified_hardware` or null; non-null ONLY with checked issuer signature and exact subject/certificate/credential binding |
| `proof_binds_grade` | true ONLY if a valid raw proof selects that authenticated credential/grade; false on a checked mismatch/invalid proof; null if proof was absent, unsupported, unavailable or not evaluated |
| `credential` / `snapshot_ref` | Exact credential/event selector and its authenticated model-snapshot/policy reference, or null; never another listed key's grade/snapshot |
| `currentness` | `current`, `not_current`, `unknown`, `not_evaluated`; includes checked identity key, as_of/status observation and trust references |
| `continuity` | `unbroken`, `assisted`, `recreated`, `broken`, `unknown`; since or null, with supporting transition references |

The fields describe one creation/adoption/transition event. JSON may list its
separately checked credential/transition entries using this same result shape;
there is no person-wide maximum grade. The default line summarises this link's
creation/adoption claim, not the strongest current credential. Current
receipt verification selects the actual signing credential in B. Later
stronger enrollment never raises creation's grade.

Absent evidence means statement/proof not_evaluated/missing_statement, grade
and credential/snapshot null, proof_binds_grade null, currentness not_evaluated,
continuity unknown. A present malformed statement is invalid/malformed, with
no grade. A failed issuer signature or subject binding yields no grade at all.
Unavailable trust inputs are not a manufactured invalid signature. Unsupported
versions are reported unsupported without interpreting their grade fields.

If the issuer statement authenticates but its creation receipt is absent,
keep its issuer_authenticated_grade, with proof unavailable/absent_proof and
proof_binds_grade null. This supports "issuer states", not "created with".
A bad assertion has invalid proof; a new unsupported algorithm has unsupported
proof; missing trust inputs are unavailable. None is an invalid message or
ID-chain signature. Missing history is unknown; a known identity-key change
without its required approval ends continuity. Saved historical integrity and
current usability remain separate facts.

### 8.3 Export parser and release boundary

**Required before the first aw release containing verify:** adck reserves the
optional adjacent `evidence` member of export envelopev1. Coordinator owns the
release ordering, independently of adcl.5 implementation. Keep signed_payload,
encrypted_envelope and id_chain unchanged, with the existing total input limit.

Within a well-formed outer export, absent evidence is neutral; malformed,
duplicate-member, unknown-field or bad-binding evidence gives an evidence
result while preserving the independently checked message/chain result and
exit. An unsupported payload version is reported unsupported, without
interpreting its claimed fields. The parser must preserve the evidence value's
raw token boundary so nested duplicates are detected before ordinary decoding
loses them. Current DAB verify.go:96-103 uses encoding/json v1 and DOES NOT reject
duplicate outer names: the last value wins. Adck must add/test explicit outer
duplicate rejection BEFORE the first verify release, including duplicate outer
evidence members; this is a NEW parser requirement, not an existing guarantee.
Neutral evidence handling does not relax malformed outer JSON, unrelated
unknown outer fields or the existing total-size limit; those keep envelope
errors. Duplicates inside the evidence value produce an evidence error, while
duplicate outer fields produce the newly required envelope error. Unbalanced nested JSON makes the outer JSON
malformed. No catch-all converts outer parse failures into neutral evidence.

### 8.4 Default aw verify wording, one line per checked link

After the existing message/chain verdict, print one line per link, labelled by
its checked subject ID (and position where needed). Untrusted strings are
escaped for terminal display. Never use a raw unauthenticated grade. Proposed
reviewed phrases, selected in this order:

| Condition for this link's creation/adoption event | Default text after the ID |
| --- | --- |
| No statement | `no evidence` |
| Unsupported statement | `evidence version unsupported` |
| Invalid statement | `evidence invalid: <stable reason>`; no grade |
| Required issuer trust input unavailable | `evidence unavailable: <stable reason>`; no grade |
| Statement valid, grade certified_hardware, proof valid and binds grade | `created with certified hardware; proof checked` |
| Statement valid, grade passkey_uv, proof valid and binds grade | `created with a passkey and user verification; proof checked` |
| Statement valid, grade authenticated, proof absent | `issuer states <grade words>; proof not presented` |
| Statement valid, proof not_evaluated | `issuer states <grade words>; proof not checked` |
| Statement valid, proof unsupported/unavailable/invalid | `issuer states <grade words>; proof unsupported/unavailable/invalid: <reason>` |
| Statement valid but no authenticated grade for this event | `issuer statement checked; grade unavailable`; append proof status |

For agent issuance/adoption, replace "created with" by "issuance approved with"
or "adoption approved with" as its checked event states. This attributes the
human's assertion, never an agent's own physical key. Grade words are exactly
"certified hardware" or "a passkey and user verification". A statement claiming
hardware without a presented valid receipt always uses "issuer states", never
"created with". Failed proof never erases independently authenticated issuer
facts, and never inherits a parent's stronger evidence.

For a valid statement append currentness when it is not current: `not current`,
`currentness unknown`, or `currentness not checked`. Append assisted/recreated/
broken/unknown continuity and its recorded since-time if present. Do not
rewrite an unbroken historical creation claim as failed just because its key
is no longer current. `--json` retains all typed reasons, per-credential/event
results, trust/as-of/snapshot references and transition detail. Evidence
absence/failure/unsupported/unavailable cases keep the same independently
valid chain verdict and exit code. These rendering words are format-review
claims, not existing aw output or an implementation receipt.

## 9. Enforcer verification and effect

The enforcer compares the receipt to its own complete expected request,
reconstructs the challenge, verifies the raw assertion with issuer-trusted key
binding and exact origin/RP, and checks the required grade. It checks its own
MAC value, original deadline and current requirement/allowed approver. It
authenticates the receipt presenter under the SAME canonical requester
descriptor covered in R, refuses a different member/key/certificate, and
rechecks its own rule about who may receive the act. Approval-service admission
is not permission to obtain a Secrets key or add a person. A made-up MAC is
refused even if a person approved the invented request. Current
person key and team-certificate evidence must be acquired from trusted public
data no older than60seconds. For this AUTHORITY decision, membership verifies
under the enforcer's admitted team key/current authenticated transitions,
not the admission-only team key returned by a registry status answer. An unreadable rule/status is not approval. Adding
or raising requirements needs no approval; lowering/removing one satisfies the
old requirement; fixed human floors cannot be lowered.

For BOTH first gates, a person approving what their OWN agent asks for is the
main case and the default. There is NO approver-differs rule in v1. A future
version adding such a rule must compare the humans, not the identities: use
the requester's nearest human from its checked chain, rather than comparing
an agent ID, alias or certificate key with the approver. This is a note for
that future design, not a v1 refusal of certificate-only requesters.


Its effect is exactly idempotent, or it consumes the nonce atomically with the
effect. Signature success alone cannot consume a nonce or report application.
The service-local decision transaction cannot span this enforcer transaction.
Changing expected state, rights, requester, identity key, audience or deadline
requires a new exact request and approval, not reusing its old signature.
Application receipts/effect reconciliation and key-holder audit stay with their
owners; no generic service API marks external effects applied.

### 9.1 A person approves a deployment root

`agent.root.authorize@1` covers exactly `{person, root_id, root_key, mode, teams}`,
where mode is `issue` or `adopt` and teams is at most 128 distinct canonical
full team IDs in the request's exact organisation. The approver is that person.
The existing act-level `expected_revision` fences the enforcer's state.

For a holder or hosted organisation, the team-key holder/Cloud key process is
the enforcer. It owns every listed team, verifies the receipt live, and records
the entire replacement grant: this root ID may request routine admission of its
own descendants to exactly these teams. Empty teams withdraws the grant; there
is no separate revoke act and no union with the previous list. Nonce consumption
and the grant change are atomic in that enforcer. A self-held aw enforcer accepts
only `teams=[]`; its receipt is evidence, not a lock on the person's key. The
person's own identity key signs the person-to-root certificate wherever it lives.
That ordinary signing step needs no second receipt.

Adoption attaches the receipt to an existing person-to-root link. A root directly
under the organisation instead gets a person-parented certificate with the same
ID and key. A root rotates unattended through the existing SDK's checked old-key
continuity proof. The grant and receipt follow its stable root ID while the
approved root key remains in that continuous history; a different ID or broken
key history cannot inherit them. No certificate digest is added to this act, so
routine re-signing of unchanged ancestry does not require another approval.

The optional per-certificate `root_proof` profile is `{version:1, receipt:C}`.
It is distinct from the human-creation `statement` profile. Historical checking
uses the same shared verifier for holder, Cloud and aw audiences, without live
effect deadlines. It binds the exact human-to-root link, not an arbitrary
descendant with the same nearest human. SDK-checked root key history and explicit
as-of person Trust/checked lifecycle continuity are inputs, never claims accepted
from this proof. It returns its continuity basis: unbroken person continuity
keeps the root approval; assisted/recreated breaks report that the approval
predates a break; unavailable history is unknown. The since-time is that checked
history basis, not a WebAuthn signing time manufactured from request timestamps.

A person approves the root once; agents issued by agents below it carry no
additional receipt and are attributed through the ID chain. A missing root
receipt is reported without refusing a valid chain. The honest descendant claim
is that it descends from a root the person approved, not that the person approved
each descendant. Historical evidence does not assert that a team grant was
applied or that the agent currently has admission permission.

## 10. Extraction names and migration boundary

Boundaryca9a7c95 supplied the accepted adcl.2 inventory at DAB and states there
are **no approved replacement names yet**. New names are assigned on extraction,
not by in-place rename first; files that stay get renamed once, last. Proposed
initial mapping (one line per candidate/public name, not an exhaustive final
survivor certification):

| Existing file/public name | Proposed extracted name or disposition |
| --- | --- |
| `runtime/protected_signer` | `approval` package; no executor/custody/effects imported |
| `VerifiedProtectedEffect` | `VerifiedActAssertion`; opaque local verified-passkey token, not an external effect proof |
| `ProtectedKeyContext` | `ApprovalContext`; extract only person/ceremony binding, remove old custody meaning |
| `PasskeyInstallationContext` | `EnrollmentContext`; new enrollment binding, not legacy installation authority |
| `protected_signer/catalog.py` | `act_definitions.py`; schema/display portion only |
| `protected_signer/operation_display.py` | `act_display.py` |
| `assets/protected-display.mjs` | `assets/act-display.mjs` |
| `assets/protected-presentation.mjs` | `assets/approval-presentation.mjs` |
| `docs/protected-operation-definitions.md` | `docs/act-definitions.md` |
| `docs/protected-operations-v1.json` | `docs/act-definitions-v1.json` |
| generated `protected_operations` selection | generated `act_definitions` schema/display selection only |
| surviving protected-named catalog/display/request vectors | new versioned act/receipt/enrollment vectors by exact final inventory |
| `awid/protected_request.py` / `verify_protected_request` | Leave untouched in OSS until coordinated extraction; proposed requester-possession vocabulary, no effect claim |
| passkeys006 / `authority_context` storage | Preserve old B3 evidence until explicitly migrated; do not copy old schema as new-service authority |
| old `notifications.py` / mailed-link description | Superseded; no service notification replacement. Requester-owned notice contract in §5 |

The mapping above describes extraction vocabulary. The new service uses its
own schema and APIs; old protected-named files are not copied unchanged.
Deleted registry lock, service-key/effect proof, retained-effect and observation
machinery are not compatibility adapters. Old records remain old records;
do not rewrite their bytes as this new format.

## 11. Acceptance cases

- Exact-namespace ID requester; certificate-only member including a private
  team; a global member admitted by this org; sibling *.aweb.ai member without
  admission refused; parent controller without exact bootstrap authority
  refused. Use the exact public certificate status route, never GET team.
- Same-org member submitting R for a different requester refused; same D polled
  by another descriptor refused; receipt presented by another member refused.
  An invented request may receive UV but its receipt fails the enforcer MAC;
  an invented identity act never earns issuer evidence. Both gates name the
  dashboard person; own-agent requests approved by their responsible person
  are the default for both gates. No v1 different-requester/approver refusal
  or new app-installation/public registry authority is required.
- One-key enrollment works; a second is offered; loss of the only key follows
  visible assisted continuity/recreation. Two person IDs remain unlinked with
  separate credentials/handles/sessions/pending lists. Initial issuer page or
  command may direct enrollment, but arrival/invitation grants no session;
  only observed committed certificate+matching evidence activates it.
- Person-ID-only ordinary approver selection, enforcer lists allowed public
  person IDs, and changing the chosen person requires new R/nonce. No binding
  lookup at the enforcer. Service returns original B/chain with the assertion;
  issuer/current-person-key/credential checks reject substituted bindings.
- Acyclic creation construction, and BEFORE-approval /
  AFTER-certificate/binding construction for transition. No self-digest or
  previously committed target requirement. An agent adoption target differs
  from its human approver. A separate existing-human permission receipt cannot
  replace the new person's own creation proof.
- Mixed-grade credentials in both directions: passkey assertion alongside a
  certified key remains passkey; the certified key's assertion reports only
  its own grade/snapshot. Creation uses its actual assertion key; later stronger
  enrollment cannot upgrade creation.
- The page loads local assets only and matches frozen canonical bytes;
  origin/CSRF/session checks and post-wait original bounds hold. A moved origin,
  redirect or configuration relabel cannot activate old enrollment.
- Shared Python/Go/browser lexical cases: 1 accepted, 1.0/1e0/1E+0/-0 refused,
  both positive/negative safe-integer limits accepted and adjacent overflow
  refused; Unicode/null/omission, duplicates, binary trailing bits and raw
  clientDataJSON unchanged. ES256/EdDSA/RS256 positives and wrong key/algorithm,
  credential selector, origin/RP or no-UV negatives. Zero/zero counters work.
- Real certified hardware with pinned dated MDS and model/status/BE neighbors;
  enterprise attestation refused. Software authenticator proves passkey only.
  Public results report issuer-authenticated hardware grade, never a private
  attestation-assessment field. A compromised enrollment service may add a
  passkey-grade key; a hardware-required act refuses that key. Actual
  snapshot/hash remains a review input.
- Terminal live storage retains D and raw assertion until original deadline,
  never full act/display. The same requester retrieves identical assertion
  when never connected at decision, disconnected before commit, or losing a
  poll response after commit. Wrong requester/D/locator refuses; deadline
  erases assertion without renewal. Saved requester proof stays historically
  verifiable. No enforcer effect without complete receipt; no second approval
  for a dropped response. Ordinary backup rotation is sufficient.
- Same valid message/ID chain with absent, invalid, unsupported or unavailable
  evidence produces identical chain output/exits. A missing statement differs
  from missing referenced proof; authenticated issuer claim survives the latter
  but proof_binds_grade is null and default rendering says "issuer states".
  Nested malformed/duplicate evidence
  is neutral to the envelope. The NEW pre-release outer duplicate rejection
  produces an envelope error; malformed outer JSON, unknown outer fields and
  total-size violations retain their existing envelope errors.
- Original nonce/deadline across retries/rotation, replay/concurrent decisions,
  changed expected state/rights and other audiences, and effect+nonce atomicity
  with actual add-human and Secrets read-write enforcers. Rules unreadable
  refuse; a stronger requirement cannot be removed using a weaker approval.

The message-export `evidence` member is reserved before the first release
containing `aw verify`, preserving independently checked message/chain results
when evidence is absent, invalid or unsupported.

## Additional construction rules

Assisted recovery uses the HELPER's current binding/chain and assertion;
act.target retains the recovering person's BEFORE/AFTER. The approver is the
helper. Same-person transition uses its own BEFORE binding. A helper must not
be relabelled as the target or reported as unbroken continuity.

Every renderer row that prints a grade requires a non-null issuer-authenticated
grade. A binding mismatch is invalid proof and prints issuer states ...; proof
invalid: binding_mismatch, never created with. Null-grade fallback precedes all
grade-printing rows. Agent wording identifies issuance/adoption approval.

Live verification uses the CURRENT issuer-signed binding and its actual signing
credential grade. A carried-over credential may verify the unchanged assertion
under a later binding before the original deadline; this is accepted. A later
binding dropping it refuses, and a superseded binding refuses on current person
key. All three refuse after deadline. Neither R nor C requires a binding digest.
Historical verification uses the saved binding and explicit auditor as-of inputs.

The service's saved original binding is retrieval data, not a claim that a live
enforcer must reject every later binding that retains the same credential.
