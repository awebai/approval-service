# Approval service

Exact human approval using enrolled keys. The service holds no organisation
private keys and performs no application effects. Enforcers verify receipts
under their own rules. Implementation follows the approved architecture and
approval protocol; releases are held.

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
