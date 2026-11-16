# Approval service

Exact human approval using enrolled keys. The service holds no organisation
private keys and performs no application effects. Enforcers verify receipts
under their own rules. Implementation follows the approved architecture and
approval protocol; releases are held.

Receipt verifiers take independently checked `Trust`; a binding carried in a
receipt is not its own trust anchor. Python `approval_service.trust.read_trust`
and Go `verify.ReadTrust` obtain public ID status and DNS authority through the
configured AWID SDK resolver (Python uses the production 0.5.39
`CachedRegistryClient` with Redis), then use the single chain-to-trust implementation
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
