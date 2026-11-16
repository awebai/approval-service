"""Offline, pinned FIDO MDS input. No network call occurs during enrollment."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime
from importlib.resources import files
from itertools import pairwise

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

POLICY = json.loads(
    files("approval_service").joinpath("data/mds-policy-v1.json").read_text()
)


METADATA_WARNING_SECONDS = 7 * 86400


def metadata_health(snapshot, *, now):
    """One operator warning rule, shared by the service and its monitor CLI."""
    remaining = int((snapshot.valid_until - now).total_seconds())
    warning = (
        "metadata_expired"
        if remaining <= 0
        else "metadata_expiring"
        if remaining <= METADATA_WARNING_SECONDS
        else None
    )
    return {
        "sequence": snapshot.sequence,
        "digest": snapshot.digest,
        "next_update": snapshot.next_update.isoformat(),
        "valid_until": snapshot.valid_until.isoformat(),
        "seconds_remaining": remaining,
        "warning": warning,
    }


class MetadataRefused(ValueError):
    pass


def _pairs(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise MetadataRefused("duplicate_metadata_member")
        out[key] = value
    return out


def _json(raw):
    return json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_pairs,
        parse_constant=lambda s: (_ for _ in ()).throw(
            MetadataRefused("invalid_number")
        ),
    )


def _url64(raw):
    value = base64.b64decode(
        raw + b"=" * (-len(raw) % 4), altchars=b"-_", validate=True
    )
    if base64.urlsafe_b64encode(value).rstrip(b"=") != raw:
        raise MetadataRefused("metadata_encoding")
    return value


@dataclass(frozen=True)
class Snapshot:
    digest: str
    sequence: int
    next_update: datetime
    entries: tuple[dict, ...]
    by_aaguid: dict[str, dict]
    valid_until: datetime

    def model(self, aaguid, *, now, attestation_chain=(), authenticator_version=None):
        """Return one eligible model, or None (only passkey grade is established)."""
        if now >= min(self.next_update, self.valid_until):
            return None
        entry = self.by_aaguid.get(aaguid.lower())
        if entry is None:
            return None
        statement = entry.get("metadataStatement")
        if not isinstance(statement, dict):
            return None
        certified = False
        for report in entry.get("statusReports", []):
            status = report.get("status")
            date = report.get("effectiveDate")
            if date:
                try:
                    effective = datetime.fromisoformat(date).replace(tzinfo=UTC)
                except ValueError:
                    return None
                if effective > now:
                    continue
            if status in POLICY["certifications"]:
                minimum = report.get("authenticatorVersion")
                if minimum is not None:
                    if type(minimum) is not int or authenticator_version is None:
                        return None
                    if authenticator_version < minimum:
                        continue
                certified = True
            elif status in POLICY["withdrawals"]:
                scoped = report.get("batchCertificate") or report.get("certificate")
                if scoped:
                    try:
                        scope = base64.b64decode(scoped, validate=True)
                    except ValueError:
                        return None
                    if not attestation_chain:
                        return None
                    if scope not in attestation_chain:
                        continue
                # An incident against N does not establish safety of older
                # firmware. Without a certificate scope this withdraws the model.
                return None
            elif status not in POLICY["other_known"]:
                # Unsupported eligibility information cannot establish this grade.
                return None
        if not certified or not statement.get("attestationRootCertificates"):
            return None
        return entry


def load_snapshot(
    *, blob, root_der, crls, blob_sha256, root_sha256, minimum_sequence, now
):
    """Verify supplied public artifacts before allowing any model lookup."""
    try:
        if (
            now.tzinfo is None
            or not isinstance(blob, bytes)
            or len(blob) > 32 * 1024 * 1024
        ):
            raise MetadataRefused("metadata_size_or_clock")
        if (
            hashlib.sha256(blob).hexdigest() != blob_sha256
            or hashlib.sha256(root_der).hexdigest() != root_sha256
        ):
            raise MetadataRefused("metadata_pin_mismatch")
        header64, payload64, signature64 = blob.strip().split(b".")
        header = _json(_url64(header64))
        if header.get("alg") != "RS256" or header.get("x5u") or header.get("crit"):
            raise MetadataRefused("metadata_header_unsupported")
        chain_data = header.get("x5c")
        if not isinstance(chain_data, list) or not 1 <= len(chain_data) <= 6:
            raise MetadataRefused("metadata_chain_missing")
        certificates = [
            x509.load_der_x509_certificate(base64.b64decode(value, validate=True))
            for value in chain_data
        ]
        root = x509.load_der_x509_certificate(root_der)
        chain = (
            PolicyBuilder()
            .store(Store([root]))
            .time(now)
            .max_chain_depth(5)
            .build_server_verifier(x509.DNSName("mds.fidoalliance.org"))
            .verify(certificates[0], certificates[1:])
        )
        revocations = [x509.load_der_x509_crl(raw) for raw in crls]
        validation_deadlines = [c.not_valid_after_utc for c in chain]
        for certificate, parent in pairwise(chain):
            valid = []
            for crl in revocations:
                if crl.issuer != parent.subject or not crl.is_signature_valid(
                    parent.public_key()
                ):
                    continue
                if (
                    crl.next_update_utc is None
                    or not crl.last_update_utc <= now < crl.next_update_utc
                ):
                    continue
                if any(
                    isinstance(
                        ext.value,
                        (x509.DeltaCRLIndicator, x509.IssuingDistributionPoint),
                    )
                    for ext in crl.extensions
                ):
                    continue
                valid.append(crl)
            if not valid:
                raise MetadataRefused("metadata_revocation_unavailable")
            validation_deadlines.append(max(crl.next_update_utc for crl in valid))
            if any(
                crl.get_revoked_certificate_by_serial_number(certificate.serial_number)
                is not None
                for crl in valid
            ):
                raise MetadataRefused("metadata_signer_revoked")
        key = chain[0].public_key()
        if not isinstance(key, rsa.RSAPublicKey):
            raise MetadataRefused("metadata_signer_algorithm")
        key.verify(
            _url64(signature64),
            header64 + b"." + payload64,
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
        body = _json(_url64(payload64))
        sequence = body.get("no")
        if type(sequence) is not int or sequence < minimum_sequence:
            raise MetadataRefused("metadata_rollback")
        next_update = datetime.strptime(body["nextUpdate"], "%Y-%m-%d").replace(
            tzinfo=UTC
        )
        if now >= next_update:
            raise MetadataRefused("metadata_expired")
        entries = body.get("entries")
        if not isinstance(entries, list) or not entries or len(entries) > 10000:
            raise MetadataRefused("metadata_entries_invalid")
        index = {}
        for entry in entries:
            if not isinstance(entry, dict):
                raise MetadataRefused("metadata_entry_invalid")
            aaguid = entry.get("aaguid")
            if aaguid:
                name = aaguid.lower()
                if name in index:
                    raise MetadataRefused("metadata_model_duplicate")
                index[name] = entry
        return Snapshot(
            blob_sha256,
            sequence,
            next_update,
            tuple(entries),
            index,
            min(next_update, *validation_deadlines),
        )
    except MetadataRefused:
        raise
    except (
        ValueError,
        KeyError,
        TypeError,
        UnicodeError,
        InvalidSignature,
        VerificationError,
    ) as exc:
        raise MetadataRefused("metadata_invalid") from exc
