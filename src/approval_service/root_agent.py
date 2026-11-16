"""Root-link proof and grant checks; custody/effects stay with their enforcer.

RootIdentity and PersonContinuity are independently checked SDK/lifecycle ports,
just like Trust. NEVER build them from a receipt's keys or claimed ancestry.
Historical proof does not establish current permission or an applied team grant.
"""

from dataclasses import dataclass

from jsonschema import ValidationError

from .canonical import parse
from .definitions import check_definition
from .encoding import decode
from .seams import check_presentation
from .verify import CheckedApproval, Refused, verify_historical
from .wire import validate


@dataclass(frozen=True)
class RootIdentity:
    """The ID/current key and continuous key history already checked by the SDK."""

    id: str
    current_key: str
    continuous_keys: tuple[str, ...]


@dataclass(frozen=True)
class PersonContinuity:
    """Checked continuity FROM the receipt's person key TO the chosen as-of key.

    This is not the person's entire creation history. `since` is the existing
    checked continuity basis, not a signing time inferred from WebAuthn or R.
    A caller lacking that verified history supplies mode=unknown, since=None.
    """

    from_key: str
    current_key: str
    mode: str
    since: int | None


@dataclass(frozen=True)
class CheckedRootAgent:
    approval: CheckedApproval
    person: str
    root_id: str
    root_key: str
    mode: str
    teams: tuple[str, ...]
    enforcer: str
    status: str
    continuity: str = "unknown"
    since: int | None = None


def _target(request, root, trust, parent_person):
    check_definition(request)
    if request["definition"]["id"] != "agent.root.authorize":
        raise Refused("root_act_invalid")
    t = request["act"]["target"]
    if (
        t["person"] != trust.person
        or request["approver"] != trust.person
        or parent_person != trust.person
    ):
        raise Refused("root_person_mismatch")
    if request["organisation"] != trust.organisation:
        raise Refused("root_person_mismatch")
    if t["root_id"] != root.id:
        raise Refused("root_identity_mismatch")
    if not root.continuous_keys or root.current_key not in root.continuous_keys:
        raise Refused("root_history_unavailable")
    if t["root_key"] not in root.continuous_keys:
        raise Refused("root_key_discontinuous")
    # Full canonical team IDs have their lexical shape/uniqueness checked by
    # the single bundled definition; exact namespace equality is semantic.
    if any(team.partition(":")[2] != request["organisation"] for team in t["teams"]):
        raise Refused("root_team_organisation_mismatch")
    return t


def _result(checked, request, target, status, continuity="unknown", since=None):
    return CheckedRootAgent(
        checked,
        target["person"],
        target["root_id"],
        target["root_key"],
        target["mode"],
        tuple(target["teams"]),
        request["enforcer"]["audience"],
        status,
        continuity,
        since,
    )


def check_root_agent_presentation(
    value,
    *,
    expected_request,
    root,
    trust,
    now,
    presenter,
    required_grade,
    nonce_keys,
    origin,
    audience,
    enforcer_kind,
    owned_teams,
    revision,
):
    """Check a live exact grant; return the ENTIRE replacement list, not a union.

    The custody owner supplies its own audience/kind, owned team descriptors,
    revision and SDK-checked root identity. It atomically consumes the nonce and
    records this replacement (empty withdraws) with its own effect transaction.
    aw has no team-key effect here and therefore accepts ONLY teams=[].
    """
    t = _target(expected_request, root, trust, trust.person)
    if expected_request["enforcer"]["audience"] != audience:
        raise Refused("root_enforcer_mismatch")
    if enforcer_kind not in ("aw", "key_holder", "cloud_key_process"):
        raise Refused("root_enforcer_invalid")
    if enforcer_kind == "aw" and t["teams"]:
        raise Refused("root_teams_not_supported")
    if any(team not in owned_teams for team in t["teams"]):
        raise Refused("root_team_not_owned")
    if (
        type(revision) is not int
        or expected_request["act"]["expected_revision"] != revision
    ):
        raise Refused("root_revision_mismatch")
    checked = check_presentation(
        value,
        expected_request=expected_request,
        presenter=presenter,
        origin=origin,
        now=now,
        trust=trust,
        required_grade=required_grade,
        nonce_keys=nonce_keys,
    )
    return _result(checked, expected_request, t, "checked")


def verify_root_agent_proof(value, *, root, parent_person, trust, continuity):
    """Historical C at a checked HUMAN -> root link, independent of enforcer kind.

    parent_person comes from that exact checked link, NOT nearest-human copied
    onto an agent->agent link. Root key continuity is the SDK's checked history;
    person continuity comes from the shared lifecycle checker/as-of inputs.
    The outer consumer reports missing/invalid/unsupported/unavailable evidence
    neutrally, preserving its independently checked ID-chain result and exit.
    """
    if (
        isinstance(value, dict)
        and type(value.get("version")) is int
        and value["version"] != 1
    ):
        raise Refused("root_proof_unsupported")
    try:
        validate("root_agent_proof", value)
    except (ValueError, TypeError, ValidationError) as exc:
        raise Refused("root_proof_invalid") from exc
    receipt = value["receipt"]
    try:
        request = parse(decode(receipt["request_bytes"]))
    except (ValueError, TypeError) as exc:
        raise Refused("root_proof_invalid") from exc
    t = _target(request, root, trust, parent_person)
    checked = verify_historical(receipt, expected_request=request, trust=trust)
    if (
        continuity.from_key != trust.identity_key
        or not continuity.current_key
        or continuity.mode not in ("unbroken", "assisted", "recreated", "unknown")
        or (
            continuity.mode != "unknown"
            and (type(continuity.since) is not int or continuity.since < 0)
        )
    ):
        raise Refused("root_history_unavailable")
    status = {
        "unbroken": "approved",
        "assisted": "approval_predates_break",
        "recreated": "approval_predates_break",
        "unknown": "continuity_unknown",
    }[continuity.mode]
    return _result(checked, request, t, status, continuity.mode, continuity.since)
