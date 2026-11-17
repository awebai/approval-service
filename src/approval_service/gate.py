"""Optional organisation policy over the shared receipt verifier.

This module owns no custody, storage, network client or application effect.
An enforcer supplies its authenticated requester, independently read Trust and
expected act, then rechecks this gate at its locked effect. None means only
that the organisation has not required approval; ordinary authority still applies.
"""

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from jsonschema import ValidationError

from .canonical import canonical, parse
from .definitions import check_definition
from .seams import check_presentation, make_needs_human
from .verify import Refused
from .wire import validate_site

# The configuration name and existing frozen act definition are distinct.
ACTIONS = {"organisation.human.add": "human.add"}
LEVELS = {"passkey": "passkey_uv", "hardware": "certified_hardware"}


@dataclass(frozen=True)
class Policy:
    service: str | None
    requirements: tuple[tuple[str, str], ...]

    @classmethod
    def from_section(cls, section):
        """An absent section is off; malformed/unsupported input never is."""
        if section is None:
            section = {}
        try:
            if not isinstance(section, dict) or set(section) - {"service", "require"}:
                raise ValueError("unknown configuration member")
            requirements = section.get("require", {})
            if not isinstance(requirements, dict):
                raise TypeError("requirements must be an object")
            if any(
                action not in ACTIONS or level not in LEVELS
                for action, level in requirements.items()
            ):
                raise ValueError("unsupported action or level")
            service = section.get("service")
            if requirements and service is None:
                raise ValueError("approval service required")
            if service is not None:
                if not isinstance(service, str):
                    raise ValueError("service must be an HTTPS origin")
                validate_site(service, urlsplit(service).hostname)
            return cls(service, tuple(sorted(requirements.items())))
        except (ValueError, TypeError, ValidationError) as exc:
            raise Refused("human_approval_invalid") from exc

    def as_section(self):
        value = {"require": dict(self.requirements)}
        if self.service is not None:
            value["service"] = self.service
        return value

    def grade(self, action):
        if action not in ACTIONS:
            raise Refused("approval_action_unknown")
        level = dict(self.requirements).get(action)
        return LEVELS[level] if level is not None else None


class Gate:
    def __init__(self, policy: Policy, *, organisation: str, audience: str):
        self.policy = policy
        self.organisation = organisation
        self.audience = audience

    def evaluate(
        self,
        action,
        *,
        request=None,
        presentation=None,
        presenter=None,
        trust=None,
        now=None,
        nonce_keys=None,
    ):
        """None, an existing 428 packet, or scoped checked receipt bindings.

        The request is the enforcer's independently reconstructed expected act,
        not permission derived from a receipt. The enforcer owns its nonce key,
        revision, effect transaction and consumed-value record. A changed policy
        must be loaded again before that transaction uses the result.
        """
        grade = self.policy.grade(action)
        if grade is None:
            return None
        check_definition(request)
        if (
            not isinstance(request, dict)
            or request.get("organisation") != self.organisation
            or request.get("enforcer") != {"audience": self.audience}
            or request.get("act", {}).get("operation") != ACTIONS[action]
            or request.get("definition", {}).get("id") != ACTIONS[action]
        ):
            raise Refused("approval_act_mismatch")
        if presentation is None:
            return make_needs_human(request, origin=self.policy.service)
        return check_presentation(
            presentation,
            expected_request=request,
            presenter=presenter,
            origin=self.policy.service,
            now=now,
            trust=trust,
            required_grade=grade,
            nonce_keys=nonce_keys,
        )


def render_policy(organisation, section):
    """One non-secret snapshot rendered from the deployment's section."""
    if not isinstance(organisation, str) or not organisation:
        raise Refused("human_approval_invalid")
    return canonical(
        {
            "organisation": organisation,
            "human_approval": Policy.from_section(section).as_section(),
        }
    )


def load_policy(path, *, organisation):
    """No configured source is off; failure of an explicit source is not."""
    if path is None:
        return Policy.from_section(None)
    try:
        with Path(path).open("rb") as stream:
            raw = stream.read(65537)
    except OSError as exc:
        raise Refused("human_approval_unavailable") from exc
    try:
        if len(raw) > 65536:
            raise ValueError("configuration too large")
        value = parse(raw)
        if (
            not isinstance(value, dict)
            or set(value) != {"organisation", "human_approval"}
            or value["organisation"] != organisation
            or not isinstance(value["human_approval"], dict)
        ):
            raise ValueError("invalid organisation configuration")
        return Policy.from_section(value["human_approval"])
    except (ValueError, TypeError) as exc:
        raise Refused("human_approval_invalid") from exc
