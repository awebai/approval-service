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
ACTIONS = {"organisation.human.add": ("human.add", "organisation.person.admit")}
LEVELS = {"passkey": "passkey_uv", "hardware": "certified_hardware"}
POLICY_CHANGE = "organisation.human_approval.change"


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

    def changes_requiring_approval(self, next_policy):
        """Changing the service or weakening a current requirement uses it first."""
        rank = {None: 0, "passkey": 1, "hardware": 2}
        after = dict(next_policy.requirements)
        return tuple(
            action
            for action, level in self.requirements
            if self.service != next_policy.service
            or rank[after.get(action)] < rank[level]
        )

    def change_target(self, action, next_policy, *, organisation):
        self.grade(action)  # Unknown actions are never treated as unconfigured.
        return {
            "organisation": organisation,
            "action": action,
            "before": {
                "service": self.service,
                "level": dict(self.requirements).get(action, "none"),
            },
            "after": {
                "service": next_policy.service,
                "level": dict(next_policy.requirements).get(action, "none"),
            },
        }


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
        return self._evaluate(
            ACTIONS[action],
            grade,
            request=request,
            presentation=presentation,
            presenter=presenter,
            trust=trust,
            now=now,
            nonce_keys=nonce_keys,
        )

    def evaluate_policy_change(
        self, action, next_policy, *, revision, request=None, **inputs
    ):
        """The enforcer supplies the locked before/after policy and revision.

        This checks one affected action at its OLD level/service. Ordinary
        management authority and availability of enrolled approvers are owned
        by the enforcer, including when this method returns None for a raise.
        """
        grade = self.policy.grade(action)
        if action not in self.policy.changes_requiring_approval(next_policy):
            return None
        try:
            if (
                request["definition"]["id"] != POLICY_CHANGE
                or type(revision) is not int
                or request["act"]["expected_revision"] != revision
                or canonical(request["act"]["target"])
                != canonical(
                    self.policy.change_target(
                        action, next_policy, organisation=self.organisation
                    )
                )
            ):
                raise Refused("approval_policy_mismatch")
        except (KeyError, TypeError, ValueError) as exc:
            raise Refused("approval_policy_mismatch") from exc
        return self._evaluate((POLICY_CHANGE,), grade, request=request, **inputs)

    def _evaluate(
        self,
        definitions,
        grade,
        *,
        request,
        presentation=None,
        presenter=None,
        trust=None,
        now=None,
        nonce_keys=None,
    ):
        definition = check_definition(request)
        selector = definition.get("policy_organisation", "request.organisation")
        if selector == "act.target.organisation":
            organisation = request["act"]["target"].get("organisation")
        elif selector == "request.organisation":
            organisation = request.get("organisation")
        else:
            raise Refused("definition_invalid")
        if (
            not isinstance(request, dict)
            or organisation != self.organisation
            or request.get("enforcer") != {"audience": self.audience}
            or definition["id"] not in definitions
            or request.get("act", {}).get("operation") != definition["id"]
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
