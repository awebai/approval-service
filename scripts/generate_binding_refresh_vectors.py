"""Generate the additive answer-binding neighbors from the shared receipt fixture."""

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
from receipts import fixture
from approval_service.seams import commitment

binding = fixture()["receipt"]["binding"]
answer = {
    "version": 1,
    "person": binding["binding"]["person"],
    "state": "active",
    "binding_commitment": commitment("binding_commitment", binding),
}
cases = [
    {
        "id": "exact-binding",
        "binding": binding,
        "answer": answer,
        "status": 200,
        "accept": True,
    }
]
for field, value, code in [
    ("person", "did:aw:another-person", "person_mismatch"),
    ("binding_commitment", "sha256:" + "f" * 64, "binding_mismatch"),
    ("state", "pending", "service_response_invalid"),
    ("extra", True, "service_response_invalid"),
]:
    cases.append(
        {
            "id": "changed-" + field,
            "binding": binding,
            "answer": {**copy.deepcopy(answer), field: value},
            "status": 200,
            "accept": False,
            "code": code,
        }
    )
cases.append(
    {
        "id": "actionable-refusal",
        "binding": binding,
        "answer": {
            "version": 1,
            "error": {
                "code": "binding_refresh_state_changed",
                "message": "Use the last successful binding.",
            },
        },
        "status": 400,
        "accept": False,
        "code": "binding_refresh_state_changed",
    }
)
(ROOT / "vectors/binding-refresh-v1.json").write_text(
    json.dumps({"profile": "aweb.awsign.binding-refresh@1", "cases": cases}, indent=2)
    + "\n"
)
