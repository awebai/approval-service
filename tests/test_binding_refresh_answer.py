"""A refresh answer must name the exact binding the person submitted."""

import copy

import pytest
from receipts import fixture

from approval_service.binding_refresh_answers import read_binding_refresh_answer
from approval_service.seams import commitment
from approval_service.verify import Refused


def test_refresh_answer_is_bound_to_person_and_signed_binding():
    binding = fixture()["receipt"]["binding"]
    answer = {"version": 1, "person": binding["binding"]["person"],
              "state": "active", "binding_commitment": commitment("binding_commitment", binding)}
    assert read_binding_refresh_answer(answer, status=200, binding=binding) == answer
    for field, value in [("person", "did:aw:someone-else"), ("binding_commitment", "sha256:" + "f" * 64), ("state", "pending")]:
        wrong = {**copy.deepcopy(answer), field: value}
        with pytest.raises(Refused):
            read_binding_refresh_answer(wrong, status=200, binding=binding)


def test_refresh_refusal_preserves_the_controlled_next_step():
    binding = fixture()["receipt"]["binding"]
    with pytest.raises(Refused) as refusal:
        read_binding_refresh_answer({"version": 1, "error": {"code": "binding_refresh_state_changed", "message": "Use the last successful binding."}}, status=400, binding=binding)
    assert refusal.value.code == "binding_refresh_state_changed"
