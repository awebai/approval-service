"""The shared crypto owner retains the live approval profile's refusal code."""

import pytest
from receipts import fixture

from approval_service.encoding import decode
from approval_service.verify import Refused, Trust, verify_receipt_with_counter


def test_live_approval_counter_refusal_keeps_its_released_code():
    world = fixture()
    proof = world["receipt"]
    count = int.from_bytes(
        decode(proof["assertion"]["authenticator_data"])[33:37], "big"
    )
    with pytest.raises(Refused) as refused:
        verify_receipt_with_counter(
            proof,
            expected_request=world["request"],
            trust=Trust(**world["status"]),
            sign_count=max(1, count),
        )
    assert refused.value.code == "approval_assertion_invalid"
