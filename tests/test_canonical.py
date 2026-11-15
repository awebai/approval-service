import pytest

from approval_service.canonical import InvalidJSON, canonical, parse


@pytest.mark.parametrize(
    "raw, expected",
    [
        (b'{"x":1}', b'{"x":1}'),
        (
            b'{ "z": null, "a": [true, -9007199254740991, 9007199254740991] }',
            b'{"a":[true,-9007199254740991,9007199254740991],"z":null}',
        ),
        (b'{"\\uffff":1,"\\ud83d\\ude00":2}', '{"\uffff":1,"😀":2}'.encode()),
    ],
)
def test_strict_input_has_one_canonical_form(raw, expected):
    assert canonical(parse(raw)) == expected


@pytest.mark.parametrize(
    "raw",
    [
        b'{"x":1.0}',
        b'{"x":1e0}',
        b'{"x":1E+0}',
        b'{"x":-0}',
        b'{"x":9007199254740992}',
        b'{"x":-9007199254740992}',
        b'{"x":1,"x":2}',
        b'{"x":{"a":1,"a":2}}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":"\\ud800"}',
        b'{"x":"\xff"}',
        b"{} {}",
        b"[]",
    ],
)
def test_ambiguous_input_refuses_before_json_normalisation(raw):
    with pytest.raises(InvalidJSON):
        parse(raw)


def test_object_input_cannot_bypass_numeric_or_unicode_checks():
    for value in ({"x": 1.0}, {"x": 2**53}, {"x": "\ud800"}):
        with pytest.raises(InvalidJSON):
            canonical(value)


def test_shared_canonical_vectors():
    import json
    from pathlib import Path

    corpus = json.loads(
        (Path(__file__).parents[1] / "vectors/canonical-json.json").read_text()
    )
    for case in corpus["cases"]:
        raw = bytes.fromhex(case["input_hex"])
        if case.get("refused"):
            with pytest.raises(InvalidJSON):
                parse(raw)
        else:
            assert canonical(parse(raw)).hex() == case["canonical_hex"], case["id"]
