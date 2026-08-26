from __future__ import annotations

from pathlib import Path

import pytest

from strict_barrier_contract import (
    FIXTURE_DIR,
    INVALID_CASES,
    PT_QUARTET,
    PT_QUARTET_SET,
    VALID_CASES,
    InvalidCase,
    ValidCase,
    assert_fixture_schema,
    event_counts,
    event_names,
    fixture_names,
    load_fixture,
)
from verify_strict_barrier import TraceViolation, verify_path


@pytest.mark.parametrize(
    "fixture_name",
    fixture_names(),
)
def test_fixtures_decode_as_identity_only_json_objects(fixture_name: str) -> None:
    # Given: a JSONL fixture path.
    path = FIXTURE_DIR / fixture_name

    # When: the fixture is decoded independently from the verifier stub.
    records = load_fixture(path)

    # Then: every line is a syntactically valid identity-only event object.
    assert_fixture_schema(records)


@pytest.mark.parametrize("case", VALID_CASES)
def test_valid_sequences_match_the_canonical_contract(case: ValidCase) -> None:
    # Given: a fixture that should be accepted by the future verifier.
    path = FIXTURE_DIR / case.fixture_name
    records = load_fixture(path)

    # When: the event stream is read directly from JSONL.
    actual_events = event_names(records)

    # Then: the canonical event sequence matches the independently encoded contract.
    assert actual_events == case.expected_events
    assert actual_events[-1] in {"STRICT_ACK", "GUEST_EXECUTED"}


@pytest.mark.parametrize("case", VALID_CASES)
def test_valid_sequences_are_accepted(case: ValidCase) -> None:
    # Given: an accepted strict barrier trace fixture.
    path = FIXTURE_DIR / case.fixture_name
    records = load_fixture(path)
    assert event_names(records)[0] == "REGISTER_COMMIT"

    # When: the verifier boundary is invoked on the JSONL path.
    # Then: no typed violation should be raised for an accepted fixture.
    verify_path(path)


def test_guest_execution_before_dump_end_fixture_contains_the_target_regression() -> None:
    # Given: the rejected early-guest-execution fixture.
    records = load_fixture(FIXTURE_DIR / "invalid_guest_before_dump_end.jsonl")

    # When: event positions are inspected directly.
    actual_events = event_names(records)

    # Then: guest execution is encoded before dump end.
    assert actual_events.index("GUEST_EXECUTED") < actual_events.index("QEMU_DUMP_END")


def test_stale_generation_ack_fixture_contains_the_target_regression() -> None:
    # Given: the rejected stale-generation fixture.
    records = load_fixture(FIXTURE_DIR / "invalid_stale_generation_ack.jsonl")

    # When: the pre-ack registration and ack generations are extracted.
    latest_register_commit = records[-2]
    stale_ack = records[-1]

    # Then: the final ack uses an older generation than the latest register commit.
    assert latest_register_commit.event == "REGISTER_COMMIT"
    assert stale_ack.event == "STRICT_ACK"
    assert stale_ack.generation < latest_register_commit.generation


def test_duplicate_ack_fixture_contains_the_target_regression() -> None:
    # Given: the rejected duplicate-ack fixture.
    records = load_fixture(FIXTURE_DIR / "invalid_duplicate_ack.jsonl")

    # When: event multiplicities are counted.
    counts = event_counts(records)

    # Then: strict acknowledgement appears more than once.
    assert counts["STRICT_ACK"] == 2


def test_duplicate_guest_executed_fixture_contains_the_target_regression() -> None:
    # Given: the rejected duplicate-consumption fixture.
    records = load_fixture(FIXTURE_DIR / "invalid_duplicate_guest_executed.jsonl")

    # When: event multiplicities are counted.
    counts = event_counts(records)

    # Then: guest execution appears more than once.
    assert counts["GUEST_EXECUTED"] == 2


def test_incomplete_pt_quartet_fixture_contains_the_target_regression() -> None:
    # Given: the rejected partial PT-rearm fixture.
    records = load_fixture(FIXTURE_DIR / "invalid_incomplete_pt_quartet.jsonl")

    # When: PT-quartet membership is compared against the full contract.
    seen_pt_events = tuple(
        record.event for record in records if record.event in PT_QUARTET_SET
    )

    # Then: some, but not all, quartet events are present.
    assert seen_pt_events
    assert seen_pt_events != PT_QUARTET


def test_missing_strict_ack_fixture_contains_the_target_regression() -> None:
    # Given: the rejected missing-ack fixture.
    records = load_fixture(FIXTURE_DIR / "invalid_missing_strict_ack.jsonl")

    # When: event multiplicities are counted.
    counts = event_counts(records)

    # Then: the mandatory acknowledgement event is absent.
    assert counts.get("STRICT_ACK", 0) == 0


@pytest.mark.parametrize("case", INVALID_CASES)
def test_invalid_sequences_raise_expected_typed_violation(case: InvalidCase) -> None:
    # Given: a rejected strict barrier trace fixture and its independent expected code.
    path = FIXTURE_DIR / case.fixture_name
    records = load_fixture(path)
    assert_fixture_schema(records)

    # When: the verifier boundary is invoked.
    with pytest.raises(TraceViolation) as exc_info:
        verify_path(path)

    # Then: the machine-consumable violation code matches the contract.
    assert exc_info.value.code == case.expected_code
