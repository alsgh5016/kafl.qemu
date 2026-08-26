from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Sequence, Tuple

from verify_strict_barrier import ViolationCode


FIXTURE_DIR = Path(__file__).with_name("fixtures")
IDENTITY_FIELDS = ("event", "range_id", "page_index", "generation")
IDENTITY_FIELD_SET = frozenset(IDENTITY_FIELDS)
PT_QUARTET = (
    "PT_WRITE",
    "PT_REWALK",
    "TARGET_NX_INSTALL",
    "TLB_FLUSH",
)
PT_QUARTET_SET = frozenset(PT_QUARTET)


@dataclass(frozen=True)
class EventRecord:
    event: str
    range_id: int
    page_index: int
    generation: int


@dataclass(frozen=True)
class ValidCase:
    fixture_name: str
    expected_events: Tuple[str, ...]


@dataclass(frozen=True)
class InvalidCase:
    fixture_name: str
    expected_code: ViolationCode


VALID_CASES: Tuple[ValidCase, ...] = (
    ValidCase(
        fixture_name="valid_direct_registration.jsonl",
        expected_events=(
            "REGISTER_COMMIT",
            "STRICT_EXEC_EXIT",
            "QEMU_DUMP_BEGIN",
            "QEMU_DUMP_END",
            "STRICT_ACK",
            "GUEST_EXECUTED",
        ),
    ),
    ValidCase(
        fixture_name="valid_direct_registration_without_guest.jsonl",
        expected_events=(
            "REGISTER_COMMIT",
            "STRICT_EXEC_EXIT",
            "QEMU_DUMP_BEGIN",
            "QEMU_DUMP_END",
            "STRICT_ACK",
        ),
    ),
    ValidCase(
        fixture_name="valid_remap_complete_quartet.jsonl",
        expected_events=(
            "REGISTER_COMMIT",
            "PT_WRITE",
            "PT_REWALK",
            "TARGET_NX_INSTALL",
            "TLB_FLUSH",
            "STRICT_EXEC_EXIT",
            "QEMU_DUMP_BEGIN",
            "QEMU_DUMP_END",
            "STRICT_ACK",
            "GUEST_EXECUTED",
        ),
    ),
)

INVALID_CASES: Tuple[InvalidCase, ...] = (
    InvalidCase(
        fixture_name="invalid_guest_before_dump_end.jsonl",
        expected_code=ViolationCode.GUEST_EXECUTED_BEFORE_DUMP_END,
    ),
    InvalidCase(
        fixture_name="invalid_stale_generation_ack.jsonl",
        expected_code=ViolationCode.STALE_GENERATION_ACK,
    ),
    InvalidCase(
        fixture_name="invalid_duplicate_ack.jsonl",
        expected_code=ViolationCode.DUPLICATE_ACK_OR_CONSUMPTION,
    ),
    InvalidCase(
        fixture_name="invalid_duplicate_guest_executed.jsonl",
        expected_code=ViolationCode.DUPLICATE_ACK_OR_CONSUMPTION,
    ),
    InvalidCase(
        fixture_name="invalid_incomplete_pt_quartet.jsonl",
        expected_code=ViolationCode.INCOMPLETE_PT_QUARTET,
    ),
    InvalidCase(
        fixture_name="invalid_missing_strict_ack.jsonl",
        expected_code=ViolationCode.MISSING_MANDATORY_EVENT,
    ),
)


def fixture_names() -> Tuple[str, ...]:
    return tuple(case.fixture_name for case in VALID_CASES) + tuple(
        case.fixture_name for case in INVALID_CASES
    )


def load_fixture(path: Path) -> List[EventRecord]:
    records: List[EventRecord] = []

    with path.open("r", encoding="utf-8") as handle:
        for line_number, raw_line in enumerate(handle, start=1):
            stripped_line = raw_line.strip()
            if not stripped_line:
                continue
            records.append(parse_record(path, line_number, stripped_line))

    return records


def parse_record(path: Path, line_number: int, raw_line: str) -> EventRecord:
    raw_value = json.loads(raw_line)
    if not isinstance(raw_value, dict):
        raise AssertionError(f"{path}:{line_number} must decode to a JSON object")

    if frozenset(raw_value.keys()) != IDENTITY_FIELD_SET:
        raise AssertionError(
            f"{path}:{line_number} must contain exactly {sorted(IDENTITY_FIELD_SET)}"
        )

    event = raw_value["event"]
    range_id = raw_value["range_id"]
    page_index = raw_value["page_index"]
    generation = raw_value["generation"]

    if not isinstance(event, str):
        raise AssertionError(f"{path}:{line_number} event must be a string")
    if not isinstance(range_id, int):
        raise AssertionError(f"{path}:{line_number} range_id must be an int")
    if not isinstance(page_index, int):
        raise AssertionError(f"{path}:{line_number} page_index must be an int")
    if not isinstance(generation, int):
        raise AssertionError(f"{path}:{line_number} generation must be an int")

    return EventRecord(
        event=event,
        range_id=range_id,
        page_index=page_index,
        generation=generation,
    )


def event_names(records: Sequence[EventRecord]) -> Tuple[str, ...]:
    return tuple(record.event for record in records)


def event_counts(records: Iterable[EventRecord]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for record in records:
        previous_count = counts.get(record.event, 0)
        counts[record.event] = previous_count + 1
    return counts


def assert_fixture_schema(records: Sequence[EventRecord]) -> None:
    assert records
    assert records[0].event == "REGISTER_COMMIT"
