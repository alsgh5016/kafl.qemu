# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
# How to run: PYTHONPATH=tests/nyx python3 -m pytest -q tests/nyx/test_verify_strict_barrier.py

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Dict, List, Sequence, Tuple


class ViolationCode(str, Enum):
    GUEST_EXECUTED_BEFORE_DUMP_END = "GUEST_EXECUTED_BEFORE_DUMP_END"
    STALE_GENERATION_ACK = "STALE_GENERATION_ACK"
    DUPLICATE_ACK_OR_CONSUMPTION = "DUPLICATE_ACK_OR_CONSUMPTION"
    INCOMPLETE_PT_QUARTET = "INCOMPLETE_PT_QUARTET"
    MISSING_MANDATORY_EVENT = "MISSING_MANDATORY_EVENT"


class TraceViolation(Exception):
    def __init__(self, code: ViolationCode, path: Path) -> None:
        self.code = code
        self.path = path
        super().__init__(code.value)


IDENTITY_FIELDS = ("event", "range_id", "page_index", "generation")
IDENTITY_FIELD_SET = frozenset(IDENTITY_FIELDS)
PT_QUARTET = (
    "PT_WRITE",
    "PT_REWALK",
    "TARGET_NX_INSTALL",
    "TLB_FLUSH",
)
PT_EVENT_SET = frozenset(PT_QUARTET)
CORE_TAIL = (
    "STRICT_EXEC_EXIT",
    "QEMU_DUMP_BEGIN",
    "QEMU_DUMP_END",
    "STRICT_ACK",
)
OPTIONAL_GUEST = "GUEST_EXECUTED"
REGISTER_COMMIT = "REGISTER_COMMIT"


@dataclass(frozen=True)
class EventRecord:
    event: str
    range_id: int
    page_index: int
    generation: int


Identity = Tuple[int, int, int]
PageKey = Tuple[int, int]


def verify_path(path: Path) -> None:
    records = _load_records(path)
    sequences: Dict[Identity, List[str]] = {}
    latest_generation_by_page: Dict[PageKey, int] = {}
    ack_counts: Dict[Identity, int] = {}
    guest_counts: Dict[Identity, int] = {}
    dump_end_seen: Dict[Identity, bool] = {}

    for record in records:
        identity = (record.range_id, record.page_index, record.generation)
        page_key = (record.range_id, record.page_index)
        sequence = sequences.setdefault(identity, [])
        sequence.append(record.event)

        if record.event == REGISTER_COMMIT:
            previous_generation = latest_generation_by_page.get(page_key)
            if previous_generation is None or record.generation > previous_generation:
                latest_generation_by_page[page_key] = record.generation
            continue

        if record.event == "STRICT_ACK":
            latest_generation = latest_generation_by_page.get(page_key)
            if latest_generation is not None and record.generation < latest_generation:
                _raise(ViolationCode.STALE_GENERATION_ACK, path)
            ack_counts[identity] = ack_counts.get(identity, 0) + 1
            if ack_counts[identity] > 1:
                _raise(ViolationCode.DUPLICATE_ACK_OR_CONSUMPTION, path)
            continue

        if record.event == "QEMU_DUMP_END":
            dump_end_seen[identity] = True
            continue

        if record.event == OPTIONAL_GUEST:
            guest_counts[identity] = guest_counts.get(identity, 0) + 1
            if guest_counts[identity] > 1:
                _raise(ViolationCode.DUPLICATE_ACK_OR_CONSUMPTION, path)
            if not dump_end_seen.get(identity, False):
                _raise(ViolationCode.GUEST_EXECUTED_BEFORE_DUMP_END, path)

    for sequence in sequences.values():
        _validate_sequence(sequence, path)


def _load_records(path: Path) -> List[EventRecord]:
    records: List[EventRecord] = []

    with path.open("r", encoding="utf-8") as handle:
        for raw_line in handle:
            stripped_line = raw_line.strip()
            if not stripped_line:
                continue
            records.append(_parse_record(stripped_line, path))

    if not records:
        _raise(ViolationCode.MISSING_MANDATORY_EVENT, path)
    return records


def _parse_record(raw_line: str, path: Path) -> EventRecord:
    raw_value = json.loads(raw_line)
    if not isinstance(raw_value, dict):
        _raise(ViolationCode.MISSING_MANDATORY_EVENT, path)
    if frozenset(raw_value.keys()) != IDENTITY_FIELD_SET:
        _raise(ViolationCode.MISSING_MANDATORY_EVENT, path)

    event = raw_value["event"]
    range_id = raw_value["range_id"]
    page_index = raw_value["page_index"]
    generation = raw_value["generation"]
    if not isinstance(event, str):
        _raise(ViolationCode.MISSING_MANDATORY_EVENT, path)
    if not isinstance(range_id, int):
        _raise(ViolationCode.MISSING_MANDATORY_EVENT, path)
    if not isinstance(page_index, int):
        _raise(ViolationCode.MISSING_MANDATORY_EVENT, path)
    if not isinstance(generation, int):
        _raise(ViolationCode.MISSING_MANDATORY_EVENT, path)

    return EventRecord(
        event=event,
        range_id=range_id,
        page_index=page_index,
        generation=generation,
    )


def _validate_sequence(sequence: Sequence[str], path: Path) -> None:
    pt_events = tuple(event for event in sequence if event in PT_EVENT_SET)
    if pt_events and pt_events != PT_QUARTET:
        _raise(ViolationCode.INCOMPLETE_PT_QUARTET, path)

    expected_sequence = (REGISTER_COMMIT,) + CORE_TAIL
    if pt_events:
        expected_sequence = (REGISTER_COMMIT,) + PT_QUARTET + CORE_TAIL

    if tuple(sequence) == expected_sequence:
        return
    if tuple(sequence) == expected_sequence + (OPTIONAL_GUEST,):
        return
    _raise(ViolationCode.MISSING_MANDATORY_EVENT, path)


def _raise(code: ViolationCode, path: Path) -> None:
    raise TraceViolation(code, path)


__all__ = ["TraceViolation", "ViolationCode", "verify_path"]
