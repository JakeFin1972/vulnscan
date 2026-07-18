"""Shared types for language backends."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


@dataclass
class Hit:
    kind: str            # "source" | "sink"
    category: str
    file: str
    line: int
    name: str
    language: str = ""   # filled in by the orchestrator if a backend leaves it blank


# Attacker-proximity ranking shared across languages; lower = closer to attacker.
SOURCE_RANK: dict[str, int] = {
    "http_handler": 0,
    "ws_handler": 1,
    "grpc_handler": 1,
    "queue_consumer": 2,
    "razor_handler": 0,
}


class LanguageBackend(Protocol):
    """A per-language locator. Implementations must be pure functions of the file."""

    name: str
    extensions: tuple[str, ...]

    def scan_file(self, path: Path) -> list[Hit]:
        ...
