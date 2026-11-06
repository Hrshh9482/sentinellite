"""
base.py — Abstract parser interface.

All parsers yield Events from a line iterator, making them easy to test
and swap without touching detection or storage code.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Iterator
from pathlib import Path

from sentinellite.models import Event


class BaseParser(ABC):
    """Parse a log source and yield normalised Events."""

    @abstractmethod
    def parse_lines(self, lines: Iterator[str], assumed_year: int | None = None) -> Iterator[Event]:
        """
        Yield Events from an iterable of raw log lines.

        - Malformed lines are silently skipped (never raise).
        - assumed_year: year injected into syslog timestamps that omit the year.
          If None the parser uses the current year.
        """

    def parse_file(self, path: Path, assumed_year: int | None = None) -> Iterator[Event]:
        """Convenience: open a file and call parse_lines."""
        with path.open(encoding="utf-8", errors="replace") as fh:
            yield from self.parse_lines(fh, assumed_year=assumed_year)
