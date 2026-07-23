"""The state-store interface.

`RunState` is fully serializable, which is what makes persistence a thin
adapter rather than a rewrite. The same property will later allow a scan to
be resumed, distributed to a worker queue, or served by an API — none of
which requires the core to know that a database exists.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from deptrace.core.state import RunState


@runtime_checkable
class StateStore(Protocol):
    """Persists and retrieves scan state, keyed by `scan_id`."""

    def save(self, state: RunState) -> None:
        """Write (or overwrite) the state for one scan."""
        ...

    def load(self, scan_id: str) -> RunState | None:
        """Return a stored scan, or None when it is unknown."""
        ...

    def list_scans(self, limit: int = 20) -> list[RunState]:
        """Most recent scans first."""
        ...
