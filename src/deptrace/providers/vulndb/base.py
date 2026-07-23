"""The vulnerability-database provider interface.

OSV is the default and only v1 implementation, but the orchestrator depends
on this protocol rather than on `OSVProvider` directly. That keeps the core
free of any particular vendor's schema and makes the eval harness able to
run against a fully offline fake provider with no network at all.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from deptrace.core.state import Dependency, Vulnerability


@runtime_checkable
class VulnDBProvider(Protocol):
    """Maps dependencies to the known vulnerabilities affecting them."""

    name: str

    async def find_vulnerabilities(
        self, dependencies: list[Dependency]
    ) -> dict[str, list[Vulnerability]]:
        """Look up advisories for many dependencies at once.

        Returns a mapping of normalized package name -> vulnerabilities that
        actually apply to that dependency's version. Implementations must:

          * batch where the upstream API allows it,
          * never raise for a single failed package (degrade, don't abort),
          * return an entry only for packages with at least one match.
        """
        ...
