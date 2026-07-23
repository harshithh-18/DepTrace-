"""Tests for the OSV provider.

Every test here runs fully offline against a mocked httpx transport. No test
in this suite may touch the network — CI has no egress guarantee and the
eval harness must be reproducible.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx
import pytest

from deptrace.core.state import Dependency
from deptrace.providers.vulndb.base import VulnDBProvider
from deptrace.providers.vulndb.osv import OSVProvider, to_vulnerability

PYYAML_RECORD: dict[str, Any] = {
    "id": "GHSA-6757-jp84-gxfx",
    "aliases": ["CVE-2020-1747", "PYSEC-2020-96"],
    "summary": "Improper Input Validation in PyYAML",
    "details": "full_load and FullLoader allow arbitrary code execution.",
    "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N"}],
    "database_specific": {"severity": "CRITICAL"},
    "references": [{"type": "ADVISORY", "url": "https://nvd.nist.gov/x"}],
    "affected": [
        {
            "package": {"name": "pyyaml", "ecosystem": "PyPI"},
            "ranges": [
                {
                    "type": "ECOSYSTEM",
                    "events": [{"introduced": "5.1b7"}, {"fixed": "5.3.1"}],
                }
            ],
        }
    ],
}


def _dep(name: str, version: str | None) -> Dependency:
    return Dependency(name=name, version=version, source="requirements.txt")


def _transport(record: dict[str, Any] = PYYAML_RECORD, *, calls: list[str] | None = None):
    """Mock OSV: querybatch returns IDs, vulns/{id} returns the full record."""

    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(str(request.url))
        if request.url.path == "/v1/querybatch":
            return httpx.Response(
                200, json={"results": [{"vulns": [{"id": record["id"]}]}]}
            )
        if request.url.path.startswith("/v1/vulns/"):
            return httpx.Response(200, json=record)
        return httpx.Response(404, json={})

    return httpx.MockTransport(handler)


def _provider(cache_dir: Path, transport: httpx.MockTransport, **kw: Any) -> OSVProvider:
    """Build a provider against a mock transport and an explicit cache dir.

    Tests that exercise cache behaviour pass the same dir to two providers.
    """
    client = httpx.AsyncClient(transport=transport)
    return OSVProvider(cache_dir=cache_dir, client=client, **kw)


# -- conversion ------------------------------------------------------------


def test_to_vulnerability_maps_osv_schema() -> None:
    vuln = to_vulnerability(PYYAML_RECORD)

    assert vuln.id == "GHSA-6757-jp84-gxfx"
    assert "CVE-2020-1747" in vuln.aliases
    assert vuln.severity == "CRITICAL"  # label preferred over CVSS vector
    assert vuln.fixed_version == "5.3.1"
    assert vuln.references == ("https://nvd.nist.gov/x",)


def test_to_vulnerability_leaves_symbols_empty() -> None:
    """Symbols are LLM claims from Phase 5 — the DB layer never invents them."""
    assert to_vulnerability(PYYAML_RECORD).symbols == ()


def test_to_vulnerability_falls_back_to_cvss_vector() -> None:
    record = {**PYYAML_RECORD, "database_specific": {}}
    assert to_vulnerability(record).severity == "CVSS:3.1/AV:N"


def test_to_vulnerability_survives_sparse_record() -> None:
    vuln = to_vulnerability({"id": "GHSA-x"})
    assert vuln.id == "GHSA-x"
    assert vuln.summary == ""
    assert vuln.fixed_version is None


# -- lookup ----------------------------------------------------------------


async def test_finds_vulnerability_for_affected_version(tmp_path: Path) -> None:
    provider = _provider(tmp_path, _transport())
    results = await provider.find_vulnerabilities([_dep("pyyaml", "5.3")])

    assert "pyyaml" in results
    assert results["pyyaml"][0].id == "GHSA-6757-jp84-gxfx"
    await provider.aclose()


async def test_filters_out_patched_version(tmp_path: Path) -> None:
    """5.4 is past the 5.3.1 fix — OSV may return it, we must drop it."""
    provider = _provider(tmp_path, _transport())
    results = await provider.find_vulnerabilities([_dep("pyyaml", "5.4")])

    assert results == {}
    await provider.aclose()


async def test_unpinned_version_is_kept_for_review(tmp_path: Path) -> None:
    """Undecidable must not be silently dropped as safe."""
    provider = _provider(tmp_path, _transport())
    results = await provider.find_vulnerabilities([_dep("pyyaml", None)])

    assert "pyyaml" in results
    await provider.aclose()


async def test_withdrawn_advisories_are_skipped(tmp_path: Path) -> None:
    record = {**PYYAML_RECORD, "withdrawn": "2024-01-01T00:00:00Z"}
    provider = _provider(tmp_path, _transport(record))
    results = await provider.find_vulnerabilities([_dep("pyyaml", "5.3")])

    assert results == {}
    await provider.aclose()


async def test_empty_dependency_list_makes_no_requests(tmp_path: Path) -> None:
    calls: list[str] = []
    provider = _provider(tmp_path, _transport(calls=calls))

    assert await provider.find_vulnerabilities([]) == {}
    assert calls == []
    await provider.aclose()


# -- caching ---------------------------------------------------------------


async def test_second_run_is_cache_hot(tmp_path: Path) -> None:
    """The advisory is hydrated once; the rerun must not refetch it."""
    calls: list[str] = []
    cache = tmp_path / "cache"

    p1 = _provider(cache, _transport(calls=calls))
    await p1.find_vulnerabilities([_dep("pyyaml", "5.3")])
    await p1.aclose()
    first = [c for c in calls if "/v1/vulns/" in c]
    assert len(first) == 1

    calls.clear()
    p2 = _provider(cache, _transport(calls=calls))
    results = await p2.find_vulnerabilities([_dep("pyyaml", "5.3")])
    await p2.aclose()

    assert [c for c in calls if "/v1/vulns/" in c] == []  # served from cache
    assert results["pyyaml"][0].id == "GHSA-6757-jp84-gxfx"


async def test_offline_mode_makes_no_network_calls(tmp_path: Path) -> None:
    """A cold cache in offline mode yields nothing, but never a request."""
    calls: list[str] = []
    provider = _provider(tmp_path, _transport(calls=calls), offline=True)

    assert await provider.find_vulnerabilities([_dep("pyyaml", "5.3")]) == {}
    assert calls == []
    await provider.aclose()


async def test_warm_cache_serves_full_results_offline(tmp_path: Path) -> None:
    """Regression: offline must reproduce online results from cache alone.

    Caching only hydrated advisories is not enough — without the stage-1
    package->IDs mapping there is nothing to look them up by, so an offline
    run would return zero findings despite a fully populated cache.
    """
    cache = tmp_path / "cache"
    online = _provider(cache, _transport())
    expected = await online.find_vulnerabilities([_dep("pyyaml", "5.3")])
    await online.aclose()
    assert expected["pyyaml"][0].id == "GHSA-6757-jp84-gxfx"

    calls: list[str] = []
    offline = _provider(cache, _transport(calls=calls), offline=True)
    actual = await offline.find_vulnerabilities([_dep("pyyaml", "5.3")])
    await offline.aclose()

    assert calls == []  # genuinely no network
    assert [v.id for v in actual["pyyaml"]] == [v.id for v in expected["pyyaml"]]


async def test_clean_result_is_cached_as_a_negative(tmp_path: Path) -> None:
    """"No vulnerabilities" is an answer worth caching, not a cache miss."""
    calls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json={"results": [{}]})

    cache = tmp_path / "cache"
    transport = httpx.MockTransport(handler)

    p1 = _provider(cache, transport)
    assert await p1.find_vulnerabilities([_dep("requests", "2.32.0")]) == {}
    await p1.aclose()
    assert len(calls) == 1

    calls.clear()
    p2 = _provider(cache, transport)
    assert await p2.find_vulnerabilities([_dep("requests", "2.32.0")]) == {}
    await p2.aclose()
    assert calls == []  # negative served from cache


async def test_cache_is_keyed_on_version_not_just_package(tmp_path: Path) -> None:
    """pyyaml 5.3 and 6.0.1 are different questions with different answers."""
    cache = tmp_path / "cache"
    p1 = _provider(cache, _transport())
    await p1.find_vulnerabilities([_dep("pyyaml", "5.3")])
    await p1.aclose()

    # The patched version was never cached, so offline must not reuse 5.3's
    # entry and wrongly report 6.0.1 as vulnerable.
    p2 = _provider(cache, _transport(), offline=True)
    assert await p2.find_vulnerabilities([_dep("pyyaml", "6.0.1")]) == {}
    await p2.aclose()


# -- resilience ------------------------------------------------------------


async def test_batch_failure_degrades_without_crashing(tmp_path: Path) -> None:
    """A dead API must yield no findings, not an exception mid-scan."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={})

    provider = _provider(tmp_path, httpx.MockTransport(handler))
    assert await provider.find_vulnerabilities([_dep("pyyaml", "5.3")]) == {}
    await provider.aclose()


async def test_hydration_failure_skips_that_advisory(tmp_path: Path) -> None:
    """Batch finds an ID but the detail fetch 404s: skip, don't crash."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "GHSA-x"}]}]})
        return httpx.Response(404, json={})

    provider = _provider(tmp_path, httpx.MockTransport(handler))
    assert await provider.find_vulnerabilities([_dep("pyyaml", "5.3")]) == {}
    await provider.aclose()


async def test_retries_on_server_error_then_succeeds(tmp_path: Path) -> None:
    """5xx is retried with backoff rather than surfaced as a scan failure."""
    attempts = {"n": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            attempts["n"] += 1
            if attempts["n"] == 1:
                return httpx.Response(503, json={})
            return httpx.Response(
                200, json={"results": [{"vulns": [{"id": PYYAML_RECORD["id"]}]}]}
            )
        return httpx.Response(200, json=PYYAML_RECORD)

    provider = _provider(tmp_path, httpx.MockTransport(handler))
    results = await provider.find_vulnerabilities([_dep("pyyaml", "5.3")])

    assert attempts["n"] == 2  # proved a retry happened
    assert "pyyaml" in results
    await provider.aclose()


async def test_clean_package_yields_no_entry(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/querybatch":
            return httpx.Response(200, json={"results": [{}]})
        return httpx.Response(404, json={})

    provider = _provider(tmp_path, httpx.MockTransport(handler))
    assert await provider.find_vulnerabilities([_dep("requests", "2.32.0")]) == {}
    await provider.aclose()


def test_osv_satisfies_the_provider_protocol() -> None:
    """The orchestrator depends on the interface, not on OSV specifically."""
    assert isinstance(OSVProvider(cache_dir=None), VulnDBProvider)


@pytest.mark.parametrize("version", ["5.3", "5.3.0", "5.2"])
async def test_affected_versions_all_detected(tmp_path: Path, version: str) -> None:
    provider = _provider(tmp_path, _transport())
    results = await provider.find_vulnerabilities([_dep("pyyaml", version)])
    assert "pyyaml" in results
    await provider.aclose()
