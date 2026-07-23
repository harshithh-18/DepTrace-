"""OSV.dev vulnerability provider.

OSV is free, keyless, and covers PyPI well, which is what makes DepTrace
runnable on a clean clone with no accounts.

**The two-stage shape of this client is forced by the API.** `/v1/querybatch`
is cheap and takes many packages at once, but it returns only vulnerability
*IDs* — no summary, no severity, no affected ranges. The advisory prose that
Phase 5's LLM needs, and the ranges this module needs to filter on version,
only come from `/v1/vulns/{id}`. So:

    stage 1  querybatch(packages)      -> candidate IDs        (1 request)
    stage 2  vulns/{id} for each ID    -> full advisory        (N requests)

Stage 2 dominates, and IDs repeat heavily across packages and across runs,
so the disk cache is what makes repeated eval runs fast and offline-capable.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
from pathlib import Path
from typing import Any

import httpx
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential_jitter,
)

from deptrace.core.state import Dependency, Vulnerability

from .ranges import extract_fixed_version, is_affected

OSV_API = "https://api.osv.dev"
BATCH_SIZE = 100  # OSV's documented per-request query cap
_CACHE_VERSION = "v1"  # bump to invalidate all cached advisories


class RetryableStatusError(Exception):
    """A 429/5xx response worth retrying with backoff."""


def _severity_of(record: dict[str, Any]) -> str | None:
    """Prefer GitHub's human-readable label over a raw CVSS vector."""
    db_specific = record.get("database_specific")
    if isinstance(db_specific, dict):
        label = db_specific.get("severity")
        if isinstance(label, str) and label:
            return label.upper()

    severity = record.get("severity")
    if isinstance(severity, list):
        for item in severity:
            if isinstance(item, dict):
                score = item.get("score")
                if isinstance(score, str) and score:
                    return score
    return None


def _references_of(record: dict[str, Any]) -> tuple[str, ...]:
    refs = record.get("references")
    if not isinstance(refs, list):
        return ()
    urls: list[str] = []
    for ref in refs:
        if isinstance(ref, dict):
            url = ref.get("url")
            if isinstance(url, str) and url:
                urls.append(url)
    return tuple(urls)


def to_vulnerability(record: dict[str, Any]) -> Vulnerability:
    """Convert a raw OSV record into the domain model.

    `symbols` is deliberately left empty: this layer reports *facts from the
    database*. Which symbol an advisory implicates is an LLM claim, produced
    later in Phase 5 and never inferred here.
    """
    aliases = record.get("aliases")
    affected = record.get("affected")
    affected_list = affected if isinstance(affected, list) else []

    return Vulnerability(
        id=str(record.get("id", "")),
        aliases=tuple(a for a in aliases if isinstance(a, str))
        if isinstance(aliases, list)
        else (),
        summary=str(record.get("summary") or ""),
        details=str(record.get("details") or ""),
        severity=_severity_of(record),
        fixed_version=extract_fixed_version(affected_list),
        references=_references_of(record),
    )


class OSVProvider:
    """Async OSV.dev client with disk caching and retry.

    Args:
        cache_dir: where advisories are persisted between runs.
        offline: when True, never touch the network; serve cache only. This
            is what lets CI and the eval harness run with no egress.
        concurrency: cap on simultaneous hydration requests, so a large repo
            does not hammer a free public API.
    """

    name = "osv"

    def __init__(
        self,
        cache_dir: Path | str | None = None,
        *,
        client: httpx.AsyncClient | None = None,
        offline: bool = False,
        concurrency: int = 10,
        timeout: float = 30.0,
    ) -> None:
        self._client = client
        self._owns_client = client is None
        self._offline = offline
        self._timeout = timeout
        self._semaphore = asyncio.Semaphore(concurrency)
        self._cache = self._open_cache(cache_dir)

    @staticmethod
    def _open_cache(cache_dir: Path | str | None) -> Any:
        """Open a diskcache, degrading to no caching if unavailable.

        A broken cache must never be fatal — it is an optimization.
        """
        if cache_dir is None:
            cache_dir = Path.home() / ".cache" / "deptrace" / "osv"
        try:
            import diskcache

            return diskcache.Cache(str(cache_dir))
        except Exception:  # pragma: no cover - environment-dependent
            return None

    # -- caching ---------------------------------------------------------

    def _cache_get(self, key: str) -> dict[str, Any] | None:
        if self._cache is None:
            return None
        try:
            raw = self._cache.get(f"{_CACHE_VERSION}:{key}")
        except Exception:  # pragma: no cover
            return None
        if isinstance(raw, str):
            try:
                parsed: dict[str, Any] = json.loads(raw)
                return parsed
            except json.JSONDecodeError:
                return None
        return None

    def _cache_set(self, key: str, value: dict[str, Any]) -> None:
        if self._cache is None:
            return
        with contextlib.suppress(Exception):  # caching is an optimization
            self._cache.set(f"{_CACHE_VERSION}:{key}", json.dumps(value))

    # -- HTTP ------------------------------------------------------------

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=self._timeout)
        return self._client

    @retry(
        retry=retry_if_exception_type((RetryableStatusError, httpx.TransportError)),
        wait=wait_exponential_jitter(initial=1, max=20),
        stop=stop_after_attempt(4),
        reraise=True,
    )
    async def _request(self, method: str, url: str, **kwargs: Any) -> dict[str, Any]:
        """Issue one request, retrying 429/5xx with exponential backoff+jitter.

        429 is explicit rather than lumped into 5xx: free-tier rate limits are
        the expected failure during an eval sweep, not an exceptional one.
        """
        client = await self._get_client()
        response = await client.request(method, url, **kwargs)

        if response.status_code == 429 or response.status_code >= 500:
            raise RetryableStatusError(f"{response.status_code} from {url}")
        if response.status_code >= 400:
            return {}  # 404 etc: a genuine "nothing here", not worth retrying

        try:
            payload: dict[str, Any] = response.json()
        except (json.JSONDecodeError, ValueError):
            return {}
        return payload

    # -- stage 1: discover candidate IDs ---------------------------------

    @staticmethod
    def _batch_key(dep: Dependency) -> str:
        """Cache key for stage 1, keyed on (package, version) as specified."""
        return f"batch:{dep.name}@{dep.version or '*'}"

    async def _query_batch(self, deps: list[Dependency]) -> dict[str, list[str]]:
        """Map package name -> candidate vulnerability IDs via querybatch.

        The per-package ID list is cached alongside the advisories themselves.
        Caching only the hydrated records would leave the cache unreachable
        offline: without stage 1 there are no IDs to look them up by.
        """
        if not deps:
            return {}

        found: dict[str, list[str]] = {}
        pending: list[Dependency] = []

        for dep in deps:
            cached = self._cache_get(self._batch_key(dep))
            if cached is not None:
                ids = cached.get("ids")
                if isinstance(ids, list):
                    if ids:
                        found[dep.name] = [i for i in ids if isinstance(i, str)]
                    continue
            pending.append(dep)

        if self._offline or not pending:
            return found

        for start in range(0, len(pending), BATCH_SIZE):
            chunk_deps = pending[start : start + BATCH_SIZE]
            queries: list[dict[str, Any]] = []
            for dep in chunk_deps:
                query: dict[str, Any] = {"package": {"name": dep.name, "ecosystem": "PyPI"}}
                if dep.version:
                    query["version"] = dep.version
                queries.append(query)

            try:
                payload = await self._request(
                    "POST", f"{OSV_API}/v1/querybatch", json={"queries": queries}
                )
            except Exception:
                continue  # one bad chunk must not abort the whole scan

            results = payload.get("results")
            if not isinstance(results, list):
                continue
            for dep, result in zip(chunk_deps, results, strict=False):
                if not isinstance(result, dict):
                    continue
                vulns = result.get("vulns")
                ids = (
                    [
                        v["id"]
                        for v in vulns
                        if isinstance(v, dict) and isinstance(v.get("id"), str)
                    ]
                    if isinstance(vulns, list)
                    else []
                )
                # Cache negatives too — "this version is clean" is exactly
                # the answer we want to serve offline without a round trip.
                self._cache_set(self._batch_key(dep), {"ids": ids})
                if ids:
                    found.setdefault(dep.name, []).extend(ids)
        return found

    # -- stage 2: hydrate full advisories --------------------------------

    async def _fetch_vuln(self, vuln_id: str) -> dict[str, Any] | None:
        """Fetch one advisory, preferring cache. Returns None if unavailable."""
        cached = self._cache_get(vuln_id)
        if cached is not None:
            return cached
        if self._offline:
            return None

        async with self._semaphore:
            try:
                record = await self._request("GET", f"{OSV_API}/v1/vulns/{vuln_id}")
            except Exception:
                return None

        if not record or not record.get("id"):
            return None
        self._cache_set(vuln_id, record)
        return record

    # -- public API ------------------------------------------------------

    async def find_vulnerabilities(
        self, dependencies: list[Dependency]
    ) -> dict[str, list[Vulnerability]]:
        """Resolve dependencies to the vulnerabilities that actually apply."""
        if not dependencies:
            return {}

        ids_by_package = await self._query_batch(dependencies)

        # Hydrate each unique ID exactly once; the same GHSA routinely
        # affects several packages in one dependency tree.
        unique_ids = {vid for ids in ids_by_package.values() for vid in ids}
        records: dict[str, dict[str, Any]] = {}

        async def load(vuln_id: str) -> None:
            record = await self._fetch_vuln(vuln_id)
            if record is not None:
                records[vuln_id] = record

        if unique_ids:
            async with asyncio.TaskGroup() as tg:
                for vuln_id in sorted(unique_ids):
                    tg.create_task(load(vuln_id))

        results: dict[str, list[Vulnerability]] = {}
        by_name = {dep.name: dep for dep in dependencies}

        for package, vuln_ids in ids_by_package.items():
            dep = by_name.get(package)
            if dep is None:
                continue
            matched: list[Vulnerability] = []
            for vuln_id in dict.fromkeys(vuln_ids):  # dedupe, keep order
                record = records.get(vuln_id)
                if record is None or record.get("withdrawn"):
                    continue  # withdrawn advisories are not findings

                affected = record.get("affected")
                verdict = is_affected(
                    dep.version, affected if isinstance(affected, list) else []
                )
                # None means undecidable (unpinned or unparseable version).
                # Keep it: the finding proceeds to triage and lands in
                # NEEDS_REVIEW rather than being silently dropped as safe.
                if verdict is False:
                    continue
                matched.append(to_vulnerability(record))

            if matched:
                results[package] = matched

        return results

    async def aclose(self) -> None:
        """Close the HTTP client if this provider created it."""
        if self._owns_client and self._client is not None:
            await self._client.aclose()
            self._client = None
