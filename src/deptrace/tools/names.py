"""Package-name normalization and distribution -> import-name mapping.

Why this module exists at all: the name you install is frequently not the
name you import. `pip install pyyaml` gives you `import yaml`. If DepTrace
searches the AST for `pyyaml` it finds nothing, reports NOT_REACHABLE, and
is confidently wrong. That is the worst failure mode we have, because it
looks exactly like success. So the mapping gets its own module and its own
tests.

Resolution strategy, in order:
  1. `importlib.metadata.packages_distributions()` — ground truth for what
     is actually installed in the current environment. Correct by
     construction, but only covers installed packages.
  2. A curated static table — covers the well-known offenders when the
     package is not installed (the common case: we scan a repo whose
     dependencies were never installed here).
  3. Normalized guess — `foo-bar` -> `foo_bar`. Right most of the time.
"""

from __future__ import annotations

import re
from functools import cache
from importlib import metadata

_NORMALIZE_RE = re.compile(r"[-_.]+")

# Curated distribution -> import roots. Keys MUST be PEP 503 normalized.
# Only entries where the guess would be wrong belong here; a mapping that
# agrees with the fallback is noise.
_STATIC_MAP: dict[str, tuple[str, ...]] = {
    "pyyaml": ("yaml",),
    "beautifulsoup4": ("bs4",),
    "pillow": ("PIL",),
    "scikit-learn": ("sklearn",),
    "scikit-image": ("skimage",),
    "msgpack-python": ("msgpack",),
    "python-dateutil": ("dateutil",),
    "python-dotenv": ("dotenv",),
    "python-magic": ("magic",),
    "python-multipart": ("multipart",),
    "attrs": ("attr", "attrs"),
    "protobuf": ("google.protobuf",),
    "opencv-python": ("cv2",),
    "opencv-python-headless": ("cv2",),
    "pycryptodome": ("Crypto",),
    "pycryptodomex": ("Cryptodome",),
    "pyjwt": ("jwt",),
    "pymysql": ("pymysql",),
    "mysqlclient": ("MySQLdb",),
    "psycopg2-binary": ("psycopg2",),
    "typing-extensions": ("typing_extensions",),
    "setuptools": ("setuptools", "pkg_resources"),
    "memcached": ("memcache",),
    "faiss-cpu": ("faiss",),
    "faiss-gpu": ("faiss",),
    "google-cloud-storage": ("google.cloud.storage",),
    "azure-storage-blob": ("azure.storage.blob",),
    "grpcio": ("grpc",),
    "django-cors-headers": ("corsheaders",),
    "djangorestframework": ("rest_framework",),
    "flask-sqlalchemy": ("flask_sqlalchemy",),
    "sqlalchemy": ("sqlalchemy",),
    "ruamel-yaml": ("ruamel.yaml",),
    "pyserial": ("serial",),
    "pytest-asyncio": ("pytest_asyncio",),
    "importlib-metadata": ("importlib_metadata",),
    "pynacl": ("nacl",),
    "pyopenssl": ("OpenSSL",),
    "pyusb": ("usb",),
    "pysocks": ("socks",),
    "pytest-cov": ("pytest_cov",),
    "docker-py": ("docker",),
    "jinja2": ("jinja2",),
    "markupsafe": ("markupsafe",),
}


def normalize(name: str) -> str:
    """Normalize a distribution name per PEP 503.

    Lowercase and collapse any run of `-`, `_`, `.` into a single `-`.
    `Foo.Bar_baz` and `foo-bar-baz` are the same project on PyPI, and OSV
    keys on the normalized form, so every name entering DepTrace passes
    through here exactly once.
    """
    return _NORMALIZE_RE.sub("-", name.strip()).lower()


@cache
def _installed_map() -> dict[str, tuple[str, ...]]:
    """Invert `packages_distributions()` into distribution -> import roots.

    Cached because it walks every dist-info in the environment; a scan asks
    about hundreds of packages and the answer cannot change mid-run.
    """
    inverted: dict[str, set[str]] = {}
    try:
        pkg_to_dists = metadata.packages_distributions()
    except Exception:  # pragma: no cover - environment-dependent
        return {}
    for import_name, dists in pkg_to_dists.items():
        for dist in dists:
            inverted.setdefault(normalize(dist), set()).add(import_name)
    return {dist: tuple(sorted(roots)) for dist, roots in inverted.items()}


def import_names_for(dist_name: str) -> tuple[str, ...]:
    """Best-effort import roots for a distribution name.

    Never returns empty: an empty result would make the reachability engine
    silently skip the package. When we genuinely do not know, the normalized
    guess is returned and may simply match nothing in the AST — a visible
    miss rather than an invisible one.
    """
    normalized = normalize(dist_name)

    installed = _installed_map().get(normalized)
    if installed:
        return installed

    static = _STATIC_MAP.get(normalized)
    if static:
        return static

    return (normalized.replace("-", "_"),)
