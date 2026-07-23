"""Ground truth: NOT_REACHABLE.

First-party code only calls safe_load. The vulnerable call exists solely in
the vendored .venv next to it, which must be excluded from the scan.
"""

import yaml


def load_config(path):
    with open(path) as handle:
        return yaml.safe_load(handle)
