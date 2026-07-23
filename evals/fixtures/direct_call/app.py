"""Ground truth: REACHABLE. `yaml.load` is called directly at line 11."""

import yaml


def load_config(path):
    with open(path) as handle:
        # The classic CVE-2020-1747 pattern: load() without a safe loader.
        return yaml.load(handle)


def safe_alternative(path):
    with open(path) as handle:
        return yaml.safe_load(handle)
