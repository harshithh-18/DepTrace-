"""Ground truth for `yaml.load`: NOT_REACHABLE.

A sharper false-positive trap than `not_reachable`. Here the decoy symbols
share the target's *full* dotted prefix rather than just its first segment:

    target      yaml.load
    decoys      yaml.loader   yaml.load_all   yaml.loads

Naive prefix matching (`resolved.startswith("yaml.load")`) reports all three
as hits. Only matching on dot boundaries — `yaml.load` exactly, or something
under `yaml.load.` — rejects them.

This fixture exists because an earlier version of the eval could not detect
a deliberately broken matcher; every decoy in the dataset differed too early
in the string to expose the bug.
"""

import yaml


def loader_config():
    """`yaml.loader` starts with "yaml.load" but is a different module."""
    return yaml.loader.SafeLoader


def load_many(path):
    """`yaml.load_all` starts with "yaml.load" but is a different function."""
    with open(path) as handle:
        return list(yaml.load_all(handle, Loader=yaml.SafeLoader))


def safe(path):
    with open(path) as handle:
        return yaml.safe_load(handle)
