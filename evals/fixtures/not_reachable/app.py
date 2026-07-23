"""Ground truth: NOT_REACHABLE.

pyyaml is imported and used, but only via `safe_load`. The vulnerable
`load` symbol is never reached. This fixture is the whole point of DepTrace:
a manifest-only scanner flags this repo, and it is wrong to.

The decoy names below must NOT match — `yaml_helper` and `myyaml` share a
prefix with `yaml` but are different modules, which is why matching is done
on dot boundaries rather than raw string prefixes.
"""

import yaml

import myyaml
import yaml_helper


def load_config(path):
    with open(path) as handle:
        return yaml.safe_load(handle)


def decoys(path):
    yaml_helper.load(path)
    myyaml.load(path)
    return "load"  # a bare string, not a symbol
