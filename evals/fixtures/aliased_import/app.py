"""Ground truth: REACHABLE. The module is aliased, so a naive text search
for "yaml.load" finds nothing — resolution must go through the import table.
"""

import yaml as y


def load_config(path):
    with open(path) as handle:
        return y.load(handle)
