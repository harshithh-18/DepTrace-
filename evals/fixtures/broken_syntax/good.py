"""Ground truth: REACHABLE. This file parses fine and must still be found
even though its sibling `app.py` fails to parse.
"""

import yaml


def load_config(path):
    with open(path) as handle:
        return yaml.load(handle)
