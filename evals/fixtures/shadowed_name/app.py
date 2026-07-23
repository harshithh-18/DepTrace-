"""Ground truth for `yaml.load`: NOT_REACHABLE.

A false-positive trap. Every line below mentions `load`, and one binds the
name `yaml` to a completely different module. A scanner that matches on text
rather than resolved imports reports REACHABLE here and is wrong.
"""

import json as yaml  # the name `yaml` now refers to json


def load(path):
    """A local function that shadows nothing dangerous."""
    with open(path) as handle:
        return yaml.load(handle)  # this is json.load


class Loader:
    def load(self, data):
        """A method called `load` on an unrelated class."""
        return data
