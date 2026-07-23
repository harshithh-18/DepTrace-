"""Ground truth: the relative import must resolve to `pkg.helpers.parse`,
a first-party symbol, and must NOT be confused with the `yaml` package.

`helpers.py` does call the vulnerable symbol, and it is found there on its
own line — but the relative import here is not itself evidence.
"""

from . import helpers
from .helpers import parse


def run(stream):
    helpers.parse(stream)
    return parse(stream)
