"""Ground truth for `yaml.load`: REACHABLE, once (line 12).

`from X import y` binds the symbol itself, so the call site is a bare Name
with no module prefix at all. `sl` is an alias for the *different* symbol
`yaml.safe_load`, and must resolve to that rather than to `yaml.load` —
aliasing changes the local name, never which symbol is meant.
"""

from yaml import load
from yaml import safe_load as sl


def load_config(path):
    with open(path) as handle:
        return load(handle)


def load_safely(path):
    with open(path) as handle:
        return sl(handle)
