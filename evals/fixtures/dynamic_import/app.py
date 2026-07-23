"""Ground truth: NEEDS_REVIEW, flagged once.

`import_module(name)` takes a *computed* module name, so static analysis
cannot decide whether the vulnerable symbol is reached. Claiming REACHABLE
would be a guess; claiming NOT_REACHABLE would be a silent false negative.
Flagging it for review is the only honest answer.

The `getattr(module, "load")` below is deliberately NOT flagged: its
attribute is a literal, making it exactly as analyzable as `module.load`.
Only the computed argument defeats the engine.
"""

import importlib


def load_config(name, path):
    module = importlib.import_module(name)
    loader = getattr(module, "load")
    with open(path) as handle:
        return loader(handle)
