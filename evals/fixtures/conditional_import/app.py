"""Ground truth: REACHABLE.

The vulnerable call is real but buried where naive analysis misses it: the
import is inside a try/except, and the call sits inside a nested function
under a conditional. A false negative here is the costly failure mode — a
missed reachable CVE that looks exactly like a clean scan.
"""

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None


def make_parser(strict=False):
    def parse(stream):
        if strict:
            return yaml.safe_load(stream)
        return yaml.load(stream)

    return parse
