"""Ground truth: REACHABLE. A deep dotted chain must resolve end to end."""

import os.path
import yaml.composer


def compose(stream):
    return yaml.composer.Composer().compose_document(stream)


def joined(a, b):
    return os.path.join(a, b)
