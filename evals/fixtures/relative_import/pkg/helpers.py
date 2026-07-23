"""A first-party sibling module. Not a third-party dependency."""

import yaml


def parse(stream):
    return yaml.load(stream)
