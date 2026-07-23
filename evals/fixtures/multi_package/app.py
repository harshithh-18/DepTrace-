"""Ground truth: one package reachable, one not, in the same project.

`yaml.load` IS called (reachable). `jinja2.Template` is imported but the
vulnerable sandbox API is never touched (not reachable). A scanner that
decides per-project rather than per-symbol gets one of these wrong.
"""

import yaml
from jinja2 import Template


def load_config(path):
    with open(path) as handle:
        return yaml.load(handle)


def render(source, **context):
    return Template(source).render(**context)
