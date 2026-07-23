"""Ground truth: this file must be recorded as failed and skipped.

A Python 2 print statement. Real repos contain unparseable files; a scanner
that crashes on one is useless. The scan must continue and still find the
reachable call in `good.py` next door.
"""

import yaml

print "this is python 2"

yaml.load(open("x"))
