"""Run the staff notification verbs as a Python module."""
import sys

from agathodaimon.notify import index

raise SystemExit(index.main(sys.argv[1:]))
