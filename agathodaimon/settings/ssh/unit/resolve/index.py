"""SSH exposure unit/resolve stop."""
from agathodaimon.settings.ssh import _stops

def main(argv=None):
    return _stops.main('unit_resolve')
