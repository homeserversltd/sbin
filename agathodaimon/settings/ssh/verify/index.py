"""SSH exposure verify stop."""
from agathodaimon.settings.ssh import _stops

def main(argv=None):
    return _stops.main('verify')
