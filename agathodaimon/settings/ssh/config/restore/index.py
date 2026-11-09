"""SSH exposure config/restore stop."""
from agathodaimon.settings.ssh import _stops

def main(argv=None):
    return _stops.main('config_restore')
