"""SSH exposure config/read stop."""
from agathodaimon.settings.ssh import _stops

def main(argv=None):
    return _stops.main('config_read')
