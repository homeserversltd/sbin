"""SSH exposure config/set stop. state is on or off."""
from agathodaimon.settings.ssh import _stops

def main(argv=None):
    return _stops.main('config_set', known_fields=('state',))
