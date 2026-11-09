"""SSH exposure verify stop. state is on or off; unit is the resolved SSH service."""
from agathodaimon.settings.ssh import _stops

def main(argv=None):
    return _stops.main('verify', known_fields=('state', 'unit'))
