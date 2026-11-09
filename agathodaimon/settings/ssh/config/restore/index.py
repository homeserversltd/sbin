"""SSH exposure config/restore stop. original is the previous config text; changed is its mutation witness."""
from agathodaimon.settings.ssh import _stops

def main(argv=None):
    return _stops.main('config_restore', known_fields=('original', 'changed'))
