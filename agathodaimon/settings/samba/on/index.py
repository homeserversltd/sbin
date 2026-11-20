"""Enable and start the loaded Samba and Windows discovery services."""
from agathodaimon.settings.samba import _switch


def main(argv=None):
    return _switch.main(enabled=True)
