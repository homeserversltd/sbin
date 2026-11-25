"""Export a box PIN inlet for one act."""
from importlib import import_module


def main(argv=None):
    return import_module("agathodaimon.storage.backup.pin-inlet._inlet").main("export")
