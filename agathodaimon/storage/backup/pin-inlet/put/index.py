"""Store a box PIN inlet."""
from importlib import import_module


def main(argv=None):
    return import_module("agathodaimon.storage.backup.pin-inlet._inlet").main("put")
