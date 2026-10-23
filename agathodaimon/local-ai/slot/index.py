"""Local AI slot staff door."""
from agathodaimon._local_ai import main as _main, slot_action as select_action


def main(args=None):
    return _main('slot', args)
