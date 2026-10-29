"""Notification shelf entry shared by the module and staff CLI."""
import sys


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if args == ["post"]:
        from agathodaimon.notify.post.index import main as run
    elif args == ["act"]:
        from agathodaimon.notify.act.index import main as run
    else:
        print('{"ok":false,"firstMissingSignal":"notify-verb-invalid"}')
        return 1
    return run([])
