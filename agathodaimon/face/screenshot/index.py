"""HomeTV FaceDoor screenshot verb."""
from agathodaimon.face._shared import invoke, screenshot as _operation


def main(args=None):
    return invoke("screenshot", _operation)
