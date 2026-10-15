"""HomeTV FaceDoor app verb."""
from agathodaimon.face._shared import invoke, app as _operation

def main(args=None):
    return invoke("app", _operation)
