"""HomeTV FaceDoor bar verb."""
from agathodaimon.face._shared import invoke, bar as _operation

def main(args=None):
    return invoke("bar", _operation)
