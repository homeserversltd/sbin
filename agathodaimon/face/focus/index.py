"""HomeTV FaceDoor focus verb."""
from agathodaimon.face._shared import invoke, focus as _operation

def main(args=None):
    return invoke("focus", _operation)
