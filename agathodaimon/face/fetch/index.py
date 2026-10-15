"""HomeTV FaceDoor fetch verb."""
from agathodaimon.face._shared import invoke, fetch as _operation

def main(args=None):
    return invoke("fetch", _operation)
