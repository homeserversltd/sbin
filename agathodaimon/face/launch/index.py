"""HomeTV FaceDoor launch verb."""
from agathodaimon.face._shared import invoke, launch as _operation

def main(args=None):
    return invoke("launch", _operation)
