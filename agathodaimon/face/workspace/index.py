"""HomeTV FaceDoor workspace verb."""
from agathodaimon.face._shared import invoke, workspace as _operation

def main(args=None):
    return invoke("workspace", _operation)
