"""HomeTV FaceDoor badge verb."""
from agathodaimon.face._shared import invoke, badge as _operation

def main(args=None):
    return invoke("badge", _operation)
