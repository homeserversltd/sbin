"""HomeTV FaceDoor meter verb."""
from agathodaimon.face._shared import invoke, meter as _operation

def main(args=None):
    return invoke("meter", _operation)
