"""HomeTV FaceDoor volume verb."""
from agathodaimon.face._shared import invoke, volume as _operation

def main(args=None):
    return invoke("volume", _operation)
