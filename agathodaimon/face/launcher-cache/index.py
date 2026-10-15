"""HomeTV FaceDoor launcher-cache verb."""
from agathodaimon.face._shared import invoke, launcher_cache as _operation

def main(args=None):
    return invoke("launcher-cache", _operation)
