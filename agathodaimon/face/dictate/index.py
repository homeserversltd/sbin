"""FaceDoor push-to-talk dictation toggle."""
from agathodaimon.face._shared import dictate as _operation, invoke


def main(args=None):
    return invoke("dictate", _operation)
