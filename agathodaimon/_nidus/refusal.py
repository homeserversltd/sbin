class Refusal(RuntimeError):
    """A bounded actuation refusal."""


class BadRequest(ValueError):
    """A bounded refusal of the request itself."""
