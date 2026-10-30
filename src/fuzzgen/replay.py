"""replay stage stub; lands in a later unit."""

from .cli import Stopped


def run(args) -> int:
    raise Stopped("replay is not implemented yet")
