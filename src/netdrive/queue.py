"""One transfer runs. One more may wait. Anything further is busy."""


def classify(active: bool, waiting: bool) -> str:
    """`run`, `wait`, or `busy`."""
    if not active and not waiting:
        return "run"
    if active and not waiting:
        return "wait"
    return "busy"
