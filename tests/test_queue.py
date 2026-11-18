from netdrive.queue import classify


def test_queue_policy():
    assert classify(False, False) == "run"
    assert classify(True, False) == "wait"
    assert classify(True, True) == "busy"
