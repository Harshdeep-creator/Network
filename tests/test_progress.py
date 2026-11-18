from netdrive.progress import Progress, format_eta


def test_progress_edges():
    clock = {"t": 100.0}

    def now():
        return clock["t"]

    bar = Progress(0, "empty.txt", clock=now)
    assert "100%" in bar.render()
    assert "ETA 00:00" in bar.render()
    bar = Progress(1000, "report.pdf", clock=now)
    assert "ETA --:--" in bar.render()
    assert bar.due(1.0)
    assert not bar.due(1.0)
    clock["t"] = 101.1
    assert bar.due(1.0)
    bar.update(1000)
    clock["t"] = 104.0
    bar.samples.append((104.0, 1000))
    assert "100%" in bar.finish()
    assert format_eta(61) == "01:01"
