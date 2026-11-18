import io
from pathlib import Path

from netdrive.sender import send_files
from tests.support import listen


def _src(tmp_path: Path) -> Path:
    path = tmp_path / "n.txt"
    path.write_text("n")
    return path


def test_sixth_offer_and_mute(tmp_path: Path):
    src = _src(tmp_path)
    prompts = []

    def prompt(summary, offer):
        prompts.append(1)
        return True

    dst = tmp_path / "dst"
    receiver = listen(dst, prompt=prompt, mute_after=100)
    for _ in range(5):
        assert send_files([src], "127.0.0.1", receiver.port, "Ada", out=io.StringIO()) == 0
    before = len(prompts)
    assert send_files([src], "127.0.0.1", receiver.port, "Ada", out=io.StringIO()) == 1
    assert len(prompts) == before
    receiver.stop()

    prompts.clear()

    def decline(summary, offer):
        prompts.append(1)
        return False

    dst2 = tmp_path / "dst2"
    receiver = listen(dst2, prompt=decline, mute_after=3)
    for _ in range(3):
        send_files([src], "127.0.0.1", receiver.port, "Ada", out=io.StringIO())
    assert len(prompts) == 3
    send_files([src], "127.0.0.1", receiver.port, "Ada", out=io.StringIO())
    assert len(prompts) == 3
    receiver.stop()
