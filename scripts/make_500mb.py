"""Write a 500 MB file for a manual transfer. Not used by pytest."""

from pathlib import Path

TARGET = Path("five-hundred.bin")
CHUNK = 1024 * 1024

def main() -> None:
    with TARGET.open("wb") as handle:
        block = b"n" * CHUNK
        for _ in range(500):
            handle.write(block)
    print(TARGET.resolve(), "500 MB")

if __name__ == "__main__":
    main()
