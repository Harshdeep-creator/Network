# NetDrive

Send a file to someone on the same network. Both sides show a short code. The file is written only after the receiver accepts, and only if the hash matches.

Design choices: discovery port 47821; discover window 3 seconds; handshake timeout 10 seconds; files are hashed in one streaming pass and then sent; an offer holds at most 100 files; characters Windows forbids become `_`; a leading dot is prefixed with `_`; a browser token lasts 5 minutes; resume chunks are 64 KiB; the browser code uses the certificate's public key; auto-accept defaults off and, when enabled for a verified contact, stops at 10 MB; three declines mute a peer for 15 minutes; a notice is at most 512 bytes; the mesh cache holds 1,000 ids; Everyone does not ask an extra confirmation; the ND02 transcript is an HKDF stand-in, not Noise XX; the UI binds to 127.0.0.1:8765. BLE, Wi-Fi Direct, and a phone keystore are simulated here. The real transfer is TCP on the LAN.

```text
python -m venv .venv
.venv\Scripts\python -m pip install -e ".[dev]"
.venv\Scripts\python -m pytest -q
.venv\Scripts\python -m netdrive receive --nick Maya
.venv\Scripts\python -m netdrive send notes.txt --to 127.0.0.1:PORT
.venv\Scripts\python -m netdrive demo_mitm
.venv\Scripts\python -m netdrive ui
```

On a Mac the same commands use `source .venv/bin/activate` and `python` instead of the Windows path. Open the UI at http://127.0.0.1:8765/ and use “Send a sample file to this computer” if you only have one machine.
