# Threat model

| Threat | What this build does | What it does not do |
|---|---|---|
| Passive listener on the LAN | File names and bytes are inside ChaCha20-Poly1305 after the handshake | It does not hide that two machines are talking, or how much data moves |
| Active proxy (MITM) | Each side shows a different code, and `demo_mitm` prints MISMATCH | The program does not decide for the person. If nobody compares the code, the proxy can re-encrypt |
| Grinding the 8-digit code | The identity path commits to a random value before revealing it | An 8-digit ephemeral code can still be ground in about 2^26 tries if the commit step is not used |
| Tampered or replayed frame | The tag check closes the session | A malicious sender can still offer a file the receiver chooses to accept |
| Path traversal and odd names | Names are reduced to a basename, `..` is rejected in folder lists, and the final path has to stay in the receive folder | It does not scan the file for malware |
| Full disk or a huge offer | The offer is refused before the prompt when it exceeds the limit or the free space | A disk that fills after accept stops the write and deletes the partial |
| BLE tracking | Rotating ids are implemented in the simulator and recognised only with a contact secret | This build has no BLE radio. Two captures of a real phone are not measured |
| Relay of file bytes | The mesh sim forwards a ciphertext control message and keeps no key | Files are not relayed. The 20-node run is in-process |

H1 and H2 (whether people are blocked from sharing, and whether they would try an alternative) are not measured. Throughput, discovery time, and battery are not measured on hardware.
