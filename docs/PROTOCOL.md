# NetDrive protocol

Multi-byte integers are big-endian.

The LAN handshake is 37 bytes: `ND01`, version 1, and a 32-byte X25519 public key. The sender writes first. The shared secret is expanded with HKDF-SHA256, salt `initiator_pub || responder_pub`, info `netdrive-v0.1 keys`, to 64 bytes. The first 32 encrypt sender to receiver. The second 32 encrypt the other way.

Frames are a 4-byte length and a ChaCha20-Poly1305 ciphertext. The nonce is 4 zero bytes and an 8-byte counter that each side counts for itself. The additional data is `ND01`. A failed tag closes the session. A length above 1 MiB closes it immediately. The third unknown type closes it too.

| Type | Name | Payload |
|---|---|---|
| 0x01 | OFFER | JSON: v, offer_id, sender_nick, files, optional sender_pk, text, and rotating |
| 0x02 | ACCEPT | empty |
| 0x03 | DECLINE | reason, optional sentence after a newline |
| 0x04 | FILE_START | 4-byte index |
| 0x05 | CHUNK | up to 64 KiB |
| 0x06 | FILE_END | index and SHA-256 |
| 0x07 | FILE_RESULT | index, 1 or 0, reason |
| 0x08 | CANCEL | empty |
| 0x09 | ERROR | text |
| 0x0A | CHUNK_ACK | index and a bitmap |
| 0x0B | RESUME_REQUEST | 16-byte offer id, then the 32-byte file hash |
| 0x0C | TEXT | at most 4 KB |
| 0x0D | FOLDER_MANIFEST | JSON list of relative paths |
| 0x0E | UPGRADE_OFFER | JSON path, host, port, token |
| 0x0F | UPGRADE_ACCEPT | empty |
| 0x10 | PING | empty |
| 0x11 | COMMIT | SHA-256 of the reveal, then the 32-byte static public key |
| 0x12 | REVEAL | the 32 random bytes named in the commit |

The session code is `SHA-256("netdrive-v0.1 sas" || initiator_pub || responder_pub)`, then the first 4 bytes as an integer mod 10^8, shown as `NNNN NNNN`. The program never compares the two screens. A person does.

The identity path stores an Ed25519 key in `.netdrive/identity.key`. When a static key is used, COMMIT and REVEAL run before the offer: each side sends the hash of its reveal, then the reveal. A reveal that does not match its hash closes the handshake. The code is `identity_code(transcript, initiator static, responder static, both reveals)`. The transcript is HKDF with info `netdrive-nd02 transcript`. That is not Noise XX.

A contact link is `netdrive://c?pk=<hex>&secret=<hex>`. Contacts-only mode accepts an offer only when its rotating token matches that secret. Visibility Off declines every offer and stops the beacon. Everyone reverts to the previous mode after 10 minutes.

Discovery is a UDP beacon on port 47821. The JSON is `app`, `v`, `nick`, `port`, and a per-run `sid`. A `WHO` datagram, or JSON with `"op":"who"`, gets that beacon back. Visibility Off sends nothing. Contacts only answers a WHO whose rotating id matches the contact secret. A blocked key or token gets no reply. No hardware address is included.

Partials live in `.netdrive-tmp/<offer id>/<index>.part` with a JSON bitmap beside them. A failed simulated link waits 10 seconds before the next path. `netdrive identity rotate-now` prints two rotating ids a step apart. A normal send uses the saved identity, so both screens show the commit-then-reveal code.
