# SIP004 KAT fixtures (independent oracle)

These fixtures are the golden wire bytes used by `tests/sip004_kat.rs`. They are
produced **only** by `generate_kat.py`, which re-derives every byte from the
SIP004 text using independent primitives:

| Item | Source |
|---|---|
| `EVP_BytesToKey` (MD5, no salt, 1 iteration) | Python stdlib `hashlib` |
| HKDF-SHA1 | hand-rolled RFC 5869 on stdlib `hmac` + RFC 5869 A.4 self-check |
| chacha20-ietf-poly1305 | Python `cryptography` 47.0.0 (not the Rust crate) |
| nonce / chunk framing | SIP004 text (12B LE counter, +1 per encrypted chunk) |

The Rust crate under test is never imported or invoked here. Reviewers can
re-derive the fixtures with:

```sh
python3 crates/nexus-outbound-shadowsocks/tests/kat/generate_kat.py --check
```

## Parameters

- password: `ss-kat-password-3`
- plaintext: `encode_request(Ipv4(1.2.3.4, 8388))` (7B) + 16483 payload bytes
  `(i * 31 + 7) % 251`, payload length `0x3FFF + 100` → 16490B total in two
  chunks (16383 + 107)
- KAT-3 tx salt: `0x00..0x1f`
- KAT-4 tx salt: `0x20..0x3f`

## Wire arithmetic (pinned in the tests)

- single chunk overhead: `(2 + 16) + 16 = 34B`
- first chunk adds the 32B salt → `66B`
- 1B plaintext: first seal `67B`, second seal `35B`
- single chunk (16383B) wire: `16417B`; first chunk incl. salt: `16449B`
- KAT-3 wire: `32 + 18 + 16399 + 18 + 123 = 16590B` (first chunk ends at 16449)

## Fixtures (sha256)

| File | Bytes | sha256 |
|---|---|---|
| `kat3_client_wire.bin` | 16590 | `bc03f6b05aa1ce63979505021b10e3d1a11fff7b782c3d2fa5525b144c9e6a42` |
| `kat4_server_wire.bin` | 16590 | `604b4e1675617630f02a179beb2ba64c88087e4f1545198275dbcb7b190b6c3a` |
| `kat_neg_len_0x4000.bin` | 50 | `9af798d5c5b08d9d474faf60fd50857345c637696ab81b072dfeac22fda560c0` |
| `kat_neg_len_0.bin` | 50 | `49450e8f85484bf878dee358f727a203d36c3d630d4afe4170a9be5db5f6e83f` |

`kat_neg_len_*.bin` are `salt(0x00..0x1f) || AEAD(len)` only: a legitimate key
encrypts an out-of-range length so the decoder must reject it with
`InvalidFrame`.

## KAT-1 / KAT-2 expected values

- KAT-1 `"password"`: `5f4dcc3b5aa765d61d8327deb882cf99` `2b95990a9151374abd8ff8c5a7a0fe08`
  (first 16B cross-checked with `printf password | openssl dgst -md5`)
- KAT-1 `"pässwörd-密码"`: `fd0dc7425473fe807455ba8a82344b98186ec57b1c431ad997ef90eae98f74bc`
- KAT-1 64-char password (`0123456789abcdef` × 4):
  `fe3a1ff59f3b89b2ad3d33f08984874bf3101797f67e6effc9b7946fbd3b8847`
- KAT-2 (master = KAT-1 `"password"`, salt = 32×0x00, info = `ss-subkey`):
  `8c945d161c1cb5a06f884ba84d32352eecc2367284af3b975f921a67b804b69e`
