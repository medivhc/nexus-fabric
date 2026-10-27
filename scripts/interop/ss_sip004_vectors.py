#!/usr/bin/env python3
"""Independent SIP004 subkey oracle for the ss_std vector report (step 1.5).

This script MUST NOT import or invoke the Rust crate under test. It derives the
SIP004 expected values from the frozen formula with independent primitives:

    master = EVP_BytesToKey(password, key_len=32)      # MD5, no salt, 1 iteration
    subkey = HKDF-SHA1(ikm=master, salt=salt, info=b"ss-subkey", L=32)

The generated JSON is consumed by the `ss_sip004_vector_report` ignored test,
which calls the *real* `apps/nexusd/src/proxy_fwd/ss_std.rs::derive_subkey` and
records actual values. The 1-byte / 16-byte password vectors are only available
from this oracle; the 64-byte / all-zero-salt master key is cross-checked against
the fixes-2 KAT-1 vector, and the 8-byte / all-zero-salt KAT-2 subkey is checked
directly. HKDF-SHA1 is self-checked against RFC 5869 A.4.

Usage:
    python3 scripts/interop/ss_sip004_vectors.py --out scripts/interop/ss_sip004_expected.json
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import sys
from pathlib import Path

INFO = b"ss-subkey"
METHOD = "chacha20-ietf-poly1305"
REFERENCE = "independent-python-evp-bytestokey+hkdf-sha1"


def evp_bytes_to_key(password: bytes, key_len: int = 32) -> bytes:
    """SIP004 password -> master key (MD5 chain, no salt, one iteration)."""
    out = b""
    prev = b""
    while len(out) < key_len:
        prev = hashlib.md5(prev + password).digest()
        out += prev
    return out[:key_len]


def hkdf_sha1(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF with SHA-1, hand-rolled with hmac/hashlib."""
    prk = hmac.new(salt, ikm, hashlib.sha1).digest()
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha1).digest()
        okm += block
        counter += 1
    return okm[:length]


def sip004_subkey(password: bytes, salt: bytes) -> bytes:
    return hkdf_sha1(evp_bytes_to_key(password), salt, INFO, 32)


def self_check() -> None:
    # RFC 5869 A.4 (SHA-1): IKM=0x0b*11, salt=0x00..0x0c, info=0xf0..0xf9, L=42.
    expected_rfc = bytes.fromhex(
        "085a01ea1b10f36933068b56efa5ad81"
        "a4f14b822f5b091568a9cdd4f155fda2"
        "c22e422478d305f3f896"
    )
    if hkdf_sha1(bytes.fromhex("0b" * 11), bytes(range(13)), bytes(range(0xF0, 0xFA)), 42) != expected_rfc:
        raise SystemExit("HKDF-SHA1 self-check against RFC 5869 A.4 FAILED")

    # fixes-2 KAT-1 #3: 64-byte password -> master key.
    kat1_pw = b"0123456789abcdef" * 4
    expected_master = "fe3a1ff59f3b89b2ad3d33f08984874bf3101797f67e6effc9b7946fbd3b8847"
    if evp_bytes_to_key(kat1_pw).hex() != expected_master:
        raise SystemExit("EVP_BytesToKey self-check against fixes-2 KAT-1#3 FAILED")

    # fixes-2 KAT-2: password "password", all-zero salt -> subkey.
    expected_kat2 = "8c945d161c1cb5a06f884ba84d32352eecc2367284af3b975f921a67b804b69e"
    if sip004_subkey(b"password", bytes(32)).hex() != expected_kat2:
        raise SystemExit("SIP004 subkey self-check against fixes-2 KAT-2 FAILED")


def vector(vector_id: str, password: bytes, salt: bytes) -> dict:
    return {
        "vector_id": vector_id,
        "password_sha256": hashlib.sha256(password).hexdigest(),
        "password_hex": password.hex(),
        "password_len": len(password),
        "salt_hex": salt.hex(),
        "expected_subkey_hex": sip004_subkey(password, salt).hex(),
    }


def build_vectors() -> list[dict]:
    return [
        vector("sip004-vec-1", b"a", bytes(range(0x40, 0x60))),
        vector("sip004-vec-2", b"0123456789abcdef", bytes(range(0x60, 0x80))),
        # 64-byte password, all-zero salt: master matches fixes-2 KAT-1#3.
        vector("sip004-vec-3", b"0123456789abcdef" * 4, bytes(32)),
        # Direct fixes-2 KAT-2 cross-check (8-byte password, all-zero salt).
        vector("sip004-vec-4", b"password", bytes(32)),
    ]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        default=str(Path(__file__).with_name("ss_sip004_expected.json")),
        help="write expected vectors JSON to this path",
    )
    args = parser.parse_args(argv)

    self_check()
    payload = {
        "schema_version": 1,
        "method": METHOD,
        "info": INFO.decode(),
        "reference": REFERENCE,
        "vectors": build_vectors(),
    }
    text = json.dumps(payload, indent=2, sort_keys=False) + "\n"
    out = Path(args.out)
    out.write_text(text, encoding="utf-8")
    for v in payload["vectors"]:
        print(
            f"{v['vector_id']} len={v['password_len']} "
            f"subkey={v['expected_subkey_hex']}"
        )
    print(f"wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
