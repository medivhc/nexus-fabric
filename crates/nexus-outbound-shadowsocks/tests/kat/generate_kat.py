#!/usr/bin/env python3
"""Independent KAT generator for the SIP004 shadowsocks wire format.

This script is the *independent* oracle for the golden fixtures consumed by
`tests/sip004_kat.rs`. It MUST NOT import or invoke the Rust crate under test;
it re-derives everything from the SIP004 text plus the standard primitives:

  password -> master key : EVP_BytesToKey(MD5, no salt, 1 iteration)
  master key -> subkey   : HKDF-SHA1(salt = direction salt, info = "ss-subkey")
  wire format            : salt(32) || chunk*
  chunk                  : AEAD(len=2B BE) || AEAD(payload)
  AEAD                   : chacha20-ietf-poly1305, tag 16B, empty AAD
  nonce                  : 12B little-endian counter, +1 per encrypted chunk

Dependencies: Python 3.8+, `cryptography` (ChaCha20Poly1305), stdlib hashlib/hmac.

Usage:
    python3 tests/kat/generate_kat.py            # (re)write fixtures + print hex
    python3 tests/kat/generate_kat.py --check    # verify fixtures match on disk
"""

import hashlib
import hmac
import os
import sys

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURE_DIR = os.path.normpath(os.path.join(HERE, "..", "fixtures"))

KAT1_PASSWORDS = [
    "password",
    "pässwörd-密码",
    "0123456789abcdef" * 4,
]

KAT3_PASSWORD = "ss-kat-password-3"
KAT3_SALT = bytes(range(32))            # 0x00..0x1f
KAT4_SALT = bytes(range(0x20, 0x40))    # 0x20..0x3f
KAT3_PAYLOAD_LEN = 0x3FFF + 100         # 16483 payload bytes appended to the header


def evp_bytes_to_key(password: bytes) -> bytes:
    """D1 = MD5(pw); Di = MD5(D(i-1) || pw); concat, truncate to 32B."""
    out = b""
    prev = b""
    while len(out) < 32:
        prev = hashlib.md5(prev + password).digest()
        out += prev
    return out[:32]


def hkdf_sha1(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869 HKDF with SHA-1 (independent hand-rolled implementation)."""
    prk = hmac.new(salt, ikm, hashlib.sha1).digest()
    okm = b""
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha1).digest()
        okm += t
        counter += 1
    return okm[:length]


def nonce_bytes(counter: int) -> bytes:
    return counter.to_bytes(8, "little") + b"\x00\x00\x00\x00"


def seal_stream(master: bytes, salt: bytes, plaintext: bytes) -> bytes:
    """salt || per-chunk AEAD of (2B BE len) then payload; nonce +1 per chunk."""
    subkey = hkdf_sha1(master, salt, b"ss-subkey", 32)
    aead = ChaCha20Poly1305(subkey)
    out = bytearray(salt)
    counter = 0
    for off in range(0, len(plaintext), 0x3FFF):
        chunk = plaintext[off:off + 0x3FFF]
        out += aead.encrypt(nonce_bytes(counter), len(chunk).to_bytes(2, "big"), None)
        counter += 1
        out += aead.encrypt(nonce_bytes(counter), chunk, None)
        counter += 1
    return bytes(out)


def seal_len_chunk_only(master: bytes, salt: bytes, len_value: int) -> bytes:
    """salt || AEAD(len) only — used for the invalid-length negative fixtures."""
    subkey = hkdf_sha1(master, salt, b"ss-subkey", 32)
    aead = ChaCha20Poly1305(subkey)
    return salt + aead.encrypt(nonce_bytes(0), len_value.to_bytes(2, "big"), None)


def request_header(payload: bytes) -> bytes:
    # encode_request(Ipv4(1.2.3.4, 8388)) == 0x01 01 02 03 04 20 c4
    return b"\x01\x01\x02\x03\x04\x20\xc4" + payload


def kat3_plaintext() -> bytes:
    payload = bytes((i * 31 + 7) % 251 for i in range(KAT3_PAYLOAD_LEN))
    return request_header(payload)


def selfcheck_rfc5869_sha1() -> None:
    """RFC 5869 A.4 (SHA-1) test vector — guards the hand-rolled HKDF.

    Hash = SHA-1, IKM = 0x0b*11, salt = 0x00..0x0c, info = 0xf0..0xf9, L = 42.
    """
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    ikm = bytes.fromhex("0b" * 11)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected = bytes.fromhex(
        "085a01ea1b10f36933068b56efa5ad81"
        "a4f14b822f5b091568a9cdd4f155fda2"
        "c22e422478d305f3f896"
    )
    if hkdf_sha1(ikm, salt, info, 42) != expected:
        raise SystemExit("HKDF-SHA1 self-check against RFC 5869 A.4 FAILED")
    # Second, independent implementation (cryptography) must agree too.
    third_party = HKDF(
        algorithm=hashes.SHA1(), length=42, salt=salt, info=info
    ).derive(ikm)
    if third_party != expected:
        raise SystemExit("cryptography HKDF-SHA1 disagrees with RFC 5869 A.4")


def fixtures() -> dict:
    master = evp_bytes_to_key(KAT3_PASSWORD.encode())
    plain = kat3_plaintext()
    return {
        "kat3_client_wire.bin": seal_stream(master, KAT3_SALT, plain),
        "kat4_server_wire.bin": seal_stream(master, KAT4_SALT, plain),
        "kat_neg_len_0x4000.bin": seal_len_chunk_only(master, KAT3_SALT, 0x4000),
        "kat_neg_len_0.bin": seal_len_chunk_only(master, KAT3_SALT, 0),
    }


def main(argv) -> int:
    selfcheck_rfc5869_sha1()
    check = "--check" in argv[1:]

    for pw in KAT1_PASSWORDS:
        print("KAT-1 pw=%r master=%s" % (pw, evp_bytes_to_key(pw.encode()).hex()))
    kat1 = evp_bytes_to_key(KAT1_PASSWORDS[0].encode())
    print("KAT-2 master=%s subkey=%s" % (kat1.hex(), hkdf_sha1(kat1, bytes(32), b"ss-subkey", 32).hex()))

    plain = kat3_plaintext()
    print("KAT-3 plaintext_len=%d chunks=%s" % (len(plain), [min(0x3FFF, len(plain)), max(0, len(plain) - 0x3FFF)]))

    mismatches = []
    os.makedirs(FIXTURE_DIR, exist_ok=True)
    for name, data in fixtures().items():
        path = os.path.join(FIXTURE_DIR, name)
        if check:
            if not os.path.exists(path):
                mismatches.append(name + " (missing)")
            else:
                with open(path, "rb") as fh:
                    if fh.read() != data:
                        mismatches.append(name + " (content mismatch)")
            print("check %-26s %s sha256=%s" % (name, len(data), hashlib.sha256(data).hexdigest()))
        else:
            with open(path, "wb") as fh:
                fh.write(data)
            print("write %-26s %s sha256=%s" % (name, len(data), hashlib.sha256(data).hexdigest()))

    # Wire-length arithmetic that the Rust tests also pin (spec §1.2 / KAT-3).
    wire = seal_stream(evp_bytes_to_key(KAT3_PASSWORD.encode()), KAT3_SALT, plain)
    assert len(plain) == 16490, len(plain)
    assert len(wire) == 16590, len(wire)
    print("KAT-3 wire_len=%d first_chunk_end=%d" % (len(wire), 16449))

    if check and mismatches:
        print("MISMATCH: " + ", ".join(mismatches))
        return 1
    if check:
        print("fixtures up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
