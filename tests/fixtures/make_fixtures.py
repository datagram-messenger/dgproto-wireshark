#!/usr/bin/env python3
"""Deterministic synthetic DGProto v1 fixtures for the Wireshark dissector.

This module builds a libpcap capture, a matching synthetic keylog, and the
expected per-frame field values consumed by ``tests/run_fixtures.py``. It has
no third-party dependencies (same constraint as ``scripts/validate.py``).

Everything here is synthetic and public: session IDs, traffic keys, nonces,
ephemeral keys, and payloads are generated from fixed constants in this file.
Nothing is derived from real traffic, real captures, or real secret material,
so the generated keylog is safe to use in CI logs. The capture and keylog are
regenerated on every run (``build/`` is git-ignored) rather than committed, so
``*.pcap`` / ``*keylog*`` never enter version control.

Wire layout mirrors ``plugin/dgproto.lua`` (the dissector under test) and the
DGProto v1 draft: a fixed 40-byte header, optional ciphertext + 16-byte AEAD
tag, and optional trailing padding. ChaCha20-Poly1305 is implemented per
RFC 8439 and is checked at import time against the exact known-answer vector
embedded in the dissector's own self-test, which guarantees that fixtures
generated here decrypt under the dissector.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import struct

# ── ChaCha20-Poly1305 (RFC 8439), pure Python ────────────────────────────────

_CHACHA_CONST = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)


def _rotl32(v: int, c: int) -> int:
    v &= 0xFFFFFFFF
    return ((v << c) | (v >> (32 - c))) & 0xFFFFFFFF


def _quarter_round(s: list, a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF; s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF; s[b] = _rotl32(s[b] ^ s[c], 7)


def _chacha20_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    state = list(_CHACHA_CONST)
    state += list(struct.unpack("<8I", key))
    state.append(counter & 0xFFFFFFFF)
    state += list(struct.unpack("<3I", nonce))
    work = state[:]
    for _ in range(10):
        _quarter_round(work, 0, 4, 8, 12)
        _quarter_round(work, 1, 5, 9, 13)
        _quarter_round(work, 2, 6, 10, 14)
        _quarter_round(work, 3, 7, 11, 15)
        _quarter_round(work, 0, 5, 10, 15)
        _quarter_round(work, 1, 6, 11, 12)
        _quarter_round(work, 2, 7, 8, 13)
        _quarter_round(work, 3, 4, 9, 14)
    out = [(work[i] + state[i]) & 0xFFFFFFFF for i in range(16)]
    return struct.pack("<16I", *out)


def _chacha20(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 64):
        block = _chacha20_block(key, counter + (i // 64), nonce)
        chunk = data[i:i + 64]
        out += bytes(b ^ block[j] for j, b in enumerate(chunk))
    return bytes(out)


_P1305 = (1 << 130) - 5
_R_CLAMP = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF


def _poly1305_mac(msg: bytes, otk: bytes) -> bytes:
    r = int.from_bytes(otk[0:16], "little") & _R_CLAMP
    s = int.from_bytes(otk[16:32], "little")
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        acc = (acc + int.from_bytes(block + b"\x01", "little")) % _P1305
        acc = (acc * r) % _P1305
    acc = (acc + s) & ((1 << 128) - 1)
    return acc.to_bytes(16, "little")


def _pad16(n: int) -> bytes:
    return b"\x00" * ((16 - (n % 16)) % 16)


def chacha20_poly1305_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Return ciphertext || 16-byte Poly1305 tag (RFC 8439 AEAD construction)."""
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    if len(nonce) != 12:
        raise ValueError("nonce must be 12 bytes")
    otk = _chacha20_block(key, 0, nonce)[0:32]
    ciphertext = _chacha20(key, 1, nonce, plaintext)
    mac_data = aad + _pad16(len(aad)) + ciphertext + _pad16(len(ciphertext))
    mac_data += struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ciphertext))
    tag = _poly1305_mac(mac_data, otk)
    return ciphertext + tag


def _crypto_selftest() -> None:
    """Reproduce the exact RFC 8439 2.8.2 vector used by the dissector self-test."""
    key = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    plaintext = (
        b"Ladies and Gentlemen of the class of '99: If I could offer "
        b"you only one tip for the future, sunscreen would be it."
    )
    want = (
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691"
    )
    got = chacha20_poly1305_encrypt(key, nonce, plaintext, aad).hex()
    if got != want:
        raise SystemExit(
            "generator crypto self-test failed: ChaCha20-Poly1305 output does not "
            "match RFC 8439 2.8.2; fixtures would not decrypt under the dissector"
        )


# Fail fast at import time so a broken crypto change never emits silent garbage.
_crypto_selftest()


# ── DGProto v1 wire format ───────────────────────────────────────────────────

MAGIC = b"DGP1"
HEADER_LEN = 40
AEAD_TAG_LEN = 16
NO_TAG = {0x01, 0x02}  # handshake flights carry no AEAD tag
FLAG_PADDING = 0x02
VERSION = 0x01

# Synthetic, public session + traffic key shared by all encrypted fixtures.
SESSION_ID = bytes(range(16))                          # 000102...0f
TRAFFIC_KEY = bytes((0x40 + i) & 0xFF for i in range(32))  # 4041...5f


def _header(msg_type: int, sequence: int, payload_len: int, pad_len: int) -> bytes:
    flags = FLAG_PADDING if pad_len > 0 else 0x00
    hdr = bytearray()
    hdr += MAGIC
    hdr += bytes([VERSION, flags, msg_type & 0xFF, 0x00])  # version, flags, type, reserved1
    hdr += SESSION_ID                                      # 16-byte session id
    hdr += struct.pack("<Q", sequence)                    # sequence (LE64)
    hdr += struct.pack("<I", payload_len)                 # payload length (LE32)
    hdr += bytes([pad_len & 0xFF])                        # pad length
    hdr += b"\x00\x00\x00"                                # reserved2
    assert len(hdr) == HEADER_LEN, len(hdr)
    return bytes(hdr)


def _padding(pad_len: int) -> bytes:
    return bytes((0xA0 + i) & 0xFF for i in range(pad_len))


def plain_frame(msg_type: int, sequence: int, payload: bytes, pad_len: int = 0) -> bytes:
    """A frame with no AEAD tag (handshake flights)."""
    header = _header(msg_type, sequence, len(payload), pad_len)
    header = header[:8] + bytes(16) + header[24:]  # session assigned only after flight 3
    return header + payload + _padding(pad_len)


def encrypted_frame(msg_type: int, sequence: int, plaintext: bytes, pad_len: int = 0) -> bytes:
    """A frame whose payload is ChaCha20-Poly1305 ciphertext + tag.

    nonce = 4 zero bytes + the wire-order LE64 sequence; AAD = header || padding
    (exactly what ``plugin/dgproto.lua`` reconstructs before decrypting).
    """
    payload_len = len(plaintext)  # ciphertext length == plaintext length
    header = _header(msg_type, sequence, payload_len, pad_len)
    padding = _padding(pad_len)
    nonce = b"\x00\x00\x00\x00" + struct.pack("<Q", sequence)
    aad = header + padding
    ct_tag = chacha20_poly1305_encrypt(TRAFFIC_KEY, nonce, plaintext, aad)
    return header + ct_tag + padding


def keylog_text() -> str:
    """A synthetic keylog that unlocks every encrypted fixture (epoch 1)."""
    return (
        "# Synthetic DGProto keylog - public test material, not real keys.\n"
        f"DGPROTO_SESSION_KEY {SESSION_ID.hex()} tx 1 {TRAFFIC_KEY.hex()}\n"
    )


# ── Synthetic payloads for each message type ─────────────────────────────────

def _hs_init_payload() -> bytes:
    return bytes([0x01, 0x00, 0x00, 0x00]) + bytes((0x10 + i) & 0xFF for i in range(32))


def _hs_response_payload() -> bytes:
    server_ephem = bytes((0x20 + i) & 0xFF for i in range(32))
    noise = bytes((0x30 + i) & 0xFF for i in range(64))
    return server_ephem + noise


def _hs_finish_payload() -> bytes:
    return bytes((0x50 + i) & 0xFF for i in range(64))


def _encdata_plaintext(stream_id: int, app_type: int, tlv: bytes) -> bytes:
    return struct.pack("<H", stream_id) + bytes([app_type, 0x00]) + tlv


def _ping_plaintext(is_response: int) -> bytes:
    base = 0x00 if is_response == 0 else 0x08
    return bytes([is_response & 0xFF]) + bytes((base + i) & 0xFF for i in range(8))


def _text_plaintext(code: int, text: bytes) -> bytes:
    tlv = b"\x01" + struct.pack("<H", len(text)) + text
    return struct.pack("<H", code) + tlv + bytes((-len(tlv)) % 4)


def _close_plaintext(code: int) -> bytes:
    return _text_plaintext(code, b"protocol error")


def _ack_plaintext(seqs: list) -> bytes:
    body = bytes([len(seqs)])
    for s in seqs:
        body += struct.pack("<Q", s)
    return body


def _rekey_plaintext(epoch: int) -> bytes:
    return struct.pack("<I", epoch) + bytes((0x60 + i) & 0xFF for i in range(32))


def _error_plaintext(code: int) -> bytes:
    return _text_plaintext(code, b"synthetic")


# ── Ethernet / IPv4 / TCP framing + libpcap writer ───────────────────────────

_PCAP_GLOBAL = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)  # LINKTYPE_ETHERNET
_MAC_CLIENT = bytes.fromhex("020000000001")
_MAC_SERVER = bytes.fromhex("020000000002")
_IP_CLIENT = bytes([10, 0, 0, 1])
_IP_SERVER = bytes([10, 0, 0, 2])


def _checksum16(data: bytes) -> int:
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    total = (total >> 16) + (total & 0xFFFF)
    total += total >> 16
    return (~total) & 0xFFFF


def _ipv4(src: bytes, dst: bytes, payload: bytes, ident: int) -> bytes:
    total_len = 20 + len(payload)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0x00, total_len, ident, 0x4000, 64, 6, 0, src, dst)
    checksum = _checksum16(hdr)
    hdr = struct.pack(">BBHHHBBH4s4s", 0x45, 0x00, total_len, ident, 0x4000, 64, 6, checksum, src, dst)
    return hdr + payload


def _tcp(src_port: int, dst_port: int, seq: int, ack: int, payload: bytes) -> bytes:
    # data offset 5 (20 bytes), flags PSH|ACK, zero checksum (tshark does not
    # validate TCP checksums by default for synthetic captures).
    hdr = struct.pack(">HHIIBBHHH", src_port, dst_port, seq & 0xFFFFFFFF,
                      ack & 0xFFFFFFFF, 0x50, 0x18, 65535, 0, 0)
    return hdr + payload


class _Stream:
    """One client->server TCP conversation with contiguous client sequence."""

    def __init__(self, client_port: int) -> None:
        self.client_port = client_port
        self.cseq = 1
        self.ident = client_port & 0xFFFF

    def to_server(self, payload: bytes) -> bytes:
        tcp = _tcp(self.client_port, 9900, self.cseq, 1, payload)
        ip = _ipv4(_IP_CLIENT, _IP_SERVER, tcp, self.ident)
        self.cseq += len(payload)
        self.ident = (self.ident + 1) & 0xFFFF
        return _MAC_SERVER + _MAC_CLIENT + struct.pack(">H", 0x0800) + ip


# tshark -T fields extraction order (frame.number first). Shared with the runner.
FIELDS = [
    "frame.number",
    "dgproto.validation.code",
    "_ws.col.Info",
    "dgproto.magic",
    "dgproto.version",
    "dgproto.msg_type",
    "dgproto.sequence",
    "dgproto.payload_len",
    "dgproto.pad_len",
    "dgproto.hs.pattern",
    "dgproto.stream_id",
    "dgproto.app_msg_type",
    "dgproto.close_code",
    "dgproto.error_code",
    "dgproto.rekey_epoch",
    "dgproto.acked_count",
    "dgproto.acked_seq",
    "dgproto.is_response",
]


class _Capture:
    def __init__(self) -> None:
        self.packets: list = []       # (ts_sec, ts_usec, bytes, reported_length)
        self.frames: dict = {}        # frame_number -> {"fields": {...}, "absent": [...]}
        self._ts = 1577836800         # 2020-01-01T00:00:00Z, fixed for determinism

    def add(self, data: bytes, fields=None, absent=None, reported_length=None) -> int:
        self.packets.append((self._ts, 0, data, reported_length or len(data)))
        self._ts += 1
        n = len(self.packets)
        self.frames[n] = {"fields": fields or {}, "absent": absent or []}
        return n

    def pcap_bytes(self) -> bytes:
        out = bytearray(_PCAP_GLOBAL)
        for ts_sec, ts_usec, data, reported_length in self.packets:
            out += struct.pack("<IIII", ts_sec, ts_usec, len(data), reported_length)
            out += data
        return bytes(out)


def _new_stream(port_seq: list) -> _Stream:
    port_seq[0] += 1
    return _Stream(40000 + port_seq[0])


def build_capture():
    """Return (pcap_bytes, keylog_text, expectations_dict).

    Expectations map frame.number -> {"fields": {field: int|str|list},
    "absent": [field, ...]}. Integer values are compared numerically (tshark
    may print hex or decimal); lists allow multiple occurrences in one frame.
    """
    cap = _Capture()
    port = [0]  # mutable counter so each PDU gets its own isolated TCP stream

    def one(payload, fields=None, absent=None):
        return cap.add(_new_stream(port).to_server(payload), fields, absent)

    H = {"dgproto.magic": "DGP1", "dgproto.version": 0x01}

    # ── Handshake flights (no AEAD tag) ──────────────────────────────────────
    one(plain_frame(0x01, 0, _hs_init_payload()),
        {**H, "dgproto.msg_type": 0x01, "dgproto.payload_len": 36,
         "dgproto.pad_len": 0, "dgproto.hs.pattern": 0x01})
    one(plain_frame(0x02, 0, _hs_response_payload()),
        {**H, "dgproto.msg_type": 0x02, "dgproto.payload_len": 96, "dgproto.pad_len": 0})
    one(plain_frame(0x02, 0, _hs_finish_payload()),
        {**H, "dgproto.msg_type": 0x02, "dgproto.payload_len": 64, "dgproto.pad_len": 0})

    # ── Encrypted data (decryptable via the synthetic keylog) ────────────────
    pt3 = _encdata_plaintext(7, 0x10, b"synthetic-tlv")
    one(encrypted_frame(0x03, 100, pt3),
        {**H, "dgproto.msg_type": 0x03, "dgproto.sequence": 100,
         "dgproto.payload_len": len(pt3), "dgproto.pad_len": 0,
         "dgproto.stream_id": 7, "dgproto.app_msg_type": 0x10})
    pt3p = _encdata_plaintext(9, 0x11, b"pad")
    one(encrypted_frame(0x03, 101, pt3p, pad_len=8),
        {**H, "dgproto.msg_type": 0x03, "dgproto.sequence": 101,
         "dgproto.payload_len": len(pt3p), "dgproto.pad_len": 8,
         "dgproto.stream_id": 9, "dgproto.app_msg_type": 0x11})

    # ── Ping / Pong ──────────────────────────────────────────────────────────
    one(encrypted_frame(0x04, 102, _ping_plaintext(0)),
        {**H, "dgproto.msg_type": 0x04, "dgproto.sequence": 102, "dgproto.is_response": 0})
    one(encrypted_frame(0x04, 103, _ping_plaintext(1)),
        {**H, "dgproto.msg_type": 0x04, "dgproto.sequence": 103, "dgproto.is_response": 1})

    # ── SessionClose / Ack / ResumptionTicket / RekeyInit / Error ────────────
    one(encrypted_frame(0x05, 104, _close_plaintext(2)),
        {**H, "dgproto.msg_type": 0x05, "dgproto.sequence": 104, "dgproto.close_code": 2})
    one(encrypted_frame(0x06, 105, _ack_plaintext([10, 20, 30])),
        {**H, "dgproto.msg_type": 0x06, "dgproto.sequence": 105,
         "dgproto.acked_count": 3, "dgproto.acked_seq": [10, 20, 30]})
    pt7 = b"synthetic-resumption-ticket"
    one(encrypted_frame(0x07, 106, pt7),
        {**H, "dgproto.msg_type": 0x07, "dgproto.sequence": 106,
         "dgproto.payload_len": len(pt7)})
    one(encrypted_frame(0x08, 107, _rekey_plaintext(1)),
        {**H, "dgproto.msg_type": 0x08, "dgproto.sequence": 107, "dgproto.rekey_epoch": 1})
    one(encrypted_frame(0x09, 108, _error_plaintext(42)),
        {**H, "dgproto.msg_type": 0x09, "dgproto.sequence": 108, "dgproto.error_code": 42})

    # ── Fragmented frame: one EncryptedData split across two TCP segments ─────
    frag = encrypted_frame(0x03, 200, _encdata_plaintext(11, 0x12, b"fragmented-frame"))
    frag_stream = _new_stream(port)
    cut = HEADER_LEN + 6  # split inside the ciphertext
    cap.add(frag_stream.to_server(frag[:cut]), absent=["dgproto.msg_type"])  # partial, pending reassembly
    cap.add(frag_stream.to_server(frag[cut:]),
            {**H, "dgproto.msg_type": 0x03, "dgproto.sequence": 200,
             "dgproto.stream_id": 11})  # completes on the second segment

    # ── Multiple frames coalesced into one TCP segment ───────────────────────
    coalesced = encrypted_frame(0x04, 201, _ping_plaintext(0)) + \
        encrypted_frame(0x09, 202, _error_plaintext(7))
    one(coalesced, {"dgproto.msg_type": [0x04, 0x09], "dgproto.sequence": [201, 202]})

    # ── Malformed / truncated frames must fail safely (no over-read, no crash) ─
    # Truncated header (only magic + a few bytes): dissector asks for more data.
    one(MAGIC + b"\x00" * 10, absent=["dgproto.msg_type"])
    # Declared payload length far beyond the captured bytes: reassembly pends.
    one(_header(0x03, 300, 0xFFFFFF00, 0), absent=["dgproto.msg_type"])
    # Wrong magic on the DGProto port: dissector declines, no false positive.
    one(b"XXXX" + b"\x00" * 40, absent=["dgproto.msg_type"])

    # ── Bounds safety: valid AEAD frames whose plaintext is too short / unknown ─
    # RekeyInit plaintext shorter than the 36-byte record: sub-dissection must
    # bail out, leaving rekey_epoch unset, without reading past the buffer.
    one(encrypted_frame(0x08, 205, b"ABCD"),
        {**H, "dgproto.msg_type": 0x08, "dgproto.sequence": 205},
        absent=["dgproto.rekey_epoch"])
    # Unknown message type: decrypts, no sub-fields, no crash.
    one(encrypted_frame(0x7F, 206, b"unknown-type-payload"),
        {**H, "dgproto.msg_type": 0x7F, "dgproto.sequence": 206})

    # Header and handshake diagnostics: each case isolates one wire violation.
    def mutated(wire, offset, value):
        return wire[:offset] + bytes([value]) + wire[offset + 1:]

    good = plain_frame(1, 0, _hs_init_payload())
    for offset, value, code in [(4, 2, "version"), (5, 0x80, "flags"),
                                (7, 1, "reserved"), (37, 1, "reserved"),
                                (5, 2, "padding"), (8, 1, "session_id"),
                                (24, 1, "sequence"), (40, 2, "handshake_pattern"),
                                (41, 1, "handshake_reserved")]:
        one(mutated(good, offset, value), {"dgproto.validation.code": code})
    one(mutated(plain_frame(1, 0, _hs_init_payload(), 1), 5, 0),
        {"dgproto.validation.code": "padding"})
    for msg_type, length in [(1, 0), (1, 35), (1, 37), (2, 63), (2, 65), (2, 95), (2, 97)]:
        payload = (_hs_init_payload() + bytes(100))[:length] if msg_type == 1 else bytes(length)
        one(plain_frame(msg_type, 0, payload), {"dgproto.validation.code": "handshake_length"})
    for msg_type in (3, 4, 5, 6, 8, 9):
        wire = encrypted_frame(msg_type, 1, b"synthetic")
        one(wire[:8] + bytes(16) + wire[24:], {"dgproto.validation.code": "session_id"})
        body = {3: bytes(4), 4: _ping_plaintext(0), 5: bytes(2),
                6: _ack_plaintext([1]), 8: _rekey_plaintext(2), 9: bytes(2)}[msg_type]
        one(encrypted_frame(msg_type, 0, body), {"dgproto.validation.code": "sequence"})
    one(b"XXXX" + bytes(40), {"dgproto.validation.code": "magic"}, absent=["dgproto.msg_type"])
    one(_header(3, 1, 65535, 0), {"dgproto.validation.code": "frame_size"}, absent=["dgproto.msg_type"])
    one(encrypted_frame(0x07, 1, b"reserved"), {"dgproto.validation.code": "message_type"})
    one(encrypted_frame(0x7f, 1, b"unknown"), {"dgproto.validation.code": "message_type"})

    # A malformed reassembled handshake emits diagnostics only after completion.
    bad = mutated(good, 24, 1)
    stream = _new_stream(port)
    cap.add(stream.to_server(bad[:13]), absent=["dgproto.validation.code"])
    cap.add(stream.to_server(bad[13:]), {"dgproto.validation.code": "sequence"})
    # Canonical padded handshake and large uint64 sequences are valid.
    one(plain_frame(2, 0, _hs_finish_payload(), 255), absent=["dgproto.validation.code"])
    one(encrypted_frame(3, (1 << 64) - 1, bytes(4)), absent=["dgproto.validation.code"])

    # Authenticated malformed control records; no secrets or external crypto.
    for msg_type, minimum in ((3, 4), (4, 9), (5, 2), (6, 1), (8, 36), (9, 2)):
        for length in range(1, minimum):
            one(encrypted_frame(msg_type, 400 + length, bytes(length)),
                {"dgproto.validation.code": "payload_length"})
    for msg_type, body in ((4, bytes(10)), (8, _rekey_plaintext(2) + b"x")):
        one(encrypted_frame(msg_type, 450, body), {"dgproto.validation.code": "payload_length"})
    for msg_type, body in ((3, b"\x00\x00\x00\x01"), (4, b"\x02" + bytes(8)),
                           (5, struct.pack("<H", 4)), (8, bytes(36))):
        one(encrypted_frame(msg_type, 451, body), {"dgproto.validation.code": "payload_value"})
    for body in (b"\x00", b"\x02" + struct.pack("<Q", 10),
                 _ack_plaintext([10]) + b"x", b"\xff" + bytes(8)):
        one(encrypted_frame(6, 452, body), {"dgproto.validation.code": "ack_count"})
    for msg_type in (5, 9):
        for body in (b"\x00\x00x", b"\x00\x00\x02\x00\x00\x00",
                     _text_plaintext(0, b"abc")[:-1],
                     _text_plaintext(0, b"abc") + bytes(4)):
            one(encrypted_frame(msg_type, 453, body), {"dgproto.validation.code": "control_envelope"})
        for text in (b"\xc0\x80", b"\xed\xa0\x80", b"\xf4\x90\x80\x80", b"\xe2\x82", b"\xff"):
            one(encrypted_frame(msg_type, 454, _text_plaintext(0, text)),
                {"dgproto.validation.code": "payload_value"})
        for text in (b"", b"a", b"ab", b"abc", b"abcd", "Привет 😀".encode("utf-8"), b"a\x00b"):
            one(encrypted_frame(msg_type, 455, _text_plaintext(0, text)), absent=["dgproto.validation.code"])
        one(encrypted_frame(msg_type, 456, bytes(2)), absent=["dgproto.validation.code"])
        # Alignment octets are opaque, not required to be zero on receive.
        one(encrypted_frame(msg_type, 457, _text_plaintext(0, b"ab")[:-3] + b"XYZ"),
            absent=["dgproto.validation.code"])
    one(encrypted_frame(6, 458, _ack_plaintext(list(range(255)))), absent=["dgproto.validation.code"])
    wire = encrypted_frame(6, 459, b"\x02" + struct.pack("<Q", 1))
    stream = _new_stream(port)
    cap.add(stream.to_server(wire[:44]), absent=["dgproto.validation.code"])
    cap.add(stream.to_server(wire[44:]), {"dgproto.validation.code": "ack_count", "dgproto.acked_seq": 1})
    for cut in (HEADER_LEN + 1, len(wire) - 1):
        packet = _new_stream(port).to_server(wire)
        captured = packet[:54 + cut]
        cap.add(captured, {"dgproto.validation.code": "truncated"}, reported_length=len(packet))
    cap.frames[8]["fields"]["_ws.col.Info"] = "[SessionClose seq=104 code=2]"
    cap.frames[9]["fields"]["_ws.col.Info"] = "[Ack seq=105 count=3]"
    cap.frames[11]["fields"]["_ws.col.Info"] = "[RekeyInit seq=107 epoch=1]"
    cap.frames[12]["fields"]["_ws.col.Info"] = "[Error seq=108 code=42]"

    # Existing happy paths must stay diagnostic-free; the post-MVP and malformed
    # baseline probes are intentionally not canonical.
    for n in (1, 2, 3, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14, 15):
        cap.frames[n]["absent"].append("dgproto.validation.code")
    return cap.pcap_bytes(), keylog_text(), cap.frames


def write(out_dir: pathlib.Path):
    out_dir.mkdir(parents=True, exist_ok=True)
    pcap, keylog, frames = build_capture()
    pcap_path = out_dir / "dgproto.pcap"
    keylog_path = out_dir / "dgproto_keylog.txt"
    expected_path = out_dir / "expected.json"
    pcap_path.write_bytes(pcap)
    keylog_path.write_text(keylog, encoding="ascii", newline="\n")
    expected_path.write_text(json.dumps({"fields": FIELDS, "frames": frames}, indent=2),
                             encoding="ascii", newline="\n")
    return pcap_path, keylog_path, expected_path


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out-dir", type=pathlib.Path, default=pathlib.Path("build/fixtures"))
    parser.add_argument("--selftest", action="store_true",
                        help="run only the crypto known-answer self-test and exit")
    args = parser.parse_args()
    if args.selftest:
        _crypto_selftest()
        print("generator crypto self-test: ok")
        return
    pcap_path, keylog_path, expected_path = write(args.out_dir)
    pcap, _, frames = build_capture()
    print(f"wrote {pcap_path} ({len(pcap)} bytes, {len(frames)} frames)")
    print(f"wrote {keylog_path}")
    print(f"wrote {expected_path}")


if __name__ == "__main__":
    main()
