<div align="center">

# DGProto for Wireshark

**A standalone Wireshark dissector for the DGProto v1 draft wire format.**

[![CI](https://github.com/datagram-messenger/dgproto-wireshark/actions/workflows/ci.yml/badge.svg)](https://github.com/datagram-messenger/dgproto-wireshark/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/datagram-messenger/dgproto-wireshark)](https://github.com/datagram-messenger/dgproto-wireshark/releases/latest)
[![Wireshark](https://img.shields.io/badge/Wireshark-4.x-1679A7?logo=wireshark&logoColor=white)](https://www.wireshark.org/)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

[Install](#installation) · [Configure](#configuration) · [Decrypt](#keylog-decryption) · [Develop](#development)

</div>

---

## Overview

DGProto for Wireshark is a single-file Lua dissector for inspecting DGProto v1 traffic. It supports stream reassembly, Noise XX handshake inspection, encrypted frame metadata, control messages, and optional authenticated payload decryption from local keylogs.

> [!IMPORTANT]
> Releases before `1.0.0` track the evolving DGProto v1 draft and may include breaking protocol or display-filter changes. Version `1.0.0` is reserved for the first stable release.

## Features

- Discovery by TCP port `9900`, `DGP1` heuristic detection, and **Decode As…**
- TCP reassembly for fragmented and coalesced frames
- Fixed-header, payload, AEAD tag, and padding inspection
- Sub-dissection of all three Noise XX handshake flights
- Encrypted data, ping/pong, close, acknowledgement, rekey, and error fields
- Optional ChaCha20-Poly1305 decryption from DGProto keylogs
- Forward traffic-key ratchet derivation from epoch 1
- Built-in RFC 8439 and RFC 4231 cryptographic self-tests

The runtime is self-contained: no Python process or external decryption helper is required.

## Requirements

- Wireshark 4.x with Lua enabled
- A standard Wireshark Lua runtime with 64-bit integers and native bitwise operations
- DGProto v1 traffic using the current draft profile over TCP

## Installation

1. Download the latest archive from [GitHub Releases](https://github.com/datagram-messenger/dgproto-wireshark/releases/latest).
2. Extract `dgproto.lua` into Wireshark's **Personal Lua Plugins** directory.
3. Select **Analyze → Reload Lua Plugins**, or restart Wireshark.

Find the exact plugin directory under **Help → About Wireshark → Folders**. Common locations:

| Platform | Personal Lua Plugins directory |
| --- | --- |
| Windows | `%APPDATA%\Wireshark\plugins` |
| Linux | `~/.local/lib/wireshark/plugins` |
| macOS | `~/.local/lib/wireshark/plugins` |

For a one-off launch:

```sh
wireshark -X lua_script:/absolute/path/to/dgproto.lua
```

## Configuration

Open **Edit → Preferences → Protocols → DGProto v1**.

| Preference | Default | Purpose |
| --- | --- | --- |
| `TCP Port` | `9900` | Port registered for DGProto traffic |
| `Keylog File` | empty | Keylog path; overrides `DGPROTO_KEYLOG` |

For traffic on another port, update `TCP Port` or use **Analyze → Decode As…**.

Keylogs are resolved in this order:

1. `Keylog File` preference
2. `DGPROTO_KEYLOG` environment variable
3. `%APPDATA%\Wireshark\dgproto_keylog.txt` on Windows

## Keylog decryption

Set `DGPROTO_KEYLOG` before starting a local DGProto process and establishing a session. Expected entries:

```text
DGPROTO_SESSION_KEY <32-hex-session-id> <send|recv> 1 <64-hex-key>
```

The dissector tries available session keys and accepts plaintext only after Poly1305 authentication succeeds. It can derive later traffic-key epochs from an epoch-1 entry.

> [!CAUTION]
> Keylogs contain live traffic keys and remove transport confidentiality. Use them only in controlled development environments. Never commit, publish, attach, or use production keylogs. Delete them after debugging.

Reload or reopen the capture after adding keys. Successful decryption adds a **Decrypted Payload** subtree; failures appear in Expert Information without exposing unauthenticated plaintext.

## Usage

1. Start a capture or open a trusted capture.
2. Confirm that the **Protocol** column shows `DGProto`.
3. Expand **DGProto v1 → Header** to inspect framing and sequence data.
4. Add a keylog when decrypted fields are needed.
5. Open **Analyze → Expert Information** to review protocol and decryption warnings.

### Display filters

| Goal | Filter |
| --- | --- |
| All DGProto traffic | `dgproto` |
| Encrypted data frames | `dgproto.msg_type == 0x03` |
| A specific session | `dgproto.session_id == 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff` |
| Sequence number range | `dgproto.sequence >= 100` |
| A logical stream | `dgproto.stream_id == 1` |
| Padded frames | `dgproto.flags.padding == 1` |
| Error message codes (not validation failures) | `dgproto.error_code` |
| Close message codes | `dgproto.close_code` |
| Any protocol diagnostic | `dgproto.validation.code` |
| A specific diagnostic | `dgproto.validation.code == "ack_count"` |
| Capture-truncated frames | `dgproto.validation.truncated` |
| Noncanonical sender header fields | `dgproto.validation.flags || dgproto.validation.reserved` |
| Decryption failures | `dgproto.decrypt_fail` |

### Protocol diagnostics

Each finding adds a generated string to `dgproto.validation.code` and a focused
Expert Information filter named `dgproto.validation.<code>`. A frame may have
multiple findings. These describe the bytes inspected, not a receiver's acceptance
or rejection decision. Header/Noise diagnostics do not require a keylog; encrypted
payload checks require successful authentication, except that empty encrypted
records are diagnosed from their wire length.

| Code | Severity | Condition |
| --- | --- | --- |
| `magic` | ERROR | Bad `DGP1` magic on explicitly selected traffic; no lengths are trusted |
| `version` | WARN | Header version is not 1 |
| `flags` | NOTE | Sender sets bits other than the supported padding flag |
| `reserved` | NOTE | Nonzero fixed-header reserved bytes |
| `padding` | ERROR | Padding flag and pad length disagree |
| `frame_size` | ERROR | Header describes more than 65,535 total wire bytes |
| `truncated` | ERROR | Complete header, incomplete frame, and captured length below reported length |
| `handshake_length` | ERROR | Noise XX flight is not 36 bytes (init), 96 bytes (response), or 64 bytes (finish) |
| `handshake_pattern` | WARN | Init wrapper's pattern is not Noise XX (1) |
| `handshake_reserved` | ERROR | Nonzero init-wrapper reserved bytes |
| `session_id` | ERROR | Nonzero handshake session ID or zero encrypted MVP session ID |
| `sequence` | ERROR | Nonzero handshake sequence or zero encrypted MVP sequence |
| `message_type` | WARN | Type is outside the strict MVP profile |
| `payload_length` | ERROR | Empty encrypted MVP record, short required plaintext prefix, or non-exact Ping/Pong (9 bytes) / RekeyInit (36 bytes) |
| `payload_value` | ERROR | Nonzero Data reserved byte, Ping/Pong response outside 0/1, Close code outside 0..3, zero Rekey epoch, or invalid control-text UTF-8 |
| `control_envelope` | ERROR | Close/Error text is not exactly one aligned type-1 TLV after the two-byte code |
| `ack_count` | ERROR | Ack count is zero or payload size is not exactly `1 + count * 8` |

Fixed-header reserved flags/bytes are **NOTE**, not protocol rejection: Go receivers
ignore reserved flag bits and preserve header reserved bytes for authentication.
This does not relax reserved fields inside typed payloads. Close/Error may contain
only their code (no text); text checks cover envelope size/type and UTF-8, not TLV
padding-byte contents. Application TLVs remain raw bytes.

After decryption, Info summaries include Close/Error codes, Ack count (with
`invalid` for inconsistent counts/lengths), and Rekey epoch, alongside existing
stream and Ping/Pong details. A valid SessionClose is no longer marked by a
warning-level Error-message expert; a malformed Close can still have diagnostics.

## Compatibility

| Release | Stability policy |
| --- | --- |
| `0.x` | Draft-tracking; minor releases may contain breaking protocol or filter changes |
| `1.0.0` | First stable release after wire-contract freeze and interoperability validation |
| `1.x+` | Incompatible public changes require a new major version |

## Known limitations

- Historical and proposed future DGProto profiles are not supported.
- Encrypted Noise handshake payloads are not decrypted.
- Application-specific TLV schemas remain raw bytes.
- Authenticated trial decryption selects the matching key; keylog direction labels do not determine capture direction.
- Forward ratchet search is bounded to keep redissection responsive.
- Sequence/session diagnostics are frame-local: no stateful replay, monotonicity,
  session binding, or Rekey key-confirm validation is performed.
- Bounds checks avoid reading unavailable header/payload/tag/padding bytes. A complete
  header describing an oversized frame is diagnosed before requesting reassembly.
  Incomplete frames normally request TCP reassembly; `truncated` is emitted only
  when a full header is available and Wireshark reports more bytes than captured.
  Short headers, missing TCP segments, and unfinished streams may remain undecoded
  or awaiting reassembly without that diagnostic. There is no resynchronization scan
  after invalid magic or an oversized frame.
- Automated GUI testing is not yet cross-platform.

## Protocol source of truth

This project inspects DGProto; it does not define it. The [DGProto v1 specification](https://github.com/datagram-messenger/dgproto-go/blob/main/docs/protocol/dgproto-v1.md), reference implementation, keylog format, and wire vectors in [`dgproto-go`](https://github.com/datagram-messenger/dgproto-go) are authoritative.

## Development

```sh
# Ubuntu/Debian
sudo apt-get install lua5.3 lua-check tshark

# Syntax, lint, static validation, tshark self-test, and protocol fixtures
make check LUA=lua5.3 LUAC=luac5.3

# Protocol dissection fixtures only (generate a synthetic capture, run tshark)
make fixtures

# Deterministic release archive and SHA-256 checksum
make package LUA=lua5.3 LUAC=luac5.3 VERSION=0.3.0
```

Python is used only by repository validation and packaging scripts, never by the plugin at runtime. CI installs `tshark` and runs the complete validation suite.

### Validation fixtures

`tests/run_fixtures.py` drives the dissector against synthetic DGProto traffic to
keep decoding reproducible and catch field-layout regressions. `tests/fixtures/make_fixtures.py`
deterministically generates a libpcap capture, a matching keylog, and the expected
displayed-field values; the runner loads the plugin in `tshark`, extracts `-T fields`,
and asserts the results. The fixtures cover:

- all three Noise XX handshake flights;
- encrypted data and every control message type, decrypted via the keylog;
- padded frames, frames fragmented across TCP segments, and multiple frames coalesced
  into one segment;
- malformed, truncated, and unknown frames, which must fail safely without crashing,
  over-reading, or dissecting foreign traffic.

Captures and keylogs are regenerated on every run (under the ignored `build/` directory)
rather than committed, and contain only synthetic, public material — no real traffic or
secrets. The generator's ChaCha20-Poly1305 is checked against the RFC 8439 known-answer
vector so generated frames decrypt under the dissector. If `tshark` is not installed the
field checks are skipped, so run them in CI for full coverage.

## Releases

Pushing a stable SemVer tag such as `v0.3.0` validates the project and publishes:

```text
dgproto-wireshark-0.3.0.zip
dgproto-wireshark-0.3.0.zip.sha256
```

The archive contains `dgproto.lua`, this README, and the license under one versioned directory. Verify a downloaded archive with:

```sh
sha256sum --check dgproto-wireshark-0.3.0.zip.sha256
```

## License

Licensed under the [Apache License 2.0](LICENSE).
