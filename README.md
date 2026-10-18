# DGProto Wireshark dissector

[![CI](https://github.com/datagram-messenger/dgproto-wireshark/actions/workflows/ci.yml/badge.svg)](https://github.com/datagram-messenger/dgproto-wireshark/actions/workflows/ci.yml)

A standalone Wireshark Lua dissector for the current **DGProto v1 draft** wire format.

> **Status:** pre-1.0 / implementation-track. Releases in the `0.x` series follow the evolving DGProto v1 draft and may contain breaking wire-interpretation or display-filter changes. Version `1.0.0` will be the first stable release and will require a stabilized DGProto v1 wire contract plus interoperability validation.

## Features

The implementation currently provides:

- DGProto discovery by TCP port (default `9900`), heuristic detection using the `DGP1` magic, and **Decode As…** support;
- TCP stream reassembly for split frames and multiple frames in one segment;
- the 40-byte little-endian header, payload, 16-byte data-frame AEAD tag, and optional padding;
- handshake sub-dissection for all three Noise XX flights, including the canonical tagless third flight carried as type `0x02`;
- payload fields for encrypted data, ping/pong, session close, acknowledgements, rekey initiation, and errors;
- optional keylog-assisted ChaCha20-Poly1305 decryption implemented entirely inside the Lua plugin;
- forward key-ratchet derivation from epoch-1 keylog entries; and
- load-time RFC 8439 ChaCha20-Poly1305 and RFC 4231 HMAC-SHA256 known-answer tests.

No Python runtime or external decryption helper is used by the plugin.

## Supported environment

- Wireshark 4.x with Lua enabled;
- Lua with 64-bit integer and native bitwise support (the normal Lua runtime in supported Wireshark 4.x builds); and
- DGProto v1 over TCP as implemented by the current draft profile.

The project is checked in CI on Ubuntu with Lua 5.3, `luacheck`, and `tshark`. Windows and macOS Wireshark installations use the same single Lua file, but are not yet exercised by this repository's CI matrix.

## Installation

Download a release archive or copy [`plugin/dgproto.lua`](plugin/dgproto.lua) from a trusted revision into Wireshark's **Personal Lua Plugins** directory.

Find the exact directory under **Help → About Wireshark → Folders**. Common locations are:

- Windows: `%APPDATA%\Wireshark\plugins`
- Linux: `~/.local/lib/wireshark/plugins`
- macOS: `~/.local/lib/wireshark/plugins`

Then choose **Analyze → Reload Lua Plugins** or restart Wireshark. For a one-off launch:

```sh
wireshark -X lua_script:/absolute/path/to/dgproto.lua
```

If Lua loading is disabled by local policy, enable it before using the plugin.

## Preferences and configuration

Open **Edit → Preferences → Protocols → DGProto v1**:

| Preference | Default | Purpose |
| --- | --- | --- |
| `TCP Port` | `9900` | TCP port registered for DGProto traffic. |
| `Keylog File` | empty | Explicit keylog path; overrides `DGPROTO_KEYLOG`. |

For traffic on another port, change the preference or select a packet and use **Analyze → Decode As…**.

The keylog lookup order is:

1. the `Keylog File` preference;
2. the `DGPROTO_KEYLOG` environment variable; and
3. `%APPDATA%\Wireshark\dgproto_keylog.txt` on Windows.

## Keylog decryption

Set `DGPROTO_KEYLOG` for a local DGProto process before establishing a session. The Go reference implementation writes entries in this format:

```text
DGPROTO_SESSION_KEY <32-hex-session-id> <send|recv> 1 <64-hex-key>
```

The plugin tries each key recorded for the session and accepts only a key that verifies the Poly1305 tag. It derives later traffic-key epochs from an epoch-1 key when needed. The frame nonce is `00000000 || LE64(sequence)` and authenticated data is the complete 40-byte header followed by padding, matching the protocol reference.

> **Secret warning:** keylogs contain live session traffic keys and remove transport confidentiality. Generate them only in controlled local debugging environments. Never use key logging in production, share a keylog, commit one, attach one to an issue, or include one in an artifact. Delete keylogs securely when debugging is complete.

After adding keys, redisplay or reopen the capture. Successful decryption adds a **Decrypted Payload** subtree; authentication failures appear as expert information and never expose unauthenticated plaintext.

## Usage

1. Start a capture or open a trusted capture.
2. Confirm the **Protocol** column shows `DGProto`.
3. Expand **DGProto v1 → Header** to inspect framing and sequence information.
4. Configure a keylog if decrypted application/control fields are required.
5. Use **Analyze → Expert Information** to review handshake, encryption, decryption, and protocol warnings.

Useful display filters include:

```text
dgproto
dgproto.msg_type == 0x03
dgproto.session_id == 00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff
dgproto.sequence >= 100
dgproto.stream_id == 1
dgproto.flags.padding == 1
dgproto.error_code
dgproto.decrypt_fail
```

## Compatibility and stability

- `0.x` releases are pre-stable: breaking interpretation and display-filter changes may ship in a minor release when the DGProto v1 draft changes.
- `1.0.0` is reserved for the first stable release. It requires a frozen DGProto v1 wire contract, cross-implementation wire-vector/pcap validation, and documented compatibility expectations.
- After `1.0.0`, incompatible public display-filter or supported-wire changes require a new major release; compatible fields and protocol coverage may be added in minor releases.

## Limitations

- The dissector follows the current DGProto draft profile, not historical or proposed future profiles.
- Noise handshake envelopes and public fields are dissected, but encrypted Noise handshake payloads are not decrypted internally.
- Application TLVs are exposed as bytes rather than decoded into every application-specific schema.
- Keylog direction labels are not used to infer capture direction; authenticated trial decryption selects a key.
- Forward ratchet search is bounded to keep packet redissection responsive.
- There is no automated cross-platform GUI test matrix yet.

## Protocol relationship and source of truth

This repository is a diagnostic consumer of DGProto; it does not define the protocol. The normative implementation-track specification and reference behavior live in [`datagram-messenger/dgproto-go`](https://github.com/datagram-messenger/dgproto-go), especially `docs/protocol/dgproto-v1.md`, framing/crypto code, keylog format, and wire-vector tests. Changes here should follow that source rather than introduce a new wire interpretation.

## Development

The validation toolchain uses Python only for repository checks and deterministic packaging, not at plugin runtime.

```sh
# Ubuntu/Debian prerequisites
sudo apt-get install lua5.3 lua-check tshark

# Syntax, lint, static checks, and tshark load-time crypto self-test
make check LUA=lua5.3 LUAC=luac5.3

# Build a local deterministic package and checksum
make package LUA=lua5.3 LUAC=luac5.3 VERSION=0.3.0
```

If `tshark` is unavailable, `scripts/validate.py` reports that integration step as skipped; CI requires and runs it. `luac -p` and `luacheck` remain required by `make check`.

## Release artifacts

Pushing a stable SemVer tag such as `v0.3.0` runs validation, builds the deterministic package and checksum, and publishes a GitHub Release containing:

```text
dgproto-wireshark-0.3.0.zip
dgproto-wireshark-0.3.0.zip.sha256
```

The ZIP has one top-level directory and contains exactly:

```text
dgproto-wireshark-0.3.0/
├── dgproto.lua
├── README.md
└── LICENSE
```

Verify it with `sha256sum --check dgproto-wireshark-0.3.0.zip.sha256` before distribution.

## License

Licensed under the [Apache License 2.0](LICENSE).
