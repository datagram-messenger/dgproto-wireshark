#!/usr/bin/env python3
"""Validate the standalone DGProto Wireshark plugin without third-party Python packages."""

from __future__ import annotations

import argparse
import pathlib
import shutil
import subprocess
import sys

REQUIRED_SNIPPETS = (
    'Proto("dgproto", "DGProto v1")',
    'Pref.uint  ("TCP Port",        9900',
    'Pref.string("Keylog File"',
    'local HEADER_LEN   = 40',
    'local AEAD_TAG_LEN = 16',
    'local MAGIC        = "DGP1"',
    'DGPROTO_SESSION_KEY',
    'ChaCha20-Poly1305 decryption (pure Lua)',
    'RFC 8439',
    'CRYPTO_SELFTEST_OK',
    'dgproto:register_heuristic("tcp"',
)
FORBIDDEN_SNIPPETS = (
    "dgproto_decrypt.py",
    "os.execute(",
    "io.popen(",
)


def fail(message: str) -> None:
    raise SystemExit(f"validation failed: {message}")


def static_validation(plugin: pathlib.Path) -> None:
    source = plugin.read_text(encoding="utf-8")
    if source.startswith("\ufeff"):
        fail("plugin has a UTF-8 BOM")
    for snippet in REQUIRED_SNIPPETS:
        if snippet not in source:
            fail(f"required implementation marker is missing: {snippet!r}")
    for snippet in FORBIDDEN_SNIPPETS:
        if snippet in source:
            fail(f"external helper/subprocess marker is present: {snippet!r}")
    if "python" in source.lower():
        allowed = ("no python",)
        lines = [line for line in source.lower().splitlines() if "python" in line]
        if any(not any(marker in line for marker in allowed) for line in lines):
            fail("unexpected Python integration remains in the plugin")
    print("static validation: ok")


def tshark_validation(plugin: pathlib.Path, command: str) -> None:
    executable = shutil.which(command)
    if executable is None:
        print(f"tshark validation: skipped ({command!r} not found)")
        return
    result = subprocess.run(
        [executable, "-X", f"lua_script:{plugin.resolve()}", "-G", "protocols"],
        check=False,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    output = result.stdout + result.stderr
    if result.returncode != 0:
        fail(f"tshark could not load the plugin (exit {result.returncode})\n{output}")
    if "ChaCha20-Poly1305 self-test FAILED" in output:
        fail("the load-time cryptographic known-answer test failed")
    if "DGProto v1" not in output and "dgproto" not in output.lower():
        fail("tshark loaded but did not register DGProto")
    print("tshark load and crypto self-test: ok")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plugin", type=pathlib.Path, default=pathlib.Path("plugin/dgproto.lua"))
    parser.add_argument("--tshark", default="tshark")
    args = parser.parse_args()
    if not args.plugin.is_file():
        fail(f"plugin does not exist: {args.plugin}")
    static_validation(args.plugin)
    tshark_validation(args.plugin, args.tshark)


if __name__ == "__main__":
    main()
