#!/usr/bin/env python3
"""Build a deterministic public release ZIP and its SHA-256 checksum."""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import zipfile

FILES = (
    (pathlib.Path("plugin/dgproto.lua"), "dgproto.lua"),
    (pathlib.Path("README.md"), "README.md"),
    (pathlib.Path("LICENSE"), "LICENSE"),
)
TIMESTAMP = (2020, 1, 1, 0, 0, 0)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version", required=True)
    parser.add_argument("--output-dir", type=pathlib.Path, default=pathlib.Path("dist"))
    args = parser.parse_args()
    if not re.fullmatch(r"(?:v)?[0-9]+\.[0-9]+\.[0-9]+|dev", args.version):
        raise SystemExit("version must be dev or vMAJOR.MINOR.PATCH")
    missing = [str(path) for path, _ in FILES if not path.is_file()]
    if missing:
        raise SystemExit("missing release input: " + ", ".join(missing))

    version = args.version.removeprefix("v")
    root = f"dgproto-wireshark-{version}"
    args.output_dir.mkdir(parents=True, exist_ok=True)
    archive = args.output_dir / f"{root}.zip"
    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as bundle:
        for source, destination in FILES:
            info = zipfile.ZipInfo(f"{root}/{destination}", TIMESTAMP)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            bundle.writestr(info, source.read_bytes())

    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum = archive.with_suffix(archive.suffix + ".sha256")
    checksum.write_text(f"{digest}  {archive.name}\n", encoding="ascii", newline="\n")
    print(archive)
    print(checksum)


if __name__ == "__main__":
    main()
