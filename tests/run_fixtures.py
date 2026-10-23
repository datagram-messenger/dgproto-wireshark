#!/usr/bin/env python3
"""Run the DGProto dissector against deterministic synthetic fixtures via tshark.

Workflow:

1. Generate a synthetic capture + keylog + expected field values (see
   ``tests/fixtures/make_fixtures.py``). Artifacts are written under a
   git-ignored ``build/`` directory and regenerated every run.
2. Load the plugin in ``tshark`` and extract ``-T fields`` for the capture.
3. Assert every displayed field matches the expected wire layout, that
   coalesced and reassembled frames dissect, and that malformed / truncated
   frames fail safely (no crash, no over-read, no false-positive dissection).

If ``tshark`` is not installed the field checks are skipped (the generator and
its crypto self-test still run), mirroring ``scripts/validate.py``. CI installs
``tshark`` and therefore runs the full comparison.

No third-party Python packages are used.
"""

from __future__ import annotations

import argparse
import os
import pathlib
import shutil
import subprocess
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "fixtures"))
import make_fixtures  # noqa: E402

_STRING_FIELDS = {"dgproto.magic", "dgproto.validation.code", "_ws.col.Info"}
_ERROR_MARKERS = (
    "lua error", "lua: error", "dissector bug", "dissector_bug",
    "self-test failed", "runtime error", "stack traceback",
    "sanitizer", "segmentation fault",
)


def _as_int(text: str) -> int:
    text = text.strip().lower()
    return int(text, 16) if text.startswith("0x") else int(text, 10)


def _split_occurrences(raw: str) -> list:
    return [part for part in raw.split(",") if part.strip() != ""]


def _run_tshark(tshark: str, plugin: pathlib.Path, pcap: pathlib.Path,
                keylog: pathlib.Path, fields: list):
    cmd = [
        tshark, "-r", str(pcap),
        "-X", f"lua_script:{plugin.resolve()}",
        "-n",
        "-o", "tcp.desegment_tcp_streams:TRUE",
        # Default -T fields separator is a tab; keep it and set occurrence/aggregator
        # explicitly so multi-occurrence fields come back comma-joined.
        "-T", "fields", "-E", "occurrence=a", "-E", "aggregator=,",
    ]
    for name in fields:
        cmd += ["-e", name]
    env = dict(os.environ)
    env["DGPROTO_KEYLOG"] = str(keylog.resolve())
    proc = subprocess.run(cmd, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=env)
    return proc


def _parse_rows(stdout: str, fields: list) -> dict:
    rows = {}
    for line in stdout.splitlines():
        if line == "":
            continue
        cols = line.split("\t")
        cols += [""] * (len(fields) - len(cols))
        row = {fields[i]: cols[i].strip() for i in range(len(fields))}
        try:
            frame_no = int(row["frame.number"])
        except ValueError:
            continue
        rows[frame_no] = row
    return rows


def _check_frame(frame_no: int, spec: dict, row: dict) -> list:
    problems = []
    for field, expected in spec.get("fields", {}).items():
        got = row.get(field, "")
        if field in _STRING_FIELDS:
            if got != expected:
                problems.append(f"frame {frame_no}: {field} = {got!r}, expected {expected!r}")
            continue
        if isinstance(expected, list):
            try:
                got_vals = sorted(_as_int(x) for x in _split_occurrences(got))
            except ValueError:
                got_vals = None
            if got_vals != sorted(expected):
                problems.append(f"frame {frame_no}: {field} = {got!r}, expected {expected}")
            continue
        try:
            if got == "" or _as_int(got) != expected:
                problems.append(f"frame {frame_no}: {field} = {got!r}, expected {expected}")
        except ValueError:
            problems.append(f"frame {frame_no}: {field} = {got!r} is not an integer (expected {expected})")
    for field in spec.get("absent", []):
        got = row.get(field, "")
        if got != "":
            problems.append(f"frame {frame_no}: {field} should be absent but was {got!r}")
    return problems


def run(plugin: pathlib.Path, tshark: str, out_dir: pathlib.Path, keep: bool) -> int:
    # Determinism: the generator must produce identical bytes every run.
    pcap_a, keylog_a, _ = make_fixtures.build_capture()
    pcap_b, keylog_b, frames = make_fixtures.build_capture()
    if pcap_a != pcap_b or keylog_a != keylog_b:
        print("FAIL: fixture generation is not deterministic", file=sys.stderr)
        return 1
    print(f"fixture generation: ok (deterministic, {len(frames)} frames, {len(pcap_a)} pcap bytes)")

    pcap_path, keylog_path, expected_path = make_fixtures.write(out_dir)

    executable = shutil.which(tshark)
    if executable is None:
        print(f"tshark field validation: skipped ({tshark!r} not found); "
              f"artifacts written to {out_dir}")
        return 0

    fields = make_fixtures.FIELDS
    proc = _run_tshark(executable, plugin, pcap_path, keylog_path, fields)

    combined = (proc.stdout + "\n" + proc.stderr).lower()
    for marker in _ERROR_MARKERS:
        if marker in combined:
            print(f"FAIL: tshark reported '{marker}'\n{proc.stderr}", file=sys.stderr)
            return 1
    if proc.returncode != 0:
        print(f"FAIL: tshark exited {proc.returncode}\n{proc.stderr}", file=sys.stderr)
        return 1

    rows = _parse_rows(proc.stdout, fields)
    dissected = [n for n, r in rows.items() if r.get("dgproto.msg_type", "") != ""]
    if not dissected:
        print("FAIL: dissector produced no dgproto fields; did the plugin load?",
              file=sys.stderr)
        print(proc.stdout, file=sys.stderr)
        return 1

    problems = []
    for frame_no, spec in frames.items():
        problems += _check_frame(frame_no, spec, rows.get(frame_no, {}))

    if problems:
        print(f"FAIL: {len(problems)} field-layout mismatch(es):", file=sys.stderr)
        for p in problems:
            print(f"  - {p}", file=sys.stderr)
        if not keep:
            _cleanup(pcap_path, keylog_path, expected_path)
        return 1

    print(f"tshark field validation: ok ({len(frames)} frames, "
          f"{len(dissected)} dissected, malformed frames failed safely)")
    if not keep:
        _cleanup(pcap_path, keylog_path, expected_path)
    return 0


def _cleanup(*paths) -> None:
    for p in paths:
        try:
            pathlib.Path(p).unlink()
        except OSError:
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plugin", type=pathlib.Path, default=pathlib.Path("plugin/dgproto.lua"))
    parser.add_argument("--tshark", default="tshark")
    parser.add_argument("--out-dir", type=pathlib.Path, default=pathlib.Path("build/fixtures"))
    parser.add_argument("--keep", action="store_true",
                        help="keep generated capture/keylog/expected artifacts")
    args = parser.parse_args()
    if not args.plugin.is_file():
        raise SystemExit(f"plugin does not exist: {args.plugin}")
    raise SystemExit(run(args.plugin, args.tshark, args.out_dir, args.keep))


if __name__ == "__main__":
    main()
