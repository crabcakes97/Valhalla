#!/usr/bin/env python3
"""Apply the verified Milan-only post-unlock branch change to an LK payload.

This does not unpack, sign, repack, or flash an LK partition image. It accepts
only the exact erase-serial payload tested in docs/milan-xt2211dl-results.md.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


EXPECTED_SIZE = 1_567_952
EXPECTED_SHA256 = "82845ef8bd32fe459fcda1641b1d0f216c95ee535c279ef62e48ea6c17504688"
BRANCH_OFFSET = 0x83BF4
EXPECTED_CONTEXT = bytes.fromhex("47f2ee72934264d047f270029342")
PATCHED_CONTEXT = bytes.fromhex("47f2ee72934209d047f270029342")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def patch_payload(
    data: bytes,
    *,
    expected_size: int = EXPECTED_SIZE,
    expected_sha256: str = EXPECTED_SHA256,
    branch_offset: int = BRANCH_OFFSET,
    expected_context: bytes = EXPECTED_CONTEXT,
    patched_context: bytes = PATCHED_CONTEXT,
) -> bytes:
    context_changes = [
        index
        for index, (old, new) in enumerate(zip(expected_context, patched_context))
        if old != new
    ]
    if len(expected_context) != len(patched_context) or context_changes != [6]:
        raise ValueError("invalid internal branch-patch definition")

    digest = sha256(data)
    if len(data) != expected_size:
        raise ValueError(f"refusing input size {len(data)}; expected {expected_size}")
    if digest != expected_sha256:
        raise ValueError(
            f"refusing input sha256 {digest}; expected {expected_sha256}"
        )

    context_offset = branch_offset - context_changes[0]
    actual_context = data[context_offset : context_offset + len(expected_context)]
    if actual_context != expected_context:
        raise ValueError(
            f"refusing bytes at 0x{context_offset:x}: found "
            f"{actual_context.hex()}, expected {expected_context.hex()}"
        )

    patched = bytearray(data)
    patched[context_offset : context_offset + len(patched_context)] = patched_context
    changed_offsets = [
        index for index, (old, new) in enumerate(zip(data, patched)) if old != new
    ]
    if changed_offsets != [branch_offset]:
        raise ValueError(
            f"internal error: changed offsets were {[hex(i) for i in changed_offsets]}"
        )
    return bytes(patched)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="exact analyzed erase-serial LK payload")
    parser.add_argument("output", type=Path, help="output payload for guarded repacking")
    args = parser.parse_args()

    original = args.input.read_bytes()
    try:
        patched = patch_payload(original)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    args.output.write_bytes(patched)
    print(f"input : {args.input} ({sha256(original)})")
    print(f"output: {args.output} ({sha256(patched)})")
    print(
        f"change: 0x{BRANCH_OFFSET:x}: "
        f"0x{original[BRANCH_OFFSET]:02x} -> 0x{patched[BRANCH_OFFSET]:02x}"
    )


if __name__ == "__main__":
    main()
