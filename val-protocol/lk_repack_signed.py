#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


PART_MAGIC = 0x58881688
PART_HDR_SIZE = 512
PART_HDR_FORMAT = "<II32sIIIIIIIIII"
SCRIPT_DIR = Path(__file__).resolve().parent
PWNAGE_DIR = SCRIPT_DIR / "tools"


class RepackError(Exception):
    pass


class PartHdr:
    def __init__(self, values: tuple[object, ...]) -> None:
        self.magic = int(values[0])
        self.dsize = int(values[1])
        self.name = bytes(values[2]).split(b"\0", 1)[0].decode("latin-1")
        self.maddr = int(values[3])
        self.mode = int(values[4])
        self.ext_magic = int(values[5])
        self.hdr_sz = int(values[6])
        self.hdr_ver = int(values[7])
        self.img_type = int(values[8])
        self.img_list_end = int(values[9])
        self.align_sz = int(values[10])
        self.dsize_extend = int(values[11])
        self.maddr_extend = int(values[12])

    @classmethod
    def parse_from(cls, data: bytes, offset: int) -> "PartHdr":
        if offset + PART_HDR_SIZE > len(data):
            raise RepackError(f"no hay header completo en offset 0x{offset:x}")
        return cls(struct.unpack_from(PART_HDR_FORMAT, data, offset))

    def padded_data_size(self) -> int:
        if self.align_sz <= 0:
            raise RepackError(f"align_sz invalido en {self.name}: {self.align_sz}")
        return (self.dsize + self.align_sz - 1) & ~(self.align_sz - 1)

    def next_offset(self, offset: int) -> int:
        return offset + PART_HDR_SIZE + self.padded_data_size()

    def is_cert(self) -> bool:
        return self.name.lower().startswith("cert")


def run_command(cmd: list[str], cwd: Path) -> None:
    print("+ " + " ".join(str(part) for part in cmd))
    result = subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if result.returncode != 0:
        raise RepackError(f"comando fallo con codigo {result.returncode}: {' '.join(cmd)}")


def find_signed_region(data: bytes, image_name: str) -> tuple[int, int, PartHdr]:
    offset = 0
    while offset + PART_HDR_SIZE <= len(data):
        hdr = PartHdr.parse_from(data, offset)
        if hdr.magic != PART_MAGIC:
            raise RepackError(f"magic invalido en offset 0x{offset:x}: 0x{hdr.magic:08x}")

        next_offset = hdr.next_offset(offset)
        if next_offset > len(data):
            raise RepackError(f"entrada {hdr.name} excede el tamano del archivo")

        region_end = next_offset
        probe = next_offset
        for _ in range(2):
            if probe + PART_HDR_SIZE > len(data):
                break
            probe_hdr = PartHdr.parse_from(data, probe)
            if probe_hdr.magic != PART_MAGIC or not probe_hdr.is_cert():
                break
            region_end = probe_hdr.next_offset(probe)
            probe = region_end

        if hdr.name == image_name:
            return offset, region_end, hdr

        offset = region_end
        if hdr.img_list_end:
            break

    raise RepackError(f"no se encontro la subimagen {image_name!r}")


def replace_payload_in_signed_block(signed_block: bytes, payload: bytes, image_name: str) -> bytes:
    hdr = PartHdr.parse_from(signed_block, 0)
    if hdr.magic != PART_MAGIC:
        raise RepackError("el bloque firmado no empieza con part_hdr_t valido")
    if hdr.name != image_name:
        raise RepackError(f"el bloque firmado es {hdr.name!r}, no {image_name!r}")
    if len(payload) != hdr.dsize:
        raise RepackError(
            f"tamano payload no coincide: patched={len(payload)} original dsize={hdr.dsize}. "
            "Este flujo solo acepta parches in-place del mismo tamano."
        )

    out = bytearray(signed_block)
    out[PART_HDR_SIZE:PART_HDR_SIZE + hdr.dsize] = payload
    return bytes(out)


def default_output_path(original_image: Path) -> Path:
    return original_image.with_name(original_image.stem + ".patched" + original_image.suffix)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Reinserta un lk.bin parcheado en el lk.img original, actualiza CERT2 "
            "y verifica el resultado."
        )
    )
    parser.add_argument("--original-image", type=Path, required=True, help="lk.img original contenedor.")
    parser.add_argument("--patched-lk-bin", type=Path, required=True, help="Payload lk.bin parcheado.")
    parser.add_argument("--output", type=Path, help="Imagen final. Por defecto: <original>.patched.img")
    parser.add_argument("--name", default="lk", help="Subimagen a reemplazar. Por defecto: lk.")
    parser.add_argument(
        "--pwnage-dir",
        type=Path,
        default=PWNAGE_DIR,
        help=f"Carpeta con sign_mtk_cert.py/build-part-img.py. Por defecto: {PWNAGE_DIR}",
    )
    parser.add_argument(
        "--no-legacy-cert",
        action="store_true",
        help="No usar --legacy al actualizar CERT2.",
    )
    parser.add_argument(
        "--keep-workdir",
        type=Path,
        help="Conservar archivos intermedios en esta carpeta.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()
    original_image = args.original_image.resolve()
    patched_payload = args.patched_lk_bin.resolve()
    output_image = (args.output or default_output_path(original_image)).resolve()
    pwnage_dir = args.pwnage_dir.resolve()

    try:
        if not original_image.is_file():
            raise RepackError(f"no existe original-image: {original_image}")
        if not patched_payload.is_file():
            raise RepackError(f"no existe patched-lk-bin: {patched_payload}")
        sign_script = pwnage_dir / "sign_mtk_cert.py"
        build_script = pwnage_dir / "build-part-img.py"
        verify_script = pwnage_dir / "verify_mtk_image.py"
        for script in (sign_script, build_script, verify_script):
            if not script.is_file():
                raise RepackError(f"no existe script requerido: {script}")

        original_data = original_image.read_bytes()
        region_start, region_end, hdr = find_signed_region(original_data, args.name)
        payload = patched_payload.read_bytes()
        print(f"Original image : {original_image}")
        print(f"Patched payload: {patched_payload}")
        print(f"Output image   : {output_image}")
        print(f"Subimage       : {args.name}")
        print(f"Region         : 0x{region_start:x}-0x{region_end:x}")
        print(f"Payload size   : {len(payload)} bytes")
        print(f"Original dsize : {hdr.dsize} bytes")

        if args.keep_workdir:
            workdir = args.keep_workdir.resolve()
            workdir.mkdir(parents=True, exist_ok=True)
            cleanup = False
        else:
            temp = tempfile.TemporaryDirectory(prefix="lk_repack_")
            workdir = Path(temp.name)
            cleanup = True

        try:
            signed_original = workdir / f"{args.name}.signed.original.bin"
            unsigned_patched = workdir / f"{args.name}.patched.unsigned.bin"
            signed_patched = workdir / f"{args.name}.patched.signed.bin"

            signed_original.write_bytes(original_data[region_start:region_end])
            unsigned_patched.write_bytes(
                replace_payload_in_signed_block(signed_original.read_bytes(), payload, args.name)
            )

            sign_cmd = [sys.executable, str(sign_script), "-w"]
            if not args.no_legacy_cert:
                sign_cmd.append("--legacy")
            sign_cmd.extend([str(unsigned_patched), "-o", str(signed_patched)])
            run_command(sign_cmd, pwnage_dir)

            run_command([sys.executable, str(verify_script), str(signed_patched)], pwnage_dir)

            if output_image.exists():
                backup = output_image.with_suffix(output_image.suffix + ".bak")
                shutil.copy2(output_image, backup)
                print(f"Backup output : {backup}")

            run_command(
                [
                    sys.executable,
                    str(build_script),
                    "replace",
                    str(original_image),
                    "--name",
                    args.name,
                    "--file",
                    str(signed_patched),
                    "-o",
                    str(output_image),
                    "-v",
                ],
                pwnage_dir,
            )

            run_command([sys.executable, str(verify_script), str(output_image), "-n", args.name], pwnage_dir)
            print(f"Final image    : {output_image}")
            print(f"Workdir        : {workdir}")
        finally:
            if cleanup:
                temp.cleanup()

    except RepackError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"Error I/O: {exc}", file=sys.stderr)
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
