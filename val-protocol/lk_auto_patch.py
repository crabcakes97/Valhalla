#!/usr/bin/env python3
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_PWNAGE_DIR = SCRIPT_DIR / "tools"
PRESETS = (
    "manual",
    "unlock-imei",
    "erase-imei",
    "unlock-imei-nvdata",
    "unlock-serial",
    "erase-serial",
    "unlock-serial-nvdata",
)


def run_command(cmd: list[str], cwd: Path) -> None:
    print("+ " + " ".join(str(part) for part in cmd))
    result = subprocess.run(cmd, cwd=str(cwd), text=True, capture_output=True)
    if result.stdout:
        print(result.stdout, end="")
    if result.stderr:
        print(result.stderr, end="", file=sys.stderr)
    if result.returncode != 0:
        raise RuntimeError(f"comando fallo con codigo {result.returncode}: {' '.join(cmd)}")


def default_analysis_dir(image: Path) -> Path:
    return image.with_name(image.stem + "_analysis")


def default_output_image(image: Path) -> Path:
    return image.with_name(image.stem + ".patched" + image.suffix)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Automatiza el flujo completo: analiza lk.img, aplica los 3 parches "
            "y reempaca con CERT2 actualizado."
        )
    )
    parser.add_argument("image", type=Path, help="lk.img original a parchear.")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Imagen final. Por defecto: <directorio del lk>/<nombre>.patched.img",
    )
    parser.add_argument(
        "--analysis-dir",
        type=Path,
        help="Directorio de analisis/intermedios. Por defecto: junto al lk, <nombre>_analysis.",
    )
    parser.add_argument(
        "--preset",
        choices=PRESETS,
        default="manual",
        help=(
            "Perfil de parches. manual conserva los flags sueltos; unlock-imei, "
            "erase-imei y unlock-imei-nvdata quedan como alias compatibles, pero "
            "ahora derivan KEY desde serialno en runtime. unlock-serial, "
            "erase-serial y unlock-serial-nvdata son los nombres explicitos."
        ),
    )
    parser.add_argument(
        "--imei",
        help=(
            "IMEI comun para derivar constantes fuera del LK. Si se usa, rellena "
            "--key-token-imei y --erase-token-imei cuando no se pasen por separado. "
            "No habilita verificacion runtime del IMEI."
        ),
    )
    parser.add_argument(
        "--erase-partition",
        default="cache",
        help="Particion que reemplazara a nvdata. Por defecto: cache.",
    )
    parser.add_argument(
        "--frp-compare-value",
        type=int,
        choices=[0, 1],
        default=1,
        help="Valor para cmp w8,#N en FRP. Por defecto: 1.",
    )
    parser.add_argument(
        "--no-key-force-success",
        action="store_true",
        help="No aplicar mov w0,w20 -> mov w0,#1 en KEY validator.",
    )
    parser.add_argument(
        "--key-custom-signature",
        help=(
            "Firma ASCII exacta de 20 bytes que sera aceptada por KEY validator. "
            "Si se usa, reemplaza al parche --key-force-success."
        ),
    )
    parser.add_argument(
        "--key-cave-offset",
        help="Offset HxD manual para el code cave usado por --key-custom-signature.",
    )
    parser.add_argument(
        "--key-token-secret",
        help=(
            "Secret para aceptar KEYs generadas por lk_keygen.py. Ejemplo: Valeria. "
            "Si se usa, reemplaza al parche --key-force-success."
        ),
    )
    parser.add_argument(
        "--key-token-device",
        default="",
        help="Identificador opcional usado para generar KEYs distintas por dispositivo.",
    )
    parser.add_argument(
        "--key-token-imei",
        help=(
            "IMEI de 15 digitos usado como identificador estatico para derivar KEYs. "
            "Acepta el valor copiado desde fastboot getvar all; el LK no lo consulta "
            "en runtime."
        ),
    )
    parser.add_argument(
        "--key-token-runtime-serial",
        action="store_true",
        help=(
            "Deriva el token KEY desde serialno en runtime. Usalo con "
            "--key-token-secret."
        ),
    )
    parser.add_argument(
        "--key-token-debug-log",
        action="store_true",
        help=(
            "Obsoleto para runtime-serial compacto. Usa --key-token-debug-stop "
            "para checkpoints seguros."
        ),
    )
    parser.add_argument(
        "--key-token-debug-stop",
        choices=(
            "caller_before_key",
            "entry",
            "before_serial",
            "after_serial",
            "token_ok",
            "token_fail",
        ),
        help=(
            "DIAGNOSTICO seguro: genera un checkpoint que retorna por la ruta "
            "normal de Code validation failure con un mensaje LKDBG."
        ),
    )
    parser.add_argument(
        "--key-token-alphabet",
        choices=["alnum", "printable"],
        default="alnum",
        help="Alfabeto esperado para KEYs generadas por lk_keygen.py. Por defecto: alnum.",
    )
    parser.add_argument(
        "--erase-token-partition",
        help="Particion protegida que se permitira borrar con formato <particion>__TOKEN.",
    )
    parser.add_argument(
        "--erase-token-secret",
        help="Secret usado para tokens de borrado protegidos. Ejemplo: Valeria.",
    )
    parser.add_argument(
        "--erase-token-device",
        default="",
        help="Identificador del equipo/modelo usado para derivar tokens de borrado.",
    )
    parser.add_argument(
        "--erase-token-imei",
        help=(
            "IMEI de 15 digitos usado como identificador estatico para tokens "
            "de borrado. Acepta el valor copiado desde fastboot getvar all; el LK "
            "no lo consulta en runtime."
        ),
    )
    parser.add_argument(
        "--erase-token-alphabet",
        choices=["alnum", "printable"],
        default="alnum",
        help="Alfabeto esperado para tokens de borrado. Por defecto: alnum.",
    )
    parser.add_argument(
        "--erase-token-cave-offset",
        help="Offset HxD manual para el code cave usado por --erase-token-partition.",
    )
    parser.add_argument(
        "--pwnage-dir",
        type=Path,
        default=DEFAULT_PWNAGE_DIR,
        help=f"Carpeta pwnage24mtk-main. Por defecto: {DEFAULT_PWNAGE_DIR}",
    )
    parser.add_argument(
        "--keep-workdir",
        action="store_true",
        help="Conservar carpeta repack_work con intermedios firmados.",
    )
    parser.add_argument(
        "--full-disasm",
        action="store_true",
        help="Generar lk_full_disasm.asm completo. Por defecto se omite para ser mas rapido.",
    )
    parser.add_argument(
        "--name",
        default="lk",
        help="Subimagen a reemplazar. Por defecto: lk.",
    )
    return parser


def require_arg(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def append_key_token_args(patch_cmd: list[str], args: argparse.Namespace) -> None:
    patch_cmd.extend(["--key-token-secret", args.key_token_secret])
    if args.key_token_runtime_serial:
        patch_cmd.append("--key-token-runtime-serial")
    if args.key_token_debug_log:
        patch_cmd.append("--key-token-debug-log")
    if args.key_token_debug_stop:
        patch_cmd.extend(["--key-token-debug-stop", args.key_token_debug_stop])
    if args.key_token_device:
        patch_cmd.extend(["--key-token-device", args.key_token_device])
    key_imei = args.key_token_imei or args.imei
    if key_imei:
        patch_cmd.extend(["--key-token-imei", key_imei])
    patch_cmd.extend(["--key-token-alphabet", args.key_token_alphabet])
    if args.key_cave_offset:
        patch_cmd.extend(["--key-cave-offset", args.key_cave_offset])


def append_key_runtime_serial_args(
    patch_cmd: list[str],
    secret: str,
    alphabet: str,
    key_cave_offset: str | None,
    debug_log: bool = False,
) -> None:
    patch_cmd.extend(
        [
            "--key-token-secret",
            secret,
            "--key-token-runtime-serial",
            "--key-token-alphabet",
            alphabet,
        ]
    )
    if debug_log:
        patch_cmd.append("--key-token-debug-log")
    # Los presets runtime llaman esta funcion; el checkpoint se agrega fuera
    # desde build_patch_command para conservar el parametro explicito del parser.
    if key_cave_offset:
        patch_cmd.extend(["--key-cave-offset", key_cave_offset])


def append_erase_token_args(patch_cmd: list[str], args: argparse.Namespace) -> None:
    patch_cmd.extend(
        [
            "--erase-token-partition",
            args.erase_token_partition,
            "--erase-token-secret",
            args.erase_token_secret,
            "--erase-token-alphabet",
            args.erase_token_alphabet,
        ]
    )
    if args.erase_token_device:
        patch_cmd.extend(["--erase-token-device", args.erase_token_device])
    erase_imei = args.erase_token_imei or args.imei
    if erase_imei:
        patch_cmd.extend(["--erase-token-imei", erase_imei])
    if args.erase_token_cave_offset:
        patch_cmd.extend(["--erase-token-cave-offset", args.erase_token_cave_offset])


def build_patch_command(args: argparse.Namespace, root: Path, analysis_dir: Path, patched_bin: Path) -> list[str]:
    patch_cmd = [
        sys.executable,
        str(root / "lk_patch_partition.py"),
        "--analysis-dir",
        str(analysis_dir),
        "--apply",
        "--output",
        str(patched_bin),
    ]

    if args.preset in {"unlock-imei", "unlock-serial"}:
        require_arg(args.key_token_secret, f"--preset {args.preset} requiere --key-token-secret.")
        if args.key_token_debug_log:
            raise RuntimeError("debug-log directo deshabilitado; usa --key-token-debug-stop")
        patch_cmd.append("--frp-skip-check")
        append_key_runtime_serial_args(
            patch_cmd,
            args.key_token_secret,
            args.key_token_alphabet,
            args.key_cave_offset,
            args.key_token_debug_log,
        )
        if args.key_token_debug_stop:
            patch_cmd.extend(["--key-token-debug-stop", args.key_token_debug_stop])
        return patch_cmd

    if args.preset in {"erase-imei", "erase-serial"}:
        require_arg(args.erase_token_partition, f"--preset {args.preset} requiere --erase-token-partition.")
        require_arg(args.erase_token_secret, f"--preset {args.preset} requiere --erase-token-secret.")
        if args.key_token_debug_log:
            raise RuntimeError("debug-log directo deshabilitado; usa --key-token-debug-stop")
        patch_cmd.extend(
            [
                "--erase-partition",
                args.erase_token_partition,
                "--frp-skip-check",
                "--unlock-erase-only",
            ]
        )
        append_key_runtime_serial_args(
            patch_cmd,
            args.erase_token_secret,
            args.erase_token_alphabet,
            args.key_cave_offset,
            args.key_token_debug_log,
        )
        if args.key_token_debug_stop:
            patch_cmd.extend(["--key-token-debug-stop", args.key_token_debug_stop])
        return patch_cmd

    if args.preset in {"unlock-imei-nvdata", "unlock-serial-nvdata"}:
        require_arg(args.key_token_secret, f"--preset {args.preset} requiere --key-token-secret.")
        require_arg(args.erase_partition, f"--preset {args.preset} requiere --erase-partition.")
        if args.key_token_debug_log:
            raise RuntimeError("debug-log directo deshabilitado; usa --key-token-debug-stop")
        patch_cmd.extend(
            [
                "--erase-partition",
                args.erase_partition,
                "--frp-skip-check",
            ]
        )
        append_key_runtime_serial_args(
            patch_cmd,
            args.key_token_secret,
            args.key_token_alphabet,
            args.key_cave_offset,
            args.key_token_debug_log,
        )
        if args.key_token_debug_stop:
            patch_cmd.extend(["--key-token-debug-stop", args.key_token_debug_stop])
        return patch_cmd

    patch_cmd.extend(
        [
            "--erase-partition",
            args.erase_partition,
            "--frp-compare-value",
            str(args.frp_compare_value),
        ]
    )
    key_modes = [bool(args.key_custom_signature), bool(args.key_token_secret)]
    if sum(key_modes) > 1:
        raise RuntimeError("usa solo uno: --key-custom-signature o --key-token-secret")

    if args.key_custom_signature:
        patch_cmd.extend(["--key-custom-signature", args.key_custom_signature])
        if args.key_cave_offset:
            patch_cmd.extend(["--key-cave-offset", args.key_cave_offset])
    elif args.key_token_secret:
        append_key_token_args(patch_cmd, args)
    elif not args.no_key_force_success:
        patch_cmd.append("--key-force-success")

    if args.erase_token_partition or args.erase_token_secret:
        if not args.erase_token_partition or not args.erase_token_secret:
            raise RuntimeError("usa ambos: --erase-token-partition y --erase-token-secret")
        append_erase_token_args(patch_cmd, args)

    return patch_cmd


def main() -> int:
    args = build_parser().parse_args()
    root = Path(__file__).resolve().parent
    image = args.image.resolve()
    analysis_dir = (args.analysis_dir or default_analysis_dir(image)).resolve()
    output = (args.output or default_output_image(image)).resolve()
    patched_bin = analysis_dir / f"{args.name}.auto.patched.bin"
    repack_work = analysis_dir / "repack_work"

    if not image.is_file():
        print(f"Error: no existe {image}", file=sys.stderr)
        return 2

    try:
        analysis_cmd = [
            sys.executable,
            str(root / "lk_static_analyzer.py"),
            str(image),
            "-o",
            str(analysis_dir),
        ]
        if not args.full_disasm:
            analysis_cmd.append("--no-full-disasm")
        run_command(analysis_cmd, root)

        patch_cmd = build_patch_command(args, root, analysis_dir, patched_bin)
        run_command(patch_cmd, root)

        repack_cmd = [
            sys.executable,
            str(root / "lk_repack_signed.py"),
            "--original-image",
            str(image),
            "--patched-lk-bin",
            str(patched_bin),
            "--output",
            str(output),
            "--name",
            args.name,
            "--pwnage-dir",
            str(args.pwnage_dir.resolve()),
        ]
        if args.keep_workdir:
            repack_cmd.extend(["--keep-workdir", str(repack_work)])
        run_command(repack_cmd, root)

    except RuntimeError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print()
    print("Done")
    print(f"Analysis dir : {analysis_dir}")
    print(f"Patched bin  : {patched_bin}")
    print(f"Patched image: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
