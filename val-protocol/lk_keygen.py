#!/usr/bin/env python3
from __future__ import annotations

import argparse
import random
import secrets
from collections.abc import Iterable

from lk_patch_partition import (
    derive_erase_token_constants,
    derive_runtime_serial_compact_constants,
    derive_token_constants,
    parse_partition_name,
    resolve_device_or_imei,
    token_bytes_for_alphabet,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Genera KEYs de 20 caracteres para el modo --key-token-secret "
            "de lk_patch_partition.py / lk_auto_patch.py."
        )
    )
    parser.add_argument(
        "--secret",
        default="Valeria",
        help="Secret usado para derivar las constantes. Por defecto: Valeria.",
    )
    parser.add_argument(
        "--device",
        default="",
        help="Identificador usado al parchear con --key-token-device o --erase-token-device.",
    )
    parser.add_argument(
        "--imei",
        help=(
            "IMEI de 15 digitos para derivar KEYs por equipo fuera del LK. Puede "
            "ser una linea copiada desde fastboot getvar all; no implica lectura "
            "runtime de IMEI."
        ),
    )
    parser.add_argument(
        "--serialno",
        help=(
            "Serial reportado por fastboot getvar serialno/all para KEYs del modo "
            "experimental --key-token-runtime-serial. No se usa con --erase-partition."
        ),
    )
    parser.add_argument(
        "--erase-partition",
        help=(
            "Genera tokens para borrado protegido de esta particion. "
            "Ejemplo: super. Si se omite, genera KEYs para --key-token-secret."
        ),
    )
    parser.add_argument(
        "--count",
        type=int,
        default=5,
        help="Cantidad de KEYs a generar. Por defecto: 5.",
    )
    parser.add_argument(
        "--alphabet",
        choices=["alnum", "printable"],
        default="alnum",
        help="Alfabeto usado por el patcher. Por defecto: alnum.",
    )
    parser.add_argument(
        "--safe",
        action="store_true",
        help=(
            "Alias compatible de --alphabet alnum."
        ),
    )
    parser.add_argument(
        "--seed",
        help="Semilla opcional para reproducir las mismas KEYs en pruebas.",
    )
    return parser


def random_choice(alphabet: str, rng: random.Random | None) -> str:
    if rng is not None:
        return rng.choice(alphabet)
    return secrets.choice(alphabet)


def make_key(constants: bytes, alphabet: str, rng: random.Random | None) -> str:
    alphabet_set = set(ord(ch) for ch in alphabet)
    left: list[int] = []
    right: list[int] = []

    for constant in constants:
        candidates = list(alphabet)
        for _ in range(5000):
            first = ord(random_choice(candidates, rng))
            second = first ^ constant
            if second in alphabet_set:
                left.append(first)
                right.append(second)
                break
        else:
            raise ValueError(
                "no se pudo generar una KEY con el alfabeto elegido; "
                "quita --safe para usar ASCII imprimible completo"
            )

    raw = bytes(left + list(reversed(right)))
    if len(raw) != 20:
        raise ValueError(f"KEY invalida generada: {len(raw)} bytes")
    return raw.decode("ascii")


def unique_keys(constants: bytes, count: int, alphabet: str, rng: random.Random | None) -> Iterable[str]:
    seen: set[str] = set()
    while len(seen) < count:
        key = make_key(constants, alphabet, rng)
        if key in seen:
            continue
        seen.add(key)
        yield key


def main() -> int:
    args = build_parser().parse_args()
    if args.count < 1:
        raise SystemExit("Error: --count debe ser >= 1")

    alphabet_name = "alnum" if args.safe else args.alphabet
    erase_partition = parse_partition_name(args.erase_partition) if args.erase_partition else None
    try:
        device, device_kind = resolve_device_or_imei(args.device, args.imei)
    except ValueError as exc:
        raise SystemExit(f"Error: {exc}") from exc
    if args.serialno and erase_partition:
        raise SystemExit("Error: --serialno solo aplica al token KEY, no a --erase-partition")
    if args.serialno and (args.device or args.imei):
        raise SystemExit("Error: usa --serialno o --device/--imei, no ambos")

    if erase_partition:
        constants = derive_erase_token_constants(
            args.secret,
            device,
            erase_partition,
            alphabet_name,
        )
    elif args.serialno:
        constants = derive_runtime_serial_compact_constants(
            args.secret,
            args.serialno,
        )
        device = args.serialno.strip()
        device_kind = "runtime-serial"
    else:
        constants = derive_token_constants(args.secret, device, alphabet_name)
    alphabet = "".join(chr(value) for value in token_bytes_for_alphabet(alphabet_name))
    rng = random.Random(args.seed) if args.seed is not None else None

    mode = "erase-token" if erase_partition else "key-token"
    print(f"Mode   : {mode}")
    print(f"Secret : {args.secret!r}")
    print(f"Device : {device if device else '<global>'!r} ({device_kind})")
    if erase_partition:
        print(f"Partition: {erase_partition}")
    print(f"Alphabet: {alphabet_name}")
    print(f"Const  : {constants.hex()}")
    print()
    for key in unique_keys(constants, args.count, alphabet, rng):
        if erase_partition:
            print(f"{erase_partition}__{key}")
            print(f"fastboot erase {erase_partition}__{key}")
        else:
            print(key)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
