#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

def _without_script_dir_on_sys_path() -> list[str]:
    script_dir = Path(__file__).resolve().parent
    original = list(sys.path)
    filtered: list[str] = []
    for entry in original:
        try:
            candidate = Path(entry or ".").resolve()
        except OSError:
            filtered.append(entry)
            continue
        if candidate != script_dir:
            filtered.append(entry)
    sys.path[:] = filtered
    return original


def _clear_imported_package(package: str) -> None:
    for name in list(sys.modules):
        if name == package or name.startswith(package + "."):
            del sys.modules[name]


try:
    from capstone import (
        CS_ARCH_ARM,
        CS_ARCH_ARM64,
        CS_MODE_ARM,
        CS_MODE_LITTLE_ENDIAN,
        CS_MODE_THUMB,
        Cs,
    )
except ImportError as first_exc:
    original_sys_path: list[str] | None = None
    if (Path(__file__).resolve().parent / "capstone").is_dir():
        original_sys_path = _without_script_dir_on_sys_path()
        _clear_imported_package("capstone")
        try:
            from capstone import (
                CS_ARCH_ARM,
                CS_ARCH_ARM64,
                CS_MODE_ARM,
                CS_MODE_LITTLE_ENDIAN,
                CS_MODE_THUMB,
                Cs,
            )
        except ImportError as second_exc:
            if original_sys_path is not None:
                sys.path[:] = original_sys_path
            raise SystemExit(
                "Error: falta la dependencia 'capstone'. Instalacion sugerida:\n"
                "  python -m pip install capstone\n"
                f"Detalle: {second_exc}"
            ) from second_exc
        finally:
            if original_sys_path is not None:
                sys.path[:] = original_sys_path
    else:
        raise SystemExit(
            "Error: falta la dependencia 'capstone'. Instalacion sugerida:\n"
            "  python -m pip install capstone\n"
            f"Detalle: {first_exc}"
        ) from first_exc

try:
    from liblk.exceptions import InvalidLkPartition, LkImageError
    from liblk.image import LkImage
except ImportError as exc:
    raise SystemExit(
        "Error: falta la dependencia 'liblk'. Instalacion sugerida:\n"
        "  python -m pip install liblk\n"
    ) from exc


DEFAULT_TARGETS = [
    "fastboot oem unlock",
    "This command requires you to first unlock the bootloader",
    "Check 'Allow OEM Unlock'",
    "Code validation failure",
    "Invalid boot state for unlocking",
    "A unlock code may be required",
    "Now unlocked for flashing",
    "Bootloader is unlocked",
    "Already unlocked",
    "flashing_locked",
    "flashing_unlocked",
    "userdata",
    "metadata",
    "md_udc",
    "nvdata",
    "frp",
    "frp-state",
    "Invalid partition table!",
    "FRP partition is invalid, lock anyway!",
    "Couldn't read from %llx",
    "mot_sec: Invalid partition table!",
    "mot_sec: FRP partition is invalid, lock anyway!",
    "mot_sec: Couldn't read from %llx",
    "hash calculation failure!",
    "hash at offset i:",
    "validate_hash_password: Version 2 datablock",
    "validate_hash_password: Version 1 datablock",
    "validate_hash_password: Unsupported datablock",
    "mot_sec: hash calculation failure!",
    "mot_sec: hash at offset i:",
    "mot_sec: validate_hash_password: Version 2 datablock",
    "mot_sec: validate_hash_password: Version 1 datablock",
    "mot_sec: validate_hash_password: Unsupported datablock",
    "validate_hash_password",
    "fboot_cmd_erase_permission_validate",
    "erase permission denied",
    "Invalid partition name %s",
    "Disallow to erase partition %s on oem_locked device",
    "debug_token",
    "avb_custom_key",
    "cache",
    "all",
    "securestate",
    "iswarrantyvoid",
    "max-download-size",
    "is-userspace",
    "serialno",
    "barcode",
    "version-bootloader",
    "imei",
    "imei2",
    "meid",
    "esimid",
    "sku",
    "battid",
    "iccid",
]

CORE_FLOW_TARGETS = {
    "fastboot oem unlock": 7,
    "Check 'Allow OEM Unlock'": 10,
    "Bootloader is unlocked": 9,
    "Code validation failure": 9,
    "Now unlocked for flashing": 8,
    "This command requires you to first unlock the bootloader": 6,
    "Invalid boot state for unlocking": 5,
    "A unlock code may be required": 5,
    "Already unlocked": 4,
    "flashing_locked": 3,
    "flashing_unlocked": 3,
}

CONTEXT_FLOW_TARGETS = {
    "userdata": 2,
    "metadata": 2,
    "md_udc": 2,
    "nvdata": 2,
}

TARGET_ERASE_PARTITIONS = {"userdata", "metadata", "md_udc", "nvdata"}

FRP_FLOW_TARGETS = {
    "frp": 3,
    "frp-state": 2,
    "Invalid partition table!": 4,
    "FRP partition is invalid, lock anyway!": 6,
    "Couldn't read from %llx": 5,
    "mot_sec: Invalid partition table!": 5,
    "mot_sec: FRP partition is invalid, lock anyway!": 7,
    "mot_sec: Couldn't read from %llx": 6,
}

KEY_VALIDATOR_TARGETS = {
    "hash calculation failure!": 6,
    "hash at offset i:": 6,
    "validate_hash_password: Version 2 datablock": 7,
    "validate_hash_password: Version 1 datablock": 4,
    "validate_hash_password: Unsupported datablock": 4,
    "mot_sec: hash calculation failure!": 7,
    "mot_sec: hash at offset i:": 7,
    "mot_sec: validate_hash_password: Version 2 datablock": 8,
    "mot_sec: validate_hash_password: Version 1 datablock": 5,
    "mot_sec: validate_hash_password: Unsupported datablock": 4,
    "validate_hash_password": 3,
}

ERASE_PERMISSION_TARGETS = {
    "fboot_cmd_erase_permission_validate": 14,
    "erase permission denied": 12,
    "Invalid partition name %s": 8,
    "Disallow to erase partition %s on oem_locked device": 10,
    "debug_token": 5,
    "avb_custom_key": 5,
    "cache": 3,
    "all": 3,
}

ERASE_PERMISSION_NAME_TARGETS = {"cache", "debug_token", "avb_custom_key", "all"}
EXACT_C_STRING_TARGETS = ERASE_PERMISSION_NAME_TARGETS


@dataclass(frozen=True)
class Instruction:
    address: int
    mnemonic: str
    operands: str
    raw: bytes
    mode: str = "aarch64"


@dataclass(frozen=True)
class StringHit:
    target: str
    offset: int
    address: int
    text: str


@dataclass(frozen=True)
class XrefHit:
    insn_index: int
    target: StringHit
    address: int
    mnemonic: str
    operands: str
    effective_address: int
    via: str


@dataclass(frozen=True)
class FunctionFlow:
    start_index: int
    end_index: int
    start_address: int
    end_address: int
    xrefs: tuple[XrefHit, ...]
    calls: tuple[int, ...]
    branches: tuple[tuple[int, int, str], ...]
    score: int
    matched_targets: tuple[str, ...]


@dataclass(frozen=True)
class FrpChecker:
    flow: FunctionFlow
    confidence: int
    evidence: tuple[str, ...]
    callers: tuple[tuple[int, int], ...]


@dataclass(frozen=True)
class KeyValidator:
    flow: FunctionFlow
    confidence: int
    evidence: tuple[str, ...]
    callers: tuple[tuple[int, int], ...]
    failure_edges: tuple[tuple[int, int, str], ...]


@dataclass(frozen=True)
class ErasePermissionCheck:
    flow: FunctionFlow
    confidence: int
    evidence: tuple[str, ...]
    callers: tuple[tuple[int, int], ...]
    name_checks: tuple[tuple[int, str, int | None, int | None], ...]
    permission_calls: tuple[tuple[int, int], ...]
    denied_edges: tuple[tuple[int, int, str], ...]


@dataclass(frozen=True)
class PartitionEraseOperation:
    flow_start: int
    partition: str
    operation: str
    xref_address: int
    string_address: int
    string_text: str
    reference_mode: str
    xref_mnemonic: str
    xref_operands: str
    xref_via: str
    call_site: int | None
    call_target: int | None
    result_check_address: int | None
    failure_target: int | None
    failure_message_address: int | None
    failure_message: str | None


def parse_int(value: str) -> int:
    return int(value, 0)


def read_c_string(data: bytes, offset: int, limit: int = 512) -> str:
    end = data.find(b"\x00", offset, min(len(data), offset + limit))
    if end == -1:
        end = min(len(data), offset + limit)
    return data[offset:end].decode("latin1", errors="replace")


def printable_context(data: bytes, center: int, radius: int = 96) -> str:
    start = max(0, center - radius)
    end = min(len(data), center + radius)
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data[start:end])


def load_lk_payload(path: Path, raw_base: int | None) -> tuple[bytes, int, str]:
    if raw_base is not None:
        return path.read_bytes(), raw_base, "raw lk payload"

    try:
        image = LkImage(path)
    except (InvalidLkPartition, LkImageError) as exc:
        raise ValueError(
            "el archivo no parece ser una imagen LK/LKS contenedora; "
            "si es un lk.bin ya extraido, usa --base 0x..."
        ) from exc

    partition = image.partitions.get("lk")
    if partition is None:
        raise ValueError("la imagen no contiene una subparticion llamada 'lk'")

    if partition.lk_address is not None:
        base = int(partition.lk_address)
    else:
        header_address = int(partition.header.memory_address)
        if header_address == 0xFFFFFFFF:
            raise ValueError(
                "no se pudo detectar Memory Address para 'lk'; usa --base 0x..."
            )
        base = header_address

    return bytes(partition.data), base, "lk partition from container"


def find_targets(data: bytes, base: int, targets: Iterable[str]) -> list[StringHit]:
    hits: list[StringHit] = []
    lowered = data.lower()

    for target in targets:
        needle = target.encode("latin1", errors="ignore").lower()
        if not needle:
            continue

        if target in EXACT_C_STRING_TARGETS:
            offset = 0
            while True:
                offset = lowered.find(needle, offset)
                if offset == -1:
                    break
                before_ok = offset == 0 or data[offset - 1] == 0
                after = offset + len(needle)
                after_ok = after < len(data) and data[after] == 0
                if before_ok and after_ok:
                    hits.append(
                        StringHit(
                            target=target,
                            offset=offset,
                            address=base + offset,
                            text=read_c_string(data, offset),
                        )
                    )
                offset += max(1, len(needle))
            continue

        offset = 0
        while True:
            offset = lowered.find(needle, offset)
            if offset == -1:
                break

            string_start = data.rfind(b"\x00", 0, offset) + 1
            for reference_offset in sorted({string_start, offset}):
                hits.append(
                    StringHit(
                        target=target,
                        offset=reference_offset,
                        address=base + reference_offset,
                        text=read_c_string(data, reference_offset),
                    )
                )
            offset += max(1, len(needle))

    unique: dict[tuple[str, int], StringHit] = {}
    for hit in hits:
        unique[(hit.target, hit.offset)] = hit
    return sorted(unique.values(), key=lambda item: (item.offset, item.target))


def detect_architecture(data: bytes, base: int) -> str:
    first_word = int.from_bytes(data[:4].ljust(4, b"\x00"), "little")
    if (first_word & 0x0F000000) == 0x0A000000:
        return "arm32_thumb"
    if base < 0x1_0000_0000 and (first_word >> 24) in {0xEA, 0xEB}:
        return "arm32_thumb"
    return "aarch64"


def disassemble(data: bytes, base: int, architecture: str = "aarch64") -> list[Instruction]:
    if architecture == "arm32_thumb":
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
        step = 2
        max_size = 4
    else:
        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        step = 4
        max_size = 4
    md.detail = False
    instructions: list[Instruction] = []

    # LK mixes executable code with literal pools and strings. A single
    # md.disasm(data, base) call stops at the first undecodable word, so scan
    # each aligned instruction slot independently.
    for offset in range(0, len(data) - 1, step):
        word = data[offset : offset + max_size]
        decoded = list(md.disasm(word, base + offset, count=1))
        if not decoded:
            continue

        insn = decoded[0]
        if architecture == "aarch64" and insn.size != 4:
            continue
        if architecture == "arm32_thumb" and insn.size not in {2, 4}:
            continue

        instructions.append(
            Instruction(
                address=insn.address,
                mnemonic=insn.mnemonic,
                operands=insn.op_str,
                raw=bytes(insn.bytes),
                mode=architecture,
            )
        )

    return instructions


def parse_adrp(operands: str) -> tuple[str, int] | None:
    match = re.match(r"\s*(x\d+),\s*#(0x[0-9a-fA-F]+)\s*$", operands)
    if not match:
        return None
    return match.group(1), int(match.group(2), 16)


def parse_add_address(operands: str, reg: str) -> int | None:
    match = re.match(
        rf"\s*{reg},\s*{reg},\s*#(0x[0-9a-fA-F]+|\d+)\s*$", operands
    )
    if not match:
        return None
    return int(match.group(1), 0)


def parse_mem_offset(operands: str, reg: str) -> int | None:
    match = re.search(
        rf"\[{reg}(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]", operands
    )
    if not match:
        return None
    if match.group(1) is None:
        return 0
    return int(match.group(1), 0)


def parse_thumb_literal_ldr(operands: str) -> tuple[str, int] | None:
    match = re.match(
        r"\s*(r\d+),\s*\[pc(?:,\s*#(0x[0-9a-fA-F]+|\d+))?\]\s*$",
        operands,
    )
    if not match:
        return None
    return match.group(1), int(match.group(2) or "0", 0)


def is_thumb_add_pc(operands: str, reg: str) -> bool:
    return bool(
        re.match(rf"\s*{reg},\s*pc\s*$", operands)
        or re.match(rf"\s*{reg},\s*{reg},\s*pc\s*$", operands)
    )


def signed_u32_at(data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 4 > len(data):
        return None
    value = int.from_bytes(data[offset : offset + 4], "little")
    if value & 0x80000000:
        value -= 0x1_0000_0000
    return value


def match_string_target(effective: int, by_address: dict[int, StringHit], hits: list[StringHit]) -> StringHit | None:
    target = by_address.get(effective)
    if target is not None:
        return target
    for hit in hits:
        end = hit.address + max(1, len(hit.text.encode("latin1", errors="replace")) + 1)
        if hit.address - 4 <= effective < end:
            return hit
    return None


def find_string_xrefs(
    instructions: list[Instruction],
    string_hits: list[StringHit],
    lookahead: int = 12,
    data: bytes | None = None,
    base: int | None = None,
) -> list[XrefHit]:
    by_address = {hit.address: hit for hit in string_hits}
    by_page: dict[int, list[StringHit]] = {}
    for hit in string_hits:
        by_page.setdefault(hit.address & ~0xFFF, []).append(hit)

    xrefs: list[XrefHit] = []
    for index, insn in enumerate(instructions):
        if insn.mnemonic == "adrp":
            parsed = parse_adrp(insn.operands)
            if parsed is not None:
                reg, page = parsed
                if page in by_page:
                    for probe_index in range(index + 1, min(len(instructions), index + lookahead + 1)):
                        probe = instructions[probe_index]

                        if probe.mnemonic == "add":
                            imm = parse_add_address(probe.operands, reg)
                            if imm is None:
                                continue
                            effective = page + imm
                            target = by_address.get(effective)
                            if target is not None:
                                xrefs.append(
                                    XrefHit(
                                        insn_index=probe_index,
                                        target=target,
                                        address=probe.address,
                                        mnemonic=probe.mnemonic,
                                        operands=probe.operands,
                                        effective_address=effective,
                                        via=f"adrp/add {reg}",
                                    )
                                )

                        elif probe.mnemonic in {"ldr", "ldrb", "ldrh", "ldrsw", "str", "strb", "strh"}:
                            imm = parse_mem_offset(probe.operands, reg)
                            if imm is None:
                                continue
                            effective = page + imm
                            target = by_address.get(effective)
                            if target is not None:
                                xrefs.append(
                                    XrefHit(
                                        insn_index=probe_index,
                                        target=target,
                                        address=probe.address,
                                        mnemonic=probe.mnemonic,
                                        operands=probe.operands,
                                        effective_address=effective,
                                        via=f"adrp/mem {reg}",
                                    )
                                )

        if insn.mode == "arm32_thumb" and data is not None and base is not None:
            parsed_thumb = parse_thumb_literal_ldr(insn.operands)
            if parsed_thumb is None:
                continue

            reg, literal_offset = parsed_thumb
            literal_address = ((insn.address + 4) & ~3) + literal_offset
            literal_value = signed_u32_at(data, literal_address - base)
            if literal_value is None:
                continue

            for probe_index in range(index + 1, min(len(instructions), index + lookahead + 1)):
                probe = instructions[probe_index]
                if probe.mode != "arm32_thumb":
                    continue
                if probe.mnemonic != "add" or not is_thumb_add_pc(probe.operands, reg):
                    continue

                effective = probe.address + 4 + literal_value
                target = match_string_target(effective, by_address, string_hits)
                if target is not None:
                    xrefs.append(
                        XrefHit(
                            insn_index=probe_index,
                            target=target,
                            address=probe.address,
                            mnemonic=probe.mnemonic,
                            operands=probe.operands,
                            effective_address=target.address,
                            via=f"thumb ldr/add-pc {reg}",
                        )
                    )

    unique: dict[tuple[int, int, str], XrefHit] = {}
    for xref in xrefs:
        unique[(xref.address, xref.effective_address, xref.via)] = xref
    return sorted(unique.values(), key=lambda item: (item.address, item.effective_address))


def looks_like_function_start(insn: Instruction) -> bool:
    if insn.mnemonic == "stp" and "x29, x30, [sp" in insn.operands:
        return True
    if insn.mnemonic == "sub" and insn.operands.startswith("sp, sp, #"):
        return True
    if insn.mnemonic in {"pacibsp", "paciasp"}:
        return True
    if insn.mnemonic in {"push", "push.w"} and "lr" in insn.operands:
        return True
    return False


def looks_like_function_end(insn: Instruction) -> bool:
    if insn.mnemonic == "ret":
        return True
    if insn.mnemonic in {"pop", "pop.w"} and "pc" in insn.operands:
        return True
    if insn.mnemonic == "bx" and insn.operands.strip() == "lr":
        return True
    return False


def estimate_function_range(instructions: list[Instruction], center_index: int) -> tuple[int, int]:
    start = max(0, center_index - 256)
    for index in range(center_index, start - 1, -1):
        if looks_like_function_start(instructions[index]):
            if (
                instructions[index].mnemonic == "stp"
                and index > 0
                and instructions[index - 1].mnemonic == "sub"
                and instructions[index - 1].operands.startswith("sp, sp, #")
            ):
                if (
                    index > 1
                    and instructions[index - 2].mnemonic in {"pacibsp", "paciasp"}
                ):
                    start = index - 2
                else:
                    start = index - 1
            elif (
                instructions[index].mnemonic == "stp"
                and index > 0
                and instructions[index - 1].mnemonic in {"pacibsp", "paciasp"}
            ):
                start = index - 1
            elif (
                instructions[index].mnemonic == "sub"
                and instructions[index].operands.startswith("sp, sp, #")
                and index > 0
                and instructions[index - 1].mnemonic in {"pacibsp", "paciasp"}
            ):
                start = index - 1
            else:
                start = index
            break

    end = min(len(instructions) - 1, center_index + 384)
    for index in range(center_index, end + 1):
        if looks_like_function_end(instructions[index]):
            end = index
            break

    return start, end


def parse_branch_target(operands: str) -> int | None:
    matches = re.findall(r"#(0x[0-9a-fA-F]+)", operands)
    if not matches:
        return None
    return int(matches[-1], 16)


def is_branch_instruction(insn: Instruction) -> bool:
    thumb_conditional = {
        "beq", "bne", "bhs", "blo", "bmi", "bpl", "bvs", "bvc",
        "bhi", "bls", "bge", "blt", "bgt", "ble",
    }
    return (
        insn.mnemonic == "b"
        or insn.mnemonic.startswith("b.")
        or insn.mnemonic in thumb_conditional
        or insn.mnemonic in {"cbz", "cbnz", "tbz", "tbnz"}
    )


def is_conditional_branch(insn: Instruction) -> bool:
    thumb_conditional = {
        "beq", "bne", "bhs", "blo", "bmi", "bpl", "bvs", "bvc",
        "bhi", "bls", "bge", "blt", "bgt", "ble",
    }
    return (
        insn.mnemonic.startswith("b.")
        or insn.mnemonic in thumb_conditional
        or insn.mnemonic in {"cbz", "cbnz", "tbz", "tbnz"}
    )


def parse_call_target(insn: Instruction) -> int | None:
    if insn.mnemonic != "bl":
        return None
    return parse_branch_target(insn.operands)


def call_target_matches_function(
    instructions: list[Instruction],
    call_target: int | None,
    function_start: int,
) -> bool:
    if call_target is None:
        return False
    if call_target == function_start:
        return True
    if call_target + 4 != function_start:
        return False
    for insn in instructions:
        if insn.address == call_target:
            return insn.mnemonic == "paciasp"
        if insn.address > call_target:
            break
    return False


def score_targets(targets: Iterable[str]) -> int:
    score = 0
    for target in set(targets):
        score += CORE_FLOW_TARGETS.get(target, 0)
        score += CONTEXT_FLOW_TARGETS.get(target, 0)
        score += FRP_FLOW_TARGETS.get(target, 0)
        score += KEY_VALIDATOR_TARGETS.get(target, 0)
        score += ERASE_PERMISSION_TARGETS.get(target, 0)
    return score


def build_function_flows(
    instructions: list[Instruction],
    xrefs: list[XrefHit],
) -> list[FunctionFlow]:
    if not xrefs:
        return []

    ranges: list[tuple[int, int]] = []
    for xref in xrefs:
        ranges.append(estimate_function_range(instructions, xref.insn_index))

    ranges.sort()
    merged: list[list[int]] = []
    for start, end in ranges:
        if not merged or start > merged[-1][1]:
            merged.append([start, end])
        else:
            merged[-1][1] = max(merged[-1][1], end)

    flows: list[FunctionFlow] = []
    for start, end in merged:
        local_xrefs = tuple(xref for xref in xrefs if start <= xref.insn_index <= end)
        if not local_xrefs:
            continue

        calls: list[int] = []
        branches: list[tuple[int, int, str]] = []
        for index in range(start, end + 1):
            insn = instructions[index]
            call_target = parse_call_target(insn)
            if call_target is not None:
                calls.append(call_target)

            if is_branch_instruction(insn):
                branch_target = parse_branch_target(insn.operands)
                if branch_target is not None:
                    branches.append((insn.address, branch_target, insn.mnemonic))

        matched_targets = tuple(sorted({xref.target.target for xref in local_xrefs}))
        score = score_targets(matched_targets) + len(local_xrefs)
        core_matches = sum(1 for target in matched_targets if target in CORE_FLOW_TARGETS)
        if core_matches >= 3:
            score += 10
        if any(target == "Check 'Allow OEM Unlock'" for target in matched_targets):
            score += 5
        frp_matches = sum(1 for target in matched_targets if target in FRP_FLOW_TARGETS)
        if frp_matches >= 3:
            score += 8
        key_matches = sum(1 for target in matched_targets if target in KEY_VALIDATOR_TARGETS)
        if key_matches >= 3:
            score += 8
        erase_perm_matches = sum(1 for target in matched_targets if target in ERASE_PERMISSION_TARGETS)
        if erase_perm_matches >= 3:
            score += 10

        flows.append(
            FunctionFlow(
                start_index=start,
                end_index=end,
                start_address=instructions[start].address,
                end_address=instructions[end].address,
                xrefs=local_xrefs,
                calls=tuple(dict.fromkeys(calls)),
                branches=tuple(branches),
                score=score,
                matched_targets=matched_targets,
            )
        )

    return sorted(flows, key=lambda item: (-item.score, item.start_address))


def flow_to_dict(flow: FunctionFlow) -> dict[str, object]:
    return {
        "start_address": f"0x{flow.start_address:016x}",
        "end_address": f"0x{flow.end_address:016x}",
        "score": flow.score,
        "matched_targets": list(flow.matched_targets),
        "calls": [f"0x{address:016x}" for address in flow.calls],
        "branches": [
            {
                "from": f"0x{source:016x}",
                "to": f"0x{target:016x}",
                "mnemonic": mnemonic,
            }
            for source, target, mnemonic in flow.branches
        ],
        "xrefs": [
            {
                "xref_address": f"0x{xref.address:016x}",
                "string_address": f"0x{xref.effective_address:016x}",
                "target": xref.target.target,
                "string": xref.target.text,
                "via": xref.via,
                "instruction": f"{xref.mnemonic} {xref.operands}".strip(),
            }
            for xref in flow.xrefs
        ],
    }


def flow_instruction_slice(
    instructions: list[Instruction],
    flow: FunctionFlow,
) -> list[Instruction]:
    return instructions[flow.start_index : flow.end_index + 1]


def identify_frp_checkers(
    instructions: list[Instruction],
    flows: list[FunctionFlow],
) -> list[FrpChecker]:
    checkers: list[FrpChecker] = []

    for flow in flows:
        insns = flow_instruction_slice(instructions, flow)
        targets = set(flow.matched_targets)
        evidence: list[str] = []
        confidence = 0

        for target, weight in FRP_FLOW_TARGETS.items():
            if target in targets:
                evidence.append(f"string target: {target}")
                confidence += weight

        if any(
            "#0x100" in insn.operands and insn.mnemonic in {"sub", "subs.w", "mov", "mov.w"}
            for insn in insns
        ):
            evidence.append("uses 0x100 byte window")
            confidence += 5

        if any(insn.mnemonic in {"sub", "subs.w"} and ", #0x100" in insn.operands for insn in insns):
            evidence.append("subtracts 0x100 from partition/end pointer")
            confidence += 4

        if any(
            (insn.mnemonic == "mov" and insn.operands == "w3, #0x100")
            or (insn.mnemonic == "mov.w" and insn.operands in {"r1, #0x100", "r2, #0x100"})
            for insn in insns
        ):
            evidence.append("passes read length 0x100 in w3")
            confidence += 4

        if any(insn.mnemonic == "ldrb" and "[sp, #0xff]" in insn.operands for insn in insns):
            evidence.append("loads last byte from stack buffer [sp,#0xff]")
            confidence += 8
        if any(insn.mnemonic == "ldrb.w" and "[r6, #0xff]" in insn.operands for insn in insns):
            evidence.append("loads last byte from stack buffer [r6,#0xff]")
            confidence += 8

        for index, insn in enumerate(insns):
            if insn.mnemonic == "cmp" and insn.operands.endswith(", #0"):
                nearby = insns[index + 1 : index + 4]
                if any(next_insn.mnemonic == "cset" and next_insn.operands.endswith(", eq") for next_insn in nearby):
                    evidence.append("returns equality result with cmp #0 / cset eq")
                    confidence += 8
                    break
            if insn.mnemonic == "clz" and insn.operands == "r0, r0":
                previous = insns[max(0, index - 4) : index]
                nearby = insns[index + 1 : index + 4]
                if (
                    any(prev_insn.mnemonic == "ldrb.w" and "[r6, #0xff]" in prev_insn.operands for prev_insn in previous)
                    and any(next_insn.mnemonic == "lsrs" and next_insn.operands == "r0, r0, #5" for next_insn in nearby)
                ):
                    evidence.append("returns equality result with ldrb/clz/lsrs")
                    confidence += 8
                    break

        callers: list[tuple[int, int]] = []
        for caller in flows:
            call_sites = [
                insn.address
                for insn in flow_instruction_slice(instructions, caller)
                if call_target_matches_function(instructions, parse_call_target(insn), flow.start_address)
            ]
            for call_site in call_sites:
                callers.append((caller.start_address, call_site))

        if callers:
            evidence.append("called by another flow candidate")
            confidence += 5

        if len({site for _, site in callers}) >= 2:
            evidence.append("called multiple times from unlock-related flow")
            confidence += 5

        if any(
            caller.start_address in {caller_start for caller_start, _ in callers}
            and flow_has_xref_target(caller, "Check 'Allow OEM Unlock'")
            for caller in flows
        ):
            evidence.append("caller contains Check 'Allow OEM Unlock' gate")
            confidence += 6

        has_frp_target = bool(targets.intersection(FRP_FLOW_TARGETS))
        has_window_evidence = any("0x100" in item for item in evidence)
        has_boolean_evidence = any("returns equality result" in item for item in evidence)
        if not has_frp_target and not (has_window_evidence and has_boolean_evidence):
            continue

        if confidence < 18:
            continue

        checkers.append(
            FrpChecker(
                flow=flow,
                confidence=confidence,
                evidence=tuple(dict.fromkeys(evidence)),
                callers=tuple(dict.fromkeys(callers)),
            )
        )

    return sorted(checkers, key=lambda item: (-item.confidence, item.flow.start_address))


def address_info(address: int, base: int) -> dict[str, str]:
    return {
        "va": f"0x{address:016x}",
        "file_offset": f"0x{file_offset_for_va(address, base):x}",
        "hxd_offset": hxd_offset_for_va(address, base),
    }


def instruction_to_dict(insn: Instruction, base: int, role: str) -> dict[str, object]:
    return {
        "role": role,
        "address": f"0x{insn.address:016x}",
        "file_offset": f"0x{file_offset_for_va(insn.address, base):x}",
        "hxd_offset": hxd_offset_for_va(insn.address, base),
        "instruction": f"{insn.mnemonic} {insn.operands}".strip(),
        "raw": insn.raw.hex(),
    }


def frp_structural_instructions(
    instructions: list[Instruction],
    checker: FrpChecker,
    base: int,
) -> list[dict[str, object]]:
    flow = checker.flow
    structural: list[dict[str, object]] = []
    seen: set[tuple[str, int]] = set()

    def add(role: str, insn: Instruction) -> None:
        key = (role, insn.address)
        if key in seen:
            return
        seen.add(key)
        structural.append(instruction_to_dict(insn, base, role))

    for index in range(flow.start_index, flow.end_index + 1):
        insn = instructions[index]
        if insn.mnemonic == "sub" and ", #0x100" in insn.operands:
            add("frp_window_start_sub_0x100", insn)
        if insn.mnemonic == "mov" and insn.operands == "w3, #0x100":
            add("frp_read_length_0x100", insn)
        if insn.mnemonic == "ldrb" and "[sp, #0xff]" in insn.operands:
            add("last_byte_load_sp_0xff", insn)
        if insn.mnemonic == "ldrb.w" and "[r6, #0xff]" in insn.operands:
            add("last_byte_load_sp_0xff", insn)
        if insn.mnemonic == "cmp" and insn.operands.endswith(", #0"):
            nearby = instructions[index + 1 : min(flow.end_index + 1, index + 4)]
            if any(next_insn.mnemonic == "cset" and next_insn.operands.endswith(", eq") for next_insn in nearby):
                add("last_byte_compare_zero", insn)
        if (
            insn.mnemonic == "clz"
            and insn.operands == "r0, r0"
            and index > flow.start_index
            and any(
                prev_insn.mnemonic == "ldrb.w" and "[r6, #0xff]" in prev_insn.operands
                for prev_insn in instructions[max(flow.start_index, index - 4) : index]
            )
            and any(
                next_insn.mnemonic == "lsrs" and next_insn.operands == "r0, r0, #5"
                for next_insn in instructions[index + 1 : min(flow.end_index + 1, index + 4)]
            )
        ):
            add("last_byte_compare_zero", insn)
        if insn.mnemonic == "cset" and insn.operands.endswith(", eq"):
            previous = instructions[max(flow.start_index, index - 3) : index]
            if any(prev_insn.mnemonic == "cmp" and prev_insn.operands.endswith(", #0") for prev_insn in previous):
                add("return_allow_oem_unlock_state", insn)

    return structural


def frp_checker_to_dict(
    checker: FrpChecker,
    base: int | None = None,
    instructions: list[Instruction] | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "function_start": f"0x{checker.flow.start_address:016x}",
        "function_end": f"0x{checker.flow.end_address:016x}",
        "confidence": checker.confidence,
        "evidence": list(checker.evidence),
        "matched_targets": list(checker.flow.matched_targets),
        "callers": [
            {
                "caller_start": f"0x{caller:016x}",
                "call_site": f"0x{site:016x}",
            }
            for caller, site in checker.callers
        ],
    }
    if base is not None:
        result.update(
            {
                "function_start_file_offset": f"0x{file_offset_for_va(checker.flow.start_address, base):x}",
                "function_start_hxd_offset": hxd_offset_for_va(checker.flow.start_address, base),
                "function_end_file_offset": f"0x{file_offset_for_va(checker.flow.end_address, base):x}",
                "function_end_hxd_offset": hxd_offset_for_va(checker.flow.end_address, base),
                "callers": [
                    {
                        "caller_start": f"0x{caller:016x}",
                        "caller_start_file_offset": f"0x{file_offset_for_va(caller, base):x}",
                        "caller_start_hxd_offset": hxd_offset_for_va(caller, base),
                        "call_site": f"0x{site:016x}",
                        "call_site_file_offset": f"0x{file_offset_for_va(site, base):x}",
                        "call_site_hxd_offset": hxd_offset_for_va(site, base),
                    }
                    for caller, site in checker.callers
                ],
            }
        )
    if base is not None and instructions is not None:
        result["structural_instructions"] = frp_structural_instructions(instructions, checker, base)
        result["xrefs"] = [
            {
                "target": xref.target.target,
                "string": xref.target.text,
                "xref_address": f"0x{xref.address:016x}",
                "xref_file_offset": f"0x{file_offset_for_va(xref.address, base):x}",
                "xref_hxd_offset": hxd_offset_for_va(xref.address, base),
                "string_address": f"0x{xref.effective_address:016x}",
                "string_file_offset": f"0x{file_offset_for_va(xref.effective_address, base):x}",
                "string_hxd_offset": hxd_offset_for_va(xref.effective_address, base),
                "instruction": f"{xref.mnemonic} {xref.operands}".strip(),
                "via": xref.via,
            }
            for xref in checker.flow.xrefs
        ]
    return result


def call_sites_for_target(
    instructions: list[Instruction],
    flows: list[FunctionFlow],
    target_address: int,
) -> list[tuple[int, int]]:
    callers: list[tuple[int, int]] = []
    for caller in flows:
        for insn in flow_instruction_slice(instructions, caller):
            if call_target_matches_function(instructions, parse_call_target(insn), target_address):
                callers.append((caller.start_address, insn.address))
    return list(dict.fromkeys(callers))


def detect_serialno_runtime_source(
    instructions: list[Instruction],
    flows: list[FunctionFlow],
    xrefs: list[XrefHit],
    base: int,
    data_size: int,
) -> dict[str, object] | None:
    del flows

    def extend_past_early_returns(start: int, end: int, max_bytes: int = 0x500) -> int:
        for index in range(start + 1, min(len(instructions), start + 256)):
            if index <= end:
                continue
            if looks_like_function_start(instructions[index]):
                if instructions[index].address - instructions[start].address <= max_bytes:
                    return index - 1
                return end
        return end

    candidates: list[tuple[int, int, int, list[XrefHit], list[dict[str, object]], int | None, list[dict[str, object]]]] = []
    for xref in xrefs:
        if xref.target.target != "serialno" or xref.target.text.strip("\x00") != "serialno":
            continue
        start, end = estimate_function_range(instructions, xref.insn_index)
        end = extend_past_early_returns(start, end)
        function_xrefs = [
            item for item in xrefs
            if start <= item.insn_index <= end
            and item.target.target in {"serialno", "barcode"}
        ]
        insns = instructions[start : end + 1]
        function_size = instructions[end].address - instructions[start].address
        calls: list[dict[str, object]] = []
        call_targets: list[int] = []
        has_call_result_gate = False
        for local_index, insn in enumerate(insns):
            target = parse_call_target(insn)
            if target is None:
                continue
            call_targets.append(target)
            calls.append(
                {
                    "site": f"0x{insn.address:016x}",
                    "site_file_offset": f"0x{file_offset_for_va(insn.address, base):x}",
                    "site_hxd_offset": hxd_offset_for_va(insn.address, base),
                    "target": f"0x{target:016x}",
                    "target_file_offset": f"0x{file_offset_for_va(target, base):x}",
                    "target_hxd_offset": hxd_offset_for_va(target, base),
                }
            )
            for probe in insns[local_index + 1 : min(len(insns), local_index + 4)]:
                if probe.mnemonic in {"cbz", "cbnz", "tbz", "tbnz", "b.eq", "b.ne"}:
                    has_call_result_gate = True
                    break

        repeated_targets = sorted({target for target in call_targets if call_targets.count(target) >= 2})
        generic_prop_get_string = repeated_targets[0] if repeated_targets else None
        cache_candidates: list[dict[str, object]] = []
        for target in dict.fromkeys(call_targets):
            if generic_prop_get_string is not None and target == generic_prop_get_string:
                continue
            cache = detect_global_cache_pattern(instructions, target, base, data_size)
            if cache is not None:
                cache_candidates.append(cache)

        exact_targets = {
            item.target.target for item in function_xrefs
            if item.target.text.strip("\x00") == item.target.target
        }
        score = 0
        if "serialno" in exact_targets:
            score += 25
        if "barcode" in exact_targets:
            score += 25
        if generic_prop_get_string is not None:
            score += 20
        if cache_candidates:
            score += 20
        if has_call_result_gate:
            score += 10
        if function_size <= 0x200:
            score += 10
        if len(calls) > 12:
            score -= 20
        candidates.append((score, start, end, function_xrefs, calls, generic_prop_get_string, cache_candidates))

    if not candidates:
        return None

    score, start, end, function_xrefs, calls, generic_prop_get_string, cache_candidates = sorted(
        candidates,
        key=lambda item: (-item[0], instructions[item[1]].address),
    )[0]

    xrefs = [
        {
            "target": xref.target.target,
            "string": xref.target.text,
            "xref_address": f"0x{xref.address:016x}",
            "xref_file_offset": f"0x{file_offset_for_va(xref.address, base):x}",
            "xref_hxd_offset": hxd_offset_for_va(xref.address, base),
            "string_address": f"0x{xref.effective_address:016x}",
            "string_file_offset": f"0x{file_offset_for_va(xref.effective_address, base):x}",
            "string_hxd_offset": hxd_offset_for_va(xref.effective_address, base),
            "instruction": f"{xref.mnemonic} {xref.operands}".strip(),
            "via": xref.via,
        }
        for xref in function_xrefs
        if xref.target.target in {"serialno", "barcode"}
    ]

    return {
        "architecture": instructions[0].mode if instructions else "unknown",
        "hw_get_serialno_string": f"0x{instructions[start].address:016x}",
        "hw_get_serialno_string_file_offset": f"0x{file_offset_for_va(instructions[start].address, base):x}",
        "hw_get_serialno_string_hxd_offset": hxd_offset_for_va(instructions[start].address, base),
        "function_end": f"0x{instructions[end].address:016x}",
        "function_end_file_offset": f"0x{file_offset_for_va(instructions[end].address, base):x}",
        "function_end_hxd_offset": hxd_offset_for_va(instructions[end].address, base),
        "generic_prop_get_string": (
            f"0x{generic_prop_get_string:016x}" if generic_prop_get_string is not None else None
        ),
        "generic_prop_get_string_file_offset": (
            f"0x{file_offset_for_va(generic_prop_get_string, base):x}"
            if generic_prop_get_string is not None else None
        ),
        "generic_prop_get_string_hxd_offset": (
            hxd_offset_for_va(generic_prop_get_string, base)
            if generic_prop_get_string is not None else None
        ),
        "xrefs": xrefs,
        "calls": calls,
        "cache_candidates": cache_candidates,
        "confidence": score,
        "notes": [
            "analysis-only; no patch runtime is generated",
            "serialno/barcode fallback chain candidate",
            "cache candidate requires read/write to the same global cell",
        ],
    }


def flow_has_xref_target(flow: FunctionFlow, target: str) -> bool:
    return any(xref.target.target == target for xref in flow.xrefs)


def find_code_validation_failure_edges(
    instructions: list[Instruction],
    flows: list[FunctionFlow],
    validator_start: int,
) -> list[tuple[int, int, str]]:
    edges: list[tuple[int, int, str]] = []

    for caller in flows:
        if not flow_has_xref_target(caller, "Code validation failure"):
            continue

        insns = flow_instruction_slice(instructions, caller)
        for local_index, insn in enumerate(insns):
            if not call_target_matches_function(instructions, parse_call_target(insn), validator_start):
                continue

            for next_insn in insns[local_index + 1 : local_index + 7]:
                if next_insn.mnemonic == "bl":
                    break
                if next_insn.mnemonic not in {"tbz", "tbnz", "cbz", "cbnz", "b.eq", "b.ne"}:
                    continue
                branch_target = parse_branch_target(next_insn.operands)
                if branch_target is None:
                    continue

                failure_xrefs = [
                    xref for xref in caller.xrefs
                    if xref.target.target == "Code validation failure"
                ]
                if any(abs(branch_target - xref.address) <= 0x40 for xref in failure_xrefs):
                    edges.append((insn.address, branch_target, next_insn.mnemonic))

    return list(dict.fromkeys(edges))


def identify_key_validators(
    instructions: list[Instruction],
    flows: list[FunctionFlow],
) -> list[KeyValidator]:
    validators: list[KeyValidator] = []

    for flow in flows:
        insns = flow_instruction_slice(instructions, flow)
        targets = set(flow.matched_targets)
        evidence: list[str] = []
        confidence = 0

        for target, weight in KEY_VALIDATOR_TARGETS.items():
            if target in targets:
                evidence.append(f"string target: {target}")
                confidence += weight

        if not targets.intersection(KEY_VALIDATOR_TARGETS):
            continue

        if any(insn.mnemonic == "mov" and insn.operands == "w0, w20" for insn in insns):
            evidence.append("returns accumulated result with mov w0, w20")
            confidence += 10

        for index, insn in enumerate(insns[:-1]):
            if insn.mnemonic == "mov" and insn.operands == "w0, w20" and insns[index + 1].mnemonic == "ldp":
                nearby = insns[index + 1 : index + 8]
                if any(next_insn.mnemonic == "ret" for next_insn in nearby):
                    evidence.append("function epilogue returns w20 before ret")
                    confidence += 8
                    break

        if any(insn.mnemonic == "mov" and insn.operands == "w20, wzr" for insn in insns):
            evidence.append("initializes/falls back result to 0 in w20")
            confidence += 5

        if any(insn.mnemonic == "mov" and insn.operands == "w20, #1" for insn in insns):
            evidence.append("sets result to 1 after successful comparisons")
            confidence += 6

        if any(insn.mnemonic == "cmp" and re.search(r"w\d+, w\d+", insn.operands) for insn in insns):
            evidence.append("contains register-to-register comparison")
            confidence += 3

        if any(insn.mnemonic in {"ldrb", "ldur"} and "w" in insn.operands for insn in insns):
            evidence.append("loads byte/word data for comparison")
            confidence += 3

        if any(insn.mnemonic == "cmp" and "#0xf" in insn.operands for insn in insns):
            evidence.append("checks Motorola helper success value 0xf")
            confidence += 4

        if any(insn.mnemonic == "bl" for insn in insns) and any("#0x20" in insn.operands for insn in insns):
            evidence.append("uses hash-sized 0x20 byte buffer")
            confidence += 4

        if sum(1 for insn in insns if parse_call_target(insn) is not None) >= 5:
            evidence.append("contains multi-stage decode/hash call chain")
            confidence += 4

        callers = tuple(call_sites_for_target(instructions, flows, flow.start_address))
        if callers:
            evidence.append("called by another flow candidate")
            confidence += 5

        failure_edges = tuple(find_code_validation_failure_edges(instructions, flows, flow.start_address))
        if failure_edges:
            evidence.append("caller branches validator failure toward Code validation failure")
            confidence += 12

        if confidence < 22:
            continue

        validators.append(
            KeyValidator(
                flow=flow,
                confidence=confidence,
                evidence=tuple(dict.fromkeys(evidence)),
                callers=callers,
                failure_edges=failure_edges,
            )
        )

    return sorted(validators, key=lambda item: (-item.confidence, item.flow.start_address))


def key_validator_structural_instructions(
    instructions: list[Instruction],
    validator: KeyValidator,
    base: int,
) -> list[dict[str, object]]:
    flow = validator.flow
    structural: list[dict[str, object]] = []
    seen: set[tuple[str, int]] = set()

    def add(role: str, insn: Instruction) -> None:
        key = (role, insn.address)
        if key in seen:
            return
        seen.add(key)
        structural.append(instruction_to_dict(insn, base, role))

    for index in range(flow.start_index, flow.end_index + 1):
        insn = instructions[index]
        if insn.mnemonic == "mov" and insn.operands == "w20, wzr":
            add("result_init_zero", insn)
        if insn.mnemonic == "mov" and insn.operands == "w20, #1":
            add("result_set_success_one", insn)
        if insn.mnemonic == "mov" and insn.operands == "w0, w20":
            add("return_result_w20", insn)
        if insn.mnemonic == "ret":
            add("function_return", insn)
        if insn.mnemonic == "cmp":
            if re.search(r"w\d+, w\d+", insn.operands):
                add("register_compare", insn)
            elif "#0" in insn.operands:
                add("zero_compare", insn)
        if insn.mnemonic in {"ldrb", "ldur"} and "w" in insn.operands:
            add("data_load_for_compare", insn)
        if "#0x20" in insn.operands:
            add("hash_0x20_buffer_or_length", insn)
        if parse_call_target(insn) is not None:
            add("call", insn)
        if any(xref.insn_index == index for xref in flow.xrefs):
            add("string_xref", insn)

    return structural


def key_validator_to_dict(
    validator: KeyValidator,
    base: int | None = None,
    instructions: list[Instruction] | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "function_start": f"0x{validator.flow.start_address:016x}",
        "function_end": f"0x{validator.flow.end_address:016x}",
        "confidence": validator.confidence,
        "evidence": list(validator.evidence),
        "matched_targets": list(validator.flow.matched_targets),
        "callers": [
            {
                "caller_start": f"0x{caller:016x}",
                "call_site": f"0x{site:016x}",
            }
            for caller, site in validator.callers
        ],
        "failure_edges": [
            {
                "call_site": f"0x{call_site:016x}",
                "failure_target": f"0x{failure_target:016x}",
                "branch": branch,
            }
            for call_site, failure_target, branch in validator.failure_edges
        ],
    }
    if base is not None:
        result.update(
            {
                "function_start_file_offset": f"0x{file_offset_for_va(validator.flow.start_address, base):x}",
                "function_start_hxd_offset": hxd_offset_for_va(validator.flow.start_address, base),
                "function_end_file_offset": f"0x{file_offset_for_va(validator.flow.end_address, base):x}",
                "function_end_hxd_offset": hxd_offset_for_va(validator.flow.end_address, base),
                "callers": [
                    {
                        "caller_start": f"0x{caller:016x}",
                        "caller_start_file_offset": f"0x{file_offset_for_va(caller, base):x}",
                        "caller_start_hxd_offset": hxd_offset_for_va(caller, base),
                        "call_site": f"0x{site:016x}",
                        "call_site_file_offset": f"0x{file_offset_for_va(site, base):x}",
                        "call_site_hxd_offset": hxd_offset_for_va(site, base),
                    }
                    for caller, site in validator.callers
                ],
                "failure_edges": [
                    {
                        "call_site": f"0x{call_site:016x}",
                        "call_site_file_offset": f"0x{file_offset_for_va(call_site, base):x}",
                        "call_site_hxd_offset": hxd_offset_for_va(call_site, base),
                        "failure_target": f"0x{failure_target:016x}",
                        "failure_target_file_offset": f"0x{file_offset_for_va(failure_target, base):x}",
                        "failure_target_hxd_offset": hxd_offset_for_va(failure_target, base),
                        "branch": branch,
                    }
                    for call_site, failure_target, branch in validator.failure_edges
                ],
            }
        )
    if base is not None and instructions is not None:
        result["structural_instructions"] = key_validator_structural_instructions(
            instructions,
            validator,
            base,
        )
        result["xrefs"] = [
            {
                "target": xref.target.target,
                "string": xref.target.text,
                "xref_address": f"0x{xref.address:016x}",
                "xref_file_offset": f"0x{file_offset_for_va(xref.address, base):x}",
                "xref_hxd_offset": hxd_offset_for_va(xref.address, base),
                "string_address": f"0x{xref.effective_address:016x}",
                "string_file_offset": f"0x{file_offset_for_va(xref.effective_address, base):x}",
                "string_hxd_offset": hxd_offset_for_va(xref.effective_address, base),
                "instruction": f"{xref.mnemonic} {xref.operands}".strip(),
                "via": xref.via,
            }
            for xref in validator.flow.xrefs
        ]
    return result


def find_nearby_branch_after_call(
    instructions: list[Instruction],
    call_index: int,
    flow_end: int,
    limit: int = 4,
) -> Instruction | None:
    for index in range(call_index + 1, min(flow_end + 1, call_index + limit + 1)):
        insn = instructions[index]
        if is_conditional_branch(insn):
            return insn
        if insn.mnemonic == "bl":
            break
    return None


def erase_permission_name_checks(
    instructions: list[Instruction],
    flow: FunctionFlow,
) -> list[tuple[int, str, int | None, int | None]]:
    checks: list[tuple[int, str, int | None, int | None]] = []
    for xref in flow.xrefs:
        if xref.target.target not in ERASE_PERMISSION_NAME_TARGETS:
            continue
        if not re.match(r"x[12],", xref.operands):
            continue

        next_call = find_next_call(instructions, xref.insn_index, flow.end_index, limit=5)
        if next_call is None:
            continue
        call_index, call_insn = next_call
        branch = find_nearby_branch_after_call(instructions, call_index, flow.end_index)
        checks.append(
            (
                xref.address,
                xref.target.target,
                parse_call_target(call_insn),
                parse_branch_target(branch.operands) if branch is not None else None,
            )
        )
    return list(dict.fromkeys(checks))


def find_denied_edges(
    instructions: list[Instruction],
    flow: FunctionFlow,
) -> list[tuple[int, int, str]]:
    denied_xrefs = [
        xref for xref in flow.xrefs
        if xref.target.target == "erase permission denied"
    ]
    if not denied_xrefs:
        return []

    edges: list[tuple[int, int, str]] = []
    for source, target, mnemonic in flow.branches:
        if any(abs(target - xref.address) <= 0x30 for xref in denied_xrefs):
            edges.append((source, target, mnemonic))
    return list(dict.fromkeys(edges))


def identify_erase_permission_checks(
    instructions: list[Instruction],
    flows: list[FunctionFlow],
) -> list[ErasePermissionCheck]:
    checks: list[ErasePermissionCheck] = []

    for flow in flows:
        insns = flow_instruction_slice(instructions, flow)
        targets = set(flow.matched_targets)
        evidence: list[str] = []
        confidence = 0

        for target, weight in ERASE_PERMISSION_TARGETS.items():
            if target in targets:
                evidence.append(f"string target: {target}")
                confidence += weight

        if "fboot_cmd_erase_permission_validate" in targets:
            evidence.append("debug tag names erase permission validator")
            confidence += 10

        if {"erase permission denied", "Invalid partition name %s"} <= targets:
            evidence.append("contains user-visible deny and invalid partition errors")
            confidence += 10

        name_checks = tuple(erase_permission_name_checks(instructions, flow))
        if len(name_checks) >= 3:
            evidence.append(f"repeated partition-name comparisons ({len(name_checks)})")
            confidence += 10
        elif name_checks:
            evidence.append(f"partition-name comparisons ({len(name_checks)})")
            confidence += 4

        if any(insn.mnemonic == "ldr" and re.search(r"x\d+, \[x\d+, #0x10\]", insn.operands) for insn in insns):
            evidence.append("reads fastboot command argument pointer at struct offset +0x10")
            confidence += 6

        if any(insn.mnemonic == "add" and re.search(r"x\d+, x\d+, #1$", insn.operands) for insn in insns):
            evidence.append("skips leading ':' with add argument pointer +1")
            confidence += 5

        permission_call_items: list[tuple[int, int]] = []
        for local_index, insn in enumerate(insns):
            target = parse_call_target(insn)
            if target is None:
                continue
            if any(
                next_insn.mnemonic in {"tbz", "tbnz", "cbz", "cbnz"}
                for next_insn in insns[local_index + 1 : min(len(insns), local_index + 4)]
            ):
                permission_call_items.append((insn.address, target))
        permission_calls = tuple(permission_call_items)
        if len(permission_calls) >= 2:
            evidence.append("contains calls whose boolean result gates erase flow")
            confidence += 5

        denied_edges = tuple(find_denied_edges(instructions, flow))
        if denied_edges:
            evidence.append("branch edge reaches erase permission denied message")
            confidence += 7

        callers = tuple(call_sites_for_target(instructions, flows, flow.start_address))
        if callers:
            evidence.append("called by another flow candidate")
            confidence += 3

        if confidence < 35:
            continue

        checks.append(
            ErasePermissionCheck(
                flow=flow,
                confidence=confidence,
                evidence=tuple(dict.fromkeys(evidence)),
                callers=callers,
                name_checks=name_checks,
                permission_calls=permission_calls,
                denied_edges=denied_edges,
            )
        )

    return sorted(checks, key=lambda item: (-item.confidence, item.flow.start_address))


def erase_permission_structural_instructions(
    instructions: list[Instruction],
    check: ErasePermissionCheck,
    base: int,
) -> list[dict[str, object]]:
    flow = check.flow
    name_check_addresses = {address for address, _, _, _ in check.name_checks}
    permission_call_addresses = {address for address, _ in check.permission_calls}
    denied_branch_addresses = {address for address, _, _ in check.denied_edges}
    structural: list[dict[str, object]] = []
    seen: set[tuple[str, int]] = set()

    def add(role: str, insn: Instruction) -> None:
        key = (role, insn.address)
        if key in seen:
            return
        seen.add(key)
        structural.append(instruction_to_dict(insn, base, role))

    for index in range(flow.start_index, flow.end_index + 1):
        insn = instructions[index]
        if insn.mnemonic == "ldr" and re.search(r"x\d+, \[x\d+, #0x10\]", insn.operands):
            add("fastboot_argument_load_struct_plus_0x10", insn)
        if insn.mnemonic == "add" and re.search(r"x\d+, x\d+, #1$", insn.operands):
            add("partition_name_skip_colon", insn)
        if insn.address in name_check_addresses:
            add("partition_name_string_xref", insn)
        if parse_call_target(insn) is not None:
            role = "permission_or_helper_call" if insn.address in permission_call_addresses else "call"
            add(role, insn)
        if is_conditional_branch(insn):
            role = "branch_to_erase_permission_denied" if insn.address in denied_branch_addresses else "conditional_branch"
            add(role, insn)
        if insn.mnemonic == "mov" and insn.operands in {"w20, wzr", "w20, #1", "w20, #3", "w0, w20"}:
            add("return_status_value", insn)
        if any(xref.insn_index == index for xref in flow.xrefs):
            add("string_xref", insn)

    return structural


def erase_permission_to_dict(
    check: ErasePermissionCheck,
    base: int | None = None,
    instructions: list[Instruction] | None = None,
) -> dict[str, object]:
    result: dict[str, object] = {
        "function_start": f"0x{check.flow.start_address:016x}",
        "function_end": f"0x{check.flow.end_address:016x}",
        "confidence": check.confidence,
        "evidence": list(check.evidence),
        "matched_targets": list(check.flow.matched_targets),
        "calls": [f"0x{address:016x}" for address in check.flow.calls],
        "callers": [
            {
                "caller_start": f"0x{caller:016x}",
                "call_site": f"0x{site:016x}",
            }
            for caller, site in check.callers
        ],
        "name_checks": [
            {
                "xref_address": f"0x{xref_address:016x}",
                "name": name,
                "compare_call_target": f"0x{call_target:016x}" if call_target is not None else None,
                "branch_target": f"0x{branch_target:016x}" if branch_target is not None else None,
            }
            for xref_address, name, call_target, branch_target in check.name_checks
        ],
        "denied_edges": [
            {
                "branch_address": f"0x{branch_address:016x}",
                "target": f"0x{target:016x}",
                "mnemonic": mnemonic,
            }
            for branch_address, target, mnemonic in check.denied_edges
        ],
    }
    if base is not None:
        result.update(
            {
                "function_start_file_offset": f"0x{file_offset_for_va(check.flow.start_address, base):x}",
                "function_start_hxd_offset": hxd_offset_for_va(check.flow.start_address, base),
                "function_end_file_offset": f"0x{file_offset_for_va(check.flow.end_address, base):x}",
                "function_end_hxd_offset": hxd_offset_for_va(check.flow.end_address, base),
                "callers": [
                    {
                        "caller_start": f"0x{caller:016x}",
                        "caller_start_file_offset": f"0x{file_offset_for_va(caller, base):x}",
                        "caller_start_hxd_offset": hxd_offset_for_va(caller, base),
                        "call_site": f"0x{site:016x}",
                        "call_site_file_offset": f"0x{file_offset_for_va(site, base):x}",
                        "call_site_hxd_offset": hxd_offset_for_va(site, base),
                    }
                    for caller, site in check.callers
                ],
                "name_checks": [
                    {
                        "xref_address": f"0x{xref_address:016x}",
                        "xref_file_offset": f"0x{file_offset_for_va(xref_address, base):x}",
                        "xref_hxd_offset": hxd_offset_for_va(xref_address, base),
                        "name": name,
                        "compare_call_target": f"0x{call_target:016x}" if call_target is not None else None,
                        "compare_call_target_file_offset": (
                            f"0x{file_offset_for_va(call_target, base):x}" if call_target is not None else None
                        ),
                        "compare_call_target_hxd_offset": (
                            hxd_offset_for_va(call_target, base) if call_target is not None else None
                        ),
                        "branch_target": f"0x{branch_target:016x}" if branch_target is not None else None,
                        "branch_target_file_offset": (
                            f"0x{file_offset_for_va(branch_target, base):x}" if branch_target is not None else None
                        ),
                        "branch_target_hxd_offset": (
                            hxd_offset_for_va(branch_target, base) if branch_target is not None else None
                        ),
                    }
                    for xref_address, name, call_target, branch_target in check.name_checks
                ],
                "denied_edges": [
                    {
                        "branch_address": f"0x{branch_address:016x}",
                        "branch_file_offset": f"0x{file_offset_for_va(branch_address, base):x}",
                        "branch_hxd_offset": hxd_offset_for_va(branch_address, base),
                        "target": f"0x{target:016x}",
                        "target_file_offset": f"0x{file_offset_for_va(target, base):x}",
                        "target_hxd_offset": hxd_offset_for_va(target, base),
                        "mnemonic": mnemonic,
                    }
                    for branch_address, target, mnemonic in check.denied_edges
                ],
            }
        )
    if base is not None and instructions is not None:
        result["structural_instructions"] = erase_permission_structural_instructions(
            instructions,
            check,
            base,
        )
        result["xrefs"] = [
            {
                "target": xref.target.target,
                "string": xref.target.text,
                "xref_address": f"0x{xref.address:016x}",
                "xref_file_offset": f"0x{file_offset_for_va(xref.address, base):x}",
                "xref_hxd_offset": hxd_offset_for_va(xref.address, base),
                "string_address": f"0x{xref.effective_address:016x}",
                "string_file_offset": f"0x{file_offset_for_va(xref.effective_address, base):x}",
                "string_hxd_offset": hxd_offset_for_va(xref.effective_address, base),
                "instruction": f"{xref.mnemonic} {xref.operands}".strip(),
                "via": xref.via,
            }
            for xref in check.flow.xrefs
        ]
    return result


def partition_reference_mode(xref: XrefHit) -> str:
    return classify_target_text(xref.target.target, xref.target.text)


def classify_target_text(target: str, text: str) -> str:
    clean_text = text.strip("\x00").strip()
    if clean_text.lower() == target.lower():
        return "direct_string"
    if target.lower() in clean_text.lower():
        return "embedded_string"
    return "address_only"


def file_offset_for_va(address: int, base: int) -> int:
    return address - base


def hxd_offset_for_va(address: int, base: int) -> str:
    return f"{file_offset_for_va(address, base):08X}"


def find_function_bounds_by_address(
    instructions: list[Instruction],
    address: int,
) -> tuple[int, int] | None:
    for index, insn in enumerate(instructions):
        if insn.address == address:
            return estimate_function_range(instructions, index)
    return None


def register_written_by_adrp(insn: Instruction) -> tuple[str, int] | None:
    if insn.mnemonic != "adrp":
        return None
    return parse_adrp(insn.operands)


def memory_access_registers(insn: Instruction) -> list[tuple[str, int]]:
    refs: list[tuple[str, int]] = []
    for reg in re.findall(r"\[(x\d+)", insn.operands):
        offset = parse_mem_offset(insn.operands, reg)
        if offset is not None:
            refs.append((reg, offset))
    return refs


def detect_global_cache_pattern(
    instructions: list[Instruction],
    function_address: int,
    base: int,
    data_size: int,
) -> dict[str, object] | None:
    bounds = find_function_bounds_by_address(instructions, function_address)
    if bounds is None:
        return None

    start, end = bounds
    for index in range(start + 1, min(len(instructions), start + 256)):
        if index <= end:
            continue
        if looks_like_function_start(instructions[index]):
            if instructions[index].address - instructions[start].address <= 0x500:
                end = index - 1
            break
    pages_by_reg: dict[str, int] = {}
    refs_by_address: dict[int, list[dict[str, object]]] = {}
    conditional_after_read = False

    for index in range(start, end + 1):
        insn = instructions[index]
        parsed_adrp = register_written_by_adrp(insn)
        if parsed_adrp is not None:
            reg, page = parsed_adrp
            pages_by_reg[reg] = page
            continue

        if insn.mnemonic not in {"ldr", "ldrb", "ldrh", "str", "strb", "strh"}:
            continue

        for reg, offset in memory_access_registers(insn):
            page = pages_by_reg.get(reg)
            if page is None:
                continue
            address = page + offset
            if base <= address < base + 0x1000:
                continue
            kind = "write" if insn.mnemonic.startswith("str") else "read"
            item = {
                "kind": kind,
                "address": f"0x{insn.address:016x}",
                "file_offset": f"0x{file_offset_for_va(insn.address, base):x}",
                "hxd_offset": hxd_offset_for_va(insn.address, base),
                "instruction": f"{insn.mnemonic} {insn.operands}".strip(),
            }
            refs_by_address.setdefault(address, []).append(item)
            if kind == "read":
                for probe in instructions[index + 1 : min(end + 1, index + 5)]:
                    if probe.mnemonic in {"cbz", "cbnz", "tbz", "tbnz", "b.eq", "b.ne"}:
                        conditional_after_read = True
                        break

    candidates: list[tuple[int, list[dict[str, object]]]] = []
    for address, refs in refs_by_address.items():
        has_read = any(ref["kind"] == "read" for ref in refs)
        has_write = any(ref["kind"] == "write" for ref in refs)
        if has_read and has_write:
            candidates.append((address, refs))

    if not candidates:
        return None

    cache_address, refs = sorted(candidates, key=lambda item: (len(item[1]), item[0]), reverse=True)[0]
    return {
        "function": f"0x{function_address:016x}",
        "function_file_offset": f"0x{file_offset_for_va(function_address, base):x}",
        "function_hxd_offset": hxd_offset_for_va(function_address, base),
        "function_end": f"0x{instructions[end].address:016x}",
        "cache_address": f"0x{cache_address:016x}",
        "cache_file_offset": (
            f"0x{file_offset_for_va(cache_address, base):x}"
            if base <= cache_address < base + data_size
            else None
        ),
        "cache_hxd_offset": (
            hxd_offset_for_va(cache_address, base)
            if base <= cache_address < base + data_size
            else None
        ),
        "has_conditional_after_read": conditional_after_read,
        "references": refs,
    }


def find_next_call(
    instructions: list[Instruction],
    start_index: int,
    end_index: int,
    limit: int = 5,
) -> tuple[int, Instruction] | None:
    for index in range(start_index + 1, min(end_index + 1, start_index + limit + 1)):
        insn = instructions[index]
        if insn.mnemonic == "bl":
            return index, insn
    return None


def classify_partition_call(
    instructions: list[Instruction],
    call_index: int,
    flow_end: int,
) -> tuple[str, int | None, int | None]:
    check_address: int | None = None
    failure_target: int | None = None

    for index in range(call_index + 1, min(flow_end + 1, call_index + 5)):
        insn = instructions[index]
        if insn.mnemonic == "cmn" and insn.operands == "w0, #1":
            check_address = insn.address
            return "lookup", check_address, None
        if insn.mnemonic == "tbnz" and insn.operands.startswith("x0, #0x3f"):
            check_address = insn.address
            failure_target = parse_branch_target(insn.operands)
            return "erase", check_address, failure_target
        if insn.mnemonic == "cmp" and insn.operands == "r0, #0":
            check_address = insn.address
            for branch_index in range(index + 1, min(flow_end + 1, index + 3)):
                branch = instructions[branch_index]
                if branch.mnemonic in {"beq", "bne", "cbz", "cbnz"}:
                    failure_target = parse_branch_target(branch.operands)
                    return "erase", check_address, failure_target
        if insn.mnemonic == "bl":
            break

    return "call", check_address, failure_target


def find_failure_message_for_target(
    flow: FunctionFlow,
    partition: str,
    failure_target: int | None,
) -> XrefHit | None:
    if failure_target is None:
        return None

    candidates = [
        xref for xref in flow.xrefs
        if xref.address >= failure_target
        and xref.address <= failure_target + 0x40
        and partition.lower() in xref.target.text.lower()
        and "erase" in xref.target.text.lower()
    ]
    if candidates:
        return sorted(candidates, key=lambda xref: xref.address)[0]
    return None


def is_unlock_flow(flow: FunctionFlow) -> bool:
    targets = {target.lower() for target in flow.matched_targets}
    unlock_markers = {
        "check 'allow oem unlock'",
        "code validation failure",
        "bootloader is unlocked",
        "now unlocked for flashing",
        "fastboot oem unlock",
    }
    partition_count = len(targets & TARGET_ERASE_PARTITIONS)
    marker_count = len(targets & unlock_markers)
    return marker_count >= 1 and partition_count >= 2


def detect_partition_erase_operations(
    instructions: list[Instruction],
    flows: list[FunctionFlow],
) -> list[PartitionEraseOperation]:
    operations: list[PartitionEraseOperation] = []
    unlock_flows = [flow for flow in flows if is_unlock_flow(flow)]
    if not unlock_flows and flows:
        unlock_flows = [flows[0]]

    for flow in unlock_flows:
        for xref in flow.xrefs:
            partition = xref.target.target.lower()
            if partition not in TARGET_ERASE_PARTITIONS:
                continue

            # Only arguments passed in x0/r0 can be partition lookup/erase names.
            # Some Thumb builds keep the name in r4 and move it into r0 just
            # before the call, so keep r4 as a narrow ARM32-only fallback.
            if not (
                xref.operands.startswith("x0, ")
                or xref.operands.startswith("r0, ")
                or (xref.operands.startswith("r4, ") and xref.via.startswith("thumb "))
            ):
                continue

            next_call = find_next_call(instructions, xref.insn_index, flow.end_index)
            if next_call is None:
                continue

            call_index, call_insn = next_call
            call_target = parse_call_target(call_insn)
            operation, check_address, failure_target = classify_partition_call(
                instructions,
                call_index,
                flow.end_index,
            )
            if operation not in {"lookup", "erase"}:
                continue

            failure_xref = find_failure_message_for_target(flow, partition, failure_target)

            operations.append(
                PartitionEraseOperation(
                    flow_start=flow.start_address,
                    partition=partition,
                    operation=operation,
                    xref_address=xref.address,
                    string_address=xref.effective_address,
                    string_text=xref.target.text,
                    reference_mode=partition_reference_mode(xref),
                    xref_mnemonic=xref.mnemonic,
                    xref_operands=xref.operands,
                    xref_via=xref.via,
                    call_site=call_insn.address,
                    call_target=call_target,
                    result_check_address=check_address,
                    failure_target=failure_target,
                    failure_message_address=failure_xref.effective_address if failure_xref else None,
                    failure_message=failure_xref.target.text if failure_xref else None,
                )
            )

    unique: dict[tuple[int, str, str, int], PartitionEraseOperation] = {}
    for operation in operations:
        unique[(operation.flow_start, operation.partition, operation.operation, operation.xref_address)] = operation
    return sorted(
        unique.values(),
        key=lambda item: (item.flow_start, item.xref_address, item.operation, item.partition),
    )


def partition_erase_to_dict(operation: PartitionEraseOperation, base: int | None = None) -> dict[str, object]:
    result: dict[str, object] = {
        "flow_start": f"0x{operation.flow_start:016x}",
        "partition": operation.partition,
        "operation": operation.operation,
        "xref_address": f"0x{operation.xref_address:016x}",
        "string_address": f"0x{operation.string_address:016x}",
        "string_text": operation.string_text,
        "reference_mode": operation.reference_mode,
        "xref_instruction": f"{operation.xref_mnemonic} {operation.xref_operands}".strip(),
        "xref_via": operation.xref_via,
        "call_site": f"0x{operation.call_site:016x}" if operation.call_site is not None else None,
        "call_target": f"0x{operation.call_target:016x}" if operation.call_target is not None else None,
        "result_check_address": f"0x{operation.result_check_address:016x}" if operation.result_check_address is not None else None,
        "failure_target": f"0x{operation.failure_target:016x}" if operation.failure_target is not None else None,
        "failure_message_address": f"0x{operation.failure_message_address:016x}" if operation.failure_message_address is not None else None,
        "failure_message": operation.failure_message,
    }
    if base is not None:
        result.update(
            {
                "flow_start_file_offset": f"0x{file_offset_for_va(operation.flow_start, base):x}",
                "flow_start_hxd_offset": hxd_offset_for_va(operation.flow_start, base),
                "xref_file_offset": f"0x{file_offset_for_va(operation.xref_address, base):x}",
                "xref_hxd_offset": hxd_offset_for_va(operation.xref_address, base),
                "string_file_offset": f"0x{file_offset_for_va(operation.string_address, base):x}",
                "string_hxd_offset": hxd_offset_for_va(operation.string_address, base),
                "call_site_file_offset": (
                    f"0x{file_offset_for_va(operation.call_site, base):x}"
                    if operation.call_site is not None
                    else None
                ),
                "call_site_hxd_offset": (
                    hxd_offset_for_va(operation.call_site, base)
                    if operation.call_site is not None
                    else None
                ),
                "call_target_file_offset": (
                    f"0x{file_offset_for_va(operation.call_target, base):x}"
                    if operation.call_target is not None
                    else None
                ),
                "call_target_hxd_offset": (
                    hxd_offset_for_va(operation.call_target, base)
                    if operation.call_target is not None
                    else None
                ),
                "failure_target_file_offset": (
                    f"0x{file_offset_for_va(operation.failure_target, base):x}"
                    if operation.failure_target is not None
                    else None
                ),
                "failure_target_hxd_offset": (
                    hxd_offset_for_va(operation.failure_target, base)
                    if operation.failure_target is not None
                    else None
                ),
            }
        )
    return result


def write_disassembly(path: Path, instructions: list[Instruction]) -> None:
    with path.open("w", encoding="utf-8") as fp:
        for insn in instructions:
            raw = insn.raw.hex()
            fp.write(f"0x{insn.address:016x}:  {raw:<10}  {insn.mnemonic:<8} {insn.operands}\n")


def write_strings(path: Path, data: bytes, hits: list[StringHit]) -> None:
    with path.open("w", encoding="utf-8") as fp:
        for hit in hits:
            fp.write(f"0x{hit.address:016x}  off=0x{hit.offset:x}  target={hit.target!r}\n")
            fp.write(f"  string: {hit.text!r}\n")
            fp.write(f"  context: {printable_context(data, hit.offset)}\n\n")


def write_xrefs(
    path: Path,
    instructions: list[Instruction],
    xrefs: list[XrefHit],
    context: int,
) -> None:
    with path.open("w", encoding="utf-8") as fp:
        if not xrefs:
            fp.write("No se encontraron xrefs por patron ADRP.\n")
            return

        for xref in xrefs:
            fp.write(
                f"XREF 0x{xref.address:016x}: {xref.mnemonic} {xref.operands} "
                f"-> 0x{xref.effective_address:016x} ({xref.target.target}) via {xref.via}\n"
            )
            fp.write(f"  string: {xref.target.text!r}\n")

            start = max(0, xref.insn_index - context)
            end = min(len(instructions), xref.insn_index + context + 1)
            for index in range(start, end):
                insn = instructions[index]
                marker = ">>" if index == xref.insn_index else "  "
                fp.write(f"{marker} 0x{insn.address:016x}: {insn.mnemonic:<8} {insn.operands}\n")
            fp.write("\n")


def write_candidate_functions(
    output_dir: Path,
    instructions: list[Instruction],
    xrefs: list[XrefHit],
) -> None:
    seen_ranges: set[tuple[int, int]] = set()
    written_count = 0
    for xref in xrefs:
        start, end = estimate_function_range(instructions, xref.insn_index)
        key = (start, end)
        if key in seen_ranges:
            continue
        seen_ranges.add(key)
        written_count += 1

        start_addr = instructions[start].address
        safe_target = re.sub(r"[^A-Za-z0-9._-]+", "_", xref.target.target).strip("_")
        path = output_dir / f"candidate_{written_count:02d}_{start_addr:016x}_{safe_target[:40]}.asm"

        with path.open("w", encoding="utf-8") as fp:
            fp.write(
                f"; candidate function around xref 0x{xref.address:016x} "
                f"to {xref.target.target!r}\n"
            )
            fp.write(f"; estimated range 0x{instructions[start].address:016x}-0x{instructions[end].address:016x}\n\n")
            for index in range(start, end + 1):
                insn = instructions[index]
                marker = ">>" if index == xref.insn_index else "  "
                fp.write(f"{marker} 0x{insn.address:016x}: {insn.mnemonic:<8} {insn.operands}\n")


def short_label(value: str, limit: int = 72) -> str:
    cleaned = value.replace("\n", "\\n").replace('"', "'")
    if len(cleaned) <= limit:
        return cleaned
    return cleaned[: limit - 3] + "..."


def write_flow_asm(
    path: Path,
    instructions: list[Instruction],
    flow: FunctionFlow,
) -> None:
    xrefs_by_index: dict[int, list[XrefHit]] = {}
    branch_targets = {target for _, target, _ in flow.branches}
    call_targets = set(flow.calls)
    for xref in flow.xrefs:
        xrefs_by_index.setdefault(xref.insn_index, []).append(xref)

    with path.open("w", encoding="utf-8") as fp:
        fp.write(f"; flow candidate 0x{flow.start_address:016x}-0x{flow.end_address:016x}\n")
        fp.write(f"; score: {flow.score}\n")
        fp.write(f"; matched targets: {', '.join(flow.matched_targets)}\n")
        fp.write(f"; calls: {', '.join(f'0x{call:016x}' for call in flow.calls)}\n\n")

        for index in range(flow.start_index, flow.end_index + 1):
            insn = instructions[index]
            if insn.address in branch_targets:
                fp.write(f"\nloc_{insn.address:016x}:\n")

            for xref in xrefs_by_index.get(index, []):
                fp.write(
                    f"; XREF string 0x{xref.effective_address:016x}: "
                    f"{xref.target.target!r} -> {xref.target.text!r}\n"
                )

            call_target = parse_call_target(insn)
            suffix = ""
            if call_target is not None:
                suffix = "  ; call"
                if call_target in call_targets:
                    suffix += f" 0x{call_target:016x}"

            marker = ">>" if index in xrefs_by_index else "  "
            fp.write(f"{marker} 0x{insn.address:016x}: {insn.mnemonic:<8} {insn.operands}{suffix}\n")


def write_flow_reports(
    output_dir: Path,
    instructions: list[Instruction],
    flows: list[FunctionFlow],
) -> None:
    flow_dir = output_dir / "flow_functions"
    flow_dir.mkdir(parents=True, exist_ok=True)

    with (output_dir / "flow_candidates.json").open("w", encoding="utf-8") as fp:
        json.dump([flow_to_dict(flow) for flow in flows], fp, indent=2)

    with (output_dir / "flow_candidates.txt").open("w", encoding="utf-8") as fp:
        if not flows:
            fp.write("No flow candidates found.\n")
            return

        for number, flow in enumerate(flows, 1):
            fp.write(
                f"[{number:02d}] score={flow.score} "
                f"range=0x{flow.start_address:016x}-0x{flow.end_address:016x} "
                f"xrefs={len(flow.xrefs)} calls={len(flow.calls)} branches={len(flow.branches)}\n"
            )
            fp.write(f"  targets: {', '.join(flow.matched_targets)}\n")
            for xref in flow.xrefs:
                fp.write(
                    f"  - 0x{xref.address:016x} -> 0x{xref.effective_address:016x} "
                    f"{xref.target.target!r} [{xref.via}]\n"
                )
            fp.write("\n")

    for number, flow in enumerate(flows, 1):
        path = flow_dir / f"flow_{number:02d}_score_{flow.score}_0x{flow.start_address:016x}.asm"
        write_flow_asm(path, instructions, flow)

    if flows:
        write_flow_asm(output_dir / "best_flow.asm", instructions, flows[0])


def write_check_allow_report(
    path: Path,
    instructions: list[Instruction],
    flows: list[FunctionFlow],
) -> None:
    with path.open("w", encoding="utf-8") as fp:
        found = False
        for flow_index, flow in enumerate(flows, 1):
            matches = [
                xref for xref in flow.xrefs
                if xref.target.target == "Check 'Allow OEM Unlock'"
            ]
            if not matches:
                continue
            found = True
            fp.write(
                f"Flow #{flow_index:02d} score={flow.score} "
                f"range=0x{flow.start_address:016x}-0x{flow.end_address:016x}\n"
            )
            fp.write(f"  matched targets: {', '.join(flow.matched_targets)}\n")
            for xref in matches:
                fp.write(
                    f"  XREF 0x{xref.address:016x}: {xref.mnemonic} {xref.operands} "
                    f"-> 0x{xref.effective_address:016x}\n"
                )
                context_start = max(flow.start_index, xref.insn_index - 16)
                context_end = min(flow.end_index + 1, xref.insn_index + 17)
                for index in range(context_start, context_end):
                    insn = instructions[index]
                    marker = ">>" if index == xref.insn_index else "  "
                    fp.write(f"{marker} 0x{insn.address:016x}: {insn.mnemonic:<8} {insn.operands}\n")
                fp.write("\n")

        if not found:
            fp.write("No xrefs to Check 'Allow OEM Unlock' found.\n")


def write_frp_checker_reports(
    output_dir: Path,
    instructions: list[Instruction],
    checkers: list[FrpChecker],
    base: int,
) -> None:
    with (output_dir / "frp_checkers.json").open("w", encoding="utf-8") as fp:
        json.dump([frp_checker_to_dict(checker, base, instructions) for checker in checkers], fp, indent=2)

    with (output_dir / "frp_checker_report.txt").open("w", encoding="utf-8") as fp:
        if not checkers:
            fp.write("No FRP checker candidates found.\n")
            return

        for number, checker in enumerate(checkers, 1):
            flow = checker.flow
            fp.write(
                f"[{number:02d}] confidence={checker.confidence} "
                f"range=0x{flow.start_address:016x}-0x{flow.end_address:016x} "
                f"HxD=0x{hxd_offset_for_va(flow.start_address, base)}-0x{hxd_offset_for_va(flow.end_address, base)}\n"
            )
            fp.write(f"  targets: {', '.join(flow.matched_targets)}\n")
            fp.write("  evidence:\n")
            for item in checker.evidence:
                fp.write(f"    - {item}\n")

            if checker.callers:
                fp.write("  callers:\n")
                for caller_start, call_site in checker.callers:
                    fp.write(
                        f"    - caller 0x{caller_start:016x}, "
                        f"HxD={hxd_offset_for_va(caller_start, base)}, "
                        f"call site 0x{call_site:016x}, "
                        f"call_HxD={hxd_offset_for_va(call_site, base)}\n"
                    )
            else:
                fp.write("  callers: none found in current flow candidates\n")

            structural = frp_structural_instructions(instructions, checker, base)
            if structural:
                fp.write("  structural instructions:\n")
                for item in structural:
                    fp.write(
                        f"    - {item['role']}: {item['address']} "
                        f"off={item['file_offset']} HxD={item['hxd_offset']} "
                        f"raw={item['raw']}  {item['instruction']}\n"
                    )

            fp.write("  key instructions:\n")
            for index in range(flow.start_index, flow.end_index + 1):
                insn = instructions[index]
                interesting = (
                    "#0x100" in insn.operands
                    or "[sp, #0xff]" in insn.operands
                    or insn.mnemonic in {"cmp", "cset"}
                    or parse_call_target(insn) is not None
                    or any(xref.insn_index == index for xref in flow.xrefs)
                )
                if interesting:
                    fp.write(
                        f"    0x{insn.address:016x} "
                        f"off=0x{file_offset_for_va(insn.address, base):x} "
                        f"HxD={hxd_offset_for_va(insn.address, base)}: "
                        f"{insn.mnemonic:<8} {insn.operands}\n"
                    )
            fp.write("\n")

    frp_dir = output_dir / "frp_checkers"
    frp_dir.mkdir(parents=True, exist_ok=True)
    for number, checker in enumerate(checkers, 1):
        details_path = frp_dir / f"frp_checker_{number:02d}_details.json"
        with details_path.open("w", encoding="utf-8") as fp:
            json.dump(frp_checker_to_dict(checker, base, instructions), fp, indent=2)
        path = frp_dir / f"frp_checker_{number:02d}_conf_{checker.confidence}_0x{checker.flow.start_address:016x}.asm"
        write_flow_asm(path, instructions, checker.flow)


def write_key_validator_reports(
    output_dir: Path,
    instructions: list[Instruction],
    validators: list[KeyValidator],
    base: int,
) -> None:
    with (output_dir / "key_validators.json").open("w", encoding="utf-8") as fp:
        json.dump([key_validator_to_dict(validator, base, instructions) for validator in validators], fp, indent=2)

    with (output_dir / "key_validator_report.txt").open("w", encoding="utf-8") as fp:
        if not validators:
            fp.write("No KEY validator candidates found.\n")
            return

        for number, validator in enumerate(validators, 1):
            flow = validator.flow
            fp.write(
                f"[{number:02d}] confidence={validator.confidence} "
                f"range=0x{flow.start_address:016x}-0x{flow.end_address:016x} "
                f"HxD=0x{hxd_offset_for_va(flow.start_address, base)}-0x{hxd_offset_for_va(flow.end_address, base)}\n"
            )
            fp.write(f"  targets: {', '.join(flow.matched_targets)}\n")
            fp.write("  evidence:\n")
            for item in validator.evidence:
                fp.write(f"    - {item}\n")

            if validator.callers:
                fp.write("  callers:\n")
                for caller_start, call_site in validator.callers:
                    fp.write(
                        f"    - caller 0x{caller_start:016x}, "
                        f"HxD={hxd_offset_for_va(caller_start, base)}, "
                        f"call site 0x{call_site:016x}, "
                        f"call_HxD={hxd_offset_for_va(call_site, base)}\n"
                    )
            else:
                fp.write("  callers: none found in current flow candidates\n")

            if validator.failure_edges:
                fp.write("  failure edges:\n")
                for call_site, failure_target, branch in validator.failure_edges:
                    fp.write(
                        f"    - call 0x{call_site:016x}, {branch} -> "
                        f"0x{failure_target:016x} "
                        f"call_HxD={hxd_offset_for_va(call_site, base)} "
                        f"failure_HxD={hxd_offset_for_va(failure_target, base)} "
                        f"(Code validation failure path)\n"
                    )

            structural = key_validator_structural_instructions(instructions, validator, base)
            if structural:
                fp.write("  structural instructions:\n")
                for item in structural:
                    fp.write(
                        f"    - {item['role']}: {item['address']} "
                        f"off={item['file_offset']} HxD={item['hxd_offset']} "
                        f"raw={item['raw']}  {item['instruction']}\n"
                    )

            fp.write("  key instructions:\n")
            for index in range(flow.start_index, flow.end_index + 1):
                insn = instructions[index]
                interesting = (
                    insn.mnemonic in {"cmp", "cset", "ldrb", "ldur", "mov", "ret"}
                    or parse_call_target(insn) is not None
                    or any(xref.insn_index == index for xref in flow.xrefs)
                    or "#0x20" in insn.operands
                )
                if interesting:
                    fp.write(
                        f"    0x{insn.address:016x} "
                        f"off=0x{file_offset_for_va(insn.address, base):x} "
                        f"HxD={hxd_offset_for_va(insn.address, base)}: "
                        f"{insn.mnemonic:<8} {insn.operands}\n"
                    )
            fp.write("\n")

    key_dir = output_dir / "key_validators"
    key_dir.mkdir(parents=True, exist_ok=True)
    for number, validator in enumerate(validators, 1):
        details_path = key_dir / f"key_validator_{number:02d}_details.json"
        with details_path.open("w", encoding="utf-8") as fp:
            json.dump(key_validator_to_dict(validator, base, instructions), fp, indent=2)
        path = key_dir / f"key_validator_{number:02d}_conf_{validator.confidence}_0x{validator.flow.start_address:016x}.asm"
        write_flow_asm(path, instructions, validator.flow)


def write_erase_permission_reports(
    output_dir: Path,
    instructions: list[Instruction],
    checks: list[ErasePermissionCheck],
    base: int,
) -> None:
    with (output_dir / "erase_permission_checks.json").open("w", encoding="utf-8") as fp:
        json.dump([erase_permission_to_dict(check, base, instructions) for check in checks], fp, indent=2)

    with (output_dir / "erase_permission_report.txt").open("w", encoding="utf-8") as fp:
        if not checks:
            fp.write("No erase permission check candidates found.\n")
            return

        for number, check in enumerate(checks, 1):
            flow = check.flow
            fp.write(
                f"[{number:02d}] confidence={check.confidence} "
                f"range=0x{flow.start_address:016x}-0x{flow.end_address:016x} "
                f"HxD=0x{hxd_offset_for_va(flow.start_address, base)}-0x{hxd_offset_for_va(flow.end_address, base)}\n"
            )
            fp.write(f"  targets: {', '.join(flow.matched_targets)}\n")
            fp.write("  evidence:\n")
            for item in check.evidence:
                fp.write(f"    - {item}\n")

            if check.callers:
                fp.write("  callers:\n")
                for caller_start, call_site in check.callers:
                    fp.write(
                        f"    - caller 0x{caller_start:016x}, "
                        f"HxD={hxd_offset_for_va(caller_start, base)}, "
                        f"call site 0x{call_site:016x}, "
                        f"call_HxD={hxd_offset_for_va(call_site, base)}\n"
                    )
            else:
                fp.write("  callers: none found in current flow candidates\n")

            if check.name_checks:
                fp.write("  fixed-name checks:\n")
                for xref_address, name, call_target, branch_target in check.name_checks:
                    call_text = f"0x{call_target:016x} HxD={hxd_offset_for_va(call_target, base)}" if call_target else "none"
                    branch_text = (
                        f"0x{branch_target:016x} HxD={hxd_offset_for_va(branch_target, base)}"
                        if branch_target
                        else "none"
                    )
                    fp.write(
                        f"    - {name}: xref=0x{xref_address:016x} "
                        f"HxD={hxd_offset_for_va(xref_address, base)} "
                        f"compare_call={call_text} branch_target={branch_text}\n"
                    )

            if check.denied_edges:
                fp.write("  denied edges:\n")
                for branch_address, target, mnemonic in check.denied_edges:
                    fp.write(
                        f"    - {mnemonic} 0x{branch_address:016x} "
                        f"HxD={hxd_offset_for_va(branch_address, base)} -> "
                        f"0x{target:016x} HxD={hxd_offset_for_va(target, base)} "
                        f"(erase permission denied path)\n"
                    )

            structural = erase_permission_structural_instructions(instructions, check, base)
            if structural:
                fp.write("  structural instructions:\n")
                for item in structural:
                    fp.write(
                        f"    - {item['role']}: {item['address']} "
                        f"off={item['file_offset']} HxD={item['hxd_offset']} "
                        f"raw={item['raw']}  {item['instruction']}\n"
                    )

            fp.write("  key instructions:\n")
            for index in range(flow.start_index, flow.end_index + 1):
                insn = instructions[index]
                interesting = (
                    parse_call_target(insn) is not None
                    or is_conditional_branch(insn)
                    or insn.mnemonic in {"ldr", "add", "mov", "ret", "cmn", "cmp"}
                    or any(xref.insn_index == index for xref in flow.xrefs)
                )
                if interesting:
                    fp.write(
                        f"    0x{insn.address:016x} "
                        f"off=0x{file_offset_for_va(insn.address, base):x} "
                        f"HxD={hxd_offset_for_va(insn.address, base)}: "
                        f"{insn.mnemonic:<8} {insn.operands}\n"
                    )
            fp.write("\n")

    check_dir = output_dir / "erase_permission_checks"
    check_dir.mkdir(parents=True, exist_ok=True)
    for number, check in enumerate(checks, 1):
        details_path = check_dir / f"erase_permission_{number:02d}_details.json"
        with details_path.open("w", encoding="utf-8") as fp:
            json.dump(erase_permission_to_dict(check, base, instructions), fp, indent=2)
        path = check_dir / f"erase_permission_{number:02d}_conf_{check.confidence}_0x{check.flow.start_address:016x}.asm"
        write_flow_asm(path, instructions, check.flow)


def find_instruction_index_by_address(instructions: list[Instruction], address: int | None) -> int | None:
    if address is None:
        return None
    for index, insn in enumerate(instructions):
        if insn.address == address:
            return index
    return None


def partition_string_inventory(
    operations: list[PartitionEraseOperation],
    base: int,
) -> dict[str, list[dict[str, object]]]:
    inventory: dict[str, list[dict[str, object]]] = {}
    for partition in sorted(TARGET_ERASE_PARTITIONS):
        keyed_entries: dict[tuple[int, str, str], dict[str, object]] = {}
        for operation in operations:
            if operation.partition != partition:
                continue

            key = (operation.string_address, operation.string_text, "partition_arg")
            keyed_entries[key] = {
                "partition": partition,
                "address": f"0x{operation.string_address:016x}",
                "file_offset": f"0x{file_offset_for_va(operation.string_address, base):x}",
                "hxd_offset": hxd_offset_for_va(operation.string_address, base),
                "text": operation.string_text,
                "reference_mode": operation.reference_mode,
                "role": "partition_arg",
                "operation": operation.operation,
                "xref_address": f"0x{operation.xref_address:016x}",
                "xref_instruction": f"{operation.xref_mnemonic} {operation.xref_operands}".strip(),
                "xref_via": operation.xref_via,
            }

            if operation.failure_message_address is not None and operation.failure_message is not None:
                failure_key = (
                    operation.failure_message_address,
                    operation.failure_message,
                    "failure_message",
                )
                keyed_entries[failure_key] = {
                    "partition": partition,
                    "address": f"0x{operation.failure_message_address:016x}",
                    "file_offset": f"0x{file_offset_for_va(operation.failure_message_address, base):x}",
                    "hxd_offset": hxd_offset_for_va(operation.failure_message_address, base),
                    "text": operation.failure_message,
                    "reference_mode": classify_target_text(partition, operation.failure_message),
                    "role": "failure_message",
                    "operation": operation.operation,
                    "xref_address": f"0x{operation.xref_address:016x}",
                    "xref_instruction": None,
                    "xref_via": None,
                }

        entries = sorted(
            keyed_entries.values(),
            key=lambda entry: (entry["address"], entry["role"], entry["operation"]),
        )
        inventory[partition] = entries
    return inventory


def write_partition_operation_asm(
    path: Path,
    instructions: list[Instruction],
    operation: PartitionEraseOperation,
    base: int,
    context: int = 24,
) -> None:
    call_index = find_instruction_index_by_address(instructions, operation.call_site)
    xref_index = find_instruction_index_by_address(instructions, operation.xref_address)
    center_index = call_index if call_index is not None else xref_index

    with path.open("w", encoding="utf-8") as fp:
        fp.write(f"; partition: {operation.partition}\n")
        fp.write(f"; operation: {operation.operation}\n")
        fp.write(
            f"; flow start: 0x{operation.flow_start:016x} "
            f"off=0x{file_offset_for_va(operation.flow_start, base):x} "
            f"HxD={hxd_offset_for_va(operation.flow_start, base)}\n"
        )
        fp.write(
            f"; string VA: 0x{operation.string_address:016x} "
            f"off=0x{file_offset_for_va(operation.string_address, base):x} "
            f"HxD={hxd_offset_for_va(operation.string_address, base)}\n"
        )
        fp.write(f"; string text: {operation.string_text!r}\n")
        fp.write(f"; reference mode: {operation.reference_mode}\n")
        fp.write(
            f"; xref: 0x{operation.xref_address:016x} "
            f"off=0x{file_offset_for_va(operation.xref_address, base):x} "
            f"HxD={hxd_offset_for_va(operation.xref_address, base)}\n"
        )
        fp.write(f"; xref instruction: {operation.xref_mnemonic} {operation.xref_operands}\n")
        fp.write(f"; xref via: {operation.xref_via}\n")
        if operation.call_site is not None:
            fp.write(
                f"; call site: 0x{operation.call_site:016x} "
                f"off=0x{file_offset_for_va(operation.call_site, base):x} "
                f"HxD={hxd_offset_for_va(operation.call_site, base)}\n"
            )
        if operation.call_target is not None:
            fp.write(
                f"; call target: 0x{operation.call_target:016x} "
                f"off=0x{file_offset_for_va(operation.call_target, base):x} "
                f"HxD={hxd_offset_for_va(operation.call_target, base)}\n"
            )
        if operation.result_check_address is not None:
            fp.write(
                f"; result check: 0x{operation.result_check_address:016x} "
                f"off=0x{file_offset_for_va(operation.result_check_address, base):x} "
                f"HxD={hxd_offset_for_va(operation.result_check_address, base)}\n"
            )
        if operation.failure_target is not None:
            fp.write(
                f"; failure target: 0x{operation.failure_target:016x} "
                f"off=0x{file_offset_for_va(operation.failure_target, base):x} "
                f"HxD={hxd_offset_for_va(operation.failure_target, base)}\n"
            )
        if operation.failure_message:
            fp.write(
                f"; failure message: 0x{operation.failure_message_address:016x} "
                f"{operation.failure_message!r}\n"
            )
        fp.write("\n")

        if center_index is None:
            fp.write("; No instruction context found for this operation.\n")
            return

        start = max(0, center_index - context)
        end = min(len(instructions), center_index + context + 1)
        for index in range(start, end):
            insn = instructions[index]
            markers: list[str] = []
            if insn.address == operation.xref_address:
                markers.append("XREF")
            if insn.address == operation.call_site:
                markers.append("CALL")
            if insn.address == operation.result_check_address:
                markers.append("CHECK")
            if insn.address == operation.failure_target:
                markers.append("FAIL")
            prefix = ">>" if markers else "  "
            marker_text = f" ; {','.join(markers)}" if markers else ""
            fp.write(f"{prefix} 0x{insn.address:016x}: {insn.mnemonic:<8} {insn.operands}{marker_text}\n")


def write_partition_erase_reports(
    output_dir: Path,
    instructions: list[Instruction],
    operations: list[PartitionEraseOperation],
    base: int,
) -> None:
    with (output_dir / "partition_erase_operations.json").open("w", encoding="utf-8") as fp:
        json.dump([partition_erase_to_dict(operation, base) for operation in operations], fp, indent=2)

    inventory = partition_string_inventory(operations, base)
    with (output_dir / "partition_string_locations.json").open("w", encoding="utf-8") as fp:
        json.dump(inventory, fp, indent=2)

    erase_dir = output_dir / "partition_erases"
    erase_dir.mkdir(parents=True, exist_ok=True)
    with (erase_dir / "index.json").open("w", encoding="utf-8") as fp:
        json.dump(
            {
                "strings": inventory,
                "operations": [partition_erase_to_dict(operation, base) for operation in operations],
            },
            fp,
            indent=2,
        )

    with (output_dir / "partition_erase_report.txt").open("w", encoding="utf-8") as fp:
        fp.write("Unlock-flow partition string locations\n")
        fp.write("======================================\n")
        for partition in sorted(TARGET_ERASE_PARTITIONS):
            entries = inventory.get(partition, [])
            direct_entries = [entry for entry in entries if entry["reference_mode"] == "direct_string"]
            embedded_entries = [entry for entry in entries if entry["reference_mode"] == "embedded_string"]
            fp.write(f"\nPartition: {partition}\n")
            if not entries:
                fp.write("  found: no\n")
            else:
                fp.write(f"  found: yes ({len(direct_entries)} direct, {len(embedded_entries)} embedded)\n")
                for entry in entries:
                    fp.write(
                        f"  - {entry['reference_mode']} VA={entry['address']} "
                        f"off={entry['file_offset']} HxD={entry['hxd_offset']} "
                        f"text={entry['text']!r}\n"
                    )

        fp.write("\nPartition erase operations\n")
        fp.write("==========================\n")
        if not operations:
            fp.write("No partition erase operations found in unlock flow.\n")
        else:
            by_flow: dict[int, list[PartitionEraseOperation]] = {}
            for operation in operations:
                by_flow.setdefault(operation.flow_start, []).append(operation)

            for flow_start, flow_operations in by_flow.items():
                fp.write(f"Flow 0x{flow_start:016x}\n")
                fp.write("=" * 34 + "\n")

                for partition in sorted(TARGET_ERASE_PARTITIONS):
                    part_ops = [op for op in flow_operations if op.partition == partition]
                    if not part_ops:
                        continue

                    fp.write(f"\nPartition: {partition}\n")
                    for operation in part_ops:
                        fp.write(
                            f"  - {operation.operation.upper()} xref=0x{operation.xref_address:016x} "
                            f"off=0x{file_offset_for_va(operation.xref_address, base):x} "
                            f"HxD={hxd_offset_for_va(operation.xref_address, base)} "
                            f"string=0x{operation.string_address:016x} "
                            f"string_off=0x{file_offset_for_va(operation.string_address, base):x} "
                            f"string_HxD={hxd_offset_for_va(operation.string_address, base)} "
                            f"mode={operation.reference_mode}\n"
                        )
                        fp.write(f"    string text: {operation.string_text!r}\n")
                        if operation.call_site is not None:
                            fp.write(
                                f"    call: 0x{operation.call_site:016x} -> "
                                f"0x{operation.call_target:016x}\n"
                            )
                        if operation.result_check_address is not None:
                            fp.write(f"    result check: 0x{operation.result_check_address:016x}\n")
                        if operation.failure_target is not None:
                            fp.write(f"    failure branch: 0x{operation.failure_target:016x}\n")
                        if operation.failure_message:
                            fp.write(
                                f"    failure message: 0x{operation.failure_message_address:016x} "
                                f"{operation.failure_message!r}\n"
                            )

                        if operation.call_site is not None:
                            call_index = next(
                                (
                                    index for index, insn in enumerate(instructions)
                                    if insn.address == operation.call_site
                                ),
                                None,
                            )
                            if call_index is not None:
                                fp.write("    context:\n")
                                for index in range(max(0, call_index - 4), min(len(instructions), call_index + 5)):
                                    insn = instructions[index]
                                    marker = ">>" if insn.address == operation.call_site else "  "
                                    fp.write(f"    {marker} 0x{insn.address:016x}: {insn.mnemonic:<8} {insn.operands}\n")

        fp.write("\nReference modes\n")
        fp.write("---------------\n")
        fp.write("direct_string: the partition name is referenced as a direct C-string via ADRP/ADD.\n")
        fp.write("embedded_string: the target appears inside a longer diagnostic string.\n")
        fp.write("address_only: a target was matched by address but not as direct text.\n")

    with (erase_dir / "strings.txt").open("w", encoding="utf-8") as fp:
        for partition in sorted(TARGET_ERASE_PARTITIONS):
            fp.write(f"{partition}\n")
            fp.write("-" * len(partition) + "\n")
            entries = inventory.get(partition, [])
            if not entries:
                fp.write("not found\n\n")
                continue
            for entry in entries:
                fp.write(
                    f"{entry['reference_mode']}  VA={entry['address']}  "
                    f"off={entry['file_offset']}  HxD={entry['hxd_offset']}  "
                    f"text={entry['text']!r}\n"
                )
            fp.write("\n")

    for partition in sorted(TARGET_ERASE_PARTITIONS):
        partition_dir = erase_dir / partition
        partition_dir.mkdir(parents=True, exist_ok=True)
        partition_operations = [operation for operation in operations if operation.partition == partition]
        with (partition_dir / "strings.json").open("w", encoding="utf-8") as fp:
            json.dump(inventory.get(partition, []), fp, indent=2)
        with (partition_dir / "operations.json").open("w", encoding="utf-8") as fp:
            json.dump([partition_erase_to_dict(operation, base) for operation in partition_operations], fp, indent=2)
        with (partition_dir / "README.txt").open("w", encoding="utf-8") as fp:
            entries = inventory.get(partition, [])
            direct_entries = [entry for entry in entries if entry["reference_mode"] == "direct_string"]
            embedded_entries = [entry for entry in entries if entry["reference_mode"] == "embedded_string"]
            fp.write(f"Partition: {partition}\n")
            fp.write(f"String found: {'yes' if entries else 'no'}\n")
            fp.write(f"Direct strings: {len(direct_entries)}\n")
            fp.write(f"Embedded strings: {len(embedded_entries)}\n")
            fp.write(f"Operations in analyzed flows: {len(partition_operations)}\n\n")
            for entry in entries:
                fp.write(
                    f"- {entry['reference_mode']} VA={entry['address']} "
                    f"off={entry['file_offset']} HxD={entry['hxd_offset']} "
                    f"text={entry['text']!r}\n"
                )
            if partition_operations:
                fp.write("\nOperations:\n")
                for operation in partition_operations:
                    call_site = f"0x{operation.call_site:016x}" if operation.call_site is not None else "None"
                    call_target = f"0x{operation.call_target:016x}" if operation.call_target is not None else "None"
                    fp.write(
                        f"- {operation.operation} xref=0x{operation.xref_address:016x} "
                        f"call={call_site} "
                        f"target={call_target} "
                        f"mode={operation.reference_mode}\n"
                    )

        for number, operation in enumerate(partition_operations, 1):
            call_site = f"0x{operation.call_site:016x}" if operation.call_site is not None else "no_call"
            write_partition_operation_asm(
                partition_dir
                / (
                    f"{number:02d}_{operation.operation}_"
                    f"0x{operation.xref_address:016x}_call_{call_site}.asm"
                ),
                instructions,
                operation,
                base,
            )


def write_flow_overview_mermaid(path: Path, flows: list[FunctionFlow], limit: int = 8) -> None:
    with path.open("w", encoding="utf-8") as fp:
        fp.write("flowchart LR\n")
        if not flows:
            fp.write('  empty["No flow candidates"]\n')
            return

        target_ids: dict[str, str] = {}
        for flow_index, flow in enumerate(flows[:limit], 1):
            flow_id = f"F{flow_index}"
            fp.write(
                f'  {flow_id}["#{flow_index} score {flow.score}<br/>'
                f'0x{flow.start_address:016x}<br/>xrefs {len(flow.xrefs)} calls {len(flow.calls)}"]\n'
            )
            for target in flow.matched_targets:
                if target not in target_ids:
                    target_id = f"T{len(target_ids) + 1}"
                    target_ids[target] = target_id
                    fp.write(f'  {target_id}["{short_label(target, 48)}"]\n')
                fp.write(f"  {flow_id} --> {target_ids[target]}\n")


def build_basic_blocks(
    instructions: list[Instruction],
    flow: FunctionFlow,
) -> tuple[list[tuple[int, int]], dict[int, list[tuple[int, str, int]]]]:
    address_to_index = {
        instructions[index].address: index
        for index in range(flow.start_index, flow.end_index + 1)
    }
    starts = {flow.start_index}

    for index in range(flow.start_index, flow.end_index + 1):
        insn = instructions[index]
        if not is_branch_instruction(insn):
            continue
        target = parse_branch_target(insn.operands)
        if target in address_to_index:
            starts.add(address_to_index[target])
        if is_conditional_branch(insn) and index + 1 <= flow.end_index:
            starts.add(index + 1)
        elif insn.mnemonic == "b" and index + 1 <= flow.end_index:
            starts.add(index + 1)

    sorted_starts = sorted(starts)
    blocks: list[tuple[int, int]] = []
    for position, start in enumerate(sorted_starts):
        if position + 1 < len(sorted_starts):
            end = min(sorted_starts[position + 1] - 1, flow.end_index)
        else:
            end = flow.end_index
        if start <= end:
            blocks.append((start, end))

    block_for_index: dict[int, int] = {}
    for block_id, (start, end) in enumerate(blocks):
        for index in range(start, end + 1):
            block_for_index[index] = block_id

    edges: dict[int, list[tuple[int, str, int]]] = {idx: [] for idx in range(len(blocks))}
    for block_id, (start, end) in enumerate(blocks):
        terminal = instructions[end]
        if is_branch_instruction(terminal):
            target = parse_branch_target(terminal.operands)
            if target in address_to_index:
                target_block = block_for_index[address_to_index[target]]
                edges[block_id].append((target_block, terminal.mnemonic, terminal.address))
            if is_conditional_branch(terminal) and block_id + 1 < len(blocks):
                edges[block_id].append((block_id + 1, "fallthrough", terminal.address))
        elif terminal.mnemonic != "ret" and block_id + 1 < len(blocks):
            edges[block_id].append((block_id + 1, "next", terminal.address))

    return blocks, edges


def write_best_flow_cfg(
    output_dir: Path,
    instructions: list[Instruction],
    flow: FunctionFlow | None,
) -> None:
    mermaid_path = output_dir / "best_flow_cfg.mmd"
    dot_path = output_dir / "best_flow_cfg.dot"

    if flow is None:
        mermaid_path.write_text('flowchart TD\n  empty["No best flow"]\n', encoding="utf-8")
        dot_path.write_text('digraph best_flow { empty [label="No best flow"]; }\n', encoding="utf-8")
        return

    blocks, edges = build_basic_blocks(instructions, flow)
    xrefs_by_block: dict[int, list[str]] = {}
    for block_id, (start, end) in enumerate(blocks):
        for xref in flow.xrefs:
            if start <= xref.insn_index <= end:
                xrefs_by_block.setdefault(block_id, []).append(xref.target.target)

    with mermaid_path.open("w", encoding="utf-8") as fp:
        fp.write("flowchart TD\n")
        for block_id, (start, end) in enumerate(blocks):
            start_addr = instructions[start].address
            end_addr = instructions[end].address
            labels = sorted(set(xrefs_by_block.get(block_id, [])))
            extra = "<br/>" + "<br/>".join(short_label(label, 42) for label in labels) if labels else ""
            fp.write(f'  B{block_id}["0x{start_addr:016x}<br/>- 0x{end_addr:016x}{extra}"]\n')
        for source, block_edges in edges.items():
            for target, label, _ in block_edges:
                fp.write(f'  B{source} -->|"{label}"| B{target}\n')

    with dot_path.open("w", encoding="utf-8") as fp:
        fp.write("digraph best_flow {\n")
        fp.write("  rankdir=TB;\n")
        for block_id, (start, end) in enumerate(blocks):
            start_addr = instructions[start].address
            end_addr = instructions[end].address
            labels = sorted(set(xrefs_by_block.get(block_id, [])))
            extra = "\\n" + "\\n".join(short_label(label, 42) for label in labels) if labels else ""
            fp.write(f'  B{block_id} [label="0x{start_addr:016x}\\n- 0x{end_addr:016x}{extra}"];\n')
        for source, block_edges in edges.items():
            for target, label, address in block_edges:
                fp.write(f'  B{source} -> B{target} [label="{label} @ 0x{address:016x}"];\n')
        fp.write("}\n")


def write_flow_diagram_html(output_dir: Path) -> None:
    overview = (output_dir / "flow_overview.mmd").read_text(encoding="utf-8")
    cfg = (output_dir / "best_flow_cfg.mmd").read_text(encoding="utf-8")
    frp = (output_dir / "frp_unlock_relation.mmd").read_text(encoding="utf-8")
    key = (output_dir / "key_validation_relation.mmd").read_text(encoding="utf-8")
    erase_permission = (output_dir / "erase_permission_relation.mmd").read_text(encoding="utf-8")
    erase = (output_dir / "partition_erase_relation.mmd").read_text(encoding="utf-8")
    html = f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LK flow analysis</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; color: #111; }}
    h1, h2 {{ font-weight: 600; }}
    .diagram {{ margin: 20px 0 40px; overflow-x: auto; border: 1px solid #ddd; padding: 16px; }}
    pre {{ white-space: pre-wrap; }}
  </style>
  <script type="module">
    import mermaid from 'https://cdn.jsdelivr.net/npm/mermaid@11/dist/mermaid.esm.min.mjs';
    mermaid.initialize({{ startOnLoad: true, securityLevel: 'loose' }});
  </script>
</head>
<body>
  <h1>LK flow analysis</h1>
  <h2>Flow overview</h2>
  <div class="diagram"><pre class="mermaid">{overview}</pre></div>
  <h2>Best flow CFG</h2>
  <div class="diagram"><pre class="mermaid">{cfg}</pre></div>
  <h2>FRP unlock relation</h2>
  <div class="diagram"><pre class="mermaid">{frp}</pre></div>
  <h2>KEY validation relation</h2>
  <div class="diagram"><pre class="mermaid">{key}</pre></div>
  <h2>Erase permission relation</h2>
  <div class="diagram"><pre class="mermaid">{erase_permission}</pre></div>
  <h2>Partition erase relation</h2>
  <div class="diagram"><pre class="mermaid">{erase}</pre></div>
</body>
</html>
"""
    (output_dir / "flow_diagram.html").write_text(html, encoding="utf-8")


def write_frp_unlock_relation_mermaid(
    path: Path,
    flows: list[FunctionFlow],
    frp_checkers: list[FrpChecker],
) -> None:
    with path.open("w", encoding="utf-8") as fp:
        fp.write("flowchart TD\n")
        if not frp_checkers:
            fp.write('  empty["No FRP checker found"]\n')
            return

        checker = frp_checkers[0]
        caller_start = checker.callers[0][0] if checker.callers else (flows[0].start_address if flows else 0)
        call_site = checker.callers[0][1] if checker.callers else 0

        fp.write(f'  U["Unlock flow<br/>0x{caller_start:016x}"]\n')
        if call_site:
            fp.write(f'  C["BL call site<br/>0x{call_site:016x}"]\n')
            fp.write("  U --> C\n")
            fp.write("  C --> F\n")
        else:
            fp.write("  U --> F\n")
        fp.write(
            f'  F["FRP checker<br/>0x{checker.flow.start_address:016x}<br/>confidence {checker.confidence}"]\n'
        )
        fp.write('  P["Locate frp partition"]\n')
        fp.write('  R["Read last 0x100 bytes"]\n')
        fp.write('  B["Load [sp,#0xff]"]\n')
        fp.write('  Z["byte == 0"]\n')
        fp.write('  L["Return lock/apply rule"]\n')
        fp.write('  A["Return allowed/no message"]\n')
        fp.write("  F --> P --> R --> B --> Z\n")
        fp.write('  Z -->|"yes"| L\n')
        fp.write('  Z -->|"no"| A\n')


def write_key_validation_relation_mermaid(
    path: Path,
    flows: list[FunctionFlow],
    validators: list[KeyValidator],
) -> None:
    with path.open("w", encoding="utf-8") as fp:
        fp.write("flowchart TD\n")
        if not validators:
            fp.write('  empty["No KEY validator found"]\n')
            return

        validator = validators[0]
        caller_start = validator.callers[0][0] if validator.callers else (flows[0].start_address if flows else 0)
        call_site = validator.callers[0][1] if validator.callers else 0
        failure_target = validator.failure_edges[0][1] if validator.failure_edges else 0
        branch = validator.failure_edges[0][2] if validator.failure_edges else "branch"

        fp.write(f'  U["Unlock flow<br/>0x{caller_start:016x}"]\n')
        if call_site:
            fp.write(f'  C["KEY validator call<br/>0x{call_site:016x}"]\n')
            fp.write("  U --> C --> K\n")
        else:
            fp.write("  U --> K\n")
        fp.write(
            f'  K["KEY validator<br/>0x{validator.flow.start_address:016x}<br/>confidence {validator.confidence}"]\n'
        )
        fp.write('  H["Hash key data"]\n')
        fp.write('  B["Compare hash bytes"]\n')
        fp.write('  R["Return w20 as w0"]\n')
        fp.write('  T["Caller tests w0 bit 0"]\n')
        fp.write('  OK["Continue unlock flow"]\n')
        fp.write('  FAIL["Code validation failure"]\n')
        fp.write("  K --> H --> B --> R --> T\n")
        fp.write('  T -->|"valid"| OK\n')
        if failure_target:
            fp.write(f'  T -->|"{branch} -> 0x{failure_target:016x}"| FAIL\n')
        else:
            fp.write('  T -->|"invalid"| FAIL\n')


def write_partition_erase_relation_mermaid(
    path: Path,
    operations: list[PartitionEraseOperation],
) -> None:
    with path.open("w", encoding="utf-8") as fp:
        fp.write("flowchart TD\n")
        erase_ops = [op for op in operations if op.operation == "erase"]
        if not erase_ops:
            fp.write('  empty["No partition erase operations found"]\n')
            return

        by_flow: dict[int, list[PartitionEraseOperation]] = {}
        for operation in erase_ops:
            by_flow.setdefault(operation.flow_start, []).append(operation)

        def group_score(group: list[PartitionEraseOperation]) -> tuple[int, int, int]:
            partitions = {operation.partition for operation in group}
            first_xref = min(operation.xref_address for operation in group)
            return (len(partitions & TARGET_ERASE_PARTITIONS), len(group), -first_xref)

        selected_flow, selected_ops = max(by_flow.items(), key=lambda item: group_score(item[1]))
        fp.write(f'  U["Unlock flow<br/>0x{selected_flow:016x}"]\n')
        for index, operation in enumerate(selected_ops, 1):
            node = f"E{index}"
            fp.write(
                f'  {node}["{operation.partition}<br/>xref 0x{operation.xref_address:016x}<br/>'
                f'call 0x{operation.call_site:016x}"]\n'
            )
            fp.write(f"  U --> {node}\n")
            if operation.failure_message:
                fail = f"F{index}"
                fp.write(f'  {fail}["failure<br/>{short_label(operation.failure_message, 48)}"]\n')
                fp.write(f'  {node} -->|error| {fail}\n')


def write_erase_permission_relation_mermaid(
    path: Path,
    checks: list[ErasePermissionCheck],
) -> None:
    with path.open("w", encoding="utf-8") as fp:
        fp.write("flowchart TD\n")
        if not checks:
            fp.write('  empty["No erase permission check found"]\n')
            return

        check = checks[0]
        fp.write(
            f'  C["cmd_erase_permission_check<br/>0x{check.flow.start_address:016x}<br/>'
            f'confidence {check.confidence}"]\n'
        )
        fp.write('  A["Read fastboot argument<br/>[cmd + 0x10] + 1"]\n')
        fp.write('  N["Fixed name checks"]\n')
        for index, (_, name, _, _) in enumerate(check.name_checks, 1):
            node = f"N{index}"
            fp.write(f'  {node}["{short_label(name, 32)}"]\n')
            fp.write(f"  N --> {node}\n")
        fp.write('  G["Permission gate / partition table attribute"]\n')
        fp.write('  OK["Proceed erase"]\n')
        fp.write('  DENY["erase permission denied"]\n')
        fp.write('  INV["Invalid partition name"]\n')
        fp.write("  C --> A --> N --> G\n")
        fp.write('  G -->|"allowed"| OK\n')
        fp.write('  G -->|"denied"| DENY\n')
        fp.write('  G -->|"not found"| INV\n')


def write_serialno_runtime_reports(output_dir: Path, serialno_runtime: dict[str, object] | None) -> None:
    with (output_dir / "serialno_runtime.json").open("w", encoding="utf-8") as fp:
        json.dump(serialno_runtime or {}, fp, indent=2)

    with (output_dir / "serialno_runtime.txt").open("w", encoding="utf-8") as fp:
        fp.write("Serialno runtime source analysis\n")
        fp.write("================================\n\n")
        fp.write("Mode: analysis-only; no runtime patch is generated.\n\n")
        if not serialno_runtime:
            fp.write("No compatible serialno/barcode fallback chain was detected.\n")
            return

        fp.write(f"Confidence : {serialno_runtime.get('confidence')}\n")
        fp.write(f"Function   : {serialno_runtime.get('hw_get_serialno_string')}\n")
        fp.write(f"HxD        : {serialno_runtime.get('hw_get_serialno_string_hxd_offset')}\n")
        fp.write(f"Generic    : {serialno_runtime.get('generic_prop_get_string')}\n")
        fp.write(f"Generic HxD: {serialno_runtime.get('generic_prop_get_string_hxd_offset')}\n\n")

        fp.write("String xrefs\n")
        fp.write("------------\n")
        for xref in serialno_runtime.get("xrefs", []):
            if not isinstance(xref, dict):
                continue
            fp.write(
                f"  {xref.get('target')}: xref={xref.get('xref_address')} "
                f"HxD={xref.get('xref_hxd_offset')} string={xref.get('string')!r}\n"
            )

        fp.write("\nCalls\n")
        fp.write("-----\n")
        for call in serialno_runtime.get("calls", []):
            if not isinstance(call, dict):
                continue
            fp.write(
                f"  {call.get('site')} HxD={call.get('site_hxd_offset')} -> "
                f"{call.get('target')} HxD={call.get('target_hxd_offset')}\n"
            )

        fp.write("\nCache candidates\n")
        fp.write("----------------\n")
        candidates = serialno_runtime.get("cache_candidates", [])
        if not candidates:
            fp.write("  No read/write global cache candidate detected.\n")
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            fp.write(
                f"  function={candidate.get('function')} HxD={candidate.get('function_hxd_offset')} "
                f"cache={candidate.get('cache_address')} "
                f"conditional_after_read={candidate.get('has_conditional_after_read')}\n"
            )
            for ref in candidate.get("references", []):
                if not isinstance(ref, dict):
                    continue
                fp.write(
                    f"    {ref.get('kind')}: {ref.get('address')} "
                    f"HxD={ref.get('hxd_offset')} {ref.get('instruction')}\n"
                )


def write_summary(
    path: Path,
    source: Path,
    source_kind: str,
    data: bytes,
    base: int,
    architecture: str,
    instructions: list[Instruction],
    strings: list[StringHit],
    xrefs: list[XrefHit],
    flows: list[FunctionFlow],
    frp_checkers: list[FrpChecker],
    key_validators: list[KeyValidator],
    erase_permission_checks: list[ErasePermissionCheck],
    erase_operations: list[PartitionEraseOperation],
) -> None:
    with path.open("w", encoding="utf-8") as fp:
        fp.write("LK static analysis summary\n")
        fp.write("==========================\n\n")
        fp.write(f"Source       : {source}\n")
        fp.write(f"Input type   : {source_kind}\n")
        fp.write(f"LK base      : 0x{base:016x}\n")
        fp.write(f"LK size      : {len(data)} bytes\n")
        fp.write(f"LK VA range  : 0x{base:016x}-0x{base + len(data) - 1:016x}\n")
        fp.write(f"Architecture : {architecture}\n")
        fp.write(f"Instructions : {len(instructions)}\n")
        fp.write(f"String hits  : {len(strings)}\n")
        fp.write(f"String xrefs : {len(xrefs)}\n\n")
        fp.write(f"Flow candidates: {len(flows)}\n")
        if flows:
            fp.write(
                f"Best flow    : 0x{flows[0].start_address:016x}-0x{flows[0].end_address:016x} "
                f"(score {flows[0].score})\n"
            )
        fp.write(f"FRP checkers : {len(frp_checkers)}\n")
        if frp_checkers:
            fp.write(
                f"Best FRP     : 0x{frp_checkers[0].flow.start_address:016x}-"
                f"0x{frp_checkers[0].flow.end_address:016x} "
                f"(confidence {frp_checkers[0].confidence})\n"
            )
        fp.write(f"KEY validators: {len(key_validators)}\n")
        if key_validators:
            fp.write(
                f"Best KEY     : 0x{key_validators[0].flow.start_address:016x}-"
                f"0x{key_validators[0].flow.end_address:016x} "
                f"(confidence {key_validators[0].confidence})\n"
            )
        fp.write(f"Erase permission checks: {len(erase_permission_checks)}\n")
        if erase_permission_checks:
            fp.write(
                f"Best erase permission: 0x{erase_permission_checks[0].flow.start_address:016x}-"
                f"0x{erase_permission_checks[0].flow.end_address:016x} "
                f"(confidence {erase_permission_checks[0].confidence})\n"
            )
        erase_count = sum(1 for operation in erase_operations if operation.operation == "erase")
        fp.write(f"Partition erase ops: {erase_count}\n")
        fp.write("\n")

        fp.write("Address mapping\n")
        fp.write("---------------\n")
        fp.write("  file_offset = virtual_address - LK base\n")
        fp.write("  virtual_address = LK base + file_offset\n\n")
        fp.write("  HxD/File offset values are relative to the extracted lk.bin written in the output folder.\n")
        fp.write("  If you open that lk.bin in HxD, use the HxD offset directly with Go to / Ctrl+G.\n\n")

        fp.write("Interesting xrefs\n")
        fp.write("-----------------\n")
        if not xrefs:
            fp.write("  No xrefs found with the current target strings.\n")
        for xref in xrefs:
            fp.write(
                f"  0x{xref.address:016x} -> 0x{xref.effective_address:016x} "
                f"{xref.target.target!r} [{xref.via}]\n"
            )

        fp.write("\nTop flow candidates\n")
        fp.write("-------------------\n")
        if not flows:
            fp.write("  No flow candidates found.\n")
        for index, flow in enumerate(flows[:10], 1):
            fp.write(
                f"  #{index:02d} score={flow.score} "
                f"0x{flow.start_address:016x}-0x{flow.end_address:016x} "
                f"xrefs={len(flow.xrefs)} calls={len(flow.calls)}\n"
            )
            fp.write(f"      targets: {', '.join(flow.matched_targets)}\n")

        fp.write("\nFRP checker candidates\n")
        fp.write("----------------------\n")
        if not frp_checkers:
            fp.write("  No FRP checker candidates found.\n")
        for index, checker in enumerate(frp_checkers[:5], 1):
            fp.write(
                f"  #{index:02d} confidence={checker.confidence} "
                f"0x{checker.flow.start_address:016x}-0x{checker.flow.end_address:016x}\n"
            )
            fp.write(f"      evidence: {', '.join(checker.evidence)}\n")
            if checker.callers:
                fp.write(
                    "      callers: "
                    + ", ".join(
                        f"0x{caller:016x}@0x{site:016x}"
                        for caller, site in checker.callers
                    )
                    + "\n"
                )

        fp.write("\nKEY validator candidates\n")
        fp.write("------------------------\n")
        if not key_validators:
            fp.write("  No KEY validator candidates found.\n")
        for index, validator in enumerate(key_validators[:5], 1):
            fp.write(
                f"  #{index:02d} confidence={validator.confidence} "
                f"0x{validator.flow.start_address:016x}-0x{validator.flow.end_address:016x}\n"
            )
            fp.write(f"      evidence: {', '.join(validator.evidence)}\n")
            if validator.callers:
                fp.write(
                    "      callers: "
                    + ", ".join(
                        f"0x{caller:016x}@0x{site:016x}"
                        for caller, site in validator.callers
                    )
                    + "\n"
                )

        fp.write("\nErase permission candidates\n")
        fp.write("---------------------------\n")
        if not erase_permission_checks:
            fp.write("  No erase permission check candidates found.\n")
        for index, check in enumerate(erase_permission_checks[:5], 1):
            fp.write(
                f"  #{index:02d} confidence={check.confidence} "
                f"0x{check.flow.start_address:016x}-0x{check.flow.end_address:016x}\n"
            )
            fp.write(f"      evidence: {', '.join(check.evidence)}\n")
            if check.name_checks:
                fp.write(
                    "      fixed names: "
                    + ", ".join(
                        f"{name}@0x{xref_address:016x}"
                        for xref_address, name, _, _ in check.name_checks
                    )
                    + "\n"
                )

        fp.write("\nPartition erase operations\n")
        fp.write("--------------------------\n")
        erase_ops = [operation for operation in erase_operations if operation.operation == "erase"]
        if not erase_ops:
            fp.write("  No partition erase operations found.\n")
        for operation in erase_ops[:20]:
            fp.write(
                f"  {operation.partition}: xref=0x{operation.xref_address:016x} "
                f"call=0x{operation.call_site:016x}->0x{operation.call_target:016x} "
                f"mode={operation.reference_mode}\n"
            )
            if operation.failure_message:
                fp.write(f"      failure: {operation.failure_message!r}\n")
            if validator.failure_edges:
                fp.write(
                    "      failure edges: "
                    + ", ".join(
                        f"0x{site:016x}->{branch}->0x{target:016x}"
                        for site, target, branch in validator.failure_edges
                    )
                    + "\n"
                )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Desensambla la subparticion lk y busca strings/xrefs utiles para analizar cmd_oem_unlock.",
    )
    parser.add_argument(
        "image",
        type=Path,
        nargs="?",
        default=Path("lk.img"),
        help="Imagen LK/LKS contenedora. Por defecto: lk.img",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=Path,
        default=Path("lk_analysis"),
        help="Directorio de salida. Por defecto: lk_analysis",
    )
    parser.add_argument(
        "--base",
        type=parse_int,
        help="Base virtual si el input es un lk.bin ya extraido.",
    )
    parser.add_argument(
        "--target",
        action="append",
        default=[],
        help="String adicional a buscar. Puede repetirse.",
    )
    parser.add_argument(
        "--only-target",
        action="store_true",
        help="Usa solo las strings pasadas con --target, sin las defaults.",
    )
    parser.add_argument(
        "--context",
        type=int,
        default=12,
        help="Instrucciones de contexto alrededor de cada xref. Por defecto: 12",
    )
    parser.add_argument(
        "--no-full-disasm",
        action="store_true",
        help="No escribe el desensamblado completo; solo resumen, strings, xrefs y candidatos.",
    )
    return parser


def main() -> int:
    args = build_parser().parse_args()

    if not args.image.is_file():
        print(f"Error: no existe el archivo: {args.image}", file=sys.stderr)
        return 2

    targets = args.target if args.only_target else [*DEFAULT_TARGETS, *args.target]
    if not targets:
        print("Error: no hay strings objetivo. Usa --target.", file=sys.stderr)
        return 2

    try:
        data, base, source_kind = load_lk_payload(args.image, args.base)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    args.output_dir.mkdir(parents=True, exist_ok=True)
    (args.output_dir / "lk.bin").write_bytes(data)

    strings = find_targets(data, base, targets)
    architecture = detect_architecture(data, base)
    instructions = disassemble(data, base, architecture)
    xrefs = find_string_xrefs(instructions, strings, data=data, base=base)
    flows = build_function_flows(instructions, xrefs)
    frp_checkers = identify_frp_checkers(instructions, flows)
    key_validators = identify_key_validators(instructions, flows)
    erase_permission_checks = identify_erase_permission_checks(instructions, flows)
    erase_operations = detect_partition_erase_operations(instructions, flows)
    serialno_runtime = detect_serialno_runtime_source(instructions, flows, xrefs, base, len(data))

    write_summary(
        args.output_dir / "summary.txt",
        args.image,
        source_kind,
        data,
        base,
        architecture,
        instructions,
        strings,
        xrefs,
        flows,
        frp_checkers,
        key_validators,
        erase_permission_checks,
        erase_operations,
    )
    write_strings(args.output_dir / "strings.txt", data, strings)
    write_xrefs(args.output_dir / "xrefs.txt", instructions, xrefs, args.context)
    write_candidate_functions(args.output_dir, instructions, xrefs)
    write_flow_reports(args.output_dir, instructions, flows)
    write_check_allow_report(args.output_dir / "check_allow_xrefs.txt", instructions, flows)
    write_frp_checker_reports(args.output_dir, instructions, frp_checkers, base)
    write_key_validator_reports(args.output_dir, instructions, key_validators, base)
    write_erase_permission_reports(args.output_dir, instructions, erase_permission_checks, base)
    write_partition_erase_reports(args.output_dir, instructions, erase_operations, base)
    write_serialno_runtime_reports(args.output_dir, serialno_runtime)
    write_flow_overview_mermaid(args.output_dir / "flow_overview.mmd", flows)
    write_best_flow_cfg(args.output_dir, instructions, flows[0] if flows else None)
    write_frp_unlock_relation_mermaid(args.output_dir / "frp_unlock_relation.mmd", flows, frp_checkers)
    write_key_validation_relation_mermaid(args.output_dir / "key_validation_relation.mmd", flows, key_validators)
    write_erase_permission_relation_mermaid(args.output_dir / "erase_permission_relation.mmd", erase_permission_checks)
    write_partition_erase_relation_mermaid(args.output_dir / "partition_erase_relation.mmd", erase_operations)
    write_flow_diagram_html(args.output_dir)

    if not args.no_full_disasm:
        write_disassembly(args.output_dir / "lk_full_disasm.asm", instructions)

    print(f"LK base      : 0x{base:016x}")
    print(f"LK size      : {len(data)} bytes")
    print(f"Architecture : {architecture}")
    print(f"Instructions : {len(instructions)}")
    print(f"String hits  : {len(strings)}")
    print(f"String xrefs : {len(xrefs)}")
    print(f"Flow candidates: {len(flows)}")
    if flows:
        print(
            f"Best flow    : 0x{flows[0].start_address:016x}-"
            f"0x{flows[0].end_address:016x} (score {flows[0].score})"
        )
    print(f"FRP checkers : {len(frp_checkers)}")
    if frp_checkers:
        print(
            f"Best FRP     : 0x{frp_checkers[0].flow.start_address:016x}-"
            f"0x{frp_checkers[0].flow.end_address:016x} "
            f"(confidence {frp_checkers[0].confidence})"
        )
    print(f"KEY validators: {len(key_validators)}")
    if key_validators:
        print(
            f"Best KEY     : 0x{key_validators[0].flow.start_address:016x}-"
            f"0x{key_validators[0].flow.end_address:016x} "
            f"(confidence {key_validators[0].confidence})"
        )
    print(f"Erase permission checks: {len(erase_permission_checks)}")
    if erase_permission_checks:
        print(
            f"Best erase permission: 0x{erase_permission_checks[0].flow.start_address:016x}-"
            f"0x{erase_permission_checks[0].flow.end_address:016x} "
            f"(confidence {erase_permission_checks[0].confidence})"
        )
    print(f"Partition erase ops: {sum(1 for operation in erase_operations if operation.operation == 'erase')}")
    if serialno_runtime:
        print(
            "Serialno runtime: "
            f"{serialno_runtime.get('hw_get_serialno_string')} "
            f"(confidence {serialno_runtime.get('confidence')})"
        )
    print(f"Output dir   : {args.output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
