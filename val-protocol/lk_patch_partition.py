#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
import shutil
import string
import struct
import sys
from pathlib import Path


CMP_W8_ZERO = bytes.fromhex("1f010071")
CMP_W8_ONE = bytes.fromhex("1f050071")
MOV_W0_W20 = bytes.fromhex("e003142a")
MOV_W0_ZERO = bytes.fromhex("00008052")
MOV_W0_ONE = bytes.fromhex("20008052")
RET = bytes.fromhex("c0035fd6")
THUMB_MOVS_R0_ONE_BX_LR = bytes.fromhex("01207047")
THUMB_MOVS_R0_ZERO_NOP = bytes.fromhex("002000bf")
THUMB_FRP_ZERO_BOOL = bytes.fromhex("b0fa80f04009")
THUMB_FRP_ONE_BOOL = bytes.fromhex("002000bf00bf")
PRINTABLE_TOKEN_BYTES = tuple(range(0x21, 0x7F))
ALNUM_TOKEN_BYTES = tuple(ord(ch) for ch in string.ascii_letters + string.digits)
RUNTIME_SERIAL_TOKEN_POSITIONS = tuple(range(10))
KEY_TOKEN_DEBUG_STOPS = (
    "caller_before_key",
    "entry",
    "before_serial",
    "after_serial",
    "token_ok",
    "token_fail",
)
THUMB_NOP = bytes.fromhex("00bf")
THUMB_POP_R4_PC = bytes.fromhex("10bd")


def parse_hxd_offset(value: str) -> int:
    value = value.strip()
    if value.lower().startswith("0x"):
        return int(value, 16)
    return int(value, 16)


def load_analysis_architecture(analysis_dir: Path) -> str:
    summary_path = analysis_dir / "summary.txt"
    if not summary_path.is_file():
        return "aarch64"
    for line in summary_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("Architecture"):
            _, _, value = line.partition(":")
            return value.strip() or "aarch64"
    return "aarch64"


def load_analysis_base(analysis_dir: Path) -> int:
    summary_path = analysis_dir / "summary.txt"
    if not summary_path.is_file():
        raise FileNotFoundError(f"no existe {summary_path}")
    for line in summary_path.read_text(encoding="utf-8", errors="replace").splitlines():
        if line.startswith("LK base"):
            _, _, value = line.partition(":")
            return int(value.strip(), 16)
    raise ValueError("summary.txt no contiene LK base")


def normalize_imei(value: str) -> str:
    text = value.strip()
    if not text:
        raise ValueError("el IMEI no puede estar vacio")
    candidates = re.findall(r"\b\d{15}\b", text)
    if not candidates:
        raise ValueError(
            "IMEI invalido: usa 15 digitos, o pega una linea que contenga el IMEI"
        )
    unique = list(dict.fromkeys(candidates))
    if len(unique) > 1:
        raise ValueError(
            "se encontraron multiples IMEI en el texto; pasa solo uno explicitamente"
        )
    return unique[0]


def resolve_device_or_imei(device: str, imei: str | None, label: str = "token") -> tuple[str, str]:
    if imei is None:
        return device, "device" if device else "global"
    normalized = normalize_imei(imei)
    if device and device != normalized:
        raise ValueError(
            f"--{label}-device y --{label}-imei no coinciden; usa solo uno o el mismo valor"
        )
    return normalized, "imei"


def u32(value: int) -> bytes:
    return struct.pack("<I", value & 0xFFFFFFFF)


def branch_imm26(source: int, target: int, opcode: int = 0x14000000) -> bytes:
    delta = target - source
    if delta % 4:
        raise ValueError(f"branch no alineado: 0x{source:x} -> 0x{target:x}")
    imm = delta // 4
    if imm < -(1 << 25) or imm >= (1 << 25):
        raise ValueError(f"branch fuera de rango: 0x{source:x} -> 0x{target:x}")
    return u32(opcode | (imm & 0x03FFFFFF))


def relocate_aarch64_branch(original_instr: bytes, original_offset: int, new_offset: int) -> bytes:
    if len(original_instr) != 4:
        raise ValueError("original_instr debe medir 4 bytes")
    word = struct.unpack("<I", original_instr)[0]
    opcode = word & 0xFC000000
    if opcode not in {0x14000000, 0x94000000}:
        return original_instr
    imm = word & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    target = original_offset + imm * 4
    return branch_imm26(new_offset, target, opcode)


def u16(value: int) -> bytes:
    return struct.pack("<H", value & 0xFFFF)


def thumb_b_w(source: int, target: int) -> bytes:
    delta = target - (source + 4)
    if delta % 2:
        raise ValueError(f"thumb branch no alineado: 0x{source:x} -> 0x{target:x}")
    imm = delta // 2
    if imm < -(1 << 24) or imm >= (1 << 24):
        raise ValueError(f"thumb branch fuera de rango: 0x{source:x} -> 0x{target:x}")
    imm &= (1 << 24) - 1
    s = (imm >> 23) & 1
    i1 = (imm >> 22) & 1
    i2 = (imm >> 21) & 1
    imm10 = (imm >> 11) & 0x3FF
    imm11 = imm & 0x7FF
    j1 = (~(i1 ^ s)) & 1
    j2 = (~(i2 ^ s)) & 1
    return u16(0xF000 | (s << 10) | imm10) + u16(0x9000 | (j1 << 13) | (j2 << 11) | imm11)


def thumb_bl(source: int, target: int) -> bytes:
    delta = target - (source + 4)
    if delta % 2:
        raise ValueError(f"thumb bl no alineado: 0x{source:x} -> 0x{target:x}")
    imm = delta // 2
    if imm < -(1 << 23) or imm >= (1 << 23):
        raise ValueError(f"thumb bl fuera de rango: 0x{source:x} -> 0x{target:x}")
    imm &= (1 << 24) - 1
    s = (imm >> 23) & 1
    i1 = (imm >> 22) & 1
    i2 = (imm >> 21) & 1
    imm10 = (imm >> 11) & 0x3FF
    imm11 = imm & 0x7FF
    j1 = (~(i1 ^ s)) & 1
    j2 = (~(i2 ^ s)) & 1
    return u16(0xF000 | (s << 10) | imm10) + u16(
        0xD000 | (j1 << 13) | (1 << 12) | (j2 << 11) | imm11
    )


def thumb_b_cond16(source: int, target: int, cond: int) -> bytes:
    delta = target - (source + 4)
    if delta % 2:
        raise ValueError(f"thumb conditional branch no alineado: 0x{source:x} -> 0x{target:x}")
    imm = delta // 2
    if imm < -128 or imm > 127:
        raise ValueError(f"thumb conditional branch fuera de rango: 0x{source:x} -> 0x{target:x}")
    return u16(0xD000 | ((cond & 0xF) << 8) | (imm & 0xFF))


def thumb_cmp_imm(reg: int, value: int) -> bytes:
    if reg < 0 or reg > 7 or value < 0 or value > 0xFF:
        raise ValueError("thumb cmp immediate fuera de rango")
    return u16(0x2800 | ((reg & 7) << 8) | value)


def thumb_movs_imm(reg: int, value: int) -> bytes:
    if reg < 0 or reg > 7 or value < 0 or value > 0xFF:
        raise ValueError("thumb movs immediate fuera de rango")
    return u16(0x2000 | ((reg & 7) << 8) | value)


def thumb_add_imm3(rd: int, rn: int, value: int) -> bytes:
    if rd < 0 or rd > 7 or rn < 0 or rn > 7 or value < 0 or value > 7:
        raise ValueError("thumb add immediate fuera de rango")
    return u16(0x1C00 | ((value & 7) << 6) | ((rn & 7) << 3) | (rd & 7))


def thumb_ldr_imm(rt: int, rn: int, offset: int) -> bytes:
    if rt < 0 or rt > 7 or rn < 0 or rn > 7 or offset % 4 or offset < 0 or offset > 124:
        raise ValueError("thumb ldr immediate fuera de rango")
    return u16(0x6800 | ((offset // 4) << 6) | ((rn & 7) << 3) | (rt & 7))


def thumb_ldrb_imm(rt: int, rn: int, offset: int) -> bytes:
    if rt < 0 or rt > 7 or rn < 0 or rn > 7 or offset < 0 or offset > 31:
        raise ValueError("thumb ldrb immediate fuera de rango")
    return u16(0x7800 | ((offset & 0x1F) << 6) | ((rn & 7) << 3) | (rt & 7))


def thumb_strb_imm(rt: int, rn: int, offset: int) -> bytes:
    if rt < 0 or rt > 7 or rn < 0 or rn > 7 or offset < 0 or offset > 31:
        raise ValueError("thumb strb immediate fuera de rango")
    return u16(0x7000 | ((offset & 0x1F) << 6) | ((rn & 7) << 3) | (rt & 7))


def thumb_eors(rd: int, rm: int) -> bytes:
    if rd < 0 or rd > 7 or rm < 0 or rm > 7:
        raise ValueError("thumb eors fuera de rango")
    return u16(0x4040 | ((rm & 7) << 3) | (rd & 7))


def thumb_push(regs: list[int] | tuple[int, ...]) -> bytes:
    low = 0
    lr = False
    for reg in regs:
        if 0 <= reg <= 7:
            low |= 1 << reg
        elif reg == 14:
            lr = True
        else:
            raise ValueError("thumb push solo soporta r0-r7 y lr")
    return u16(0xB400 | (0x100 if lr else 0) | low)


def thumb_pop(regs: list[int] | tuple[int, ...]) -> bytes:
    low = 0
    pc_bit = False
    for reg in regs:
        if 0 <= reg <= 7:
            low |= 1 << reg
        elif reg == 15:
            pc_bit = True
        else:
            raise ValueError("thumb pop solo soporta r0-r7 y pc")
    return u16(0xBC00 | (0x100 if pc_bit else 0) | low)


def thumb_sub_sp(value: int) -> bytes:
    if value < 0 or value > 0x1FC or value % 4:
        raise ValueError("thumb sub sp immediate fuera de rango")
    return u16(0xB080 | (value // 4))


def thumb_add_sp(value: int) -> bytes:
    if value < 0 or value > 0x1FC or value % 4:
        raise ValueError("thumb add sp immediate fuera de rango")
    return u16(0xB000 | (value // 4))


def thumb_add_sp_to_reg(rd: int, value: int) -> bytes:
    if rd < 0 or rd > 7 or value < 0 or value > 0x3FC or value % 4:
        raise ValueError("thumb add rd,sp,#imm fuera de rango")
    return u16(0xA800 | ((rd & 7) << 8) | (value // 4))


def thumb_mov_reg(rd: int, rm: int) -> bytes:
    if rd < 0 or rd > 15 or rm < 0 or rm > 15:
        raise ValueError("thumb mov reg fuera de rango")
    return u16(0x4600 | ((rm & 0xF) << 3) | (rd & 0x7) | ((rd & 0x8) << 4))


def thumb_str_imm(rt: int, rn: int, offset: int) -> bytes:
    if rt < 0 or rt > 7 or rn < 0 or rn > 7 or offset % 4 or offset < 0 or offset > 124:
        raise ValueError("thumb str immediate fuera de rango")
    return u16(0x6000 | ((offset // 4) << 6) | ((rn & 7) << 3) | (rt & 7))


def thumb_str_sp_imm(rt: int, offset: int) -> bytes:
    if rt < 0 or rt > 7 or offset % 4 or offset < 0 or offset > 1020:
        raise ValueError("thumb str sp immediate fuera de rango")
    return u16(0x9000 | ((rt & 7) << 8) | (offset // 4))


def thumb_cmp_reg(rn: int, rm: int) -> bytes:
    if rn < 0 or rn > 7 or rm < 0 or rm > 7:
        raise ValueError("thumb cmp reg fuera de rango")
    return u16(0x4280 | ((rm & 7) << 3) | (rn & 7))


def thumb_bx_lr() -> bytes:
    return u16(0x4770)


def branch_cond(source: int, target: int, cond: int) -> bytes:
    delta = target - source
    if delta % 4:
        raise ValueError(f"conditional branch no alineado: 0x{source:x} -> 0x{target:x}")
    imm = delta // 4
    if imm < -(1 << 18) or imm >= (1 << 18):
        raise ValueError(f"conditional branch fuera de rango: 0x{source:x} -> 0x{target:x}")
    return u32(0x54000000 | ((imm & 0x7FFFF) << 5) | (cond & 0xF))


def decode_cond_branch_target(word: int, source: int) -> int | None:
    if (word & 0xFF000010) != 0x54000000:
        return None
    imm = (word >> 5) & 0x7FFFF
    if imm & 0x40000:
        imm -= 0x80000
    return source + imm * 4


def cbz_x(source: int, target: int, rt: int) -> bytes:
    delta = target - source
    if delta % 4:
        raise ValueError(f"cbz no alineado: 0x{source:x} -> 0x{target:x}")
    imm = delta // 4
    if imm < -(1 << 18) or imm >= (1 << 18):
        raise ValueError(f"cbz fuera de rango: 0x{source:x} -> 0x{target:x}")
    return u32(0xB4000000 | ((imm & 0x7FFFF) << 5) | (rt & 0x1F))


def cbz_w(source: int, target: int, rt: int) -> bytes:
    delta = target - source
    if delta % 4:
        raise ValueError(f"cbz no alineado: 0x{source:x} -> 0x{target:x}")
    imm = delta // 4
    if imm < -(1 << 18) or imm >= (1 << 18):
        raise ValueError(f"cbz fuera de rango: 0x{source:x} -> 0x{target:x}")
    return u32(0x34000000 | ((imm & 0x7FFFF) << 5) | (rt & 0x1F))


def ldr_unsigned(rt: int, rn: int, offset: int, bits: int) -> bytes:
    if bits == 64:
        scale = 8
        opcode = 0xF9400000
    elif bits == 32:
        scale = 4
        opcode = 0xB9400000
    else:
        raise ValueError("bits debe ser 32 o 64")
    if offset % scale:
        raise ValueError(f"offset ldr no alineado: {offset}")
    imm12 = offset // scale
    if imm12 < 0 or imm12 > 0xFFF:
        raise ValueError(f"offset ldr fuera de rango: {offset}")
    return u32(opcode | (imm12 << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F))


def ldrb_unsigned(rt: int, rn: int, offset: int) -> bytes:
    if offset < 0 or offset > 0xFFF:
        raise ValueError(f"offset ldrb fuera de rango: {offset}")
    return u32(0x39400000 | (offset << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F))


def ldrb_reg(rt: int, rn: int, rm: int) -> bytes:
    return u32(0x38606800 | ((rm & 0x1F) << 16) | ((rn & 0x1F) << 5) | (rt & 0x1F))


def str_unsigned(rt: int, rn: int, offset: int, bits: int) -> bytes:
    if bits == 64:
        scale = 8
        opcode = 0xF9000000
    elif bits == 32:
        scale = 4
        opcode = 0xB9000000
    else:
        raise ValueError("bits debe ser 32 o 64")
    if offset % scale:
        raise ValueError(f"offset str no alineado: {offset}")
    imm12 = offset // scale
    if imm12 < 0 or imm12 > 0xFFF:
        raise ValueError(f"offset str fuera de rango: {offset}")
    return u32(opcode | (imm12 << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F))


def strb_unsigned(rt: int, rn: int, offset: int) -> bytes:
    if offset < 0 or offset > 0xFFF:
        raise ValueError(f"offset strb fuera de rango: {offset}")
    return u32(0x39000000 | (offset << 10) | ((rn & 0x1F) << 5) | (rt & 0x1F))


def add_imm64(rd: int, rn: int, value: int) -> bytes:
    if value < 0 or value > 0xFFF:
        raise ValueError(f"add immediate fuera de rango: {value}")
    return u32(0x91000000 | (value << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F))


def sub_imm64(rd: int, rn: int, value: int) -> bytes:
    if value < 0 or value > 0xFFF:
        raise ValueError(f"sub immediate fuera de rango: {value}")
    return u32(0xD1000000 | (value << 10) | ((rn & 0x1F) << 5) | (rd & 0x1F))


def mov_reg64(rd: int, rn: int) -> bytes:
    return u32(0xAA0003E0 | ((rn & 0x1F) << 16) | (rd & 0x1F))


def mov_reg32(rd: int, rn: int) -> bytes:
    return u32(0x2A0003E0 | ((rn & 0x1F) << 16) | (rd & 0x1F))


def mov_imm64(rd: int, value: int) -> bytes:
    out = bytearray()
    for hw in range(4):
        imm16 = (value >> (hw * 16)) & 0xFFFF
        opcode = 0xD2800000 if hw == 0 else 0xF2800000
        out += u32(opcode | (hw << 21) | (imm16 << 5) | (rd & 0x1F))
    return bytes(out)


def mov_imm32(rd: int, value: int) -> bytes:
    low = value & 0xFFFF
    high = (value >> 16) & 0xFFFF
    return (
        u32(0x52800000 | (low << 5) | (rd & 0x1F))
        + u32(0x72800000 | (1 << 21) | (high << 5) | (rd & 0x1F))
    )


def cmp_reg(rn: int, rm: int, bits: int) -> bytes:
    if bits == 64:
        return u32(0xEB00001F | ((rm & 0x1F) << 16) | ((rn & 0x1F) << 5))
    if bits == 32:
        return u32(0x6B00001F | ((rm & 0x1F) << 16) | ((rn & 0x1F) << 5))
    raise ValueError("bits debe ser 32 o 64")


def cmp_imm32(rn: int, value: int) -> bytes:
    if value < 0 or value > 0xFFF:
        raise ValueError(f"cmp immediate fuera de rango: {value}")
    return u32(0x7100001F | (value << 10) | ((rn & 0x1F) << 5))


def cmn_imm32(rn: int, value: int) -> bytes:
    if value < 0 or value > 0xFFF:
        raise ValueError(f"cmn immediate fuera de rango: {value}")
    return u32(0x3100001F | (value << 10) | ((rn & 0x1F) << 5))


def eor_reg32(rd: int, rn: int, rm: int) -> bytes:
    return u32(0x4A000000 | ((rm & 0x1F) << 16) | ((rn & 0x1F) << 5) | (rd & 0x1F))


def decode_aarch64_branch_target(word: int, source: int) -> int | None:
    opcode = word & 0xFC000000
    if opcode != 0x14000000:
        return None
    imm = word & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    return source + imm * 4


def decode_aarch64_call_target(word: int, source: int) -> int | None:
    if (word & 0xFC000000) != 0x94000000:
        return None
    imm = word & 0x03FFFFFF
    if imm & 0x02000000:
        imm -= 0x04000000
    return source + imm * 4


def decode_aarch64_cbz_tbz_target(word: int, source: int) -> int | None:
    if (word & 0x7E000000) == 0x34000000:
        imm = (word >> 5) & 0x7FFFF
        if imm & 0x40000:
            imm -= 0x80000
        return source + imm * 4
    if (word & 0x7E000000) == 0x36000000:
        imm = (word >> 5) & 0x3FFF
        if imm & 0x2000:
            imm -= 0x4000
        return source + imm * 4
    return None


def is_thumb_bl(data: bytes | bytearray, offset: int) -> bool:
    if offset < 0 or offset + 4 > len(data):
        return False
    first = struct.unpack_from("<H", data, offset)[0]
    second = struct.unpack_from("<H", data, offset + 2)[0]
    return (first & 0xF800) == 0xF000 and (second & 0xD000) == 0xD000


def is_thumb_cbnz_r0(data: bytes | bytearray, offset: int) -> bool:
    if offset < 0 or offset + 2 > len(data):
        return False
    word = struct.unpack_from("<H", data, offset)[0]
    return (word & 0xF507) == 0xB100 and (word & 0x0800) != 0


def load_flow_candidates(analysis_dir: Path) -> list[dict[str, object]]:
    path = analysis_dir / "flow_candidates.json"
    if not path.is_file():
        raise FileNotFoundError(f"no existe {path}")
    flows = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(flows, list):
        raise ValueError("flow_candidates.json invalido")
    return [flow for flow in flows if isinstance(flow, dict)]


def load_flow_for_start(analysis_dir: Path, start_address: int) -> dict[str, object]:
    for flow in load_flow_candidates(analysis_dir):
        if int(str(flow.get("start_address", "0")), 16) == start_address:
            return flow
    raise ValueError(f"no se encontro flow candidate para 0x{start_address:x}")


def audit_aarch64_direct_return_path(
    data: bytes | bytearray,
    start_offset: int,
    function_end_offset: int,
    max_steps: int = 48,
) -> dict[str, object]:
    pc = start_offset
    path: list[int] = []
    calls: list[int] = []
    conditional: list[int] = []
    terminal = "unknown"

    for _ in range(max_steps):
        if pc < 0 or pc + 4 > len(data):
            terminal = "out_of_file"
            break
        if pc > function_end_offset + 4:
            terminal = "out_of_function"
            break
        if pc in path:
            terminal = "loop"
            break
        path.append(pc)
        word = struct.unpack_from("<I", data, pc)[0]

        if word == 0xD65F03C0:
            terminal = "ret"
            break
        if (word & 0xFC000000) == 0x94000000:
            calls.append(pc)
            terminal = "call"
            break
        if (word & 0xFF000010) == 0x54000000:
            conditional.append(pc)
            terminal = "conditional_branch"
            break
        if (word & 0x7E000000) == 0x34000000 or (word & 0x7E000000) == 0x36000000:
            conditional.append(pc)
            terminal = "conditional_branch"
            break

        target = decode_aarch64_branch_target(word, pc)
        if target is not None:
            pc = target
            continue
        pc += 4
    else:
        terminal = "step_limit"

    return {
        "ok": terminal == "ret" and not calls and not conditional,
        "terminal": terminal,
        "steps": len(path),
        "path": path,
        "calls": calls,
        "conditional_branches": conditional,
    }


def decode_mov_reg64(raw: bytes) -> tuple[int, int] | None:
    if len(raw) != 4:
        return None
    word = struct.unpack("<I", raw)[0]
    if (word & 0xFFE0FFE0) != 0xAA0003E0:
        return None
    rd = word & 0x1F
    rm = (word >> 16) & 0x1F
    return rd, rm


def load_partition_arg_offsets(analysis_dir: Path, old_name: str) -> list[dict[str, object]]:
    strings_path = analysis_dir / "partition_erases" / old_name / "strings.json"
    if not strings_path.is_file():
        raise FileNotFoundError(f"no existe {strings_path}")

    entries = json.loads(strings_path.read_text(encoding="utf-8"))
    matches = [
        entry for entry in entries
        if entry.get("role") == "partition_arg"
        and entry.get("text") == old_name
        and entry.get("reference_mode") == "direct_string"
    ]
    if not matches:
        raise ValueError(
            f"no se encontraron strings directas role=partition_arg para {old_name!r}"
        )
    return matches


def load_partition_erase_operations(analysis_dir: Path) -> list[dict[str, object]]:
    path = analysis_dir / "partition_erase_operations.json"
    if not path.is_file():
        raise FileNotFoundError(f"no existe {path}")
    operations = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(operations, list):
        raise ValueError("partition_erase_operations.json invalido")
    return [operation for operation in operations if isinstance(operation, dict)]


def patch_bytes(data: bytearray, offset: int, old_name: str, new_name: str) -> None:
    old_raw = old_name.encode("ascii") + b"\x00"
    new_raw = new_name.encode("ascii") + b"\x00"
    if len(new_raw) > len(old_raw):
        raise ValueError(
            f"replacement demasiado largo: {new_name!r} necesita {len(new_raw)} bytes, "
            f"pero {old_name!r} solo ocupa {len(old_raw)} bytes con NUL"
        )

    current = bytes(data[offset : offset + len(old_raw)])
    if current != old_raw:
        raise ValueError(
            f"offset 0x{offset:x} no contiene {old_raw!r}; contiene {current!r}"
        )

    data[offset : offset + len(old_raw)] = new_raw.ljust(len(old_raw), b"\x00")


def load_frp_compare_offsets(analysis_dir: Path) -> list[dict[str, object]]:
    details_paths = sorted((analysis_dir / "frp_checkers").glob("frp_checker_*_details.json"))
    if details_paths:
        checkers = [json.loads(path.read_text(encoding="utf-8")) for path in details_paths]
    else:
        checkers_path = analysis_dir / "frp_checkers.json"
        if not checkers_path.is_file():
            raise FileNotFoundError(f"no existe {checkers_path}")
        checkers = json.loads(checkers_path.read_text(encoding="utf-8"))

    matches: list[dict[str, object]] = []
    for checker in checkers[:1]:
        fallback_thumb_load: dict[str, object] | None = None
        for item in checker.get("structural_instructions", []):
            if item.get("role") == "last_byte_compare_zero":
                matches.append(item)
            elif (
                item.get("role") == "last_byte_load_sp_0xff"
                and str(item.get("instruction", "")).startswith("ldrb.w ")
            ):
                fallback_thumb_load = item
        if fallback_thumb_load is not None and not any(
            item.get("role") == "last_byte_compare_zero"
            for item in checker.get("structural_instructions", [])
        ):
            cloned = dict(fallback_thumb_load)
            load_offset = parse_hxd_offset(str(cloned["hxd_offset"]))
            cloned["role"] = "last_byte_compare_zero"
            cloned["hxd_offset"] = f"{load_offset + 4:08X}"
            cloned["file_offset"] = f"0x{load_offset + 4:x}"
            matches.append(cloned)

    if not matches:
        raise ValueError(
            "no se encontro la instruccion FRP last_byte_compare_zero; "
            "regenera el analisis con lk_static_analyzer.py actualizado"
        )
    return matches


def load_frp_checker_entry(analysis_dir: Path) -> dict[str, object]:
    details_paths = sorted((analysis_dir / "frp_checkers").glob("frp_checker_*_details.json"))
    if details_paths:
        checkers = [json.loads(path.read_text(encoding="utf-8")) for path in details_paths]
    else:
        checkers_path = analysis_dir / "frp_checkers.json"
        if not checkers_path.is_file():
            raise FileNotFoundError(f"no existe {checkers_path}")
        checkers = json.loads(checkers_path.read_text(encoding="utf-8"))

    if not isinstance(checkers, list) or not checkers:
        raise ValueError("no se encontraron candidatos FRP/OEM checker")
    checker = checkers[0]
    if not isinstance(checker, dict) or "callers" not in checker:
        raise ValueError("FRP/OEM checker no contiene callers validos")
    return checker


def frp_skip_call_offsets(analysis_dir: Path) -> list[int]:
    checker = load_frp_checker_entry(analysis_dir)
    callers = checker.get("callers", [])
    if not isinstance(callers, list) or not callers:
        raise ValueError("FRP/OEM checker no tiene callers")

    key_caller_offset: int | None = None
    try:
        validator = load_key_validator_entry(analysis_dir)
        validator_callers = validator.get("callers", [])
        if isinstance(validator_callers, list) and validator_callers:
            caller = validator_callers[0]
            if isinstance(caller, dict) and "caller_start_file_offset" in caller:
                key_caller_offset = parse_hxd_offset(str(caller["caller_start_file_offset"]))
    except (OSError, ValueError, KeyError, json.JSONDecodeError):
        key_caller_offset = None

    offsets: list[int] = []
    for caller in callers:
        if not isinstance(caller, dict):
            continue
        if key_caller_offset is not None:
            caller_start = parse_hxd_offset(str(caller.get("caller_start_file_offset", "-1")))
            if caller_start != key_caller_offset:
                continue
        if "call_site_file_offset" not in caller:
            continue
        offsets.append(parse_hxd_offset(str(caller["call_site_file_offset"])))

    offsets = sorted(set(offsets))
    if not offsets:
        raise ValueError("no se encontraron llamadas FRP/OEM dentro del caller de unlock")
    return offsets


def load_key_primary_return_offsets(analysis_dir: Path) -> list[dict[str, object]]:
    details_paths = sorted((analysis_dir / "key_validators").glob("key_validator_*_details.json"))
    if details_paths:
        validators = [json.loads(path.read_text(encoding="utf-8")) for path in details_paths]
    else:
        validators_path = analysis_dir / "key_validators.json"
        if not validators_path.is_file():
            raise FileNotFoundError(f"no existe {validators_path}")
        validators = json.loads(validators_path.read_text(encoding="utf-8"))

    matches: list[dict[str, object]] = []
    for validator in validators[:1]:
        structural = validator.get("structural_instructions", [])
        first_ret_offset: int | None = None
        for item in structural:
            if item.get("role") != "function_return":
                continue
            first_ret_offset = parse_hxd_offset(str(item["hxd_offset"]))
            break

        for item in structural:
            if item.get("role") != "return_result_w20":
                continue
            item_offset = parse_hxd_offset(str(item["hxd_offset"]))
            if first_ret_offset is not None and item_offset > first_ret_offset:
                continue
            matches.append(item)
            break

    if not matches:
        raise ValueError(
            "no se encontro el retorno principal KEY return_result_w20; "
            "regenera el analisis con lk_static_analyzer.py actualizado"
        )
    return matches


def load_key_validator_entry(analysis_dir: Path) -> dict[str, object]:
    details_paths = sorted((analysis_dir / "key_validators").glob("key_validator_*_details.json"))
    if details_paths:
        validators = [json.loads(path.read_text(encoding="utf-8")) for path in details_paths]
    else:
        validators_path = analysis_dir / "key_validators.json"
        if not validators_path.is_file():
            raise FileNotFoundError(f"no existe {validators_path}")
        validators = json.loads(validators_path.read_text(encoding="utf-8"))

    if not validators:
        raise ValueError("no se encontraron candidatos KEY validator")

    validator = validators[0]
    if "function_start_file_offset" not in validator or "function_end_file_offset" not in validator:
        raise ValueError(
            "el candidato KEY no tiene offsets de funcion; "
            "regenera el analisis con lk_static_analyzer.py actualizado"
        )
    return validator


PACIASP_WORD = 0xD503233F
PACIBSP_WORD = 0xD503237F


def adjust_aarch64_pac_prologue_offset(data: bytes | bytearray, entry_offset: int) -> int:
    if entry_offset < 4 or entry_offset + 4 > len(data):
        return entry_offset
    prev_word = struct.unpack_from("<I", data, entry_offset - 4)[0]
    current_word = struct.unpack_from("<I", data, entry_offset)[0]
    if prev_word not in {PACIASP_WORD, PACIBSP_WORD}:
        return entry_offset
    if (current_word & 0xFFC003FF) != 0xA98003FD:
        return entry_offset
    return entry_offset - 4


def adjust_aarch64_pac_function_entry(
    data: bytes | bytearray,
    validator: dict[str, object],
    entry_offset: int,
    base: int,
) -> int:
    """Corrige funciones AArch64 donde el analizador viejo marco el inicio
    despues de PACIASP/PACIBSP, pero el caller realmente entra en ese PAC.

    Si dejamos vivo el PAC y el stub retorna con RET normal, el LR queda firmado
    y algunos LK reinician al volver al caller. Al mover el parche al target real
    del BL, el stub se ejecuta sin ese PAC previo y retorna normalmente."""
    if entry_offset < 4:
        return entry_offset
    prev_word = struct.unpack_from("<I", data, entry_offset - 4)[0]
    if prev_word not in {PACIASP_WORD, PACIBSP_WORD}:
        return entry_offset

    expected_va = base + entry_offset - 4
    for caller in validator.get("callers", []):
        if not isinstance(caller, dict) or "call_site_file_offset" not in caller:
            continue
        call_offset = parse_hxd_offset(str(caller["call_site_file_offset"]))
        if call_offset < 0 or call_offset + 4 > len(data):
            continue
        call_word = struct.unpack_from("<I", data, call_offset)[0]
        target = decode_aarch64_call_target(call_word, base + call_offset)
        if target == expected_va:
            return entry_offset - 4
    return entry_offset


def load_serialno_runtime_entry(analysis_dir: Path) -> dict[str, object]:
    path = analysis_dir / "serialno_runtime.json"
    if not path.is_file():
        raise FileNotFoundError(
            f"no existe {path}; regenera el analisis con lk_static_analyzer.py actualizado"
        )
    entry = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(entry, dict) or not entry:
        raise ValueError("serialno_runtime.json no contiene un candidato valido")

    confidence = int(entry.get("confidence") or 0)
    if confidence < 90:
        raise ValueError(
            f"serialno runtime candidate con confianza baja ({confidence}); "
            "no se aplicara el stub experimental"
        )
    if entry.get("architecture") not in (None, "aarch64", "arm32_thumb"):
        raise ValueError("el stub runtime serial no soporta esta arquitectura")
    if entry.get("hw_get_serialno_string_file_offset") is None:
        raise ValueError("serialno_runtime.json no tiene hw_get_serialno_string_file_offset")

    xref_texts = {
        str(item.get("string", "")).strip("\x00")
        for item in entry.get("xrefs", [])
        if isinstance(item, dict)
    }
    if "serialno" not in xref_texts:
        raise ValueError("el candidato serialno no referencia la string 'serialno'")
    if "barcode" not in xref_texts:
        raise ValueError("el candidato serialno no muestra fallback a 'barcode'")
    return entry


def load_fastboot_info_targets(
    analysis_dir: Path,
    data: bytes | bytearray,
) -> dict[str, int]:
    base = load_analysis_base(analysis_dir)
    info_offset = data.find(b"INFO\x00")
    if info_offset < 0:
        raise ValueError("no se encontro string INFO para mensajes fastboot debug")

    flows = load_flow_candidates(analysis_dir)
    xref_va: int | None = None
    for flow in flows[:3]:
        for xref in flow.get("xrefs", []):
            if not isinstance(xref, dict):
                continue
            if str(xref.get("target", "")) == "Code validation failure":
                xref_va = int(str(xref["xref_address"]), 16)
                break
        if xref_va is not None:
            break
    if xref_va is None:
        raise ValueError("no se encontro xref a Code validation failure para inferir fastboot_info")

    xref_offset = xref_va - base
    if xref_offset < 0 or xref_offset + 8 > len(data):
        raise ValueError("xref Code validation failure fuera del archivo")

    first_branch_word = struct.unpack_from("<I", data, xref_offset + 4)[0]
    epilogue_va = decode_aarch64_branch_target(first_branch_word, xref_va + 4)
    if epilogue_va is None:
        raise ValueError("no se pudo seguir branch desde Code validation failure")
    epilogue_offset = epilogue_va - base
    if epilogue_offset < 0 or epilogue_offset + 4 > len(data):
        raise ValueError("epilogo de fastboot_info fuera del archivo")

    print_func_va: int | None = None
    scan_end = min(len(data), epilogue_offset + 0x40)
    for offset in range(epilogue_offset, scan_end, 4):
        word = struct.unpack_from("<I", data, offset)[0]
        if (word & 0xFC000000) != 0x14000000:
            continue
        target = decode_aarch64_branch_target(word, base + offset)
        if target is None:
            continue
        target_offset = target - base
        if 0 <= target_offset < len(data):
            print_func_va = target
            break
    if print_func_va is None:
        raise ValueError("no se encontro branch final a fastboot_info")

    return {
        "info_string_offset": info_offset,
        "info_string_va": base + info_offset,
        "print_func_offset": print_func_va - base,
        "print_func_va": print_func_va,
    }


def patch_code_validation_message(
    data: bytearray,
    analysis_dir: Path,
    message: str,
) -> dict[str, object]:
    base = load_analysis_base(analysis_dir)
    validators = [load_key_validator_entry(analysis_dir)]
    caller_start: int | None = None
    callers = validators[0].get("callers", [])
    if isinstance(callers, list) and callers:
        caller = callers[0]
        if isinstance(caller, dict) and "caller_start_file_offset" in caller:
            caller_start = parse_hxd_offset(str(caller["caller_start_file_offset"]))

    flows = load_flow_candidates(analysis_dir)
    target_xref: dict[str, object] | None = None
    for flow in flows:
        if caller_start is not None:
            try:
                if int(str(flow.get("start_address", "0")), 16) - base != caller_start:
                    continue
            except ValueError:
                continue
        for xref in flow.get("xrefs", []):
            if not isinstance(xref, dict):
                continue
            if str(xref.get("target", "")) == "Code validation failure":
                target_xref = xref
                break
        if target_xref is not None:
            break
    if target_xref is None:
        raise ValueError("no se encontro string Code validation failure para checkpoint")

    string_offset = int(str(target_xref["string_address"]), 16) - base
    original = read_c_string(data, string_offset, 96)
    replacement = message.encode("ascii") + b"\x00"
    if len(replacement) > len(original) + 1:
        raise ValueError(
            f"mensaje checkpoint demasiado largo ({len(replacement)} > {len(original) + 1})"
        )
    data[string_offset : string_offset + len(original) + 1] = replacement.ljust(
        len(original) + 1,
        b"\x00",
    )
    return {
        "message_offset": string_offset,
        "original_message": original.decode("ascii", errors="replace"),
        "new_message": message,
    }


def read_c_string(data: bytes | bytearray, offset: int, max_len: int = 96) -> bytes:
    if offset < 0 or offset >= len(data):
        return b""
    end = offset
    limit = min(len(data), offset + max_len)
    while end < limit and data[end] != 0:
        end += 1
    return bytes(data[offset:end])


def find_fastboot_command_handler_offset(
    data: bytes | bytearray,
    base: int,
    command: str,
    candidate_offsets: set[int] | None = None,
) -> int | None:
    command_raw = command.encode("ascii") + b"\x00"
    string_offsets: list[int] = []
    start = 0
    while True:
        offset = data.find(command_raw, start)
        if offset < 0:
            break
        if offset == 0 or data[offset - 1] == 0:
            string_offsets.append(offset)
        start = offset + 1

    for string_offset in string_offsets:
        string_va = base + string_offset
        pointer_raw = struct.pack("<Q", string_va)
        pointer_start = 0
        while True:
            pointer_offset = data.find(pointer_raw, pointer_start)
            if pointer_offset < 0:
                break
            pointer_start = pointer_offset + 1
            if pointer_offset % 8:
                continue
            if pointer_offset + 16 > len(data):
                continue
            handler_va = struct.unpack_from("<Q", data, pointer_offset + 8)[0]
            if not (base <= handler_va < base + len(data)):
                continue
            handler_offset = handler_va - base
            if handler_offset % 4:
                continue
            if candidate_offsets is not None and handler_offset not in candidate_offsets:
                continue

            # A fastboot command table is a compact pair array: name pointer,
            # handler pointer. Require at least one neighbor row with the same
            # shape to avoid confusing unrelated pointers with command entries.
            neighbor_ok = False
            for neighbor in (pointer_offset - 16, pointer_offset + 16):
                if neighbor < 0 or neighbor + 16 > len(data):
                    continue
                name_va, code_va = struct.unpack_from("<QQ", data, neighbor)
                if not (base <= name_va < base + len(data)):
                    continue
                if not (base <= code_va < base + len(data)):
                    continue
                name_bytes = read_c_string(data, name_va - base)
                if name_bytes and all(0x20 <= byte < 0x7F for byte in name_bytes):
                    neighbor_ok = True
                    break
            if neighbor_ok:
                return handler_offset
    return None


def load_erase_permission_entry(
    analysis_dir: Path,
    data: bytes | bytearray | None = None,
) -> dict[str, object]:
    details_paths = sorted((analysis_dir / "erase_permission_checks").glob("erase_permission_*_details.json"))
    if details_paths:
        checks = [json.loads(path.read_text(encoding="utf-8")) for path in details_paths]
    else:
        checks_path = analysis_dir / "erase_permission_checks.json"
        if not checks_path.is_file():
            raise FileNotFoundError(
                f"no existe {checks_path}; regenera el analisis con lk_static_analyzer.py actualizado"
            )
        checks = json.loads(checks_path.read_text(encoding="utf-8"))

    if not checks:
        raise ValueError("no se encontraron candidatos erase_permission_check")

    if data is not None:
        try:
            candidate_offsets = {
                parse_hxd_offset(str(check["function_start_file_offset"]))
                for check in checks
                if isinstance(check, dict) and "function_start_file_offset" in check
            }
            base = load_analysis_base(analysis_dir)
            command_handler_offset = find_fastboot_command_handler_offset(
                data,
                base,
                "erase",
                candidate_offsets,
            )
            if command_handler_offset is not None:
                for check in checks:
                    if parse_hxd_offset(str(check.get("function_start_file_offset", "-1"))) == command_handler_offset:
                        return check
        except (OSError, ValueError, KeyError, struct.error):
            pass

    check = checks[0]
    required = {"function_start_file_offset", "function_end_file_offset", "structural_instructions", "denied_edges"}
    if not required <= set(check):
        raise ValueError(
            "el candidato erase_permission_check no tiene offsets/estructura; "
            "regenera el analisis con lk_static_analyzer.py actualizado"
        )
    return check


def parse_custom_signature(value: str) -> bytes:
    try:
        raw = value.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("la firma personalizada debe usar solo ASCII") from exc
    if len(raw) != 20:
        raise ValueError(
            f"la firma personalizada debe medir exactamente 20 bytes ASCII; mide {len(raw)}"
        )
    return raw


def parse_partition_name(value: str) -> str:
    name = value.strip()
    if not name:
        raise ValueError("la particion no puede estar vacia")
    try:
        name.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("usa nombres de particion ASCII") from exc
    if "__" in name:
        raise ValueError("el nombre de particion no puede contener '__'")
    if len(name) > 48:
        raise ValueError("nombre de particion demasiado largo para este stub")
    return name


def token_bytes_for_alphabet(alphabet: str) -> tuple[int, ...]:
    if alphabet == "printable":
        return PRINTABLE_TOKEN_BYTES
    if alphabet == "alnum":
        return ALNUM_TOKEN_BYTES
    raise ValueError("alphabet debe ser 'alnum' o 'printable'")


def token_xor_values_for_alphabet(alphabet: str) -> tuple[int, ...]:
    token_bytes = token_bytes_for_alphabet(alphabet)
    return tuple(sorted({left ^ right for left in token_bytes for right in token_bytes}))


def derive_token_constants(secret: str, device: str = "", alphabet: str = "alnum") -> bytes:
    try:
        secret_raw = secret.encode("utf-8")
        device_raw = device.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("secret/device no se pudieron codificar como UTF-8") from exc
    if not secret_raw:
        raise ValueError("el secret no puede estar vacio")

    mask = hashlib.sha256(b"lk-token-mask\0" + secret_raw + b"\0" + device_raw).digest()[:10]
    target = b"M" + hashlib.sha256(b"lk-token-target\0" + device_raw).digest()[:9]
    raw = hashlib.sha256(
        b"lk-token-constants\0"
        + bytes(target_byte ^ mask_byte for target_byte, mask_byte in zip(target, mask))
        + b"\0"
        + secret_raw
        + b"\0"
        + device_raw
    ).digest()
    xor_values = token_xor_values_for_alphabet(alphabet)
    return bytes(
        xor_values[value % len(xor_values)]
        for value in raw[:10]
    )


def normalize_serialno(value: str) -> str:
    text = value.strip()
    if not text:
        raise ValueError("el serialno no puede estar vacio")
    try:
        raw = text.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("serialno debe usar ASCII") from exc
    if len(raw) <= max(RUNTIME_SERIAL_TOKEN_POSITIONS):
        raise ValueError(
            f"serialno demasiado corto; se necesitan al menos "
            f"{max(RUNTIME_SERIAL_TOKEN_POSITIONS) + 1} caracteres"
        )
    if any(byte == 0 or byte >= 0x80 for byte in raw):
        raise ValueError("serialno debe contener solo ASCII 1..127")
    return text


def derive_runtime_serial_compact_masks(secret: str) -> bytes:
    try:
        secret_raw = secret.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("secret no se pudo codificar como UTF-8") from exc
    if not secret_raw:
        raise ValueError("el secret no puede estar vacio")
    raw = hashlib.sha256(b"lk-token-runtime-serial-compact\0" + secret_raw).digest()
    return bytes(byte & 0x7F for byte in raw[: len(RUNTIME_SERIAL_TOKEN_POSITIONS)])


def derive_runtime_serial_compact_constants(
    secret: str,
    serialno: str,
) -> bytes:
    serial_raw = normalize_serialno(serialno).encode("ascii")
    masks = derive_runtime_serial_compact_masks(secret)
    return bytes(
        (serial_raw[position] ^ masks[index]) & 0x7F
        for index, position in enumerate(RUNTIME_SERIAL_TOKEN_POSITIONS)
    )


def derive_erase_token_constants(
    secret: str,
    device: str,
    partition: str,
    alphabet: str = "alnum",
) -> bytes:
    try:
        secret_raw = secret.encode("utf-8")
        device_raw = device.encode("utf-8")
        partition_raw = partition.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("secret/device/partition no se pudieron codificar correctamente") from exc
    if not secret_raw:
        raise ValueError("el secret no puede estar vacio")
    if not partition_raw:
        raise ValueError("la particion no puede estar vacia")

    raw = hashlib.sha256(
        b"lk-erase-token-constants\0"
        + secret_raw
        + b"\0"
        + device_raw
        + b"\0"
        + partition_raw
    ).digest()
    xor_values = token_xor_values_for_alphabet(alphabet)
    return bytes(
        xor_values[value % len(xor_values)]
        for value in raw[:10]
    )


def find_zero_cave(data: bytes | bytearray, min_size: int, start_offset: int) -> int:
    index = max(0, start_offset)
    while index < len(data):
        if data[index] != 0:
            index += 1
            continue

        run_start = index
        while index < len(data) and data[index] == 0:
            index += 1
        run_end = index
        aligned = (run_start + 3) & ~3
        if aligned + min_size <= run_end:
            return aligned

    raise ValueError(
        f"no se encontro un code cave de {min_size} bytes NUL despues de 0x{start_offset:x}"
    )


def require_zero_cave(data: bytes | bytearray, cave_offset: int, size: int) -> None:
    if cave_offset < 0 or cave_offset + size > len(data):
        raise ValueError(f"code cave fuera del archivo: 0x{cave_offset:x}")
    if cave_offset % 4:
        raise ValueError(f"code cave no alineado a 4 bytes: 0x{cave_offset:x}")
    current = bytes(data[cave_offset : cave_offset + size])
    if current != b"\x00" * size:
        raise ValueError(f"code cave 0x{cave_offset:x} no esta vacio para {size} bytes")


def build_key_signature_stub(
    entry_offset: int,
    cave_offset: int,
    original_instr: bytes,
    signature: bytes,
) -> bytes:
    if len(original_instr) != 4:
        raise ValueError("original_instr debe medir 4 bytes")
    if len(signature) != 20:
        raise ValueError("signature debe medir 20 bytes")

    code = bytearray()
    labels: dict[str, int] = {}
    relocs: list[tuple[int, str, str]] = []

    def pc() -> int:
        return cave_offset + len(code)

    def emit(raw: bytes) -> None:
        code.extend(raw)

    def mark(label: str) -> None:
        labels[label] = pc()

    def branch_later(kind: str, label: str) -> None:
        relocs.append((len(code), kind, label))
        emit(b"\x00\x00\x00\x00")

    branch_later("cbz_x0", "original")

    emit(ldr_unsigned(9, 0, 0, 64))
    emit(mov_imm64(10, int.from_bytes(signature[0:8], "little")))
    emit(cmp_reg(9, 10, 64))
    branch_later("b.ne", "original")

    emit(ldr_unsigned(9, 0, 8, 64))
    emit(mov_imm64(10, int.from_bytes(signature[8:16], "little")))
    emit(cmp_reg(9, 10, 64))
    branch_later("b.ne", "original")

    emit(ldr_unsigned(9, 0, 16, 32))
    emit(mov_imm32(10, int.from_bytes(signature[16:20], "little")))
    emit(cmp_reg(9, 10, 32))
    branch_later("b.ne", "original")

    emit(MOV_W0_ONE)
    emit(RET)

    mark("original")
    emit(original_instr)
    emit(branch_imm26(pc(), entry_offset + 4))

    for pos, kind, label in relocs:
        source = cave_offset + pos
        target = labels[label]
        if kind == "cbz_x0":
            replacement = cbz_x(source, target, 0)
        elif kind == "b.ne":
            replacement = branch_cond(source, target, 1)
        else:
            raise ValueError(f"reloc desconocido: {kind}")
        code[pos : pos + 4] = replacement

    return bytes(code)


def build_key_token_stub(
    entry_offset: int,
    cave_offset: int,
    original_instr: bytes,
    constants: bytes,
) -> bytes:
    if len(original_instr) != 4:
        raise ValueError("original_instr debe medir 4 bytes")
    if len(constants) != 10:
        raise ValueError("constants debe medir 10 bytes")

    code = bytearray()
    labels: dict[str, int] = {}
    relocs: list[tuple[int, str, str]] = []

    def pc() -> int:
        return cave_offset + len(code)

    def emit(raw: bytes) -> None:
        code.extend(raw)

    def mark(label: str) -> None:
        labels[label] = pc()

    def branch_later(kind: str, label: str) -> None:
        relocs.append((len(code), kind, label))
        emit(b"\x00\x00\x00\x00")

    branch_later("cbz_x0", "original")
    for index, expected in enumerate(constants):
        emit(ldrb_unsigned(9, 0, index))
        emit(ldrb_unsigned(10, 0, 19 - index))
        emit(eor_reg32(9, 9, 10))
        emit(cmp_imm32(9, expected))
        branch_later("b.ne", "original")

    emit(MOV_W0_ONE)
    emit(RET)

    mark("original")
    emit(original_instr)
    emit(branch_imm26(pc(), entry_offset + 4))

    for pos, kind, label in relocs:
        source = cave_offset + pos
        target = labels[label]
        if kind == "cbz_x0":
            replacement = cbz_x(source, target, 0)
        elif kind == "b.ne":
            replacement = branch_cond(source, target, 1)
        else:
            raise ValueError(f"reloc desconocido: {kind}")
        code[pos : pos + 4] = replacement

    return bytes(code)


def build_key_runtime_serial_compact_stub(
    entry_offset: int,
    serial_func_offset: int,
    masks: bytes,
    debug_stop: str | None = None,
) -> bytes:
    if len(masks) != len(RUNTIME_SERIAL_TOKEN_POSITIONS):
        raise ValueError("masks debe medir 10 bytes")

    code = bytearray()
    labels: dict[str, int] = {}
    relocs: list[tuple[int, str, str]] = []

    def pc() -> int:
        return entry_offset + len(code)

    def emit(raw: bytes) -> None:
        code.extend(raw)

    def mark(label: str) -> None:
        labels[label] = pc()

    def branch_later(kind: str, label: str) -> None:
        relocs.append((len(code), kind, label))
        emit(b"\x00\x00\x00\x00")

    def emit_zero_return() -> None:
        emit(mov_reg32(0, 31))
        emit(RET)

    def emit_restore() -> None:
        emit(ldr_unsigned(21, 31, 0x58, 64))
        emit(ldr_unsigned(19, 31, 0x60, 64))
        emit(ldr_unsigned(30, 31, 0x68, 64))
        emit(add_imm64(31, 31, 0x70))

    def emit_restore_zero_return() -> None:
        emit_restore()
        emit_zero_return()

    branch_later("cbz_x0", "fail_direct")
    emit(sub_imm64(31, 31, 0x70))
    emit(str_unsigned(30, 31, 0x68, 64))
    emit(str_unsigned(19, 31, 0x60, 64))
    emit(str_unsigned(21, 31, 0x58, 64))
    emit(mov_reg64(19, 0))

    emit(str_unsigned(31, 31, 0x10, 32))
    emit(str_unsigned(31, 31, 0x14, 32))
    emit(str_unsigned(31, 31, 0x18, 32))
    if debug_stop == "before_serial":
        emit_restore_zero_return()
    emit(add_imm64(0, 31, 0x10))
    emit(branch_imm26(pc(), serial_func_offset, opcode=0x94000000))
    if debug_stop == "after_serial":
        emit_restore_zero_return()
    emit(add_imm64(21, 31, 0x10))

    for index, serial_pos in enumerate(RUNTIME_SERIAL_TOKEN_POSITIONS):
        emit(ldrb_unsigned(11, 21, serial_pos))
        branch_later("cbz_w11", "fail")
        emit(cmp_imm32(11, 0x7F))
        branch_later("b.hi", "fail")
        emit(mov_imm32(12, masks[index]))
        emit(eor_reg32(11, 11, 12))
        emit(ldrb_unsigned(9, 19, index))
        emit(ldrb_unsigned(10, 19, 19 - index))
        emit(eor_reg32(9, 9, 10))
        emit(cmp_reg(9, 11, 32))
        branch_later("b.ne", "fail")

    if debug_stop == "token_ok":
        emit_restore_zero_return()
    emit_restore()
    emit(MOV_W0_ONE)
    emit(RET)

    mark("fail")
    if debug_stop == "token_fail":
        emit_restore_zero_return()
    else:
        emit_restore_zero_return()

    mark("fail_direct")
    emit_zero_return()

    for pos, kind, label in relocs:
        source = entry_offset + pos
        target = labels[label]
        if kind == "cbz_x0":
            replacement = cbz_x(source, target, 0)
        elif kind == "cbz_w11":
            replacement = cbz_w(source, target, 11)
        elif kind == "b.ne":
            replacement = branch_cond(source, target, 1)
        elif kind == "b.hi":
            replacement = branch_cond(source, target, 8)
        else:
            raise ValueError(f"reloc desconocido: {kind}")
        code[pos : pos + 4] = replacement

    return bytes(code)


def key_validator_thumb_return_values(validator: dict[str, object]) -> tuple[int, int]:
    for edge in validator.get("failure_edges", []):
        if not isinstance(edge, dict):
            continue
        branch = str(edge.get("branch", "")).lower()
        if branch == "cbnz":
            return 1, 0
        if branch == "cbz":
            return 0, 1
    return 1, 0


def adjust_thumb_serial_func_offset(data: bytes | bytearray, serial_func_offset: int) -> int:
    if serial_func_offset >= 4 and serial_func_offset + 2 <= len(data):
        prev0 = struct.unpack_from("<H", data, serial_func_offset - 4)[0]
        prev1 = struct.unpack_from("<H", data, serial_func_offset - 2)[0]
        here = struct.unpack_from("<H", data, serial_func_offset)[0]
        is_ldr_r1_pc = (prev0 & 0xF800) == 0x4800 and ((prev0 >> 8) & 7) == 1
        is_mov_r2_r0 = prev1 == 0x4602
        is_push = (here & 0xFE00) == 0xB400
        if is_ldr_r1_pc and is_mov_r2_r0 and is_push:
            return serial_func_offset - 4
    return serial_func_offset


def build_thumb_key_runtime_serial_compact_stub(
    entry_offset: int,
    serial_func_offset: int,
    masks: bytes,
    success_value: int,
    fail_value: int,
) -> bytes:
    if len(masks) != len(RUNTIME_SERIAL_TOKEN_POSITIONS):
        raise ValueError("masks debe medir 10 bytes")
    if success_value not in (0, 1) or fail_value not in (0, 1):
        raise ValueError("success/fail Thumb deben ser booleanos")

    code = bytearray()
    labels: dict[str, int] = {}
    relocs: list[tuple[int, str, str]] = []

    def pc() -> int:
        return entry_offset + len(code)

    def emit(raw: bytes) -> None:
        code.extend(raw)

    def mark(label: str) -> None:
        labels[label] = pc()

    def branch_later(kind: str, label: str) -> None:
        relocs.append((len(code), kind, label))
        emit(b"\x00\x00\x00\x00\x00\x00")

    emit(thumb_cmp_imm(0, 0))
    branch_later("beq", "fail_direct")
    emit(thumb_push((4, 5, 6, 14)))
    emit(thumb_sub_sp(0x20))
    emit(thumb_mov_reg(4, 0))
    emit(thumb_movs_imm(1, 0))
    emit(thumb_str_sp_imm(1, 0))
    emit(thumb_str_sp_imm(1, 4))
    emit(thumb_str_sp_imm(1, 8))
    emit(thumb_str_sp_imm(1, 12))
    emit(thumb_str_sp_imm(1, 16))
    emit(thumb_str_sp_imm(1, 20))
    emit(thumb_str_sp_imm(1, 24))
    emit(thumb_str_sp_imm(1, 28))
    emit(thumb_add_sp_to_reg(0, 0))
    emit(thumb_bl(pc(), serial_func_offset))
    emit(thumb_add_sp_to_reg(5, 0))

    for index, serial_pos in enumerate(RUNTIME_SERIAL_TOKEN_POSITIONS):
        emit(thumb_ldrb_imm(1, 5, serial_pos))
        emit(thumb_cmp_imm(1, 0))
        branch_later("beq", "fail")
        emit(thumb_cmp_imm(1, 0x7F))
        branch_later("bhi", "fail")
        emit(thumb_movs_imm(6, masks[index]))
        emit(thumb_eors(1, 6))
        emit(thumb_ldrb_imm(2, 4, index))
        emit(thumb_ldrb_imm(3, 4, 19 - index))
        emit(thumb_eors(2, 3))
        emit(thumb_cmp_reg(2, 1))
        branch_later("bne", "fail")

    mark("success")
    emit(thumb_add_sp(0x20))
    emit(thumb_movs_imm(0, success_value))
    emit(thumb_pop((4, 5, 6, 15)))

    mark("fail")
    emit(thumb_add_sp(0x20))
    emit(thumb_movs_imm(0, fail_value))
    emit(thumb_pop((4, 5, 6, 15)))

    mark("fail_direct")
    emit(thumb_movs_imm(0, fail_value))
    emit(thumb_bx_lr())

    for pos, kind, label in relocs:
        source = entry_offset + pos
        target = labels[label]
        if kind == "beq":
            inverse_cond = 1
        elif kind == "bne":
            inverse_cond = 0
        elif kind == "bhi":
            inverse_cond = 9
        else:
            raise ValueError(f"reloc Thumb desconocido: {kind}")
        replacement = (
            thumb_b_cond16(source, source + 6, inverse_cond)
            + thumb_b_w(source + 2, target)
        )
        code[pos : pos + 6] = replacement

    return bytes(code)


def emit_byte_compare(
    code: bytearray,
    relocs: list[tuple[int, str, str]],
    rn: int,
    offset: int,
    expected: int,
    failure_label: str,
) -> None:
    code.extend(ldrb_unsigned(9, rn, offset))
    code.extend(cmp_imm32(9, expected))
    relocs.append((len(code), "b.ne", failure_label))
    code.extend(b"\x00\x00\x00\x00")


def build_erase_token_pre_stub(
    hook_offset: int,
    cave_offset: int,
    original_instr: bytes,
    partition: bytes,
    constants: bytes,
    marker: int = 0xA5,
) -> bytes:
    if len(original_instr) != 4:
        raise ValueError("original_instr debe medir 4 bytes")
    if len(constants) != 10:
        raise ValueError("constants debe medir 10 bytes")

    code = bytearray()
    labels: dict[str, int] = {}
    relocs: list[tuple[int, str, str]] = []

    def pc() -> int:
        return cave_offset + len(code)

    def emit(raw: bytes) -> None:
        code.extend(raw)

    def mark(label: str) -> None:
        labels[label] = pc()

    def branch_later(kind: str, label: str) -> None:
        relocs.append((len(code), kind, label))
        emit(b"\x00\x00\x00\x00")

    for index, expected in enumerate(partition):
        emit_byte_compare(code, relocs, 19, index, expected, "original")
    emit_byte_compare(code, relocs, 19, len(partition), ord("_"), "original")
    emit_byte_compare(code, relocs, 19, len(partition) + 1, ord("_"), "original")

    token_offset = len(partition) + 2
    for index, expected in enumerate(constants):
        emit(ldrb_unsigned(9, 19, token_offset + index))
        emit(ldrb_unsigned(10, 19, token_offset + 19 - index))
        emit(eor_reg32(9, 9, 10))
        emit(cmp_imm32(9, expected))
        branch_later("b.ne", "original")

    emit_byte_compare(code, relocs, 19, token_offset + 20, 0, "original")
    emit(strb_unsigned(31, 19, len(partition)))
    emit(mov_imm32(9, marker))
    emit(strb_unsigned(9, 19, len(partition) + 1))

    mark("original")
    emit(relocate_aarch64_branch(original_instr, hook_offset, pc()))
    emit(branch_imm26(pc(), hook_offset + 4))

    for pos, kind, label in relocs:
        source = cave_offset + pos
        target = labels[label]
        if kind == "b.ne":
            replacement = branch_cond(source, target, 1)
        else:
            raise ValueError(f"reloc desconocido: {kind}")
        code[pos : pos + 4] = replacement

    return bytes(code)


def build_erase_token_gate_stub(
    hook_offset: int,
    cave_offset: int,
    allowed_target: int,
    denied_target: int,
    partition: bytes,
    marker: int = 0xA5,
) -> bytes:
    code = bytearray()
    labels: dict[str, int] = {}
    relocs: list[tuple[int, str, str]] = []

    def pc() -> int:
        return cave_offset + len(code)

    def emit(raw: bytes) -> None:
        code.extend(raw)

    def mark(label: str) -> None:
        labels[label] = pc()

    def branch_later(kind: str, label: str) -> None:
        relocs.append((len(code), kind, label))
        emit(b"\x00\x00\x00\x00")

    emit(cmp_imm32(0, 0))
    branch_later("b.ne", "allow")

    for index, expected in enumerate(partition):
        emit_byte_compare(code, relocs, 19, index, expected, "deny")
    emit_byte_compare(code, relocs, 19, len(partition), 0, "deny")
    emit_byte_compare(code, relocs, 19, len(partition) + 1, marker, "deny")
    branch_later("b", "allow")

    mark("deny")
    emit(branch_imm26(pc(), denied_target))

    mark("allow")
    emit(branch_imm26(pc(), allowed_target))

    for pos, kind, label in relocs:
        source = cave_offset + pos
        target = labels[label]
        if kind == "b.ne":
            replacement = branch_cond(source, target, 1)
        elif kind == "b":
            replacement = branch_imm26(source, target)
        else:
            raise ValueError(f"reloc desconocido: {kind}")
        code[pos : pos + 4] = replacement

    if hook_offset % 4:
        raise ValueError(f"hook gate no alineado: 0x{hook_offset:x}")
    return bytes(code)


def build_erase_token_pre_stub_from_pointer(
    hook_offset: int,
    cave_offset: int,
    original_instr: bytes,
    partition: bytes,
    constants: bytes,
    pointer_reg: int,
    marker: int = 0xA5,
) -> bytes:
    if len(original_instr) != 4:
        raise ValueError("original_instr debe medir 4 bytes")
    if len(constants) != 10:
        raise ValueError("constants debe medir 10 bytes")

    code = bytearray()
    labels: dict[str, int] = {}
    relocs: list[tuple[int, str, str]] = []

    def pc() -> int:
        return cave_offset + len(code)

    def emit(raw: bytes) -> None:
        code.extend(raw)

    def mark(label: str) -> None:
        labels[label] = pc()

    def branch_later(kind: str, label: str) -> None:
        relocs.append((len(code), kind, label))
        emit(b"\x00\x00\x00\x00")

    for index, expected in enumerate(partition):
        emit_byte_compare(code, relocs, pointer_reg, index, expected, "original")
    emit_byte_compare(code, relocs, pointer_reg, len(partition), ord("_"), "original")
    emit_byte_compare(code, relocs, pointer_reg, len(partition) + 1, ord("_"), "original")

    token_offset = len(partition) + 2
    for index, expected in enumerate(constants):
        emit(ldrb_unsigned(9, pointer_reg, token_offset + index))
        emit(ldrb_unsigned(10, pointer_reg, token_offset + 19 - index))
        emit(eor_reg32(9, 9, 10))
        emit(cmp_imm32(9, expected))
        branch_later("b.ne", "original")

    emit_byte_compare(code, relocs, pointer_reg, token_offset + 20, 0, "original")
    emit(strb_unsigned(31, pointer_reg, len(partition)))
    emit(mov_imm32(9, marker))
    emit(strb_unsigned(9, pointer_reg, len(partition) + 1))

    mark("original")
    emit(relocate_aarch64_branch(original_instr, hook_offset, pc()))
    emit(branch_imm26(pc(), hook_offset + 4))

    for pos, kind, label in relocs:
        source = cave_offset + pos
        target = labels[label]
        if kind == "b.ne":
            replacement = branch_cond(source, target, 1)
        else:
            raise ValueError(f"reloc desconocido: {kind}")
        code[pos : pos + 4] = replacement

    return bytes(code)


def build_erase_token_gate_stub_from_argument(
    hook_offset: int,
    cave_offset: int,
    allowed_target: int,
    denied_target: int,
    partition: bytes,
    argument_reg: int,
    token_allowed_target: int | None = None,
    token_denied_target: int | None = None,
    marker: int = 0xA5,
) -> bytes:
    if token_allowed_target is None:
        token_allowed_target = allowed_target
    if token_denied_target is None:
        token_denied_target = denied_target

    code = bytearray()
    labels: dict[str, int] = {}
    relocs: list[tuple[int, str, str]] = []

    def pc() -> int:
        return cave_offset + len(code)

    def emit(raw: bytes) -> None:
        code.extend(raw)

    def mark(label: str) -> None:
        labels[label] = pc()

    def branch_later(kind: str, label: str) -> None:
        relocs.append((len(code), kind, label))
        emit(b"\x00\x00\x00\x00")

    emit(cmp_imm32(0, 0))
    branch_later("b.ne", "original_allow")
    emit(add_imm64(11, argument_reg, 1))

    for index, expected in enumerate(partition):
        emit_byte_compare(code, relocs, 11, index, expected, "deny")
    emit(ldrb_unsigned(9, 11, len(partition)))
    emit(cmp_imm32(9, 0))
    branch_later("b.ne", "target_name_invalid")
    emit(ldrb_unsigned(9, 11, len(partition) + 1))
    emit(cmp_imm32(9, marker))
    branch_later("b.ne", "target_name_denied")
    branch_later("b", "token_allow")

    mark("target_name_invalid")
    emit(cmp_imm32(9, ord("_")))
    branch_later("b.ne", "deny")

    mark("target_name_denied")
    emit(branch_imm26(pc(), token_denied_target))

    mark("deny")
    emit(branch_imm26(pc(), denied_target))

    mark("token_allow")
    emit(branch_imm26(pc(), token_allowed_target))

    mark("original_allow")
    emit(branch_imm26(pc(), allowed_target))

    for pos, kind, label in relocs:
        source = cave_offset + pos
        target = labels[label]
        if kind == "b.ne":
            replacement = branch_cond(source, target, 1)
        elif kind == "b":
            replacement = branch_imm26(source, target)
        else:
            raise ValueError(f"reloc desconocido: {kind}")
        code[pos : pos + 4] = replacement

    if hook_offset % 4:
        raise ValueError(f"hook gate no alineado: 0x{hook_offset:x}")
    return bytes(code)


def build_erase_token_gate_stub_from_pointer(
    hook_offset: int,
    cave_offset: int,
    allowed_target: int,
    denied_target: int,
    partition: bytes,
    pointer_reg: int,
    token_allowed_target: int | None = None,
    token_denied_target: int | None = None,
    marker: int = 0xA5,
) -> bytes:
    if token_allowed_target is None:
        token_allowed_target = allowed_target
    if token_denied_target is None:
        token_denied_target = denied_target

    code = bytearray()
    labels: dict[str, int] = {}
    relocs: list[tuple[int, str, str]] = []

    def pc() -> int:
        return cave_offset + len(code)

    def emit(raw: bytes) -> None:
        code.extend(raw)

    def mark(label: str) -> None:
        labels[label] = pc()

    def branch_later(kind: str, label: str) -> None:
        relocs.append((len(code), kind, label))
        emit(b"\x00\x00\x00\x00")

    emit(cmp_imm32(0, 0))
    branch_later("b.ne", "original_allow")

    for index, expected in enumerate(partition):
        emit_byte_compare(code, relocs, pointer_reg, index, expected, "deny")
    emit(ldrb_unsigned(9, pointer_reg, len(partition)))
    emit(cmp_imm32(9, 0))
    branch_later("b.ne", "target_name_invalid")
    emit(ldrb_unsigned(9, pointer_reg, len(partition) + 1))
    emit(cmp_imm32(9, marker))
    branch_later("b.ne", "target_name_denied")
    branch_later("b", "token_allow")

    mark("target_name_invalid")
    emit(cmp_imm32(9, ord("_")))
    branch_later("b.ne", "deny")

    mark("target_name_denied")
    emit(branch_imm26(pc(), token_denied_target))

    mark("deny")
    emit(branch_imm26(pc(), denied_target))

    mark("token_allow")
    emit(branch_imm26(pc(), token_allowed_target))

    mark("original_allow")
    emit(branch_imm26(pc(), allowed_target))

    for pos, kind, label in relocs:
        source = cave_offset + pos
        target = labels[label]
        if kind == "b.ne":
            replacement = branch_cond(source, target, 1)
        elif kind == "b":
            replacement = branch_imm26(source, target)
        else:
            raise ValueError(f"reloc desconocido: {kind}")
        code[pos : pos + 4] = replacement

    if hook_offset % 4:
        raise ValueError(f"hook gate no alineado: 0x{hook_offset:x}")
    return bytes(code)


def build_erase_command_gate_stub_from_pointer(
    hook_offset: int,
    cave_offset: int,
    allowed_target: int,
    denied_target: int,
    partition: bytes,
    pointer_reg: int,
    pointer_from_argument: bool = False,
    marker: int = 0xA5,
) -> bytes:
    code = bytearray()
    labels: dict[str, int] = {}
    relocs: list[tuple[int, str, str]] = []

    def pc() -> int:
        return cave_offset + len(code)

    def emit(raw: bytes) -> None:
        code.extend(raw)

    def mark(label: str) -> None:
        labels[label] = pc()

    def branch_later(kind: str, label: str) -> None:
        relocs.append((len(code), kind, label))
        emit(b"\x00\x00\x00\x00")

    active_pointer_reg = pointer_reg
    if pointer_from_argument:
        active_pointer_reg = 11
        emit(add_imm64(active_pointer_reg, pointer_reg, 1))

    for index, expected in enumerate(partition):
        emit_byte_compare(code, relocs, active_pointer_reg, index, expected, "original_decision")

    emit(ldrb_unsigned(9, active_pointer_reg, len(partition)))
    emit(cmp_imm32(9, 0))
    branch_later("b.ne", "target_name_invalid")

    emit(ldrb_unsigned(9, active_pointer_reg, len(partition) + 1))
    emit(cmp_imm32(9, marker))
    branch_later("b.eq", "token_allow")
    branch_later("b", "original_decision")

    mark("target_name_invalid")
    emit(cmp_imm32(9, ord("_")))
    branch_later("b.ne", "original_decision")
    branch_later("b", "token_deny")

    mark("token_deny")
    emit(branch_imm26(pc(), denied_target))

    mark("token_allow")
    emit(branch_imm26(pc(), allowed_target))

    mark("original_decision")
    emit(cmn_imm32(0, 1))
    branch_later("b.eq", "original_allow")
    branch_later("b", "original_deny")

    mark("original_allow")
    emit(branch_imm26(pc(), allowed_target))

    mark("original_deny")
    emit(branch_imm26(pc(), denied_target))

    for pos, kind, label in relocs:
        source = cave_offset + pos
        target = labels[label]
        if kind == "b.ne":
            replacement = branch_cond(source, target, 1)
        elif kind == "b.eq":
            replacement = branch_cond(source, target, 0)
        elif kind == "b":
            replacement = branch_imm26(source, target)
        else:
            raise ValueError(f"reloc desconocido: {kind}")
        code[pos : pos + 4] = replacement

    if hook_offset % 4:
        raise ValueError(f"hook gate no alineado: 0x{hook_offset:x}")
    return bytes(code)


def build_erase_command_late_name_stub(
    hook_offset: int,
    cave_offset: int,
    original_instr: bytes,
    partition: bytes,
    constants: bytes,
    command_reg: int = 21,
) -> bytes:
    if len(original_instr) != 4:
        raise ValueError("original_instr debe medir 4 bytes")
    if len(constants) != 10:
        raise ValueError("constants debe medir 10 bytes")

    code = bytearray()
    labels: dict[str, int] = {}
    relocs: list[tuple[int, str, str]] = []

    def pc() -> int:
        return cave_offset + len(code)

    def emit(raw: bytes) -> None:
        code.extend(raw)

    def mark(label: str) -> None:
        labels[label] = pc()

    def branch_later(kind: str, label: str) -> None:
        relocs.append((len(code), kind, label))
        emit(b"\x00\x00\x00\x00")

    emit(ldr_unsigned(11, command_reg, 0x10, 64))
    emit(add_imm64(11, 11, 1))

    for index, expected in enumerate(partition):
        emit_byte_compare(code, relocs, 11, index, expected, "original")
    emit_byte_compare(code, relocs, 11, len(partition), ord("_"), "original")
    emit_byte_compare(code, relocs, 11, len(partition) + 1, ord("_"), "original")

    token_offset = len(partition) + 2
    for index, expected in enumerate(constants):
        emit(ldrb_unsigned(9, 11, token_offset + index))
        emit(ldrb_unsigned(10, 11, token_offset + 19 - index))
        emit(eor_reg32(9, 9, 10))
        emit(cmp_imm32(9, expected))
        branch_later("b.ne", "original")

    emit_byte_compare(code, relocs, 11, token_offset + 20, 0, "original")
    emit(strb_unsigned(31, 11, len(partition)))

    mark("original")
    emit(relocate_aarch64_branch(original_instr, hook_offset, pc()))
    emit(branch_imm26(pc(), hook_offset + 4))

    for pos, kind, label in relocs:
        source = cave_offset + pos
        target = labels[label]
        if kind == "b.ne":
            replacement = branch_cond(source, target, 1)
        else:
            raise ValueError(f"reloc desconocido: {kind}")
        code[pos : pos + 4] = replacement

    return bytes(code)


def build_thumb_erase_token_pre_stub(
    hook_offset: int,
    cave_offset: int,
    partition: bytes,
    constants: bytes,
    marker: int = 0xA5,
) -> bytes:
    if len(constants) != 10:
        raise ValueError("constants debe medir 10 bytes")
    if len(partition) + 23 > 31:
        raise ValueError("particion demasiado larga para stub Thumb de token")

    code = bytearray()
    labels: dict[str, int] = {}
    relocs: list[tuple[int, str, str]] = []

    def pc() -> int:
        return cave_offset + len(code)

    def emit(raw: bytes) -> None:
        code.extend(raw)

    def mark(label: str) -> None:
        labels[label] = pc()

    def bne_later(label: str) -> None:
        relocs.append((len(code), "bne16", label))
        emit(b"\x00\x00")

    emit(thumb_ldr_imm(4, 4, 0x0C))
    emit(thumb_movs_imm(2, 0x48))
    emit(thumb_add_imm3(0, 4, 1))

    for index, expected in enumerate(partition):
        emit(thumb_ldrb_imm(3, 0, index))
        emit(thumb_cmp_imm(3, expected))
        bne_later("done")
    emit(thumb_ldrb_imm(3, 0, len(partition)))
    emit(thumb_cmp_imm(3, ord("_")))
    bne_later("done")
    emit(thumb_ldrb_imm(3, 0, len(partition) + 1))
    emit(thumb_cmp_imm(3, ord("_")))
    bne_later("done")

    token_offset = len(partition) + 2
    for index, expected in enumerate(constants):
        emit(thumb_ldrb_imm(2, 0, token_offset + index))
        emit(thumb_ldrb_imm(3, 0, token_offset + 19 - index))
        emit(thumb_eors(2, 3))
        emit(thumb_cmp_imm(2, expected))
        bne_later("done")

    emit(thumb_ldrb_imm(3, 0, token_offset + 20))
    emit(thumb_cmp_imm(3, 0))
    bne_later("done")
    emit(thumb_movs_imm(3, 0))
    emit(thumb_strb_imm(3, 0, len(partition)))
    emit(thumb_movs_imm(3, marker))
    emit(thumb_strb_imm(3, 0, len(partition) + 1))

    mark("done")
    emit(thumb_movs_imm(2, 0x48))
    emit(thumb_b_w(pc(), hook_offset + 4))

    for pos, kind, label in relocs:
        source = cave_offset + pos
        target = labels[label]
        if kind == "bne16":
            replacement = thumb_b_cond16(source, target, 1)
        else:
            raise ValueError(f"reloc Thumb desconocido: {kind}")
        code[pos : pos + 2] = replacement

    return bytes(code)


def build_thumb_key_token_stub(
    entry_offset: int,
    cave_offset: int,
    original_instr: bytes,
    constants: bytes,
) -> bytes:
    if len(original_instr) != 4:
        raise ValueError("original_instr debe medir 4 bytes")
    if len(constants) != 10:
        raise ValueError("constants debe medir 10 bytes")

    code = bytearray()
    labels: dict[str, int] = {}
    relocs: list[tuple[int, str, str]] = []

    def pc() -> int:
        return cave_offset + len(code)

    def emit(raw: bytes) -> None:
        code.extend(raw)

    def mark(label: str) -> None:
        labels[label] = pc()

    def bne_later(label: str) -> None:
        relocs.append((len(code), "bne16", label))
        emit(b"\x00\x00")

    def beq_later(label: str) -> None:
        relocs.append((len(code), "beq16", label))
        emit(b"\x00\x00")

    emit(thumb_cmp_imm(0, 0))
    beq_later("original")
    for index, expected in enumerate(constants):
        emit(thumb_ldrb_imm(2, 0, index))
        emit(thumb_ldrb_imm(3, 0, 19 - index))
        emit(thumb_eors(2, 3))
        emit(thumb_cmp_imm(2, expected))
        bne_later("original")

    emit(thumb_movs_imm(0, 1))
    emit(u16(0x4770))  # bx lr

    mark("original")
    emit(original_instr)
    emit(thumb_b_w(pc(), entry_offset + 4))

    for pos, kind, label in relocs:
        source = cave_offset + pos
        target = labels[label]
        if kind == "bne16":
            replacement = thumb_b_cond16(source, target, 1)
        elif kind == "beq16":
            replacement = thumb_b_cond16(source, target, 0)
        else:
            raise ValueError(f"reloc Thumb desconocido: {kind}")
        code[pos : pos + 2] = replacement

    return bytes(code)


def build_thumb_erase_token_gate_stub(
    hook_offset: int,
    cave_offset: int,
    allowed_target: int,
    denied_target: int,
    partition: bytes,
    marker: int = 0xA5,
) -> bytes:
    if len(partition) + 1 > 31:
        raise ValueError("particion demasiado larga para stub Thumb de gate")

    code = bytearray()
    labels: dict[str, int] = {}
    relocs: list[tuple[int, str, str]] = []

    def pc() -> int:
        return cave_offset + len(code)

    def emit(raw: bytes) -> None:
        code.extend(raw)

    def mark(label: str) -> None:
        labels[label] = pc()

    def bne_later(label: str) -> None:
        relocs.append((len(code), "bne16", label))
        emit(b"\x00\x00")

    emit(thumb_cmp_imm(0, 0))
    bne_later("allow")

    for index, expected in enumerate(partition):
        emit(thumb_ldrb_imm(3, 4, index))
        emit(thumb_cmp_imm(3, expected))
        bne_later("deny")
    emit(thumb_ldrb_imm(3, 4, len(partition)))
    emit(thumb_cmp_imm(3, 0))
    bne_later("deny")
    emit(thumb_ldrb_imm(3, 4, len(partition) + 1))
    emit(thumb_cmp_imm(3, marker))
    bne_later("deny")

    mark("allow")
    emit(u16(0x4620))  # mov r0, r4; original instruction overwritten after the hook.
    emit(thumb_b_w(pc(), allowed_target))

    mark("deny")
    emit(thumb_b_w(pc(), denied_target))

    for pos, kind, label in relocs:
        source = cave_offset + pos
        target = labels[label]
        if kind == "bne16":
            replacement = thumb_b_cond16(source, target, 1)
        else:
            raise ValueError(f"reloc Thumb desconocido: {kind}")
        code[pos : pos + 2] = replacement

    return bytes(code)


def patch_key_custom_signature(
    data: bytearray,
    analysis_dir: Path,
    signature: bytes,
    cave_offset: int | None = None,
) -> dict[str, object]:
    validator = load_key_validator_entry(analysis_dir)
    entry_offset = parse_hxd_offset(str(validator["function_start_file_offset"]))
    function_end_offset = parse_hxd_offset(str(validator["function_end_file_offset"]))

    if entry_offset < 0 or entry_offset + 4 > len(data):
        raise ValueError(f"offset KEY fuera del archivo: 0x{entry_offset:x}")

    original_instr = bytes(data[entry_offset : entry_offset + 4])
    dummy_stub = build_key_signature_stub(entry_offset, entry_offset + 0x100, original_instr, signature)
    stub_size = len(dummy_stub)

    if cave_offset is None:
        cave_offset = find_zero_cave(data, stub_size, function_end_offset)
    require_zero_cave(data, cave_offset, stub_size)

    entry_branch = branch_imm26(entry_offset, cave_offset)
    stub = build_key_signature_stub(entry_offset, cave_offset, original_instr, signature)

    data[cave_offset : cave_offset + len(stub)] = stub
    data[entry_offset : entry_offset + 4] = entry_branch

    return {
        "entry_offset": entry_offset,
        "cave_offset": cave_offset,
        "stub_size": len(stub),
        "original_instr": original_instr,
        "entry_branch": entry_branch,
        "function_start": validator.get("function_start"),
        "function_end": validator.get("function_end"),
    }


def patch_key_token_gate(
    data: bytearray,
    analysis_dir: Path,
    constants: bytes,
    cave_offset: int | None = None,
) -> dict[str, object]:
    validator = load_key_validator_entry(analysis_dir)
    entry_offset = parse_hxd_offset(str(validator["function_start_file_offset"]))
    function_end_offset = parse_hxd_offset(str(validator["function_end_file_offset"]))

    if entry_offset < 0 or entry_offset + 4 > len(data):
        raise ValueError(f"offset KEY fuera del archivo: 0x{entry_offset:x}")

    original_instr = bytes(data[entry_offset : entry_offset + 4])
    dummy_stub = build_key_token_stub(entry_offset, entry_offset + 0x100, original_instr, constants)
    stub_size = len(dummy_stub)

    if cave_offset is None:
        cave_offset = find_zero_cave(data, stub_size, function_end_offset)
    require_zero_cave(data, cave_offset, stub_size)

    entry_branch = branch_imm26(entry_offset, cave_offset)
    stub = build_key_token_stub(entry_offset, cave_offset, original_instr, constants)

    data[cave_offset : cave_offset + len(stub)] = stub
    data[entry_offset : entry_offset + 4] = entry_branch

    return {
        "entry_offset": entry_offset,
        "cave_offset": cave_offset,
        "stub_size": len(stub),
        "original_instr": original_instr,
        "entry_branch": entry_branch,
        "function_start": validator.get("function_start"),
        "function_end": validator.get("function_end"),
    }


def patch_key_runtime_serial_token_gate(
    data: bytearray,
    analysis_dir: Path,
    secret: str,
    alphabet: str,
    cave_offset: int | None = None,
    debug_log: bool = False,
    debug_stop: str | None = None,
) -> dict[str, object]:
    validator = load_key_validator_entry(analysis_dir)
    serial_entry = load_serialno_runtime_entry(analysis_dir)
    base = load_analysis_base(analysis_dir)
    architecture = load_analysis_architecture(analysis_dir)

    entry_offset = parse_hxd_offset(str(validator["function_start_file_offset"]))
    function_end_offset = parse_hxd_offset(str(validator["function_end_file_offset"]))
    serial_func_offset = parse_hxd_offset(str(serial_entry["hw_get_serialno_string_file_offset"]))

    if entry_offset < 0 or entry_offset + 4 > len(data):
        raise ValueError(f"offset KEY fuera del archivo: 0x{entry_offset:x}")
    if serial_func_offset < 0 or serial_func_offset + 4 > len(data):
        raise ValueError(f"offset serialno fuera del archivo: 0x{serial_func_offset:x}")

    if cave_offset is not None:
        raise ValueError("--key-cave-offset no aplica al modo runtime-serial compacto")
    if debug_log:
        raise ValueError(
            "--key-token-debug-log ya no aplica al modo compacto; usa --key-token-debug-stop"
        )
    if alphabet != "alnum":
        raise ValueError("runtime-serial compacto solo soporta --key-token-alphabet alnum")

    masks = derive_runtime_serial_compact_masks(secret)
    success_value: int | None = None
    fail_value: int | None = None
    if architecture == "arm32_thumb":
        if debug_stop:
            raise ValueError("--key-token-debug-stop no esta implementado para ARM32 runtime-serial")
        serial_func_offset = adjust_thumb_serial_func_offset(data, serial_func_offset)
        if serial_func_offset % 2:
            raise ValueError(f"serialno Thumb no alineado: 0x{serial_func_offset:x}")
        success_value, fail_value = key_validator_thumb_return_values(validator)
        stub = build_thumb_key_runtime_serial_compact_stub(
            entry_offset,
            serial_func_offset,
            masks,
            success_value,
            fail_value,
        )
    else:
        entry_offset = adjust_aarch64_pac_function_entry(data, validator, entry_offset, base)
        serial_func_offset = adjust_aarch64_pac_prologue_offset(data, serial_func_offset)
        function_size = function_end_offset - entry_offset
        stub = build_key_runtime_serial_compact_stub(
            entry_offset,
            serial_func_offset,
            masks,
            debug_stop,
        )
    if architecture == "arm32_thumb":
        function_size = function_end_offset - entry_offset
    if len(stub) > function_size:
        raise ValueError(
            f"stub runtime serial compacto demasiado grande: {len(stub)} > {function_size}"
        )

    original_instr = bytes(data[entry_offset : entry_offset + len(stub)])
    data[entry_offset : entry_offset + len(stub)] = stub

    return {
        "entry_offset": entry_offset,
        "cave_offset": None,
        "stub_size": len(stub),
        "architecture": architecture,
        "masks": masks,
        "success_value": success_value,
        "fail_value": fail_value,
        "serial_func_offset": serial_func_offset,
        "serial_func_va": base + serial_func_offset,
        "serial_confidence": serial_entry.get("confidence"),
        "debug_log": bool(debug_log),
        "debug_stop": debug_stop,
        "debug_print_func_offset": None,
        "debug_print_func_va": None,
        "debug_info_va": None,
        "debug_message_vas": {},
        "original_instr": original_instr,
        "entry_branch": stub,
        "function_start": validator.get("function_start"),
        "function_end": validator.get("function_end"),
    }


def patch_key_token_gate_thumb(
    data: bytearray,
    analysis_dir: Path,
    constants: bytes,
    cave_offset: int | None = None,
) -> dict[str, object]:
    validator = load_key_validator_entry(analysis_dir)
    entry_offset = parse_hxd_offset(str(validator["function_start_file_offset"]))
    function_end_offset = parse_hxd_offset(str(validator["function_end_file_offset"]))

    if entry_offset < 0 or entry_offset + 4 > len(data):
        raise ValueError(f"offset KEY fuera del archivo: 0x{entry_offset:x}")

    original_instr = bytes(data[entry_offset : entry_offset + 4])
    dummy_stub = build_thumb_key_token_stub(entry_offset, entry_offset + 0x100, original_instr, constants)
    stub_size = len(dummy_stub)

    if cave_offset is None:
        cave_offset = find_zero_cave(data, stub_size, function_end_offset)
    require_zero_cave(data, cave_offset, stub_size)

    entry_branch = thumb_b_w(entry_offset, cave_offset)
    stub = build_thumb_key_token_stub(entry_offset, cave_offset, original_instr, constants)

    data[cave_offset : cave_offset + len(stub)] = stub
    data[entry_offset : entry_offset + 4] = entry_branch

    return {
        "entry_offset": entry_offset,
        "cave_offset": cave_offset,
        "stub_size": len(stub),
        "original_instr": original_instr,
        "entry_branch": entry_branch,
        "function_start": validator.get("function_start"),
        "function_end": validator.get("function_end"),
    }


def patch_key_caller_before_key_checkpoint(
    data: bytearray,
    analysis_dir: Path,
    message: str = "LKDBG before key\n",
) -> dict[str, object]:
    validator = load_key_validator_entry(analysis_dir)
    callers = validator.get("callers", [])
    if not isinstance(callers, list) or not callers:
        raise ValueError("KEY validator no tiene caller para checkpoint")
    caller = callers[0]
    if not isinstance(caller, dict) or "call_site_file_offset" not in caller:
        raise ValueError("caller KEY invalido para checkpoint")
    call_offset = parse_hxd_offset(str(caller["call_site_file_offset"]))
    if call_offset < 0 or call_offset + 4 > len(data):
        raise ValueError(f"call KEY fuera del archivo: 0x{call_offset:x}")
    original = bytes(data[call_offset : call_offset + 4])
    if (struct.unpack("<I", original)[0] & 0xFC000000) != 0x94000000:
        raise ValueError(f"checkpoint no encontro BL KEY en 0x{call_offset:x}")
    data[call_offset : call_offset + 4] = mov_reg32(0, 31)
    message_patch = patch_code_validation_message(data, analysis_dir, message)
    return {
        "call_offset": call_offset,
        "original_instr": original,
        "replacement": bytes(data[call_offset : call_offset + 4]),
        "message_patch": message_patch,
    }


def patch_key_entry_zero_checkpoint(
    data: bytearray,
    analysis_dir: Path,
    message: str = "LKDBG entry\n",
) -> dict[str, object]:
    validator = load_key_validator_entry(analysis_dir)
    entry_offset = parse_hxd_offset(str(validator["function_start_file_offset"]))
    if entry_offset < 0 or entry_offset + 8 > len(data):
        raise ValueError(f"entrada KEY fuera del archivo: 0x{entry_offset:x}")
    original = bytes(data[entry_offset : entry_offset + 8])
    replacement = mov_reg32(0, 31) + RET
    data[entry_offset : entry_offset + 8] = replacement
    message_patch = patch_code_validation_message(data, analysis_dir, message)
    return {
        "entry_offset": entry_offset,
        "original_instr": original,
        "replacement": replacement,
        "message_patch": message_patch,
    }


def find_erase_token_hooks(check: dict[str, object]) -> tuple[int, int, int]:
    structural = check.get("structural_instructions", [])
    if not isinstance(structural, list):
        raise ValueError("erase_permission_check no tiene structural_instructions valido")

    skip_colon_offset: int | None = None
    for item in structural:
        if not isinstance(item, dict):
            continue
        if item.get("role") == "partition_name_skip_colon":
            skip_colon_offset = parse_hxd_offset(str(item["hxd_offset"]))
            break
    if skip_colon_offset is None:
        raise ValueError("no se encontro partition_name_skip_colon en erase_permission_check")

    denied_edges = check.get("denied_edges", [])
    if not isinstance(denied_edges, list) or not denied_edges:
        raise ValueError("no se encontraron denied_edges en erase_permission_check")

    first_edge = denied_edges[0]
    if not isinstance(first_edge, dict):
        raise ValueError("denied_edges invalido en erase_permission_check")

    pre_hook_offset = skip_colon_offset + 4
    gate_hook_offset = parse_hxd_offset(str(first_edge["branch_file_offset"]))
    denied_target = parse_hxd_offset(str(first_edge["target_file_offset"]))
    return pre_hook_offset, gate_hook_offset, denied_target


def find_erase_command_token_hooks(
    data: bytes | bytearray,
    check: dict[str, object],
) -> tuple[int, int, int, int]:
    structural = check.get("structural_instructions", [])
    if not isinstance(structural, list):
        raise ValueError("erase command handler no tiene structural_instructions valido")

    skip_colon_offset: int | None = None
    for item in structural:
        if not isinstance(item, dict):
            continue
        if item.get("role") == "partition_name_skip_colon":
            skip_colon_offset = parse_hxd_offset(str(item["hxd_offset"]))
            break
    if skip_colon_offset is None:
        raise ValueError("no se encontro partition_name_skip_colon en erase command handler")

    function_start = parse_hxd_offset(str(check["function_start_file_offset"]))
    function_end = parse_hxd_offset(str(check["function_end_file_offset"]))
    pre_hook_offset = skip_colon_offset + 4

    for offset in range(max(function_start, pre_hook_offset), min(function_end, len(data) - 12), 4):
        prev_word = struct.unpack_from("<I", data, offset - 4)[0] if offset >= 4 else 0
        cmn_word = struct.unpack_from("<I", data, offset)[0]
        branch_word = struct.unpack_from("<I", data, offset + 4)[0]
        if (prev_word & 0xFC000000) != 0x94000000:
            continue
        if cmn_word != 0x3100041F:  # cmn w0,#1
            continue
        if (branch_word & 0xF) != 0:
            continue
        allowed_target = decode_cond_branch_target(branch_word, offset + 4)
        if allowed_target is None:
            continue
        allowed_offset = allowed_target
        denied_offset = offset + 8
        if function_start <= allowed_offset <= function_end and denied_offset <= function_end:
            return pre_hook_offset, offset + 4, allowed_offset, denied_offset

    raise ValueError("no se encontro gate de erase command handler: bl; cmn w0,#1; b.eq")


def find_aarch64_first_skip_colon_registers(check: dict[str, object]) -> tuple[int, int] | None:
    structural = check.get("structural_instructions", [])
    if not isinstance(structural, list):
        return None

    for item in structural:
        if not isinstance(item, dict):
            continue
        if item.get("role") != "partition_name_skip_colon":
            continue
        instruction = str(item.get("instruction", ""))
        match = re.search(r"^add\s+x(\d+),\s*x(\d+),\s*#1$", instruction)
        if match:
            return int(match.group(1)), int(match.group(2))
    return None


def has_aarch64_post_gate_name_filter(check: dict[str, object], gate_hook_offset: int) -> bool:
    structural = check.get("structural_instructions", [])
    if not isinstance(structural, list):
        return False

    for item in structural:
        if not isinstance(item, dict):
            continue
        try:
            offset = parse_hxd_offset(str(item["hxd_offset"]))
        except (KeyError, ValueError):
            continue
        if offset <= gate_hook_offset:
            continue
        instruction = str(item.get("instruction", ""))
        if re.search(r"\bcbn?z\s+w8\b", instruction):
            return True
    return False


def find_aarch64_direct_allowed_return(check: dict[str, object], gate_hook_offset: int) -> int | None:
    structural = check.get("structural_instructions", [])
    if not isinstance(structural, list):
        return None

    candidates: list[int] = []
    for item in structural:
        if not isinstance(item, dict):
            continue
        if item.get("role") != "return_status_value":
            continue
        instruction = str(item.get("instruction", ""))
        if not re.search(r"^mov\s+w20,\s*#1$", instruction):
            continue
        try:
            offset = parse_hxd_offset(str(item["hxd_offset"]))
        except (KeyError, ValueError):
            continue
        if offset > gate_hook_offset + 4:
            candidates.append(offset)
    return candidates[-1] if candidates else None


def find_aarch64_direct_denied_return(check: dict[str, object], gate_hook_offset: int) -> int | None:
    structural = check.get("structural_instructions", [])
    if not isinstance(structural, list):
        return None

    candidates: list[int] = []
    for item in structural:
        if not isinstance(item, dict):
            continue
        if item.get("role") != "return_status_value":
            continue
        instruction = str(item.get("instruction", ""))
        if not re.search(r"^mov\s+w20,\s*#3$", instruction):
            continue
        try:
            offset = parse_hxd_offset(str(item["hxd_offset"]))
        except (KeyError, ValueError):
            continue
        if offset > gate_hook_offset + 4:
            candidates.append(offset)
    return candidates[-1] if candidates else None


def patch_erase_token_gate(
    data: bytearray,
    analysis_dir: Path,
    partition: str,
    constants: bytes,
    cave_offset: int | None = None,
) -> dict[str, object]:
    check = load_erase_permission_entry(analysis_dir, data)
    function_end_offset = parse_hxd_offset(str(check["function_end_file_offset"]))
    command_handler_mode = False
    try:
        pre_hook_offset, gate_hook_offset, allowed_target, denied_target = find_erase_command_token_hooks(data, check)
        command_handler_mode = True
    except ValueError:
        pre_hook_offset, gate_hook_offset, denied_target = find_erase_token_hooks(check)
        allowed_target = gate_hook_offset + 4

    if pre_hook_offset < 0 or pre_hook_offset + 4 > len(data):
        raise ValueError(f"hook pre-token fuera del archivo: 0x{pre_hook_offset:x}")
    if gate_hook_offset < 0 or gate_hook_offset + 4 > len(data):
        raise ValueError(f"hook gate fuera del archivo: 0x{gate_hook_offset:x}")
    if command_handler_mode and (allowed_target < 0 or allowed_target + 4 > len(data)):
        raise ValueError(f"hook late-token fuera del archivo: 0x{allowed_target:x}")

    partition_raw = partition.encode("ascii")
    pre_original = bytes(data[pre_hook_offset : pre_hook_offset + 4])
    gate_original = bytes(data[gate_hook_offset : gate_hook_offset + 4])
    late_original = bytes(data[allowed_target : allowed_target + 4]) if command_handler_mode else None
    skip_regs = find_aarch64_first_skip_colon_registers(check)
    pre_pointer_reg = 19
    gate_pointer_reg: int | None = 19
    gate_argument_reg: int | None = None
    token_allowed_target = allowed_target
    token_allowed_note = "command_erase_path" if command_handler_mode else "fallthrough"
    token_denied_target = denied_target
    token_denied_note = "command_deny_path" if command_handler_mode else "original_error"

    if skip_regs is not None:
        skip_dest_reg, skip_source_reg = skip_regs
        pre_pointer_reg = skip_dest_reg
        moved_reg = decode_mov_reg64(pre_original)
        if (
            moved_reg is not None
            and moved_reg[0] == 0
            and moved_reg[1] == skip_dest_reg
        ):
            gate_pointer_reg = skip_dest_reg
            gate_argument_reg = None
        elif skip_dest_reg != 0 and 19 <= skip_dest_reg <= 28:
            gate_pointer_reg = skip_dest_reg
            gate_argument_reg = None
        else:
            gate_pointer_reg = None
            gate_argument_reg = skip_source_reg

    if not command_handler_mode and has_aarch64_post_gate_name_filter(check, gate_hook_offset):
        direct_allowed = find_aarch64_direct_allowed_return(check, gate_hook_offset)
        if direct_allowed is not None:
            token_allowed_target = direct_allowed
            token_allowed_note = "direct_return"
    if not command_handler_mode:
        direct_denied = find_aarch64_direct_denied_return(check, gate_hook_offset)
        if direct_denied is not None:
            token_denied_target = direct_denied
            token_denied_note = "direct_return"

    if command_handler_mode:
        pre_dummy = build_erase_token_pre_stub_from_pointer(
            pre_hook_offset,
            pre_hook_offset + 0x100,
            pre_original,
            partition_raw,
            constants,
            pointer_reg=pre_pointer_reg,
        )
        gate_dummy = build_erase_command_gate_stub_from_pointer(
            gate_hook_offset,
            gate_hook_offset + 0x200,
            token_allowed_target,
            token_denied_target,
            partition_raw,
            pointer_reg=gate_argument_reg if gate_argument_reg is not None else (
                gate_pointer_reg if gate_pointer_reg is not None else pre_pointer_reg
            ),
            pointer_from_argument=gate_argument_reg is not None,
        )
        late_dummy = build_erase_command_late_name_stub(
            allowed_target,
            gate_hook_offset + 0x400,
            late_original if late_original is not None else b"",
            partition_raw,
            constants,
        )
    elif gate_argument_reg is not None:
        pre_dummy = build_erase_token_pre_stub_from_pointer(
            pre_hook_offset,
            pre_hook_offset + 0x100,
            pre_original,
            partition_raw,
            constants,
            pointer_reg=pre_pointer_reg,
        )
        gate_dummy = build_erase_token_gate_stub_from_argument(
            gate_hook_offset,
            gate_hook_offset + 0x200,
            allowed_target,
            denied_target,
            partition_raw,
            argument_reg=gate_argument_reg,
            token_allowed_target=token_allowed_target,
            token_denied_target=token_denied_target,
        )
        late_dummy = b""
    else:
        pre_dummy = build_erase_token_pre_stub_from_pointer(
            pre_hook_offset,
            pre_hook_offset + 0x100,
            pre_original,
            partition_raw,
            constants,
            pointer_reg=pre_pointer_reg,
        )
        gate_dummy = build_erase_token_gate_stub_from_pointer(
            gate_hook_offset,
            gate_hook_offset + 0x200,
            allowed_target,
            denied_target,
            partition_raw,
            pointer_reg=gate_pointer_reg if gate_pointer_reg is not None else 19,
            token_allowed_target=token_allowed_target,
            token_denied_target=token_denied_target,
        )
        late_dummy = b""
    total_size = len(pre_dummy) + len(gate_dummy) + len(late_dummy)

    if cave_offset is None:
        cave_offset = find_zero_cave(data, total_size, function_end_offset)
    require_zero_cave(data, cave_offset, total_size)

    if gate_argument_reg is not None:
        pre_stub = build_erase_token_pre_stub_from_pointer(
            pre_hook_offset,
            cave_offset,
            pre_original,
            partition_raw,
            constants,
            pointer_reg=pre_pointer_reg,
        )
    else:
        pre_stub = build_erase_token_pre_stub_from_pointer(
            pre_hook_offset,
            cave_offset,
            pre_original,
            partition_raw,
            constants,
            pointer_reg=pre_pointer_reg,
    )
    gate_cave_offset = cave_offset + len(pre_stub)
    if command_handler_mode:
        gate_stub = build_erase_command_gate_stub_from_pointer(
            gate_hook_offset,
            gate_cave_offset,
            token_allowed_target,
            token_denied_target,
            partition_raw,
            pointer_reg=gate_argument_reg if gate_argument_reg is not None else (
                gate_pointer_reg if gate_pointer_reg is not None else pre_pointer_reg
            ),
            pointer_from_argument=gate_argument_reg is not None,
        )
        late_cave_offset = gate_cave_offset + len(gate_stub)
        late_stub = build_erase_command_late_name_stub(
            allowed_target,
            late_cave_offset,
            late_original if late_original is not None else b"",
            partition_raw,
            constants,
        )
    elif gate_argument_reg is not None:
        gate_stub = build_erase_token_gate_stub_from_argument(
            gate_hook_offset,
            gate_cave_offset,
            allowed_target,
            denied_target,
            partition_raw,
            argument_reg=gate_argument_reg,
            token_allowed_target=token_allowed_target,
            token_denied_target=token_denied_target,
        )
    else:
        gate_stub = build_erase_token_gate_stub_from_pointer(
            gate_hook_offset,
            gate_cave_offset,
            allowed_target,
            denied_target,
            partition_raw,
            pointer_reg=gate_pointer_reg if gate_pointer_reg is not None else 19,
            token_allowed_target=token_allowed_target,
            token_denied_target=token_denied_target,
        )
        late_cave_offset = None
        late_stub = b""

    pre_branch = branch_imm26(pre_hook_offset, cave_offset)
    gate_branch = branch_imm26(gate_hook_offset, gate_cave_offset)
    late_branch = branch_imm26(allowed_target, late_cave_offset) if command_handler_mode and late_cave_offset is not None else None

    data[cave_offset : cave_offset + len(pre_stub)] = pre_stub
    data[gate_cave_offset : gate_cave_offset + len(gate_stub)] = gate_stub
    if command_handler_mode and late_cave_offset is not None:
        data[late_cave_offset : late_cave_offset + len(late_stub)] = late_stub
    data[pre_hook_offset : pre_hook_offset + 4] = pre_branch
    data[gate_hook_offset : gate_hook_offset + 4] = gate_branch
    if command_handler_mode and late_branch is not None:
        data[allowed_target : allowed_target + 4] = late_branch
    flow_audits: dict[str, object] = {}
    if token_allowed_note == "direct_return":
        flow_audits["token_allow"] = audit_aarch64_direct_return_path(
            data, token_allowed_target, function_end_offset
        )
    if token_denied_note == "direct_return":
        flow_audits["token_deny"] = audit_aarch64_direct_return_path(
            data, token_denied_target, function_end_offset
        )

    return {
        "partition": partition,
        "pre_hook_offset": pre_hook_offset,
        "gate_hook_offset": gate_hook_offset,
        "denied_target": denied_target,
        "allowed_target": allowed_target,
        "token_allowed_target": token_allowed_target,
        "token_allowed_note": token_allowed_note,
        "token_denied_target": token_denied_target,
        "token_denied_note": token_denied_note,
        "cave_offset": cave_offset,
        "gate_cave_offset": gate_cave_offset,
        "late_hook_offset": allowed_target if command_handler_mode else None,
        "late_cave_offset": late_cave_offset if command_handler_mode else None,
        "pre_stub_size": len(pre_stub),
        "gate_stub_size": len(gate_stub),
        "late_stub_size": len(late_stub),
        "stub_size": len(pre_stub) + len(gate_stub) + len(late_stub),
        "pre_original": pre_original,
        "gate_original": gate_original,
        "late_original": late_original,
        "pre_branch": pre_branch,
        "gate_branch": gate_branch,
        "late_branch": late_branch,
        "flow_audits": flow_audits,
        "erase_token_mode": "command_handler" if command_handler_mode else "permission_validator",
        "argument_register": f"x{gate_argument_reg}" if gate_argument_reg is not None else None,
        "pre_pointer_register": f"x{pre_pointer_reg}",
        "gate_pointer_expression": (
            f"x{gate_argument_reg}+1"
            if gate_argument_reg is not None
            else f"x{gate_pointer_reg if gate_pointer_reg is not None else 19}"
        ),
        "function_start": check.get("function_start"),
        "function_end": check.get("function_end"),
    }


def find_thumb_erase_token_hooks(data: bytes | bytearray, check: dict[str, object]) -> tuple[int, int, int]:
    function_start = parse_hxd_offset(str(check["function_start_file_offset"]))
    function_end = parse_hxd_offset(str(check["function_end_file_offset"]))
    function_bytes = bytes(data[function_start:function_end])
    pre_rel = function_bytes.find(bytes.fromhex("e4684822"))
    if pre_rel < 0:
        raise ValueError("no se encontro hook Thumb de argumento erase_permission (e4684822)")
    pre_hook_offset = function_start + pre_rel

    gate_hook_offset: int | None = None
    denied_target: int | None = None
    for edge in check.get("denied_edges", []):
        if not isinstance(edge, dict):
            continue
        if edge.get("mnemonic") == "cbz":
            gate_hook_offset = parse_hxd_offset(str(edge["branch_hxd_offset"]))
            denied_target = parse_hxd_offset(str(edge["target_hxd_offset"]))
            break
    if gate_hook_offset is None or denied_target is None:
        raise ValueError("no se encontro gate Thumb cbz hacia erase permission denied")

    return pre_hook_offset, gate_hook_offset, denied_target


def patch_erase_token_gate_thumb(
    data: bytearray,
    analysis_dir: Path,
    partition: str,
    constants: bytes,
    cave_offset: int | None = None,
) -> dict[str, object]:
    check = load_erase_permission_entry(analysis_dir)
    function_end_offset = parse_hxd_offset(str(check["function_end_file_offset"]))
    pre_hook_offset, gate_hook_offset, denied_target = find_thumb_erase_token_hooks(data, check)
    allowed_target = gate_hook_offset + 4

    if pre_hook_offset < 0 or pre_hook_offset + 4 > len(data):
        raise ValueError(f"hook pre-token Thumb fuera del archivo: 0x{pre_hook_offset:x}")
    if gate_hook_offset < 0 or gate_hook_offset + 4 > len(data):
        raise ValueError(f"hook gate Thumb fuera del archivo: 0x{gate_hook_offset:x}")

    partition_raw = partition.encode("ascii")
    pre_original = bytes(data[pre_hook_offset : pre_hook_offset + 4])
    gate_original = bytes(data[gate_hook_offset : gate_hook_offset + 4])
    if pre_original != bytes.fromhex("e4684822"):
        raise ValueError(f"hook pre-token Thumb inesperado: 0x{pre_hook_offset:x} contiene {pre_original.hex()}")
    if gate_original[:2] != bytes.fromhex("40b1"):
        raise ValueError(f"hook gate Thumb inesperado: 0x{gate_hook_offset:x} contiene {gate_original.hex()}")

    pre_dummy = build_thumb_erase_token_pre_stub(pre_hook_offset, pre_hook_offset + 0x100, partition_raw, constants)
    gate_dummy = build_thumb_erase_token_gate_stub(
        gate_hook_offset,
        gate_hook_offset + 0x200,
        allowed_target,
        denied_target,
        partition_raw,
    )
    total_size = len(pre_dummy) + len(gate_dummy)

    if cave_offset is None:
        cave_offset = find_zero_cave(data, total_size, function_end_offset)
    require_zero_cave(data, cave_offset, total_size)

    pre_stub = build_thumb_erase_token_pre_stub(pre_hook_offset, cave_offset, partition_raw, constants)
    gate_cave_offset = cave_offset + len(pre_stub)
    gate_stub = build_thumb_erase_token_gate_stub(
        gate_hook_offset,
        gate_cave_offset,
        allowed_target,
        denied_target,
        partition_raw,
    )

    pre_branch = thumb_b_w(pre_hook_offset, cave_offset)
    gate_branch = thumb_b_w(gate_hook_offset, gate_cave_offset)

    data[cave_offset : cave_offset + len(pre_stub)] = pre_stub
    data[gate_cave_offset : gate_cave_offset + len(gate_stub)] = gate_stub
    data[pre_hook_offset : pre_hook_offset + 4] = pre_branch
    data[gate_hook_offset : gate_hook_offset + 4] = gate_branch

    return {
        "partition": partition,
        "pre_hook_offset": pre_hook_offset,
        "gate_hook_offset": gate_hook_offset,
        "allowed_target": allowed_target,
        "denied_target": denied_target,
        "cave_offset": cave_offset,
        "gate_cave_offset": gate_cave_offset,
        "stub_size": len(pre_stub) + len(gate_stub),
        "pre_stub_size": len(pre_stub),
        "gate_stub_size": len(gate_stub),
        "pre_original": pre_original,
        "gate_original": gate_original,
        "pre_branch": pre_branch,
        "gate_branch": gate_branch,
        "function_start": check.get("function_start"),
        "function_end": check.get("function_end"),
    }


def patch_frp_compare(data: bytearray, offset: int, value: int) -> tuple[bytes, bytes]:
    current = bytes(data[offset : offset + 4])
    if current not in {CMP_W8_ZERO, CMP_W8_ONE}:
        raise ValueError(
            f"offset 0x{offset:x} no contiene cmp w8,#0 ni cmp w8,#1; "
            f"contiene {current.hex()}"
        )

    replacement = CMP_W8_ONE if value == 1 else CMP_W8_ZERO
    data[offset : offset + 4] = replacement
    return current, replacement


def patch_frp_compare_thumb(data: bytearray, offset: int, value: int) -> tuple[bytes, bytes]:
    current = bytes(data[offset : offset + 6])
    if current not in {THUMB_FRP_ZERO_BOOL, THUMB_FRP_ONE_BOOL}:
        raise ValueError(
            f"offset 0x{offset:x} no contiene el patron FRP Thumb esperado; "
            f"contiene {current.hex()}"
        )

    replacement = THUMB_FRP_ONE_BOOL if value == 1 else THUMB_FRP_ZERO_BOOL
    data[offset : offset + 6] = replacement
    return current, replacement


def patch_frp_skip_call(data: bytearray, offset: int) -> tuple[bytes, bytes]:
    current = bytes(data[offset : offset + 4])
    if len(current) != 4:
        raise ValueError(f"offset FRP/OEM fuera del archivo: 0x{offset:x}")
    word = struct.unpack("<I", current)[0]
    if (word & 0xFC000000) != 0x94000000:
        raise ValueError(
            f"offset 0x{offset:x} no contiene BL AArch64 a FRP/OEM checker; "
            f"contiene {current.hex()}"
        )
    data[offset : offset + 4] = MOV_W0_ZERO
    return current, MOV_W0_ZERO


def patch_frp_skip_call_thumb(data: bytearray, offset: int) -> tuple[bytes, bytes]:
    current = bytes(data[offset : offset + 4])
    if not is_thumb_bl(data, offset):
        raise ValueError(
            f"offset 0x{offset:x} no contiene BL Thumb a FRP/OEM checker; "
            f"contiene {current.hex()}"
        )
    data[offset : offset + 4] = THUMB_MOVS_R0_ZERO_NOP
    return current, THUMB_MOVS_R0_ZERO_NOP


def patch_key_return_success(data: bytearray, offset: int) -> tuple[bytes, bytes]:
    current = bytes(data[offset : offset + 4])
    if current not in {MOV_W0_W20, MOV_W0_ONE}:
        raise ValueError(
            f"offset 0x{offset:x} no contiene mov w0,w20 ni mov w0,#1; "
            f"contiene {current.hex()}"
        )

    data[offset : offset + 4] = MOV_W0_ONE
    return current, MOV_W0_ONE


def patch_key_entry_force_success(
    data: bytearray,
    analysis_dir: Path,
    cave_offset: int | None = None,
) -> dict[str, object]:
    validator = load_key_validator_entry(analysis_dir)
    entry_offset = parse_hxd_offset(str(validator["function_start_file_offset"]))
    function_end_offset = parse_hxd_offset(str(validator["function_end_file_offset"]))

    if entry_offset < 0 or entry_offset + 4 > len(data):
        raise ValueError(f"offset KEY fuera del archivo: 0x{entry_offset:x}")

    original_instr = bytes(data[entry_offset : entry_offset + 4])
    stub = MOV_W0_ONE + RET
    if cave_offset is None:
        cave_offset = find_zero_cave(data, len(stub), function_end_offset)
    require_zero_cave(data, cave_offset, len(stub))

    entry_branch = branch_imm26(entry_offset, cave_offset)
    data[cave_offset : cave_offset + len(stub)] = stub
    data[entry_offset : entry_offset + 4] = entry_branch

    return {
        "entry_offset": entry_offset,
        "cave_offset": cave_offset,
        "stub_size": len(stub),
        "original_instr": original_instr,
        "entry_branch": entry_branch,
        "function_start": validator.get("function_start"),
        "function_end": validator.get("function_end"),
    }


def patch_key_thumb_force_success(data: bytearray, analysis_dir: Path) -> dict[str, object]:
    validator = load_key_validator_entry(analysis_dir)
    entry_offset = parse_hxd_offset(str(validator["function_start_file_offset"]))
    if entry_offset < 0 or entry_offset + 4 > len(data):
        raise ValueError(f"offset KEY fuera del archivo: 0x{entry_offset:x}")

    original_instr = bytes(data[entry_offset : entry_offset + 4])
    data[entry_offset : entry_offset + 4] = THUMB_MOVS_R0_ONE_BX_LR
    return {
        "entry_offset": entry_offset,
        "original_instr": original_instr,
        "replacement": THUMB_MOVS_R0_ONE_BX_LR,
        "function_start": validator.get("function_start"),
        "function_end": validator.get("function_end"),
    }


def find_aarch64_next_bl(data: bytes | bytearray, start_offset: int, end_offset: int) -> int | None:
    for offset in range((start_offset + 3) & ~3, min(end_offset, len(data) - 4) + 1, 4):
        word = struct.unpack_from("<I", data, offset)[0]
        if (word & 0xFC000000) == 0x94000000:
            return offset
    return None


def build_unlock_erase_debug_stubs(
    cave_offset: int,
    erase_debug_ops: list[dict[str, object]],
    done_target: int,
    info_va: int,
    print_func_offset: int,
    message_vas: dict[str, int] | None = None,
    return_meta: bool = False,
) -> bytes | tuple[bytes, dict[str, object]]:
    code = bytearray()
    meta: dict[str, object] = {"stub_offsets": {}, "message_offsets": {}}
    messages: list[tuple[str, bytes]] = []
    if message_vas is None:
        message_vas = {}

    def pc() -> int:
        return cave_offset + len(code)

    def emit(raw: bytes) -> None:
        code.extend(raw)

    def emit_print(message_name: str) -> None:
        emit(mov_imm64(0, info_va))
        emit(mov_imm64(1, int(message_vas.get(message_name, cave_offset))))
        emit(branch_imm26(pc(), print_func_offset, opcode=0x94000000))

    for index, operation in enumerate(erase_debug_ops):
        partition = str(operation["partition"])
        message_name = f"erase_{index}_{partition}"
        cast_stubs = meta["stub_offsets"]
        if isinstance(cast_stubs, dict):
            cast_stubs[message_name] = len(code)
        messages.append((message_name, f"LKDBG: erase {partition}\n".encode("ascii") + b"\x00"))

        call_site = int(operation["call_site_offset"])
        original_target = int(operation["original_target_offset"])
        emit(sub_imm64(31, 31, 0x30))
        emit(str_unsigned(30, 31, 0x28, 64))
        emit(str_unsigned(19, 31, 0x20, 64))
        emit(mov_reg64(19, 0))
        emit_print(message_name)
        emit(mov_reg64(0, 19))
        emit(branch_imm26(pc(), original_target, opcode=0x94000000))
        emit(ldr_unsigned(19, 31, 0x20, 64))
        emit(ldr_unsigned(30, 31, 0x28, 64))
        emit(add_imm64(31, 31, 0x30))
        emit(RET)

        if call_site % 4:
            raise ValueError(f"call_site debug no alineado: 0x{call_site:x}")

    done_name = "erase_done"
    cast_stubs = meta["stub_offsets"]
    if isinstance(cast_stubs, dict):
        cast_stubs[done_name] = len(code)
    messages.append((done_name, b"LKDBG: erase done\n\x00"))
    emit_print(done_name)
    emit(branch_imm26(pc(), done_target))

    while len(code) % 16:
        emit(u32(0xD503201F))
    for name, raw in messages:
        cast_messages = meta["message_offsets"]
        if isinstance(cast_messages, dict):
            cast_messages[name] = len(code)
        code.extend(raw)
    while len(code) % 16:
        emit(b"\x00")

    blob = bytes(code)
    if return_meta:
        return blob, meta
    return blob


def patch_unlock_flow_erase_only(
    data: bytearray,
    analysis_dir: Path,
    debug_log: bool = False,
) -> dict[str, object]:
    validator = load_key_validator_entry(analysis_dir)
    base = load_analysis_base(analysis_dir)
    callers = validator.get("callers", [])
    if not isinstance(callers, list) or not callers:
        raise ValueError("KEY validator no tiene caller cmd_oem_unlock")

    caller = callers[0]
    key_call_offset = parse_hxd_offset(str(caller["call_site_file_offset"]))
    caller_start_offset = parse_hxd_offset(str(caller["caller_start_file_offset"]))

    if key_call_offset < 0 or key_call_offset + 12 > len(data):
        raise ValueError(f"call KEY fuera del archivo: 0x{key_call_offset:x}")

    failure_branch_offset = key_call_offset + 4
    ui_call_offset = find_aarch64_next_bl(data, key_call_offset + 8, key_call_offset + 0x60)
    if ui_call_offset is None:
        raise ValueError("no se encontro llamada ui_confirm_unlock despues de KEY validator")

    ui_gate_offset = ui_call_offset + 4
    ui_gate_word = struct.unpack_from("<I", data, ui_gate_offset)[0]
    silent_return_target = decode_aarch64_cbz_tbz_target(ui_gate_word, ui_gate_offset)
    if silent_return_target is None:
        raise ValueError("no se encontro gate de retorno silencioso despues de ui_confirm_unlock")

    operations = load_partition_erase_operations(analysis_dir)
    erase_ops = [
        operation for operation in operations
        if operation.get("operation") == "erase"
        and parse_hxd_offset(str(operation.get("flow_start_file_offset", "-1"))) == caller_start_offset
        and parse_hxd_offset(str(operation.get("call_site_file_offset", "0"))) > ui_call_offset
    ]
    if not erase_ops:
        raise ValueError("no se encontraron borrados de particiones despues de ui_confirm_unlock")

    erase_ops.sort(key=lambda operation: parse_hxd_offset(str(operation["call_site_file_offset"])))
    first_cluster: list[dict[str, object]] = []
    cluster_start = parse_hxd_offset(str(erase_ops[0]["call_site_file_offset"]))
    for operation in erase_ops:
        call_site = parse_hxd_offset(str(operation["call_site_file_offset"]))
        if call_site - cluster_start > 0x120:
            break
        first_cluster.append(operation)
    if not first_cluster:
        raise ValueError("no se pudo construir el bloque de borrado inicial")

    def operation_result_check_offset(operation: dict[str, object]) -> int:
        if operation.get("result_check_file_offset") is not None:
            return parse_hxd_offset(str(operation["result_check_file_offset"]))
        return int(str(operation["result_check_address"]), 16) - base

    last_operation = max(first_cluster, key=operation_result_check_offset)
    return_hook_offset = operation_result_check_offset(last_operation) + 4

    original_ui_call = bytes(data[ui_call_offset : ui_call_offset + 4])
    original_return_hook = bytes(data[return_hook_offset : return_hook_offset + 4])
    if (struct.unpack("<I", original_ui_call)[0] & 0xFC000000) != 0x94000000:
        raise ValueError(f"ui_confirm hook no contiene BL: 0x{ui_call_offset:x}")

    data[ui_call_offset : ui_call_offset + 4] = MOV_W0_ONE
    debug_patch: dict[str, object] = {}
    if debug_log:
        debug_targets = load_fastboot_info_targets(analysis_dir, data)
        erase_debug_ops: list[dict[str, object]] = []
        for operation in first_cluster:
            call_site = parse_hxd_offset(str(operation["call_site_file_offset"]))
            call_word = struct.unpack_from("<I", data, call_site)[0]
            original_target = decode_aarch64_call_target(call_word, base + call_site)
            if original_target is None:
                raise ValueError(f"erase call no contiene BL en 0x{call_site:x}")
            partition = str(operation.get("partition"))
            try:
                string_offset = parse_hxd_offset(str(operation["string_file_offset"]))
                current_partition = read_c_string(data, string_offset, 48).decode("ascii")
                if current_partition:
                    partition = current_partition
            except (KeyError, ValueError, UnicodeDecodeError):
                pass
            erase_debug_ops.append(
                {
                    "partition": partition,
                    "call_site_offset": call_site,
                    "original_target_offset": original_target - base,
                }
            )

        try:
            flow = load_flow_for_start(analysis_dir, base + caller_start_offset)
            flow_end_offset = int(str(flow["end_address"]), 16) - base
        except (OSError, ValueError, KeyError):
            flow_end_offset = caller_start_offset + 0x1000

        dummy_result = build_unlock_erase_debug_stubs(
            return_hook_offset + 0x100,
            erase_debug_ops,
            silent_return_target,
            int(debug_targets["info_string_va"]),
            int(debug_targets["print_func_offset"]),
            {},
            return_meta=True,
        )
        dummy_stub, dummy_meta = dummy_result
        debug_cave_offset = find_zero_cave(data, len(dummy_stub), flow_end_offset)
        require_zero_cave(data, debug_cave_offset, len(dummy_stub))
        message_offsets = dummy_meta.get("message_offsets", {})
        if not isinstance(message_offsets, dict):
            raise ValueError("metadata debug erase invalida")
        message_vas = {
            name: base + debug_cave_offset + int(offset)
            for name, offset in message_offsets.items()
        }
        debug_stub, debug_meta = build_unlock_erase_debug_stubs(
            debug_cave_offset,
            erase_debug_ops,
            silent_return_target,
            int(debug_targets["info_string_va"]),
            int(debug_targets["print_func_offset"]),
            message_vas,
            return_meta=True,
        )
        data[debug_cave_offset : debug_cave_offset + len(debug_stub)] = debug_stub
        stub_offsets = debug_meta.get("stub_offsets", {})
        if not isinstance(stub_offsets, dict):
            raise ValueError("metadata stubs debug erase invalida")
        for operation in erase_debug_ops:
            message_name = next(
                name for name in stub_offsets
                if str(name).startswith("erase_")
                and str(name).endswith("_" + str(operation["partition"]))
            )
            call_site = int(operation["call_site_offset"])
            data[call_site : call_site + 4] = branch_imm26(
                call_site,
                debug_cave_offset + int(stub_offsets[message_name]),
                opcode=0x94000000,
            )
        done_offset = debug_cave_offset + int(stub_offsets["erase_done"])
        data[return_hook_offset : return_hook_offset + 4] = branch_imm26(
            return_hook_offset,
            done_offset,
        )
        debug_patch = {
            "debug_log": True,
            "debug_cave_offset": debug_cave_offset,
            "debug_stub_size": len(debug_stub),
            "debug_print_func_offset": int(debug_targets["print_func_offset"]),
            "debug_message_vas": message_vas,
            "debug_erase_ops": erase_debug_ops,
        }
    else:
        data[return_hook_offset : return_hook_offset + 4] = branch_imm26(
            return_hook_offset,
            silent_return_target,
        )

    result = {
        "key_call_offset": key_call_offset,
        "failure_branch_offset": failure_branch_offset,
        "ui_call_offset": ui_call_offset,
        "ui_gate_offset": ui_gate_offset,
        "silent_return_target": silent_return_target,
        "return_hook_offset": return_hook_offset,
        "erase_partitions": [str(operation.get("partition")) for operation in first_cluster],
        "original_ui_call": original_ui_call,
        "new_ui_call": MOV_W0_ONE,
        "original_return_hook": original_return_hook,
        "new_return_hook": bytes(data[return_hook_offset : return_hook_offset + 4]),
    }
    result.update(debug_patch)
    return result


def find_thumb_ui_confirm_call(
    data: bytes | bytearray,
    caller_start_offset: int,
    key_call_offset: int,
) -> int | None:
    for offset in range(caller_start_offset, max(caller_start_offset, key_call_offset - 4), 2):
        if not is_thumb_bl(data, offset):
            continue
        if not is_thumb_cbnz_r0(data, offset + 4):
            continue
        if bytes(data[offset + 6 : offset + 8]) != THUMB_POP_R4_PC:
            continue
        return offset
    return None


def patch_unlock_flow_erase_only_thumb(data: bytearray, analysis_dir: Path) -> dict[str, object]:
    validator = load_key_validator_entry(analysis_dir)
    base = load_analysis_base(analysis_dir)
    callers = validator.get("callers", [])
    if not isinstance(callers, list) or not callers:
        raise ValueError("KEY validator no tiene caller cmd_oem_unlock")

    caller = callers[0]
    caller_start_va = int(str(caller["caller_start"]), 16)
    caller_start_offset = parse_hxd_offset(str(caller["caller_start_file_offset"]))
    key_call_offset = parse_hxd_offset(str(caller["call_site_file_offset"]))

    if key_call_offset < 0 or key_call_offset + 8 > len(data):
        raise ValueError(f"call KEY fuera del archivo: 0x{key_call_offset:x}")

    ui_call_offset = find_thumb_ui_confirm_call(data, caller_start_offset, key_call_offset)
    if ui_call_offset is None:
        raise ValueError("no se encontro patron Thumb ui_confirm_unlock antes de KEY validator")

    flow = load_flow_for_start(analysis_dir, caller_start_va)
    boot_xrefs = [
        xref for xref in flow.get("xrefs", [])
        if isinstance(xref, dict)
        and str(xref.get("target", "")).lower() == "bootloader is unlocked"
    ]
    if not boot_xrefs:
        raise ValueError("no se encontro xref Thumb a 'Bootloader is unlocked'")

    return_hook_va = int(str(boot_xrefs[0]["xref_address"]), 16)
    return_hook_offset = return_hook_va - base
    if return_hook_offset < 0 or return_hook_offset + 2 > len(data):
        raise ValueError(f"return hook fuera del archivo: 0x{return_hook_offset:x}")

    md_udc_xrefs = [
        xref for xref in flow.get("xrefs", [])
        if isinstance(xref, dict)
        and str(xref.get("target", "")).lower() == "md_udc"
        and str(xref.get("instruction", "")).startswith("add ")
    ]

    original_ui_call = bytes(data[ui_call_offset : ui_call_offset + 4])
    original_return_hook = bytes(data[return_hook_offset : return_hook_offset + 2])
    if not is_thumb_bl(data, ui_call_offset):
        raise ValueError(f"ui_confirm hook no contiene BL Thumb: 0x{ui_call_offset:x}")

    data[ui_call_offset : ui_call_offset + 4] = thumb_movs_imm(0, 1) + THUMB_NOP
    data[return_hook_offset : return_hook_offset + 2] = THUMB_POP_R4_PC

    return {
        "key_call_offset": key_call_offset,
        "ui_call_offset": ui_call_offset,
        "return_hook_offset": return_hook_offset,
        "erase_partitions": ["metadata", "userdata", "md_udc"],
        "md_udc_xrefs": [
            {
                "xref_address": xref.get("xref_address"),
                "string_address": xref.get("string_address"),
                "instruction": xref.get("instruction"),
                "via": xref.get("via"),
            }
            for xref in md_udc_xrefs
        ],
        "original_ui_call": original_ui_call,
        "new_ui_call": bytes(data[ui_call_offset : ui_call_offset + 4]),
        "original_return_hook": original_return_hook,
        "new_return_hook": bytes(data[return_hook_offset : return_hook_offset + 2]),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Parchea de forma estricta el nombre de una particion usado como "
            "argumento de borrado en el lk.bin extraido por lk_static_analyzer.py."
        )
    )
    parser.add_argument(
        "--analysis-dir",
        type=Path,
        required=True,
        help="Directorio de analisis, por ejemplo cancunf o lk_analysis.",
    )
    parser.add_argument(
        "--input",
        type=Path,
        help="lk.bin a parchear. Por defecto: <analysis-dir>/lk.bin",
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="Archivo de salida. Por defecto: <input>.patched.bin",
    )
    parser.add_argument(
        "--erase-partition",
        dest="erase_partition",
        help=(
            "Modo corto: reemplaza el argumento de borrado 'nvdata' por esta "
            "particion, validando que quepa en el espacio de nvdata."
        ),
    )
    parser.add_argument("--from", dest="old_name", help="Particion original, por ejemplo nvdata.")
    parser.add_argument("--to", dest="new_name", help="Particion nueva, por ejemplo cache.")
    parser.add_argument(
        "--frp-compare-value",
        type=int,
        choices=[0, 1],
        help=(
            "Parchea la validacion FRP/OEM para que el ultimo byte leido de FRP "
            "se compare contra este valor. 0 restaura cmp w8,#0; 1 usa cmp w8,#1."
        ),
    )
    parser.add_argument(
        "--frp-skip-check",
        action="store_true",
        help=(
            "Salta la llamada al checker FRP/OEM dentro del flujo unlock y fuerza "
            "el resultado permitido sin ejecutar esa funcion."
        ),
    )
    parser.add_argument(
        "--key-force-success",
        action="store_true",
        help=(
            "Parchea el retorno principal del KEY validator llamado por unlock: "
            "mov w0,w20 -> mov w0,#1."
        ),
    )
    parser.add_argument(
        "--key-custom-signature",
        help=(
            "Inserta un stub condicional en KEY validator: si unlock_code[0:20] "
            "coincide con esta firma ASCII exacta de 20 bytes, retorna 1; si no, "
            "continua con la validacion original."
        ),
    )
    parser.add_argument(
        "--key-cave-offset",
        help=(
            "Offset HxD manual para el code cave del stub KEY. Por defecto se "
            "busca automaticamente despues del final del candidato KEY."
        ),
    )
    parser.add_argument(
        "--key-token-secret",
        help=(
            "Inserta un stub condicional por token: el unlock_code de 20 chars "
            "debe cumplir las constantes derivadas de este secret. Ejemplo: Valeria."
        ),
    )
    parser.add_argument(
        "--key-token-device",
        default="",
        help=(
            "Identificador opcional del dispositivo para derivar tokens distintos. "
            "Debe usarse tambien al generar las KEYs con lk_keygen.py."
        ),
    )
    parser.add_argument(
        "--key-token-imei",
        help=(
            "IMEI de 15 digitos usado como identificador estatico para derivar KEYs. "
            "Puede ser el valor copiado desde fastboot getvar all; no inserta "
            "lectura runtime de IMEI en el LK."
        ),
    )
    parser.add_argument(
        "--key-token-runtime-serial",
        action="store_true",
        help=(
            "EXPERIMENTAL AArch64: el token de KEY se deriva en runtime desde "
            "hw_get_serialno_string/serialno. No inserta el serial en el LK."
        ),
    )
    parser.add_argument(
        "--key-token-debug-log",
        action="store_true",
        help=(
            "Obsoleto en runtime-serial compacto. Usa --key-token-debug-stop "
            "para checkpoints seguros."
        ),
    )
    parser.add_argument(
        "--key-token-debug-stop",
        choices=KEY_TOKEN_DEBUG_STOPS,
        help=(
            "DIAGNOSTICO seguro: detiene el flujo en un checkpoint y reemplaza "
            "Code validation failure por un mensaje LKDBG corto."
        ),
    )
    parser.add_argument(
        "--key-token-alphabet",
        choices=["alnum", "printable"],
        default="alnum",
        help="Alfabeto esperado para las KEYs generadas. Por defecto: alnum.",
    )
    parser.add_argument(
        "--erase-token-partition",
        help=(
            "Permite borrar una particion protegida solo si se usa el formato "
            "<particion>__TOKEN. Ejemplo: super."
        ),
    )
    parser.add_argument(
        "--erase-token-secret",
        help="Secret usado para derivar el token de borrado protegido. Ejemplo: Valeria.",
    )
    parser.add_argument(
        "--erase-token-device",
        default="",
        help="Identificador del equipo/modelo usado para derivar tokens de borrado distintos.",
    )
    parser.add_argument(
        "--erase-token-imei",
        help=(
            "IMEI de 15 digitos usado como identificador estatico para tokens "
            "de borrado. Puede ser el valor copiado desde fastboot getvar all; no "
            "inserta lectura runtime de IMEI en el LK."
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
        "--unlock-erase-only",
        action="store_true",
        help=(
            "Usa el flujo cmd_oem_unlock para borrar particiones, salta la UI de "
            "confirmacion y retorna antes de cambiar el estado de bootloader."
        ),
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Escribe el archivo parcheado. Sin esto solo hace dry-run.",
    )
    return parser


def resolve_partition_patch_names(args: argparse.Namespace) -> tuple[str, str] | None:
    if args.erase_partition:
        if args.old_name or args.new_name:
            raise ValueError("usa --erase-partition solo, o usa --from/--to; no mezcles ambos modos")
        return "nvdata", args.erase_partition.strip()

    if args.old_name or args.new_name:
        if not args.old_name or not args.new_name:
            raise ValueError("especifica ambos: --from <old> --to <new>")
        return args.old_name.strip(), args.new_name.strip()

    return None


def write_output_if_requested(output_path: Path, data: bytearray, apply: bool) -> int:
    if not apply:
        print("Dry-run : no se escribio ningun archivo. Usa --apply para generar el binario parcheado.")
        return 0

    if output_path.exists():
        backup_path = output_path.with_suffix(output_path.suffix + ".bak")
        shutil.copy2(output_path, backup_path)
        print(f"Backup  : {backup_path}")

    output_path.write_bytes(data)
    print("Status  : patched file written")
    return 0


def main() -> int:
    args = build_parser().parse_args()
    input_path = args.input or (args.analysis_dir / "lk.bin")
    output_path = args.output or input_path.with_name(input_path.stem + ".patched.bin")

    if not input_path.is_file():
        print(f"Error: no existe {input_path}", file=sys.stderr)
        return 2

    try:
        partition_patch = resolve_partition_patch_names(args)
        key_token_device, key_token_device_kind = resolve_device_or_imei(
            args.key_token_device,
            args.key_token_imei,
            "key-token",
        )
        erase_token_device, erase_token_device_kind = resolve_device_or_imei(
            args.erase_token_device,
            args.erase_token_imei,
            "erase-token",
        )
        erase_token_partition = (
            parse_partition_name(args.erase_token_partition)
            if args.erase_token_partition
            else None
        )
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    if erase_token_partition and not args.erase_token_secret:
        print("Error: usa --erase-token-secret junto con --erase-token-partition.", file=sys.stderr)
        return 2
    if args.erase_token_secret and not erase_token_partition:
        print("Error: usa --erase-token-partition junto con --erase-token-secret.", file=sys.stderr)
        return 2
    if args.key_token_runtime_serial and not args.key_token_secret:
        print("Error: usa --key-token-runtime-serial junto con --key-token-secret.", file=sys.stderr)
        return 2
    if args.key_token_debug_log and not args.key_token_runtime_serial:
        print("Error: --key-token-debug-log solo aplica con --key-token-runtime-serial.", file=sys.stderr)
        return 2
    if args.key_token_debug_stop and not args.key_token_secret:
        print("Error: --key-token-debug-stop requiere --key-token-secret.", file=sys.stderr)
        return 2
    if (
        args.key_token_debug_stop
        and args.key_token_debug_stop != "caller_before_key"
        and not args.key_token_runtime_serial
    ):
        print(
            "Error: --key-token-debug-stop distinto de caller_before_key requiere "
            "--key-token-runtime-serial.",
            file=sys.stderr,
        )
        return 2

    key_modes = [
        bool(args.key_force_success),
        bool(args.key_custom_signature),
        bool(args.key_token_secret),
    ]
    if sum(key_modes) > 1:
        print(
            "Error: --key-force-success, --key-custom-signature y --key-token-secret "
            "modifican la misma entrada KEY; usa solo uno.",
            file=sys.stderr,
        )
        return 2
    if args.frp_skip_check and args.frp_compare_value is not None:
        print(
            "Error: usa solo uno: --frp-skip-check o --frp-compare-value.",
            file=sys.stderr,
        )
        return 2

    if (
        partition_patch is None
        and not args.frp_skip_check
        and args.frp_compare_value is None
        and not args.key_force_success
        and not args.key_custom_signature
        and not args.key_token_secret
        and not erase_token_partition
        and not args.unlock_erase_only
    ):
        print(
            "Error: usa --erase-partition <nombre>, --from/--to, --frp-skip-check, "
            "--frp-compare-value, --key-force-success, --key-custom-signature, --key-token-secret, "
            "--erase-token-partition, --unlock-erase-only, o una combinacion.",
            file=sys.stderr,
        )
        return 2

    architecture = load_analysis_architecture(args.analysis_dir)
    if args.key_token_runtime_serial and architecture not in {"aarch64", "arm32_thumb"}:
        print(
            "Error: --key-token-runtime-serial es experimental y solo esta "
            f"implementado para AArch64/ARM32 Thumb; el analisis detecto {architecture!r}.",
            file=sys.stderr,
        )
        return 1
    if args.key_token_debug_stop and architecture != "aarch64":
        print(
            "Error: --key-token-debug-stop solo esta implementado para AArch64; "
            f"el analisis detecto {architecture!r}.",
            file=sys.stderr,
        )
        return 1
    if architecture != "aarch64":
        unsupported: list[str] = []
        if args.key_custom_signature:
            unsupported.append("--key-custom-signature")
        if unsupported:
            print(
                "Error: el analisis detecto arquitectura "
                f"{architecture!r}; estos parches aun usan stubs AArch64: "
                + ", ".join(unsupported),
                file=sys.stderr,
            )
            return 1

    if (
        architecture == "arm32_thumb"
        and args.erase_partition
        and partition_patch is not None
        and partition_patch[0] == "nvdata"
    ):
        partition_patch = ("md_udc", partition_patch[1])

    try:
        data = bytearray(input_path.read_bytes())
    except OSError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    print(f"Input   : {input_path}")
    print(f"Output  : {output_path}")

    if partition_patch is not None:
        old_name, new_name = partition_patch
        if not old_name or not new_name:
            print("Error: los nombres de particion no pueden estar vacios.", file=sys.stderr)
            return 2
        try:
            old_name.encode("ascii")
            new_name.encode("ascii")
        except UnicodeEncodeError:
            print("Error: usa nombres ASCII para particiones.", file=sys.stderr)
            return 2

        try:
            entries = load_partition_arg_offsets(args.analysis_dir, old_name)
            offsets = sorted({parse_hxd_offset(str(entry["hxd_offset"])) for entry in entries})
            for offset in offsets:
                patch_bytes(data, offset, old_name, new_name)
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            if architecture == "arm32_thumb":
                print(f"Skip    : {old_name!r} -> {new_name!r} ({exc})")
                offsets = []
            else:
                print(f"Error: {exc}", file=sys.stderr)
                return 1

        if offsets:
            print(f"Patch   : {old_name!r} -> {new_name!r}")
            print("Offsets : " + ", ".join(f"0x{offset:x} / HxD {offset:08X}" for offset in offsets))

    if args.frp_skip_check:
        try:
            offsets = frp_skip_call_offsets(args.analysis_dir)
            if architecture == "arm32_thumb":
                patches = [patch_frp_skip_call_thumb(data, offset) for offset in offsets]
            else:
                patches = [patch_frp_skip_call(data, offset) for offset in offsets]
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        print("Patch   : FRP/OEM checker call skip")
        for offset, (old_raw, new_raw) in zip(offsets, patches):
            print(
                f"Call    : 0x{offset:x} / HxD {offset:08X}  "
                f"{old_raw.hex()} -> {new_raw.hex()}"
            )

    if args.frp_compare_value is not None:
        try:
            entries = load_frp_compare_offsets(args.analysis_dir)
            offsets = sorted({parse_hxd_offset(str(entry["hxd_offset"])) for entry in entries})
            if architecture == "arm32_thumb":
                patches = [patch_frp_compare_thumb(data, offset, args.frp_compare_value) for offset in offsets]
            else:
                patches = [patch_frp_compare(data, offset, args.frp_compare_value) for offset in offsets]
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        if architecture == "arm32_thumb":
            print(f"Patch   : FRP Thumb last-byte boolean -> value {args.frp_compare_value}")
        else:
            print(f"Patch   : FRP cmp w8,#? -> cmp w8,#{args.frp_compare_value}")
        for offset, (old_raw, new_raw) in zip(offsets, patches):
            print(
                f"Offset  : 0x{offset:x} / HxD {offset:08X}  "
                f"{old_raw.hex()} -> {new_raw.hex()}"
            )

    if args.key_force_success:
        if architecture == "arm32_thumb":
            try:
                patch = patch_key_thumb_force_success(data, args.analysis_dir)
            except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
                print(f"Error: {exc}", file=sys.stderr)
                return 1

            entry_offset = int(patch["entry_offset"])
            print("Patch   : KEY Thumb entry force-success")
            print(
                f"Entry   : 0x{entry_offset:x} / HxD {entry_offset:08X}  "
                f"{patch['original_instr'].hex()} -> {patch['replacement'].hex()}"
            )
        else:
            try:
                entries = load_key_primary_return_offsets(args.analysis_dir)
                offsets = sorted({parse_hxd_offset(str(entry["hxd_offset"])) for entry in entries})
                patches = [patch_key_return_success(data, offset) for offset in offsets]
                print("Patch   : KEY primary return mov w0,w20 -> mov w0,#1")
                for offset, (old_raw, new_raw) in zip(offsets, patches):
                    print(
                        f"Offset  : 0x{offset:x} / HxD {offset:08X}  "
                        f"{old_raw.hex()} -> {new_raw.hex()}"
                    )
            except (OSError, ValueError, KeyError, json.JSONDecodeError) as primary_exc:
                try:
                    patch = patch_key_entry_force_success(data, args.analysis_dir)
                except (OSError, ValueError, KeyError, json.JSONDecodeError) as fallback_exc:
                    print(f"Error: {primary_exc}; fallback entry stub tambien fallo: {fallback_exc}", file=sys.stderr)
                    return 1

                entry_offset = int(patch["entry_offset"])
                used_cave = int(patch["cave_offset"])
                stub_size = int(patch["stub_size"])
                print("Patch   : KEY entry force-success stub")
                print(f"Reason  : primary return patch unavailable ({primary_exc})")
                print(
                    f"Entry   : 0x{entry_offset:x} / HxD {entry_offset:08X}  "
                    f"{patch['original_instr'].hex()} -> {patch['entry_branch'].hex()}"
                )
                print(f"Cave    : 0x{used_cave:x} / HxD {used_cave:08X}  size={stub_size} bytes")

    if args.key_custom_signature:
        try:
            signature = parse_custom_signature(args.key_custom_signature)
            cave_offset = parse_hxd_offset(args.key_cave_offset) if args.key_cave_offset else None
            patch = patch_key_custom_signature(data, args.analysis_dir, signature, cave_offset)
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        entry_offset = int(patch.get("entry_offset", patch.get("call_offset", 0)))
        used_cave = int(patch["cave_offset"])
        stub_size = int(patch["stub_size"])
        old_raw = patch["original_instr"]
        new_raw = patch["entry_branch"]
        print("Patch   : KEY custom signature gate")
        print(f"Signature: {signature.decode('ascii')!r}")
        print(
            f"Entry   : 0x{entry_offset:x} / HxD {entry_offset:08X}  "
            f"{old_raw.hex()} -> {new_raw.hex()}"
        )
        print(f"Cave    : 0x{used_cave:x} / HxD {used_cave:08X}  size={stub_size} bytes")

    if args.key_token_secret:
        try:
            cave_offset = parse_hxd_offset(args.key_cave_offset) if args.key_cave_offset else None
            if args.key_token_debug_stop == "caller_before_key":
                constants = None
                patch = patch_key_caller_before_key_checkpoint(
                    data,
                    args.analysis_dir,
                    "LKDBG before key\n",
                )
            elif args.key_token_debug_stop == "entry":
                constants = None
                patch = patch_key_entry_zero_checkpoint(
                    data,
                    args.analysis_dir,
                    "LKDBG entry\n",
                )
            elif args.key_token_runtime_serial:
                constants = None
                if args.key_token_debug_stop:
                    patch_code_validation_message(
                        data,
                        args.analysis_dir,
                        f"LKDBG {args.key_token_debug_stop}\n",
                    )
                patch = patch_key_runtime_serial_token_gate(
                    data,
                    args.analysis_dir,
                    args.key_token_secret,
                    args.key_token_alphabet,
                    cave_offset,
                    args.key_token_debug_log,
                    args.key_token_debug_stop,
                )
            else:
                constants = derive_token_constants(
                    args.key_token_secret,
                    key_token_device,
                    args.key_token_alphabet,
                )
                if architecture == "arm32_thumb":
                    patch = patch_key_token_gate_thumb(data, args.analysis_dir, constants, cave_offset)
                else:
                    patch = patch_key_token_gate(data, args.analysis_dir, constants, cave_offset)
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        entry_offset = int(patch.get("entry_offset", patch.get("call_offset", 0)))
        cave_value = patch.get("cave_offset")
        used_cave = int(cave_value) if cave_value is not None else 0
        stub_size = int(patch.get("stub_size", 0))
        old_raw = patch["original_instr"]
        new_raw = patch.get("entry_branch", patch.get("replacement", b""))
        device_label = key_token_device if key_token_device else "<global>"
        print("Patch   : KEY derived token gate")
        if args.key_token_debug_stop in {"caller_before_key", "entry"}:
            print(f"Mode    : DIAGNOSTIC checkpoint {args.key_token_debug_stop}")
            if args.key_token_debug_stop == "caller_before_key":
                patch_offset = int(patch["call_offset"])
                label = "Call"
            else:
                patch_offset = int(patch["entry_offset"])
                label = "Entry"
            print(
                f"{label:<7}: 0x{patch_offset:x} / HxD {patch_offset:08X}  "
                f"{old_raw.hex()} -> {new_raw.hex()}"
            )
            msg = patch.get("message_patch", {})
            if isinstance(msg, dict):
                print(
                    f"DbgMsg  : HxD {int(msg['message_offset']):08X} "
                    f"{msg['new_message']!r}"
                )
            continue_key_print = False
        else:
            continue_key_print = True
        if continue_key_print and args.key_token_runtime_serial:
            print("Mode    : EXPERIMENTAL runtime-serial-compact-inplace")
            if patch.get("architecture"):
                print(f"Arch    : {patch.get('architecture')}")
            if args.key_token_debug_stop:
                print(f"Stop    : {args.key_token_debug_stop}")
            print("Device  : runtime serialno from LK")
            print(
                f"SerialFn: 0x{int(patch['serial_func_offset']):x} / "
                f"HxD {int(patch['serial_func_offset']):08X} "
                f"VA=0x{int(patch['serial_func_va']):x}"
            )
            if patch.get("masks") is not None:
                print(f"Masks   : {bytes(patch['masks']).hex()}")
            if patch.get("success_value") is not None:
                print(
                    f"Returns : success={patch.get('success_value')} "
                    f"fail={patch.get('fail_value')}"
                )
            if patch.get("debug_log"):
                print(
                    f"Debug   : LKDBG enabled via "
                    f"0x{int(patch['debug_print_func_offset']):x} / "
                    f"HxD {int(patch['debug_print_func_offset']):08X}"
                )
                debug_messages = patch.get("debug_message_vas", {})
                if isinstance(debug_messages, dict):
                    for name, va in debug_messages.items():
                        print(f"DbgMsg  : {name}=0x{int(va):x}")
        elif continue_key_print:
            print("Mode    : static-derived-no-runtime")
            print(f"Device  : {device_label!r} ({key_token_device_kind})")
        if continue_key_print:
            print(f"Alphabet: {args.key_token_alphabet}")
            if constants is not None:
                print(f"Const   : {constants.hex()}")
            print(
                f"Entry   : 0x{entry_offset:x} / HxD {entry_offset:08X}  "
                f"{old_raw[:8].hex()} -> {new_raw[:8].hex()}"
            )
            if cave_value is None:
                print(f"InPlace : size={stub_size} bytes")
            else:
                print(f"Cave    : 0x{used_cave:x} / HxD {used_cave:08X}  size={stub_size} bytes")

    if erase_token_partition:
        try:
            erase_constants = derive_erase_token_constants(
                args.erase_token_secret,
                erase_token_device,
                erase_token_partition,
                args.erase_token_alphabet,
            )
            erase_cave_offset = (
                parse_hxd_offset(args.erase_token_cave_offset)
                if args.erase_token_cave_offset
                else None
            )
            if architecture == "arm32_thumb":
                patch = patch_erase_token_gate_thumb(
                    data,
                    args.analysis_dir,
                    erase_token_partition,
                    erase_constants,
                    erase_cave_offset,
                )
            else:
                patch = patch_erase_token_gate(
                    data,
                    args.analysis_dir,
                    erase_token_partition,
                    erase_constants,
                    erase_cave_offset,
                )
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        device_label = erase_token_device if erase_token_device else "<global>"
        pre_hook = int(patch["pre_hook_offset"])
        gate_hook = int(patch["gate_hook_offset"])
        cave = int(patch["cave_offset"])
        gate_cave = int(patch["gate_cave_offset"])
        late_hook = patch.get("late_hook_offset")
        late_cave = patch.get("late_cave_offset")
        print("Patch   : ERASE protected token gate")
        if patch.get("erase_token_mode"):
            print(f"Mode    : {patch.get('erase_token_mode')}")
        print(f"Partition: {erase_token_partition!r}")
        print(f"Device  : {device_label!r} ({erase_token_device_kind})")
        print(f"Alphabet: {args.erase_token_alphabet}")
        print(f"Const   : {erase_constants.hex()}")
        if patch.get("pre_pointer_register") or patch.get("gate_pointer_expression"):
            print(
                "ArgPtr  : "
                f"pre={patch.get('pre_pointer_register')} "
                f"gate={patch.get('gate_pointer_expression')}"
            )
        if patch.get("token_allowed_note") == "direct_return":
            token_target = int(patch["token_allowed_target"])
            print(f"TokAllow: 0x{token_target:x} / HxD {token_target:08X}  direct_return")
        if patch.get("token_denied_note") == "direct_return":
            token_target = int(patch["token_denied_target"])
            print(f"TokDeny : 0x{token_target:x} / HxD {token_target:08X}  direct_return")
        flow_audits = patch.get("flow_audits", {})
        if isinstance(flow_audits, dict):
            for audit_name, audit in flow_audits.items():
                if not isinstance(audit, dict):
                    continue
                status = "OK" if audit.get("ok") else "WARN"
                print(
                    f"Audit   : {audit_name} {status} "
                    f"terminal={audit.get('terminal')} steps={audit.get('steps')} "
                    f"calls={len(audit.get('calls', []))} "
                    f"conds={len(audit.get('conditional_branches', []))}"
                )
        print(
            f"PreHook : 0x{pre_hook:x} / HxD {pre_hook:08X}  "
            f"{patch['pre_original'].hex()} -> {patch['pre_branch'].hex()}"
        )
        print(
            f"GateHook: 0x{gate_hook:x} / HxD {gate_hook:08X}  "
            f"{patch['gate_original'].hex()} -> {patch['gate_branch'].hex()}"
        )
        if late_hook is not None and late_cave is not None:
            late_hook_int = int(late_hook)
            late_cave_int = int(late_cave)
            print(
                f"LateHook: 0x{late_hook_int:x} / HxD {late_hook_int:08X}  "
                f"{patch['late_original'].hex()} -> {patch['late_branch'].hex()}"
            )
        print(
            f"Cave    : 0x{cave:x} / HxD {cave:08X}  "
            f"pre={patch['pre_stub_size']} gate={patch['gate_stub_size']} "
            f"late={patch.get('late_stub_size', 0)} total={patch['stub_size']} bytes"
        )
        print(f"GateCave: 0x{gate_cave:x} / HxD {gate_cave:08X}")
        if late_cave is not None:
            print(f"LateCave: 0x{int(late_cave):x} / HxD {int(late_cave):08X}")

    if args.unlock_erase_only:
        try:
            if architecture == "arm32_thumb":
                patch = patch_unlock_flow_erase_only_thumb(data, args.analysis_dir)
            else:
                patch = patch_unlock_flow_erase_only(
                    data,
                    args.analysis_dir,
                    args.key_token_debug_log,
                )
        except (OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
            print(f"Error: {exc}", file=sys.stderr)
            return 1

        ui_call = int(patch["ui_call_offset"])
        return_hook = int(patch["return_hook_offset"])
        print("Patch   : unlock-flow erase-only")
        print("EraseBlk: " + ", ".join(str(part) for part in patch["erase_partitions"]))
        print(
            f"UIHook  : 0x{ui_call:x} / HxD {ui_call:08X}  "
            f"{patch['original_ui_call'].hex()} -> {patch['new_ui_call'].hex()}"
        )
        print(
            f"RetHook : 0x{return_hook:x} / HxD {return_hook:08X}  "
            f"{patch['original_return_hook'].hex()} -> {patch['new_return_hook'].hex()}"
        )
        if "silent_return_target" in patch:
            silent_return = int(patch["silent_return_target"])
            print(f"RetTo   : 0x{silent_return:x} / HxD {silent_return:08X}")
        if patch.get("md_udc_xrefs"):
            print(f"MdUdcX  : {len(patch['md_udc_xrefs'])} xrefs in unlock flow")
        if patch.get("debug_log"):
            debug_cave = int(patch["debug_cave_offset"])
            print(
                f"DbgFlow : 0x{debug_cave:x} / HxD {debug_cave:08X} "
                f"size={int(patch['debug_stub_size'])} bytes"
            )
            debug_ops = patch.get("debug_erase_ops", [])
            if isinstance(debug_ops, list):
                for operation in debug_ops:
                    if not isinstance(operation, dict):
                        continue
                    print(
                        "DbgErase: "
                        f"{operation.get('partition')} "
                        f"call=0x{int(operation.get('call_site_offset', 0)):x}"
                    )

    return write_output_if_requested(output_path, data, args.apply)


if __name__ == "__main__":
    raise SystemExit(main())
