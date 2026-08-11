# Architecture Notes

## Pipeline

The main pipeline is implemented by `lk_auto_patch.py`.

```text
input lk.img
  -> extract lk payload
  -> static analysis
  -> patch selected flow
  -> write patched lk.bin
  -> rebuild signed LK payload
  -> update MTK CERT2 image hash
  -> replace lk subimage in original container
  -> verify final image
```

## Components

### `liblk`

Parses Motorola LK/LKS container images and extracts named subimages such as `lk`, `bl2_ext`, `aee`, `lk_main_dtb`, and related certificate sections.

### `lk_static_analyzer.py`

Uses Capstone to disassemble the extracted LK payload and locate pattern-based candidates.

The analyzer is intentionally pattern-based because the same Motorola source-level flow appears across many devices with different addresses, load bases, and architectures.

Major detections:

- LK base address
- AArch64 vs ARM32 Thumb
- strings and cross references
- unlock flow candidates
- FRP/OEM checker candidates
- key validator candidates
- erase permission checks
- unlock-flow partition erase operations
- runtime serial number getter

### `lk_patch_partition.py`

Applies the actual binary patches using analysis metadata. It supports both AArch64 and ARM32 Thumb paths.

The current key-token mode is compact and in-place: it replaces the key validator body with a small runtime serial validation stub. It does not require a code cave for the runtime serial key validator.

### `lk_keygen.py`

Generates 20-character keys matching the patched runtime serial validation scheme.

### `lk_repack_signed.py`

Rebuilds the modified LK payload into the original image and calls the tools needed to update and verify MTK certificate metadata.

## Runtime Serial Validation

The patched key validator does not embed the serial number. Instead, it calls the LK routine that backs `fastboot getvar serialno`.

At a high level:

```text
fastboot oem unlock <20-char-key>
  -> patched key validator
  -> call hw_get_serialno_string(buffer)
  -> compare key-derived bytes against serial-derived bytes
  -> return success or failure
```

This lets one patched LK image be reused across devices of the same compatible build while generated keys remain device-specific.

## PAC-Protected AArch64 Functions

Some AArch64 LK builds use pointer authentication prologues:

```asm
paciasp
stp x29, x30, [sp, #-0x20]!
```

The analyzer and patcher account for these prologues. Entering a function after `PACIASP` but returning through `AUTIASP` can crash the bootloader. For that reason, function start detection includes both common forms:

```asm
paciasp
sub sp, sp, #...
stp x29, x30, [...]
```

and:

```asm
paciasp
stp x29, x30, [sp, #-...]!
```

## ARM32 Thumb Notes

ARM32 Thumb LK builds use variable-width 16-bit and 32-bit instructions. The analyzer scans Thumb instructions and handles common Motorola patterns such as PC-relative literal loads and `bl`/`cbz`/`cbnz` flow gates.

The ARM32 runtime serial path follows the same conceptual chain as AArch64:

```text
getvar serialno wrapper
  -> hw_get_serialno_string
  -> serialno fallback chain
  -> barcode/cache/default fallback if needed
```

## Verification

A patch is not considered complete until the rebuilt image reports:

```text
Result: VALID
```

from `tools/verify_mtk_image.py`.

