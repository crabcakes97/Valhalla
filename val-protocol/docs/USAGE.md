# Usage Guide

This guide explains the supported end-to-end workflows.

## 1. Prepare The Environment

```bash
python -m pip install -r requirements.txt
```

Use Python 3.11+ where possible.

## 2. Analyze Only

Run the static analyzer without patching:

```bash
python lk_static_analyzer.py "path/to/lk.img" -o "path/to/analysis" --no-full-disasm
```

Use `--full-disasm` when you need a complete disassembly file:

```bash
python lk_static_analyzer.py "path/to/lk.img" -o "path/to/analysis" --full-disasm
```

Important outputs:

- `summary.txt`
- `key_validators.json`
- `frp_checkers.json`
- `serialno_runtime.json`
- `partition_erases/`
- `flow_functions/`

## 3. Generate A Patched LK

The recommended entry point is `lk_auto_patch.py`.

```bash
python lk_auto_patch.py "path/to/lk.img" -o "path/to/output.img" --preset PRESET [options]
```

By default, the tool:

1. extracts the `lk` payload,
2. runs static analysis,
3. applies the selected preset,
4. updates the MTK certificate hash,
5. rebuilds the original image container,
6. verifies the result.

## 4. Generate A Device Key

Read serial number:

```bash
fastboot getvar serialno
```

Generate one key:

```bash
python lk_keygen.py --secret "YourSecret" --serialno "SERIAL_FROM_FASTBOOT" --count 1
```

Generate deterministic test keys:

```bash
python lk_keygen.py --secret "YourSecret" --serialno "SERIAL_FROM_FASTBOOT" --seed test --count 3
```

## 5. Preset: `unlock-serial`

Purpose:

- skip the FRP/OEM checker call in the unlock flow,
- replace key validation with runtime serial-derived validation,
- continue the normal unlock flow when the generated key is valid.

Command:

```bash
python lk_auto_patch.py "path/to/lk.img" \
  -o "path/to/lk.unlock-serial.img" \
  --preset unlock-serial \
  --key-token-secret "YourSecret"
```

Runtime command:

```bash
fastboot oem unlock GENERATED_KEY
```

## 6. Preset: `erase-serial`

Purpose:

- reuse `fastboot oem unlock <key>`,
- validate a key derived from runtime serial number,
- erase the selected partition through the known unlock erase block,
- return before changing unlock state.

Command:

```bash
python lk_auto_patch.py "path/to/lk.img" \
  -o "path/to/lk.erase-frp.img" \
  --preset erase-serial \
  --erase-token-partition frp \
  --erase-token-secret "YourSecret"
```

Runtime command:

```bash
fastboot oem unlock GENERATED_KEY
```

## 7. Preset: `unlock-serial-nvdata`

Purpose:

- skip the FRP/OEM checker call,
- use runtime serial-derived key validation,
- replace an unlock-flow partition erase string with a safer target.

Command:

```bash
python lk_auto_patch.py "path/to/lk.img" \
  -o "path/to/lk.unlock-frp.img" \
  --preset unlock-serial-nvdata \
  --key-token-secret "YourSecret" \
  --erase-partition frp
```

String replacement must fit in the original available space.

## 8. Diagnostic Checkpoints

Diagnostic checkpoints are temporary builds used to locate runtime failures. They replace the normal failure text with an `LKDBG` marker and return through normal bootloader paths.

```bash
python lk_auto_patch.py "path/to/lk.img" \
  -o "path/to/lk.chk-entry.img" \
  --preset erase-serial \
  --erase-token-partition frp \
  --erase-token-secret "YourSecret" \
  --key-token-debug-stop entry
```

Supported checkpoints:

- `caller_before_key`
- `entry`
- `before_serial`
- `after_serial`
- `token_ok`
- `token_fail`

Use checkpoint images only for diagnosis. Do not treat them as production patched images.

## 9. Legacy Alias Presets

The following names remain accepted for compatibility:

- `unlock-imei`
- `erase-imei`
- `unlock-imei-nvdata`

They now map to the serial-runtime behavior. They do not enable runtime IMEI validation.

