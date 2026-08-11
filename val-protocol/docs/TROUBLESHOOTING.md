# Troubleshooting

## `capstone` Import Error

Install Capstone in the active Python environment:

```bash
python -m pip install capstone
```

If the package is installed but still not found, confirm that the same Python executable is running the scripts:

```bash
python -c "import sys; print(sys.executable)"
python -c "import capstone; print(capstone.__version__)"
```

## Analyzer Finds No Candidates

Check:

- the input is a supported Motorola LK/LKS image,
- the image contains a subimage named `lk`,
- the correct subimage name is passed with `--name` if needed,
- the architecture is correctly detected,
- the relevant strings exist in the image.

Run full analysis:

```bash
python lk_static_analyzer.py "path/to/lk.img" -o "path/to/analysis" --full-disasm
```

Then inspect:

- `summary.txt`
- `serialno_runtime.json`
- `key_validators.json`
- `frp_checkers.json`
- `best_flow.asm`

## Device Resets After `fastboot oem unlock`

This usually means the patched flow entered an invalid function address, returned through the wrong prologue/epilogue shape, or called a runtime helper from an unsafe entry.

Inspect:

- `SerialFn` in patch output
- `serialno_runtime.json`
- the first instructions at the reported serial function
- whether AArch64 `PACIASP/AUTIASP` prologues are being entered correctly

For diagnosis, build checkpoint images:

```bash
python lk_auto_patch.py "path/to/lk.img" \
  -o "path/to/lk.chk-after-serial.img" \
  --preset erase-serial \
  --erase-token-partition frp \
  --erase-token-secret "YourSecret" \
  --key-token-debug-stop after_serial
```

## Key Always Fails

Confirm:

- the serial was copied exactly from `fastboot getvar serialno`,
- the same secret was used for patching and key generation,
- the same alphabet was used,
- the LK image flashed to the device matches the generated key mode,
- `serialno_runtime.json` points to the correct runtime serial getter.

Generate a key:

```bash
python lk_keygen.py --secret "YourSecret" --serialno "SERIAL_FROM_FASTBOOT" --count 1
```

## Repack Fails Verification

Inspect the output from:

```bash
python tools/verify_mtk_image.py "path/to/output.img" -n lk
```

The expected final line is:

```text
Result: VALID
```

## Replacement Partition Name Does Not Fit

Some presets replace an existing partition string in-place. The new name must fit within the available original string space.

Examples that usually fit:

- `frp`
- `cache`

Longer names may require a different patch strategy.

