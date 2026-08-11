# Val Protocol (Moto LK Patcher)

Motorola LK Patcher That Allows Unlock Bootloader And Remove FRP on MTK Devices Using Fastboot and LK cert exploit

## Why Val Protocol?

`Val` is short for `Valeria`.

Valeria is the girl I am in love with, and during the whole implementation of this project I could not get her out of my mind. Her name was used as the first working secret. In the earliest builds, using secrets that were longer or shorter kept shifting the generated patch layout too much, which caused unstable behavior: repeated reboots, rejected commands, or devices that would not boot until the original LK was restored.

Using her name was the key that gave the project the stability I was looking for at the beginning. Later, the implementation became flexible enough to support other secrets, but this project started working because of her and because of her name.

Static analyzer and patch automation for Motorola MediaTek LK/LKS bootloader images.

This project extracts the `lk` payload from Motorola LK container images, locates relevant bootloader control-flow patterns, applies selected research patches, rebuilds the original image layout, and updates the MTK certificate hash so the modified image can be flashed on devices that already allow custom LK flashing.

## Afected devices

Moto Edge Devices:
XT2205-3  Moto Edge (2022)
XT2305-1  Moto Edge (2023)
XT2139-1  Moto Edge 20 Lite
XT2303-2  Moto Edge 40 (2023)
XT2307-1  Moto Edge 40 Neo 5G (2023)
XT2409-2  Moto Edge 50 Neo 5G (2024)
XT2519-1  Moto Edge (2025)
XT2505-3  Moto Edge 60
XT2509-1  Moto Edge 60 Neo
XT2503-1  Moto Edge 60 Fusion
XT2507-1  Moto Edge 60 Pro
XT2607-2  Moto Edge 70 Pro

Moto G Devices:
XT2163-1  Moto G Pure
XT2213-3  Moto G 5G (2022)
XT2613-1  Moto G (2026)
XT2513-1  Moto G 5G (2025)
XT2173-3  Moto G31
XT2625-6  Moto G37
XT2167-1  Moto G41
XT2625-5  Moto G47 5G
XT2149-1  Moto G50 5G (2021)
XT2343-1  Moto G54 5G
XT2435-1  Moto G55 5G (2024)
XT2529-1  Moto G56 5G (2025)
XT2133-1  Moto G60s
XT2431-1  Moto G64 5G
XT2529-3  Moto G66j 5G
XT2621-3  Moto G67 (2026)
XT2255-3  Moto G72
XT2237-1  Moto G73 5G (2023)
XT2621-3  Moto G77 5G
XT2527-2  Moto G86 5G
XT2527-1  Moto G86 5G
XT2527-6  Moto G86 Power 5G
XT2271-5  Moto G Play (2023)
XT2615-1  Moto G Play (2026)
XT2165-5  Moto G Power (2022)
XT2311-3  Moto G Power 5G (2023)
XT2415-5  Moto G Power 5G (2024)
XT2515-2  Moto G Power 5G(2025)
XT2211-2  Moto G Stylus (2022)
XT2317DL  Moto G Stylus (2023)

Moto Razr Devices:
XT2453-1  Moto Razr 50 
XT2453-1  Moto Razr (2024)
XT2553-1  Moto Razr 60 
XT2553-1  Moto Razr (2025)

## Scope

The tool focuses on Motorola/MTK LK images that use the common Motorola unlock flow:

- `fastboot oem unlock <key>`
- FRP/OEM unlock gate checks
- key/hash validation routines
- unlock-flow partition erase calls
- runtime serial number lookup through the bootloader `serialno` getter
- MTK `CERT1`/`CERT2` image hash verification metadata

Both AArch64 and ARM32 Thumb LK payloads are supported when their patterns match the analyzer signatures.

## Safety And Legal Notice

Use this project only on devices you own or are explicitly authorized to service. Bootloader modification can permanently brick devices, erase user data, affect warranty state, and violate local law or vendor terms if used without authorization.

This repository is intended for repair, interoperability research, recovery workflows, and controlled lab analysis. Always keep the original image and a known recovery path before flashing modified firmware.

## Features

- Extracts the `lk` subimage from Motorola LK/LKS containers.
- Detects architecture automatically: AArch64 or ARM32 Thumb.
- Generates detailed static-analysis artifacts:
  - string references
  - candidate flows
  - FRP/OEM checker candidates
  - key validator candidates
  - partition erase operations
  - serial number runtime source
- Applies three high-level presets.
- Uses runtime serial number derivation for generated keys.
- Rebuilds the original multi-image container.
- Updates MTK `CERT2` image hashes.
- Verifies the rebuilt LK image after signing.

## Repository Layout

```text
.
|-- lk_auto_patch.py          # End-to-end analyzer, patcher, repacker
|-- lk_static_analyzer.py     # Static analysis and report generator
|-- lk_patch_partition.py     # Patch implementation engine
|-- lk_keygen.py              # 20-character key generator
|-- lk_repack_signed.py       # Repack signed LK payload into container
|-- liblk/                    # Minimal LK/LKS container parser
|-- tools/
|   |-- build-part-img.py     # Replace subimage in MTK part image
|   |-- sign_mtk_cert.py      # Update MTK CERT2 hashes
|   `-- verify_mtk_image.py   # Verify MTK CERT1/CERT2 image metadata
`-- docs/
```

## Requirements

- Python 3.11+ 64-bit recommended
- Capstone 5.x

Install dependencies:

```bash
python -m pip install -r requirements.txt
```

The project includes `liblk` locally. Capstone should be installed in the active Python environment. The analyzer also contains fallback logic for environments where a local `capstone/` folder shadows the installed package.

## Quick Start

Patch an LK image with the serial-based unlock preset:

```bash
python lk_auto_patch.py "path/to/lk.img" \
  -o "path/to/lk.unlock-serial.img" \
  --preset unlock-serial \
  --key-token-secret "YourSecret"
```

Read the device serial number:

```bash
fastboot getvar serialno
```

Generate a key for that serial number:

```bash
python lk_keygen.py --secret "YourSecret" --serialno "SERIAL_FROM_FASTBOOT" --count 1
```

Use the generated key:

```bash
fastboot oem unlock GENERATED_KEY
```

## Presets

### `unlock-serial`

Patches the unlock flow to use a key derived from a secret and the device serial number read internally by LK at runtime.

```bash
python lk_auto_patch.py "path/to/lk.img" \
  -o "path/to/lk.unlock-serial.img" \
  --preset unlock-serial \
  --key-token-secret "YourSecret"
```

### `erase-serial`

Reuses the `fastboot oem unlock <key>` flow, validates a serial-derived key, erases the selected partition in the unlock erase block, and returns before changing the bootloader unlock state.

```bash
python lk_auto_patch.py "path/to/lk.img" \
  -o "path/to/lk.erase-frp.img" \
  --preset erase-serial \
  --erase-token-partition frp \
  --erase-token-secret "YourSecret"
```

The runtime command is still:

```bash
fastboot oem unlock GENERATED_KEY
```

### `unlock-serial-nvdata`

Patches the unlock flow with serial-derived key validation and changes the unlock-flow partition erase target from the original radio-sensitive erase target to another partition name that fits in the original string slot.

```bash
python lk_auto_patch.py "path/to/lk.img" \
  -o "path/to/lk.unlock-frp.img" \
  --preset unlock-serial-nvdata \
  --key-token-secret "YourSecret" \
  --erase-partition frp
```

Use only replacement partition names that fit in the original string space. Short names such as `frp` and `cache` are typical examples.

## Runtime Serial Derivation

The current presets do not embed the target serial number into the LK image. Instead, the patched key validator calls the LK serial number getter at runtime and derives the validation condition from the serial reported by the device itself.

The generated key is still produced off-device:

```bash
python lk_keygen.py --secret "YourSecret" --serialno "SERIAL_FROM_FASTBOOT" --count 1
```

This allows one patched LK image per supported model/build while keys remain device-specific.

## Expected Output

A successful AArch64 patch usually includes lines similar to:

```text
Architecture : aarch64
Serialno runtime: 0x...
Patch   : FRP/OEM checker call skip
Patch   : KEY derived token gate
Mode    : EXPERIMENTAL runtime-serial-compact-inplace
Device  : runtime serialno from LK
SerialFn: 0x...
Result: VALID
```

A successful ARM32 Thumb patch usually includes:

```text
Architecture : arm32_thumb
Serialno runtime: 0x...
Patch   : KEY derived token gate
Arch    : arm32_thumb
Returns : success=... fail=...
Result: VALID
```

## Documentation

- [Usage Guide](docs/USAGE.md)
- [Architecture Notes](docs/ARCHITECTURE.md)
- [Analysis Outputs](docs/ANALYSIS_OUTPUTS.md)
- [Troubleshooting](docs/TROUBLESHOOTING.md)
- [CustomTkinter UI](docs/UI.md)
- [Publishing Checklist](docs/PUBLISHING.md)

## Credits

This project was built on top of prior public Motorola/MTK LK research and tooling. Special thanks to:

- [kasnria001/pwnage24mtk](https://github.com/kasnria001/pwnage24mtk)
- [R0rt1z2/liblk](https://github.com/R0rt1z2/liblk)
- [R0rt1z2/lkpatcher](https://github.com/R0rt1z2/lkpatcher)

See [ACKNOWLEDGEMENTS.md](ACKNOWLEDGEMENTS.md) for details.

## Compatibility

Compatibility is pattern-based, not model-name-based. A new LK is considered compatible only when:

- the `lk` payload can be extracted,
- the architecture is detected,
- the unlock flow is found,
- the FRP/OEM checker candidate is found,
- the key validator candidate is found,
- the unlock erase block is found when the selected preset needs it,
- the serial number runtime source is found,
- the rebuilt image verifies as `Result: VALID`.

Always test patched images on recoverable lab devices before using them in production workflows.

## License

GNU Affero General Public License v3.0
