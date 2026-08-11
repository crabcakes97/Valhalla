# CustomTkinter UI

The repository includes a Windows UI wrapper for the three main presets.

## Launcher

Run:

```bat
run_lk_patcher_ui.bat
```

The launcher:

1. changes to the repository directory,
2. checks that Python is available,
3. installs dependencies from `requirements.txt` if `customtkinter` is missing,
4. starts `ctk_lk_patcher_ui.py`.

## Requirements

- Windows
- Python in `PATH`
- `fastboot` in `PATH`
- a device already in fastboot mode
- a compatible original LK image for that device/build

## UI Fields

- `LK image`: original LK image selected by the user.
- `Secret`: secret used for patching and key generation. Default: `Valeria`.
- `Fastboot partition`: partition name passed to `fastboot flash`. Default: `lk`.
- `Erase target`: partition used by the `erase-serial` preset. Default: `frp`.
- `Replacement target`: partition used by `unlock-serial-nvdata`. Default: `frp`.
- `Flash patched LK automatically`: when enabled, the UI flashes the generated image and runs the operation.
- `Keep analysis directory`: when enabled, analysis files are kept beside the generated image.

## Buttons

### Unlock serial

Runs:

```bash
python lk_auto_patch.py selected_lk.img -o selected_lk.unlock-serial.patched.img --preset unlock-serial --key-token-secret Valeria
```

Then:

```bash
fastboot flash lk selected_lk.unlock-serial.patched.img
fastboot reboot bootloader
fastboot oem unlock GENERATED_KEY
```

### Erase partition

Runs:

```bash
python lk_auto_patch.py selected_lk.img -o selected_lk.erase-frp.patched.img --preset erase-serial --erase-token-partition frp --erase-token-secret Valeria
```

Then:

```bash
fastboot flash lk selected_lk.erase-frp.patched.img
fastboot reboot bootloader
fastboot oem unlock GENERATED_KEY
```

The generated key is derived from the selected secret and the runtime serial number.

### Unlock + replace erase

Runs:

```bash
python lk_auto_patch.py selected_lk.img -o selected_lk.unlock-frp.patched.img --preset unlock-serial-nvdata --key-token-secret Valeria --erase-partition frp
```

Then:

```bash
fastboot flash lk selected_lk.unlock-frp.patched.img
fastboot reboot bootloader
fastboot oem unlock GENERATED_KEY
```

## Workflow

For every button, the UI performs this sequence:

1. `fastboot getvar serialno`
2. `lk_keygen.py --secret SECRET --serialno SERIAL --count 1`
3. `lk_auto_patch.py` with the selected preset
4. `fastboot flash lk PATCHED_IMAGE`
5. `fastboot reboot bootloader`
6. wait until fastboot responds again
7. `fastboot oem unlock GENERATED_KEY`

## Safety

The UI asks for confirmation before flashing when automatic flashing is enabled. Keep the original LK image and a tested recovery path before using the UI on any device.

