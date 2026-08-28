# VALHALLA UNLOCK TOOL

Unlock bootloaders and experimentally erase FRP on Motorola MediaTek devices.

WARNING: CAN BRICK YOUR DEVICE! Use at your own risk!

---

## What this is

A simple tool that unlocks your bootloader or attempts an experimental FRP erase on Motorola MediaTek phones. It handles setup automatically — downloads the exploit, installs dependencies, sets up USB permissions on Linux, and runs the selected workflow.

No command line hacking. Just run it and click a button.

---

## Features

- Unlocks bootloader (factory reset)
- Attempts FRP erase using Val Protocol erase-serial, warns about its data wipe, and verifies `frp-state`
- Stops combined mode if FRP erase cannot be verified
- Auto-downloads Val Protocol exploit from GitHub
- Auto-installs dependencies on Linux
- Auto-sets up udev rules on Linux
- Verbose logging so you see what's happening
- Works even if OEM unlock is grayed out in Developer Options

---

## Supported Devices

- Motorola MediaTek devices
- Moto G Play 2026 (XT2615V, XT2615-1) confirmed working
- Moto G series, Edge series, Razr series with MTK chips
- May work on other MediaTek Motorola devices

### Tested status

- Moto G Play 2026 (XT2615V, XT2615-1): bootloader unlock reported working by the project author.
- Motorola Milan (XT2211DL): bootloader unlock verified on stock Android 12 LK. The original Valhalla FRP run falsely reported success while FRP remained `protected (277)`. A separate, firmware-specific post-unlock experiment subsequently cleared FRP; it is documented in [`docs/milan-xt2211dl-results.md`](docs/milan-xt2211dl-results.md) and is not automatically applied by Valhalla.

FRP support must be treated as device-specific and experimental. A successful
fastboot command is not proof that FRP was erased; Valhalla now reports success
only when the device's `frp-state` no longer says `protected`.

On an unlocked Milan, the unmodified erase-serial flow exits through the
`Already unlocked` branch before reaching its token/erase path. Val Protocol's
separate ARM32 erase-token patcher rejected this LK's control-flow shape, so its
safety check must not be bypassed or force-patched.

The erase-serial preset is destructive. Its ARM32 erase-only flow targets
`metadata`, `userdata`, and `md_udc`; Valhalla rewrites `md_udc` to `frp`.
Therefore FRP mode must be treated as a factory reset/data erase even if a
particular failed attempt appears to leave data intact.

---

## Requirements

Linux:
- Nothing! The tool installs everything automatically:
  - Python packages
  - fastboot (via apt)
  - udev rules (USB permissions)

Windows:
- Python installed (download from python.org)
- fastboot installed (Android Platform Tools)
- USB drivers for your Motorola device

---

## How to Use

Linux:

1. Clone or download this repository
2. Place your stock lk.img in the same folder as Valhalla.py
3. Run: python3 Valhalla.py
4. Select your mode, click "Check Device", then "Run Valhalla"

Windows (Python):

1. Install Python from python.org
2. Install fastboot from Android Platform Tools
3. Place lk.img in the same folder as Valhalla.py
4. Run: python Valhalla.py

Windows (EXE):

1. Build the EXE (see below) or download it
2. Place lk.img in the dist/ folder next to Valhalla.exe
3. Double-click Valhalla.exe

---

## Where to put lk.img

- Python script: same folder as Valhalla.py
- EXE (Windows): same folder as Valhalla.exe (the dist/ folder if you built it)
- Executable (Linux): same folder as the executable file (the dist/ folder if you built it)

---

## How to Build

Windows (EXE):

pip install pyinstaller
pyinstaller --onefile --windowed Valhalla.py

The EXE will be in the dist/ folder as Valhalla.exe.

Linux (Executable):

pip install pyinstaller
pyinstaller --onefile --windowed Valhalla.py

The executable will be in the dist/ folder as Valhalla (no extension). You may need to make it executable depending on your distro:

chmod +x dist/Valhalla

Then run it:

./dist/Valhalla

---

## Linux Troubleshooting

USB Permissions:

The tool tries to set up udev rules automatically. If it fails, run:

sudo bash -c 'cat > /etc/udev/rules.d/51-android.rules << EOF
SUBSYSTEM=="usb", ATTR{idVendor}=="0e8d", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="22b8", MODE="0666", GROUP="plugdev"
SUBSYSTEM=="usb", ATTR{idVendor}=="2e04", MODE="0666", GROUP="plugdev"
EOF'
sudo udevadm control --reload-rules
sudo udevadm trigger
sudo usermod -a -G plugdev $USER
sudo usermod -a -G dialout $USER

Log out and back in, then try again.

Fastboot Not Found:

sudo apt install android-tools-fastboot -y

---

## Windows Troubleshooting

Fastboot Not Found:

1. Download Android Platform Tools from: https://developer.android.com/studio/releases/platform-tools
2. Extract the ZIP
3. Add the folder to your system PATH

USB Drivers:

Install Motorola USB drivers from the official site.

---

## WARNING

THIS CAN PERMANENTLY BRICK YOUR DEVICE!

- Flashing a bad LK can hard-brick your phone
- Only flash an LK image that exactly matches the device and firmware
- Keep both the stock LK and every successfully booted patched LK backed up
- Keep a full stock firmware backup ready
- Use at your own risk! NO responsibility accepted!

---

## Credits

- RomLord14495 — Tool creation
- Maikyxd — Val Protocol exploit (https://github.com/Maikyxd/val-protocol)
- R0rt1z2 — liblk library (https://github.com/R0rt1z2/liblk)

## Contributors

- Val Protocol team — Exploit research and development
```
