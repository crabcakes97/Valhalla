# Motorola Milan (XT2211DL) test results

These results are from one Moto G Stylus 5G (2022), codename `milan`, using its
stock Android 12 LK. They do not establish compatibility with another firmware
build or device.

No device serial, generated key, firmware image, or patched image is included.
Paths and command prompts have been removed from the excerpts below.

## Verified outcomes

- Bootloader unlock succeeded and persisted as `securestate: flashing_unlocked`.
- The original Valhalla FRP run printed success even though the phone still
  reported `frp-state: protected (277)` and Setup Wizard required the previous
  Google account.
- A guarded, firmware-specific post-unlock branch experiment subsequently
  reported `frp-state: no protection (err)` while preserving
  `securestate: flashing_unlocked`.
- Android then connected over ADB as `milan` and reported
  `ro.boot.flash.locked=0`, `ro.boot.verifiedbootstate=orange`,
  `ro.boot.vbmeta.device_state=unlocked`, `user_setup_complete=1`, and
  `device_provisioned=1`.

## Why the original FRP result was false

The original tool had three independent observability/control-flow defects:

1. It flashed the patched LK and invoked the OEM command without rebooting the
   bootloader, so the old LK could still be executing from memory.
2. It parsed the Platform Tools timing footer as part of the serial number.
3. It discarded the OEM command output and return code and printed success
   without checking `frp-state`.

This pull request fixes those tool-level defects. It does not claim that the
generic erase-serial preset is compatible with this firmware.

## Post-unlock control-flow finding

After unlock, the stock Milan LK reports boot state `0x77ee`. In the analyzed
ARM32 Thumb payload, the command dispatcher compared against that value and
branched directly to the `Already unlocked` response before the patched key and
erase flow:

```text
0x4c483bee: movw r2, #0x77ee
0x4c483bf2: cmp  r3, r2
0x4c483bf4: beq  #0x4c483cc0  ; Already unlocked
```

For this exact payload only, changing the branch at file offset `0x83bf4` from
Thumb bytes `64 d0` to `09 d0` preserved the condition but redirected the
already-unlocked state to the existing patched token/erase flow:

```text
0x4c483bf4: beq  #0x4c483c0a
```

The helper in [`research/milan_post_unlock_frp.py`](../research/milan_post_unlock_frp.py)
requires the exact input size, SHA-256, and surrounding instruction bytes. It
also asserts that only the intended byte changed. It produces a payload for Val
Protocol's existing signed-image repacker; it does not flash a device.

The repacked image passed Val Protocol's image verification: CERT1/CERT2
signatures, image-header hash, and image-data hash were valid. The verifier
explicitly skipped comparison against the device's eFuse root, so successful
booting remained a separate device test.

Relevant research hashes:

```text
stock partition image:
a4d4d06fc340554001cd040688e8336d2fe6be243736bd96af55b5d0e55db34b

erase-serial payload before branch change:
82845ef8bd32fe459fcda1641b1d0f216c95ee535c279ef62e48ea6c17504688

payload after branch change:
6aacf479e8838297bef806a1fd26563068c098e5545bac63a82e656332db8189

repacked post-unlock test image:
cb63d88ddfc3ced4323114e8a7b12450d498a7f2c1777325c48cba1833f222bf
```

This offset must not be generalized or auto-applied to another LK. A proper
implementation belongs in Val Protocol's analyzer and must prove the compared
boot state, original conditional branch, `Already unlocked` target, and normal
unlock-flow target before patching.

## Sanitized command transcript

The exact stock image first booted successfully from inactive slot B:

```text
$ fastboot flash lk_b lk.img
Sending 'lk_b' (1650 KB)  OKAY
Writing 'lk_b'            OKAY

$ fastboot set_active b
Setting current slot to 'b'  OKAY

$ fastboot reboot bootloader
Rebooting into bootloader  OKAY

$ fastboot getvar current-slot
current-slot: b
$ fastboot getvar securestate
securestate: flashing_unlocked
$ fastboot getvar frp-state
frp-state: protected (277)
```

After strictly patching and repacking the payload, the experimental image was
staged on inactive slot B. Slot A was selected again immediately after B booted,
leaving the tested recovery slot as the next boot target. The generated token
and device serial are intentionally omitted:

```text
$ fastboot oem unlock REDACTED_GENERATED_TOKEN
OKAY [  0.623s]

$ fastboot getvar frp-state
frp-state: no protection (err)
$ fastboot getvar securestate
securestate: flashing_unlocked
$ fastboot getvar current-slot
current-slot: a
```

After rebooting Android:

```text
$ adb devices -l
REDACTED  device product:milan_g model:moto_g_stylus__2022_ device:milan

$ adb shell getprop ro.boot.flash.locked
0
$ adb shell getprop ro.boot.verifiedbootstate
orange
$ adb shell getprop ro.boot.vbmeta.device_state
unlocked
$ adb shell settings get secure user_setup_complete
1
$ adb shell settings get global device_provisioned
1
```

## Data-erasure behavior

Val Protocol's ARM32 `--unlock-erase-only` path explicitly identifies the erase
block as `metadata`, `userdata`, and `md_udc`. Valhalla's erase-serial preset
rewrites `md_udc` to `frp`. The successful experiment therefore intentionally
targeted `metadata`, `userdata`, and `frp` and must be presented as a destructive
data erase, not as “No Factory Reset.”

## Stock LK result

The A/B experiment above disproves the blanket claim that restoring stock LK
necessarily bricks or removes the unlock for this exact Milan firmware. It does
not prove that a mismatched stock LK, another firmware version, or another
Motorola model is safe.
