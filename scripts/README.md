# Reverse Engineering Helpers

This directory contains helper scripts for capturing Anker app behavior while
adding support for Solix devices. Captures can contain private device
identifiers, BLE addresses, serial numbers, and key material. Keep raw logs
local and sanitize any excerpts before sharing or committing fixtures.

## Folder Layout

- `root/`: stock Anker app capture through a rooted device and
  undetected-frida-server.
- `gadget/`: patched Anker app capture through Frida Gadget.
- `gadget/data/blutter/`: local-only Dart ASM/decompile staging. Put `asm/`,
  `pp.txt`, and `objs.txt` there for ASM inspection.
- `logs/`: legacy ignored log location from earlier helpers.

## Rooted Frida Capture

`root/anker_frida_capture.py` runs the rooted timed-attach workflow that works
with the stock Anker app:

1. forwards local Frida traffic to the phone over ADB,
2. force-stops and launches the Anker app,
3. waits briefly during the splash screen,
4. attaches Frida to the visible `Anker` process,
5. writes logs under `scripts/root/logs/`.

The default attach delay is `0.8` seconds. This timing may need small tuning by
device, OS version, and Anker app version.

## Requirements

- Android device connected with ADB debugging enabled
- shell root access on the device
- undetected-frida-server running on the device, commonly through Magisk
- local `adb`, `frida`, and `frida-ps` commands
- matching Frida CLI/server version, currently `17.11.0`

## Usage

From the repository root:

```sh
python scripts/root/anker_frida_capture.py
```

If multiple ADB devices are connected, the script prompts for one and prints the
matching `--device` flag for future runs.

To run without prompts:

```sh
python scripts/root/anker_frida_capture.py --device <adb-serial> --label "recharge power" --no-prompt
```

To tune the splash-screen attach timing:

```sh
python scripts/root/anker_frida_capture.py --device <adb-serial> --attach-delay 0.75
```

The default Frida hook script is `root/frida_filtered.js`, which adds timestamps
while keeping BLE, cipher, and selected preference logs. It filters noisy
product catalog, Firebase, Crashlytics, and push-service preference traffic.

## Timed Frida Gadget Capture

`gadget/anker_gadget_capture.py` runs the vanilla patched-app workflow used by the
upstream app-decoding notes. Use this after patching and installing the Anker
app with `gadget/patch.sh` or equivalent Frida Gadget injection.

This runner:

1. forwards local Frida traffic to the app Gadget port,
2. force-stops and launches the patched Anker app,
3. waits briefly during startup before attaching to `Gadget`,
4. re-opens the app after a short delay because the first attach often crashes
   the app,
5. writes logs under `scripts/gadget/logs/`.

The default attach delay is `0.8` seconds and the default re-open delay is `5`
seconds.

```sh
python scripts/gadget/anker_gadget_capture.py
```

To run without prompts:

```sh
python scripts/gadget/anker_gadget_capture.py --device <adb-serial> --label "recharge power" --no-prompt
```

To tune timing:

```sh
python scripts/gadget/anker_gadget_capture.py --device <adb-serial> --attach-delay 0.8 --reopen-delay 5
```

For discovering which app action maps to which BLE command, start with the
low-noise command trace. It records Flutter BLE method-channel calls plus final
BLE writes:

```sh
python scripts/gadget/anker_gadget_capture.py --device <adb-serial> --script scripts/gadget/frida_command_trace.js --label "feature name"
```

The useful output lines are:

```text
[FLUTTER BLE METHOD] ...
[BLE WRITE] uuid=... command=... packet_prefix=... data=...
[ASM POINTER] source=... method=... identifier=... command=... asm_search_terms=...
```

Use those lines with the decompiled Dart ASM staged under
`scripts/gadget/data/blutter/`. Search the ASM for the printed
`asm_search_terms`, `identifier`, and `command`, then inspect the matching code.

For deeper encrypted setter work, use the broader pipeline trace script. It keeps
BLE writes but also hooks the Flutter encryption bridge and nearby app helper
classes. It is intentionally noisy and should be used after the command trace
has narrowed the feature:

```sh
python scripts/gadget/anker_gadget_capture.py --device <adb-serial> --script scripts/gadget/frida_ble_pipeline.js --label "recharge power pipeline"
```

If you prefer running with a transient tool environment, use the same script
arguments with your environment manager of choice, for example:

```sh
uv run --with frida-tools scripts/root/anker_frida_capture.py --device <adb-serial>
uv run --with frida-tools scripts/gadget/anker_gadget_capture.py --device <adb-serial>
```

## Output

Raw logs are written to `scripts/root/logs/<label>_<timestamp>.log` or
`scripts/gadget/logs/<label>_<timestamp>.log`. Keep logs, downloaded tools, APKs,
and decompiled app output local-only through `.git/info/exclude`, not tracked
`.gitignore`.
