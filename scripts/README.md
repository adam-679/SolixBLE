# Reverse Engineering Helpers

This directory contains helper scripts for capturing Anker app behavior while
adding support for Solix devices. Captures can contain private device
identifiers, BLE addresses, serial numbers, and key material. Keep raw logs
local and sanitize any excerpts before sharing or committing fixtures.

## Timed Anker Frida Capture

`anker_frida_capture.py` runs the rooted timed-attach workflow that works with
the stock Anker app:

1. forwards local Frida traffic to the phone over ADB,
2. force-stops and launches the Anker app,
3. waits briefly during the splash screen,
4. attaches Frida to the visible `Anker` process,
5. writes logs under `scripts/logs/`.

The default attach delay is `0.8` seconds. This timing may need small tuning by
device, OS version, and Anker app version.

## Requirements

- Android device connected with ADB debugging enabled
- shell root access on the device
- undetected-frida-server running on the device, commonly through Magisk
- local `adb`, `frida`, and `frida-ps` commands
- matching Frida CLI/server version, currently `17.12.0`

## Usage

From the repository root:

```sh
python scripts/anker_frida_capture.py
```

If multiple ADB devices are connected, the script prompts for one and prints the
matching `--device` flag for future runs.

To run without prompts:

```sh
python scripts/anker_frida_capture.py --device <adb-serial> --label "recharge power" --no-prompt
```

To tune the splash-screen attach timing:

```sh
python scripts/anker_frida_capture.py --device <adb-serial> --attach-delay 0.75
```

The default Frida hook script is `frida_filtered.js`, which adds timestamps
while keeping BLE, cipher, and selected preference logs. It filters noisy
product catalog, Firebase, Crashlytics, and push-service preference traffic. To
use the original verbose hook script:

```sh
python scripts/anker_frida_capture.py --device <adb-serial> --script scripts/frida.js
```

If you prefer running with a transient tool environment, use the same script
arguments with your environment manager of choice, for example:

```sh
uv run --with frida-tools scripts/anker_frida_capture.py --device <adb-serial>
```

## Output

Raw logs are written to `scripts/logs/<label>_<timestamp>.log`. That directory
is ignored by git.
