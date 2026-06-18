#!/usr/bin/env python3
"""Timed Frida Gadget capture for a patched Anker app."""

from __future__ import annotations

import argparse
import datetime as dt
import re
import shutil
import subprocess
import threading
import time
from pathlib import Path

DEFAULT_PACKAGE = "com.anker.charging"
DEFAULT_PROCESS = "Gadget"
DEFAULT_LOCAL_PORT = 49152
DEFAULT_REMOTE_PORT = 49152
DEFAULT_ATTACH_DELAY = 0.8
DEFAULT_REOPEN_DELAY = 5.0

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_SCRIPT = SCRIPT_DIR / "frida.js"
DEFAULT_LOG_DIR = SCRIPT_DIR / "logs"


def run(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )


def say(message: str) -> None:
    print(message, flush=True)


def slugify(value: str) -> str:
    value = value.strip().lower()
    value = re.sub(r"[^a-z0-9]+", "_", value).strip("_")
    return value or "capture"


def prompt_label(label: str | None, *, no_prompt: bool) -> str:
    if label:
        return slugify(label)
    if no_prompt:
        return "capture"
    return slugify(input("Log label, e.g. recharge power: "))


def list_adb_devices() -> list[str]:
    result = run(["adb", "devices", "-l"])
    devices = []
    for line in result.stdout.splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "device":
            devices.append(parts[0])
    return devices


def check_device(device: str, devices: list[str] | None = None) -> None:
    devices = list_adb_devices() if devices is None else devices
    if device not in devices:
        raise SystemExit(
            f"ADB device '{device}' is not connected. Connected devices: {', '.join(devices) or 'none'}"
        )


def choose_device(device: str | None, *, no_prompt: bool) -> str:
    devices = list_adb_devices()
    if device:
        check_device(device, devices)
        return device

    if not devices:
        raise SystemExit("No ADB devices connected.")
    if no_prompt:
        if len(devices) == 1:
            return devices[0]
        raise SystemExit(
            f"Multiple ADB devices connected. Pass --device. Devices: {', '.join(devices)}"
        )
    if len(devices) == 1:
        say(f"Using ADB device: {devices[0]}")
        say(f"Next time: --device {devices[0]}")
        return devices[0]

    say("ADB devices:")
    for index, serial in enumerate(devices, start=1):
        say(f"  {index}. {serial}")
    selected = input("Select device: ").strip()
    if not selected.isdigit() or not 1 <= int(selected) <= len(devices):
        raise SystemExit("Invalid device selection.")
    chosen = devices[int(selected) - 1]
    say(f"Next time: --device {chosen}")
    return chosen


def ensure_tools() -> None:
    missing = [tool for tool in ("adb", "frida") if shutil.which(tool) is None]
    if missing:
        raise SystemExit(f"Missing required tool(s): {', '.join(missing)}")


def adb(
    device: str, *args: str, check: bool = True
) -> subprocess.CompletedProcess[str]:
    return run(["adb", "-s", device, *args], check=check)


def launch_app(device: str, package: str) -> None:
    adb(
        device,
        "shell",
        "monkey",
        "-p",
        package,
        "-c",
        "android.intent.category.LAUNCHER",
        "1",
    )


def schedule_reopen(device: str, package: str, delay: float) -> threading.Timer | None:
    if delay <= 0:
        return None

    def reopen() -> None:
        say("Re-opening Anker for Gadget after first attach...")
        launch_app(device, package)

    timer = threading.Timer(delay, reopen)
    timer.daemon = True
    timer.start()
    return timer


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--device", help="ADB device serial, e.g. from `adb devices -l`."
    )
    parser.add_argument(
        "--label", help="Log filename prefix. If omitted, prompts interactively."
    )
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="Do not prompt for label/device. Uses label 'capture' if --label is omitted.",
    )
    parser.add_argument("--attach-delay", type=float, default=DEFAULT_ATTACH_DELAY)
    parser.add_argument("--reopen-delay", type=float, default=DEFAULT_REOPEN_DELAY)
    parser.add_argument("--process-name", default=DEFAULT_PROCESS)
    parser.add_argument("--package", default=DEFAULT_PACKAGE)
    parser.add_argument("--script", type=Path, default=DEFAULT_SCRIPT)
    parser.add_argument("--log-dir", type=Path, default=DEFAULT_LOG_DIR)
    parser.add_argument("--local-port", type=int, default=DEFAULT_LOCAL_PORT)
    parser.add_argument("--remote-port", type=int, default=DEFAULT_REMOTE_PORT)
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()

    ensure_tools()
    device = choose_device(args.device, no_prompt=args.no_prompt)

    label = prompt_label(args.label, no_prompt=args.no_prompt)
    args.log_dir.mkdir(parents=True, exist_ok=True)
    timestamp = dt.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_path = args.log_dir / f"{label}_{timestamp}.log"

    say(f"Device: {device}")
    say(f"Delay:  {args.attach_delay:.2f}s")
    say(f"Reopen: {args.reopen_delay:.2f}s")
    say(f"Log:    {log_path}")

    adb(device, "forward", f"tcp:{args.local_port}", f"tcp:{args.remote_port}")
    adb(device, "shell", "am", "force-stop", args.package, check=False)

    say("Launching patched Anker...")
    launch_app(device, args.package)
    time.sleep(args.attach_delay)
    schedule_reopen(device, args.package, args.reopen_delay)

    command = [
        "frida",
        "-H",
        f"127.0.0.1:{args.local_port}",
        "-n",
        args.process_name,
        "-l",
        str(args.script),
        "-o",
        str(log_path),
    ]

    say("Attaching to Gadget. Use Anker after it re-opens, then Ctrl-C or type exit.")
    return subprocess.call(command)


if __name__ == "__main__":
    raise SystemExit(main())
