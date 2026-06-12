#!/usr/bin/env python3
"""Timed rooted Frida capture for the Anker app."""

from __future__ import annotations

import argparse
import datetime as dt
import re
import shutil
import subprocess
import time
from pathlib import Path


FRIDA_VERSION = "17.12.0"
DEFAULT_PACKAGE = "com.anker.charging"
DEFAULT_PROCESS = "Anker"
DEFAULT_LOCAL_PORT = 27043
DEFAULT_REMOTE_PORT = 27042
DEFAULT_ATTACH_DELAY = 0.8

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SCRIPT = REPO_ROOT / "scripts" / "frida_filtered.js"
DEFAULT_LOG_DIR = REPO_ROOT / "scripts" / "logs"


def run(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


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


def ensure_tools() -> None:
    missing = [tool for tool in ("adb", "frida", "frida-ps") if shutil.which(tool) is None]
    if missing:
        raise SystemExit(f"Missing required tool(s): {', '.join(missing)}")

    version = run(["frida", "--version"]).stdout.strip()
    if version != FRIDA_VERSION:
        raise SystemExit(
            f"Frida CLI is {version}, expected {FRIDA_VERSION}. "
            "Install matching frida-tools, then rerun this script."
        )


def adb(device: str, *args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return run(["adb", "-s", device, *args], check=check)


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
        raise SystemExit(f"Multiple ADB devices connected. Pass --device. Devices: {', '.join(devices)}")
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


def check_device(device: str, devices: list[str] | None = None) -> None:
    devices = list_adb_devices() if devices is None else devices
    if device not in devices:
        raise SystemExit(
            f"ADB device '{device}' is not connected. Connected devices: {', '.join(devices) or 'none'}"
        )


def check_root(device: str) -> None:
    result = adb(device, "shell", "su", "-c", "id", check=False)
    if result.returncode != 0 or "uid=0" not in result.stdout:
        raise SystemExit("ADB shell root is not available. Grant shell root in Magisk, then rerun.")


def forward_frida(device: str, local_port: int, remote_port: int) -> None:
    adb(device, "forward", f"tcp:{local_port}", f"tcp:{remote_port}")
    result = run(["frida-ps", "-H", f"127.0.0.1:{local_port}"], check=False)
    if result.returncode != 0:
        raise SystemExit(
            "Could not reach undetected-frida-server through ADB forwarding. "
            "Check the Magisk module is installed/running, then rerun."
        )


def launch_app(device: str, package: str) -> None:
    adb(device, "shell", "am", "force-stop", package, check=False)
    adb(device, "shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1")


def frida_process_names(local_port: int) -> set[str]:
    result = run(["frida-ps", "-H", f"127.0.0.1:{local_port}"], check=False)
    if result.returncode != 0:
        return set()

    names = set()
    for line in result.stdout.splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) == 2 and parts[0].isdigit():
            names.add(parts[1].strip())
    return names


def wait_for_process(local_port: int, process_name: str, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if process_name in frida_process_names(local_port):
            return
        time.sleep(0.1)
    raise SystemExit(f"Frida cannot see process '{process_name}'. Try a slightly different --attach-delay.")


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--device", help="ADB device serial, e.g. from `adb devices -l`.")
    parser.add_argument("--label", help="Log filename prefix. If omitted, prompts interactively.")
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="Do not prompt for label/device. Uses label 'capture' if --label is omitted.",
    )
    parser.add_argument("--attach-delay", type=float, default=DEFAULT_ATTACH_DELAY)
    parser.add_argument("--process-name", default=DEFAULT_PROCESS)
    parser.add_argument("--package", default=DEFAULT_PACKAGE)
    parser.add_argument("--script", type=Path, default=DEFAULT_SCRIPT)
    parser.add_argument("--log-dir", type=Path, default=DEFAULT_LOG_DIR)
    parser.add_argument("--local-port", type=int, default=DEFAULT_LOCAL_PORT)
    parser.add_argument("--remote-port", type=int, default=DEFAULT_REMOTE_PORT)
    parser.add_argument("--process-timeout", type=float, default=1.0)
    return parser


def main() -> int:
    args = build_arg_parser().parse_args()

    ensure_tools()
    device = choose_device(args.device, no_prompt=args.no_prompt)
    check_root(device)

    label = prompt_label(args.label, no_prompt=args.no_prompt)
    args.log_dir.mkdir(parents=True, exist_ok=True)
    timestamp = dt.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_path = args.log_dir / f"{label}_{timestamp}.log"

    say(f"Device: {device}")
    say(f"Delay:  {args.attach_delay:.2f}s")
    say(f"Log:    {log_path}")

    forward_frida(device, args.local_port, args.remote_port)
    say("Launching Anker...")
    launch_app(device, args.package)
    time.sleep(args.attach_delay)
    wait_for_process(args.local_port, args.process_name, args.process_timeout)

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

    say("Attaching during splash. Use Anker, then press Ctrl-C or type exit.")
    return subprocess.call(command)


if __name__ == "__main__":
    raise SystemExit(main())
