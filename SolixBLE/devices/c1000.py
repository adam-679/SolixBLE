"""C1000(X) power station model.

.. moduleauthor:: Harvey Lelliott (flip-dots) <harveylelliott@duck.com>

"""

import asyncio
import logging
from datetime import datetime, timedelta

from ..const import (
    DEFAULT_METADATA_BOOL,
    DEFAULT_METADATA_FLOAT,
    DEFAULT_METADATA_INT,
    DEFAULT_METADATA_STRING,
)
from ..device import SolixBLEDevice
from ..states import DisplayTimeout, LightStatus, PortStatus

CMD_AC_OUTPUT = "404a"
CMD_DC_OUTPUT = "404b"
CMD_STATUS_UPDATE = "4040"
CMD_AC_TIMER = "4042"
CMD_LIGHT_MODE = "404f"
CMD_DISPLAY_MODE = "404c"
CMD_DISPLAY_TIMEOUT = "4046"
CMD_DISPLAY_ON_OFF = "4052"
CMD_AC_RECHARGE_POWER = "4044"
CMD_ULTRAFAST_RECHARGE = "405e"
CMD_DC_TIMER = "4043"
CMD_DC_12V_POWER_SAVING = "4076"
CMD_AC_POWER_SAVING = "4077"
CMD_OUTPUT_AUTO_RECOVERY = "4079"

PAYLOAD_ON = "a10121a2020101"
PAYLOAD_OFF = "a10121a2020100"
PAYLOAD_STATUS_UPDATE = "a10121"
PAYLOAD_LIGHT_MODE = "a10121a20201"
PAYLOAD_TIMEOUT_TIME = "a10121a20302"
PAYLOAD_AC_RECHARGE_POWER = "a10121a20302"
PAYLOAD_TIMER_SECONDS = "a10121a20503"

MIN_AC_RECHARGE_POWER = 200
MAX_AC_RECHARGE_POWER = 1000
MAX_TIMER_SECONDS = 23 * 60 * 60 + 55 * 60

_LOGGER = logging.getLogger(__name__)

C1000_CONTROL_TELEMETRY_KEYS = {"d3", "d9", "dc", "de", "dd"}
C1000_WORK_INFO_KEYS = {"a4", "b0", "bf"}
_CONTROL_REFRESH_DEBOUNCE_SECONDS = 0.2


class C1000(SolixBLEDevice):
    """
    C1000(X) Power Station.

    Use this class to connect and monitor a C1000(X) power station.
    This model is also known as the A1761.

    """

    _EXPECTED_TELEMETRY_LENGTH: int = 253

    def __init__(self, ble_device) -> None:
        super().__init__(ble_device)
        self._operation_lock = asyncio.Lock()
        self._control_refresh_debounce_task: asyncio.Task | None = None
        self._control_refresh_in_flight = False

    async def disconnect(self) -> None:
        """Disconnect and cancel any pending control-status refresh."""
        if self._control_refresh_debounce_task is not None:
            self._control_refresh_debounce_task.cancel()
            self._control_refresh_debounce_task = None
        await super().disconnect()

    async def connect(self, max_attempts: int = 3, run_callbacks: bool = True) -> bool:
        """Connect to the C1000 and request a full status snapshot."""
        connected = await super().connect(
            max_attempts=max_attempts, run_callbacks=run_callbacks
        )
        if not connected:
            return False

        try:
            await self._process_telemetry(await self.get_status_update())
        except Exception:
            _LOGGER.debug("Unable to seed C1000 status after connect", exc_info=True)
        return True

    async def _process_telemetry(self, parameters: dict[str, bytes]) -> None:
        """Process C1000 telemetry, merging partial updates when needed."""
        if self._is_partial_telemetry(parameters):
            await self._process_partial_telemetry(parameters)
            if self._should_schedule_control_refresh(parameters):
                self._schedule_control_status_refresh()
            return
        await super()._process_telemetry(parameters)

    def _is_partial_telemetry(self, parameters: dict[str, bytes]) -> bool:
        return (
            bool(parameters)
            and self._data is not None
            and len(parameters) < len(self._data)
        )

    def _parse_known_int(
        self, key: str, begin: int = None, end: int = None, signed: bool = False
    ) -> int:
        if self._data is None or key not in self._data:
            return DEFAULT_METADATA_INT
        return self._parse_int(key, begin=begin, end=end, signed=signed)

    def _should_schedule_control_refresh(self, parameters: dict[str, bytes]) -> bool:
        """Return true when work-info fragments omit control telemetry keys."""
        if not parameters:
            return False
        if C1000_CONTROL_TELEMETRY_KEYS & parameters.keys():
            return False
        return bool(C1000_WORK_INFO_KEYS & parameters.keys())

    def _schedule_control_status_refresh(self) -> None:
        """Debounce background polls for light/display state after physical changes."""
        if self._control_refresh_debounce_task is not None:
            self._control_refresh_debounce_task.cancel()

        async def debounced_refresh() -> None:
            try:
                await asyncio.sleep(_CONTROL_REFRESH_DEBOUNCE_SECONDS)
                await self._refresh_control_status()
            except asyncio.CancelledError:
                raise

        self._control_refresh_debounce_task = asyncio.get_running_loop().create_task(
            debounced_refresh()
        )

    @property
    def ac_timer_remaining(self) -> int:
        """Time remaining on AC timer.

        :returns: Seconds remaining or default int value.
        """
        return self._parse_int("a2", begin=1)

    @property
    def ac_timer(self) -> datetime | None:
        """Timestamp of AC timer.

        :returns: Timestamp of when AC timer expires or None.
        """
        if (
            self.ac_timer_remaining != DEFAULT_METADATA_INT
            and self.ac_timer_remaining != 0
        ):
            return datetime.now() + timedelta(seconds=self.ac_timer_remaining)

    @property
    def dc_timer_remaining(self) -> int:
        """Time remaining on DC timer.

        :returns: Seconds remaining or default int value.
        """
        return self._parse_int("a3", begin=1)

    @property
    def dc_timer(self) -> datetime | None:
        """Timestamp of DC timer.

        :returns: Timestamp of when DC timer expires or None.
        """
        if (
            self.dc_timer_remaining != DEFAULT_METADATA_INT
            and self.dc_timer_remaining != 0
        ):
            return datetime.now() + timedelta(seconds=self.dc_timer_remaining)

    @property
    def hours_remaining(self) -> float:
        """Time remaining to full/empty.

        Note that any hours over 24 are overflowed to the
        days remaining. Use time_remaining if you want
        days to be included.

        :returns: Hours remaining or default float value.
        """
        if self._data is None:
            return DEFAULT_METADATA_FLOAT

        return round(divmod(self.time_remaining, 24)[1], 1)

    @property
    def days_remaining(self) -> int:
        """Time remaining to full/empty.

        Note that any partial days are overflowed into
        the hours remaining. Use time_remaining if you want
        hours to be included.

        :returns: Days remaining or default int value.
        """
        if self._data is None:
            return DEFAULT_METADATA_INT

        return round(divmod(self.time_remaining, 24)[0])

    @property
    def time_remaining(self) -> float:
        """Time remaining to full/empty in hours.

        :returns: Hours remaining or default float value.
        """
        return (
            self._parse_known_int("a4", begin=1) / 10.0
            if self._data is not None
            else DEFAULT_METADATA_FLOAT
        )

    @property
    def timestamp_remaining(self) -> datetime | None:
        """Timestamp of when device will be full/empty.

        :returns: Timestamp of when will be full/empty or None.
        """
        if self._data is None:
            return None
        return datetime.now() + timedelta(hours=self.time_remaining)

    @property
    def ac_power_in(self) -> int:
        """AC Power In.

        :returns: Total AC power in or default int value.
        """
        return self._parse_known_int("a5", begin=1)

    @property
    def ac_recharge_power_limit(self) -> int:
        """AC recharge input power limit.

        :returns: AC recharge power limit in watts or default int value.
        """
        return self._parse_int("d1", begin=1)

    @property
    def ultrafast_recharge(self) -> bool | None:
        """UltraFast AC recharge mode.

        :returns: True if UltraFast recharge is enabled, False if disabled.
        """
        return (
            bool(self._parse_int("e5", begin=1))
            if self._data is not None
            else DEFAULT_METADATA_BOOL
        )

    @property
    def ac_power_out(self) -> int:
        """AC Power Out.

        :returns: Total AC power out or default int value.
        """
        return self._parse_known_int("a6", begin=1)

    @property
    def usb_c1_power(self) -> int:
        """USB C1 Power.

        :returns: USB port C1 power or default int value.
        """
        return self._parse_int("a7", begin=1)

    @property
    def usb_c2_power(self) -> int:
        """USB C2 Power.

        :returns: USB port C2 power or default int value.
        """
        return self._parse_int("a8", begin=1)

    @property
    def usb_a1_power(self) -> int:
        """USB A1 Power.

        :returns: USB port A1 power or default int value.
        """
        return self._parse_int("a9", begin=1)

    @property
    def usb_a2_power(self) -> int:
        """USB A2 Power.

        :returns: USB port A2 power or default int value.
        """
        return self._parse_int("aa", begin=1)

    @property
    def dc_power_out(self) -> int:
        """DC Power Out.

        :returns: DC power out or default int value.
        """
        return self._parse_known_int("ad", begin=1)

    @property
    def solar_power_in(self) -> int:
        """Solar Power In.

        :returns: Total solar power in or default int value.
        """
        return self._parse_int("ae", begin=1)

    @property
    def power_in(self) -> int:
        """Total Power In.

        :returns: Total power in or default int value.
        """
        return self._parse_known_int("af", begin=1)

    @property
    def power_out(self) -> int:
        """Total Power Out.

        :returns: Total power out or default int value.
        """
        return self._parse_known_int("b0", begin=1)

    @property
    def software_version(self) -> str:
        """Main software version.

        :returns: Firmware version or default str value.
        """
        if self._data is None:
            return DEFAULT_METADATA_STRING

        return ".".join([digit for digit in str(self._parse_int("b3", begin=1))])

    @property
    def software_version_expansion(self) -> str:
        """Software version of any expansion batteries.

        If there is no expansion battery then it will be "0".

        :returns: Firmware version or default str value.
        """
        if self._data is None:
            return DEFAULT_METADATA_STRING

        return ".".join([digit for digit in str(self._parse_int("b9", begin=1))])

    @property
    def software_version_controller(self) -> str:
        """Software version of the controller.

        :returns: Firmware version or default str value.
        """
        if self._data is None:
            return DEFAULT_METADATA_STRING

        return ".".join([digit for digit in str(self._parse_int("ba", begin=1))])

    @property
    def ac_output(self) -> PortStatus:
        """AC Port Status.

        PortStatus.NOT_CONNECTED signifies off.
        PortStatus.OUTPUT signifies on.

        :returns: Status of the AC port.
        """
        if self._data is None or "bb" not in self._data:
            return PortStatus.UNKNOWN
        return PortStatus(self._parse_int("bb", begin=1))

    @property
    def dc_output(self) -> PortStatus:
        """DC Port Status.

        PortStatus.NOT_CONNECTED signifies off.
        PortStatus.OUTPUT signifies on.

        :returns: Status of the DC port.
        """
        if self._data is None or "cc" not in self._data:
            return PortStatus.UNKNOWN
        return PortStatus(self._parse_int("cc", begin=1))

    @property
    def output_auto_recovery(self) -> bool | None:
        """Configured output auto recovery mode.

        If AC output or CarPort output was on and closes because the battery
        drops below the discharge limit, the output reopens when the battery
        recovers to the discharge limit plus 10%.

        :returns: True if output auto recovery is enabled, False if disabled.
        """
        if self._data is None or "f7" not in self._data:
            return DEFAULT_METADATA_BOOL
        return bool(self._parse_int("f7", begin=1, end=2))

    @property
    def dc_12v_power_saving_mode(self) -> bool | None:
        """Configured DC 12V power saving mode.

        :returns: True if DC 12V power saving is enabled, False if disabled.
        """
        if self._data is None or "f8" not in self._data:
            return DEFAULT_METADATA_BOOL
        return self._parse_int("f8", begin=1, end=2) == 2

    @property
    def ac_power_saving_mode(self) -> bool | None:
        """Configured AC power saving mode.

        :returns: True if AC power saving is enabled, False if disabled.
        """
        if self._data is None or "f8" not in self._data:
            return DEFAULT_METADATA_BOOL
        return self._parse_int("f8", begin=2, end=3) == 2

    @property
    def display_timeout(self) -> int:
        """Configured display timeout in seconds.

        :returns: Configured display timeout or default int value.
        """
        return self._parse_known_int("d3", begin=1)

    @property
    def display_mode(self) -> LightStatus:
        """Configured display backlight brightness.

        :returns: Configured display backlight brightness.
        """
        if self._data is None:
            return LightStatus.UNKNOWN
        if "d9" not in self._data:
            return LightStatus.UNKNOWN
        if not self.is_display_on:
            return LightStatus.OFF
        return LightStatus(self._parse_int("d9", begin=1))

    @property
    def is_display_on(self) -> bool:
        """Display on status.

        :returns: Status of the display.
        """
        if self._data is None or "de" not in self._data:
            return DEFAULT_METADATA_BOOL
        return bool(self._parse_int("de", begin=1))

    @property
    def light(self) -> LightStatus:
        """Status of the LED light bar.

        :returns: Status of the LED light bar.
        """
        if self._data is None or "dc" not in self._data:
            return LightStatus.UNKNOWN
        return LightStatus(self._parse_int("dc", begin=1))

    @property
    def temperature(self) -> int:
        """Temperature of the unit (C).

        :returns: Temperature of the unit in degrees C.
        """
        return self._parse_int("bd", begin=1, signed=True)

    @property
    def temperature_expansion(self) -> int:
        """Temperature of the expansion battery if present (C).

        :returns: Temperature of expansion battery in degrees C or 0 if not present or default int value.
        """
        return self._parse_int("be", begin=1, signed=True)

    @property
    def battery_percentage(self) -> int:
        """Battery Percentage.

        :returns: Percentage charge of battery or default int value.
        """
        return self._parse_known_int("c1", begin=1)

    @property
    def battery_percentage_expansion(self) -> int:
        """Battery Percentage of the expansion battery.

        :returns: Percentage charge of expansion battery or 0 if not present or default int value.
        """
        return self._parse_int("c2", begin=1)

    @property
    def battery_health(self) -> int:
        """Battery health as a percentage.

        :returns: Percentage of battery health or default int value.
        """
        return self._parse_int("c3", begin=1)

    @property
    def battery_health_expansion(self) -> int:
        """Battery health as a percentage for expansion battery.

        :returns: Percentage of expansion battery health or 0 if not present or default int value.
        """
        return self._parse_int("c4", begin=1)

    @property
    def num_expansion(self) -> int:
        """Number of expansion batteries.

        :returns: Number of expansion batteries or default int value.
        """
        return self._parse_int("c5", begin=1)

    @property
    def serial_number(self) -> str:
        """Device serial number.

        :returns: Device serial number or default str value.
        """
        return self._parse_string("d0", begin=1)

    async def _refresh_control_status(self) -> None:
        """Poll full status and merge only control keys into cached telemetry."""
        if self._control_refresh_in_flight:
            return

        self._control_refresh_in_flight = True
        try:
            try:
                parameters = await self.get_status_update()
            except Exception:
                _LOGGER.debug("Unable to refresh C1000 control status", exc_info=True)
                return

            control_parameters = {
                key: value
                for key, value in parameters.items()
                if key in C1000_CONTROL_TELEMETRY_KEYS
            }
            if control_parameters:
                await self._process_partial_telemetry(control_parameters)
        finally:
            self._control_refresh_in_flight = False

    async def _send_command(self, cmd: bytes, payload: bytes) -> None:
        """Send a C1000 command without overlapping status-response reads."""
        async with self._operation_lock:
            await self._send_command_unlocked(cmd, payload)

    async def _send_command_unlocked(self, cmd: bytes, payload: bytes) -> None:
        """Send a command while the caller already owns the operation lock."""
        await super()._send_command(cmd, payload)

    async def turn_ac_on(self) -> None:
        """Turn the AC output on.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=bytes.fromhex(CMD_AC_OUTPUT), payload=bytes.fromhex(PAYLOAD_ON)
        )

    async def turn_ac_off(self) -> None:
        """Turn the AC output off.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=bytes.fromhex(CMD_AC_OUTPUT), payload=bytes.fromhex(PAYLOAD_OFF)
        )

    async def turn_dc_on(self) -> None:
        """Turn the DC output on.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=bytes.fromhex(CMD_DC_OUTPUT), payload=bytes.fromhex(PAYLOAD_ON)
        )

    async def turn_dc_off(self) -> None:
        """Turn the DC output off.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=bytes.fromhex(CMD_DC_OUTPUT), payload=bytes.fromhex(PAYLOAD_OFF)
        )

    async def set_ac_timer(self, seconds: int) -> None:
        """Set the AC output timer.

        :param seconds: Number of seconds until the AC output turns off. Use 0 to disable.
        :raises ValueError: If seconds is outside the encodable range.
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        if not 0 <= seconds <= MAX_TIMER_SECONDS:
            raise ValueError(
                f"Output timer must be between 0 and {MAX_TIMER_SECONDS} seconds"
            )
        await self._send_command(
            cmd=bytes.fromhex(CMD_AC_TIMER),
            payload=bytes.fromhex(PAYLOAD_TIMER_SECONDS)
            + seconds.to_bytes(length=4, byteorder="little", signed=False),
        )

    async def set_dc_12v_power_saving_mode(self, enabled: bool) -> None:
        """Set the DC 12V power saving mode.

        :param enabled: True to enable, False to disable.
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=bytes.fromhex(CMD_DC_12V_POWER_SAVING),
            payload=bytes.fromhex(PAYLOAD_ON if enabled else PAYLOAD_OFF),
        )

    async def set_ac_power_saving_mode(self, enabled: bool) -> None:
        """Set the AC power saving mode.

        :param enabled: True to enable, False to disable.
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=bytes.fromhex(CMD_AC_POWER_SAVING),
            payload=bytes.fromhex(PAYLOAD_ON if enabled else PAYLOAD_OFF),
        )

    async def set_output_auto_recovery(self, enabled: bool) -> None:
        """Set the output auto recovery mode.

        :param enabled: True to enable, False to disable.
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=bytes.fromhex(CMD_OUTPUT_AUTO_RECOVERY),
            payload=bytes.fromhex(PAYLOAD_ON if enabled else PAYLOAD_OFF),
        )

    async def set_light_mode(self, mode: LightStatus) -> None:
        """Set the light mode of the LED bar.

        :param mode: Mode to set light bar to.
        :raises ValueError: If requested mode is invalid.
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        if mode is LightStatus.UNKNOWN:
            raise ValueError("You cannot set the light status to unknown")
        await self._send_command(
            cmd=bytes.fromhex(CMD_LIGHT_MODE),
            payload=bytes.fromhex(PAYLOAD_LIGHT_MODE) + mode.value.to_bytes(),
        )

    async def set_light_mode_confirmed(self, mode: LightStatus) -> bool:
        """Set the light mode and confirm it with fresh telemetry.

        :param mode: Mode to set light bar to.
        :raises ValueError: If requested mode is invalid.
        :raises ConnectionError: If not connected to device.
        :raises TimeoutError: If no telemetry response is received.
        :raises BleakError: If command transmission fails.
        :returns: True when telemetry reports the requested light mode.
        """
        if mode is LightStatus.UNKNOWN:
            raise ValueError("You cannot set the light status to unknown")
        async with self._operation_lock:
            await self._send_command_unlocked(
                cmd=bytes.fromhex(CMD_LIGHT_MODE),
                payload=bytes.fromhex(PAYLOAD_LIGHT_MODE) + mode.value.to_bytes(),
            )
            parameters = await self._get_status_update_unlocked()
        await self._process_telemetry(parameters)
        return self.light is mode

    async def set_display_mode(self, mode: LightStatus) -> None:
        """Set the status/mode of the LCD display.

        :param mode: Mode/status to set display to (off/low/med/high).
        :raises ValueError: If requested mode is invalid.
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        if mode is LightStatus.UNKNOWN:
            raise ValueError("You cannot set the display brightness status to unknown")
        if mode is LightStatus.SOS:
            raise ValueError("You cannot set the display brightness status to SOS")
        await self._send_command(
            cmd=bytes.fromhex(CMD_DISPLAY_MODE),
            payload=bytes.fromhex(PAYLOAD_LIGHT_MODE) + mode.value.to_bytes(),
        )

    async def set_display_timeout(self, timeout: DisplayTimeout) -> None:
        """Set the status/mode of the LCD display.

        :param mode: Mode/timeout to set display to (30s, 5m, 30m, etc).
        :raises ValueError: If requested mode is invalid.
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """

        if timeout is DisplayTimeout.UNKNOWN:
            raise ValueError("You cannot set the display timeout to unknown")
        await self._send_command(
            cmd=bytes.fromhex(CMD_DISPLAY_TIMEOUT),
            payload=bytes.fromhex(PAYLOAD_TIMEOUT_TIME)
            + timeout.value.to_bytes(length=2, byteorder="little", signed=False),
        )

    async def set_ac_recharge_power(self, watts: int) -> None:
        """Set the AC recharge input power limit.

        :param watts: Recharge power limit in watts.
        :raises ValueError: If watts is outside the supported device range.
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        if not MIN_AC_RECHARGE_POWER <= watts <= MAX_AC_RECHARGE_POWER:
            raise ValueError(
                "AC recharge power must be between "
                f"{MIN_AC_RECHARGE_POWER} and {MAX_AC_RECHARGE_POWER} watts"
            )
        await self._send_command(
            cmd=bytes.fromhex(CMD_AC_RECHARGE_POWER),
            payload=bytes.fromhex(PAYLOAD_AC_RECHARGE_POWER)
            + watts.to_bytes(length=2, byteorder="little", signed=False),
        )

    async def set_ultrafast_recharge(self, enabled: bool) -> None:
        """Set UltraFast AC recharging mode.

        :param enabled: Enable or disable UltraFast AC recharging.
        :raises ValueError: If enabling while AC recharge power is below 1000W.
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        if enabled and self.ac_recharge_power_limit != MAX_AC_RECHARGE_POWER:
            raise ValueError(
                "UltraFast AC recharging requires the AC recharge power limit "
                f"to be {MAX_AC_RECHARGE_POWER} watts"
            )
        await self._send_command(
            cmd=bytes.fromhex(CMD_ULTRAFAST_RECHARGE),
            payload=bytes.fromhex(PAYLOAD_ON if enabled else PAYLOAD_OFF),
        )

    async def set_ac_timer(self, seconds: int) -> None:
        """Set the AC output timer.

        :param seconds: Number of seconds until the AC output turns off. Use 0 to disable.
        :raises ValueError: If seconds is outside the encodable range.
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        if not 0 <= seconds <= MAX_TIMER_SECONDS:
            raise ValueError(
                f"Output timer must be between 0 and {MAX_TIMER_SECONDS} seconds"
            )
        await self._send_command(
            cmd=bytes.fromhex(CMD_AC_TIMER),
            payload=bytes.fromhex(PAYLOAD_TIMER_SECONDS)
            + seconds.to_bytes(length=4, byteorder="little", signed=False),
        )

    async def set_dc_timer(self, seconds: int) -> None:
        """Set the DC output timer.

        :param seconds: Number of seconds until the DC output turns off. Use 0 to disable.
        :raises ValueError: If seconds is outside the encodable range.
        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        if not 0 <= seconds <= MAX_TIMER_SECONDS:
            raise ValueError(
                f"Output timer must be between 0 and {MAX_TIMER_SECONDS} seconds"
            )
        await self._send_command(
            cmd=bytes.fromhex(CMD_DC_TIMER),
            payload=bytes.fromhex(PAYLOAD_TIMER_SECONDS)
            + seconds.to_bytes(length=4, byteorder="little", signed=False),
        )

    async def turn_display_on(self) -> None:
        """Turn the display on.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=bytes.fromhex(CMD_DISPLAY_ON_OFF), payload=bytes.fromhex(PAYLOAD_ON)
        )

    async def turn_display_off(self) -> None:
        """Turn the display off.

        :raises ConnectionError: If not connected to device.
        :raises BleakError: If command transmission fails.
        """
        await self._send_command(
            cmd=bytes.fromhex(CMD_DISPLAY_ON_OFF), payload=bytes.fromhex(PAYLOAD_OFF)
        )

    async def get_status_update(self) -> dict[str, bytes]:
        """Request and retrieve a status update from the device.

        :raises ConnectionError: If not connected to device.
        :raises TimeoutError: If no response from device.
        :raises BleakError: If command transmission fails.
        :returns: Dictionary containing telemetry parameters.
        """
        async with self._operation_lock:
            return await self._get_status_update_unlocked()

    async def _get_status_update_unlocked(self) -> dict[str, bytes]:
        """Request a status update while the caller owns the operation lock."""
        await self._send_command_unlocked(
            cmd=bytes.fromhex(CMD_STATUS_UPDATE),
            payload=bytes.fromhex(PAYLOAD_STATUS_UPDATE),
        )

        packet_1 = await self._listen_for_packet(
            bytes.fromhex("03010f"), bytes.fromhex("c840")
        )
        if not packet_1:
            raise TimeoutError("Timed out waiting for packet 1!")

        packet_2 = await self._listen_for_packet(
            bytes.fromhex("03010f"), bytes.fromhex("c840")
        )
        if not packet_2:
            raise TimeoutError("Timed out waiting for packet 2!")

        # We need to ignore the first byte of each packet with these types
        new_payload = packet_1[1:] + packet_2[1:]
        decrypted_payload = self._decrypt_payload(new_payload)
        parameters = self._parse_payload(decrypted_payload)
        _LOGGER.debug(f"Parameters: {self._parameters_to_str(parameters, types=True)}")
        await self._process_telemetry(parameters)
        return parameters
