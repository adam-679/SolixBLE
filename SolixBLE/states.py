"""Enums for SolixBLE module.

.. moduleauthor:: Harvey Lelliott (flip-dots) <harveylelliott@duck.com>

"""

from enum import Enum


class PortStatus(Enum):
    """The status of a port on the device."""

    #: The status of the port is unknown.
    UNKNOWN = -1

    #: The port is not connected.
    NOT_CONNECTED = 0

    #: The port is an output.
    OUTPUT = 1

    #: The port is an input.
    INPUT = 2


class ChargingStatus(Enum):
    """The status of charging/discharging on a device."""

    #: The status is unknown.
    UNKNOWN = -1

    #: The device is idle (Battery not charging or discharging).
    IDLE = 0

    #: The device is discharging.
    DISCHARGING = 1

    #: The device is charging.
    CHARGING = 2


class LightStatus(Enum):
    """The status of the light on the device."""

    #: The status of the light is unknown.
    UNKNOWN = -1

    #: The light is off.
    OFF = 0

    #: The light is on low.
    LOW = 1

    #: The light is on medium.
    MEDIUM = 2

    #: The light is on high.
    HIGH = 3
