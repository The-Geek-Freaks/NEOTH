#!/usr/bin/env python3
"""Minimal StatusNotifierWatcher used only by the clean-machine release smoke."""

from __future__ import annotations

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib


WATCHER_INTERFACE = "org.kde.StatusNotifierWatcher"
PROPERTIES_INTERFACE = "org.freedesktop.DBus.Properties"
WATCHER_PATH = "/StatusNotifierWatcher"


class StatusNotifierWatcher(dbus.service.Object):
    def __init__(self, bus: dbus.Bus) -> None:
        super().__init__(bus, WATCHER_PATH)
        self._items: list[str] = []

    def _properties(self) -> dict[str, object]:
        return {
            "RegisteredStatusNotifierItems": dbus.Array(self._items, signature="s"),
            "IsStatusNotifierHostRegistered": dbus.Boolean(True),
            "ProtocolVersion": dbus.Int32(0),
        }

    @dbus.service.method(
        WATCHER_INTERFACE,
        in_signature="s",
        out_signature="",
    )
    def RegisterStatusNotifierItem(self, service: str) -> None:
        if service not in self._items:
            self._items.append(service)
            self.StatusNotifierItemRegistered(service)
        print(f"REGISTERED {service}", flush=True)

    @dbus.service.method(
        WATCHER_INTERFACE,
        in_signature="s",
        out_signature="",
    )
    def RegisterStatusNotifierHost(self, _service: str) -> None:
        self.StatusNotifierHostRegistered()

    @dbus.service.method(
        PROPERTIES_INTERFACE,
        in_signature="ss",
        out_signature="v",
    )
    def Get(self, interface: str, name: str) -> object:
        if interface != WATCHER_INTERFACE:
            raise dbus.exceptions.DBusException(
                f"unknown interface: {interface}",
                name="org.freedesktop.DBus.Error.UnknownInterface",
            )
        try:
            return self._properties()[name]
        except KeyError as error:
            raise dbus.exceptions.DBusException(
                f"unknown property: {name}",
                name="org.freedesktop.DBus.Error.UnknownProperty",
            ) from error

    @dbus.service.method(
        PROPERTIES_INTERFACE,
        in_signature="s",
        out_signature="a{sv}",
    )
    def GetAll(self, interface: str) -> dict[str, object]:
        if interface != WATCHER_INTERFACE:
            return {}
        return self._properties()

    @dbus.service.signal(WATCHER_INTERFACE, signature="s")
    def StatusNotifierItemRegistered(self, _service: str) -> None:
        pass

    @dbus.service.signal(WATCHER_INTERFACE, signature="s")
    def StatusNotifierItemUnregistered(self, _service: str) -> None:
        pass

    @dbus.service.signal(WATCHER_INTERFACE, signature="")
    def StatusNotifierHostRegistered(self) -> None:
        pass

    @dbus.service.signal(WATCHER_INTERFACE, signature="")
    def StatusNotifierHostUnregistered(self) -> None:
        pass


def main() -> None:
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SessionBus()
    bus_name = dbus.service.BusName(
        WATCHER_INTERFACE,
        bus=bus,
        do_not_queue=True,
    )
    watcher = StatusNotifierWatcher(bus)
    print("READY", flush=True)
    try:
        GLib.MainLoop().run()
    finally:
        watcher.remove_from_connection()


if __name__ == "__main__":
    main()
