#!/usr/bin/env python3
# ragnar_bt_agent.py
#
# Custom BlueZ pairing agent for the Ragnar Bluetooth-PAN bridge.
#
# Why this exists: BlueZ's stock `bt-agent --pin=<file>` only handles legacy
# pre-SSP pairings. Every modern phone (iOS, Android 2.1+) uses Secure Simple
# Pairing, where the 6-digit passkey is derived from the public-key exchange,
# not from a static file. A static PIN on the e-paper therefore never matches
# the code the phone shows.
#
# This agent registers with capability `DisplayYesNo` so SSP negotiates the
# "Numeric Comparison" association model: both sides display the same code
# and the user confirms. The Pi-side confirmation is automatic (we trust the
# user looking at the e-paper). The live passkey is written to
# /run/ragnar-bt-pan/current-passkey so the e-paper and the web banner can
# show the correct value during the pairing window.
#
# Runs as root (D-Bus system bus). Started by ragnar-bt-pan.service.

import logging
import os
import signal

import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib

LOG = logging.getLogger("ragnar-bt-agent")

AGENT_PATH = "/com/ragnar/bt_pan/agent"
CAPABILITY = "DisplayYesNo"
PASSKEY_FILE = "/run/ragnar-bt-pan/current-passkey"
STATIC_PIN_FILE = "/etc/ragnar/bt-pan.pin"  # fallback for legacy devices only


def _write_passkey(code):
    os.makedirs(os.path.dirname(PASSKEY_FILE), exist_ok=True)
    tmp = PASSKEY_FILE + ".tmp"
    with open(tmp, "w") as f:
        f.write(str(code))
    os.replace(tmp, PASSKEY_FILE)
    os.chmod(PASSKEY_FILE, 0o644)


def _clear_passkey():
    try:
        os.remove(PASSKEY_FILE)
    except FileNotFoundError:
        pass


def _read_static_pin():
    try:
        with open(STATIC_PIN_FILE) as f:
            v = f.read().strip()
            if v.isdigit():
                return v
    except (FileNotFoundError, PermissionError):
        pass
    return "0000"


class RagnarAgent(dbus.service.Object):
    IFACE = "org.bluez.Agent1"

    @dbus.service.method(IFACE, in_signature="", out_signature="")
    def Release(self):
        LOG.info("Release")
        _clear_passkey()

    @dbus.service.method(IFACE, in_signature="os", out_signature="")
    def AuthorizeService(self, device, uuid):
        LOG.info("AuthorizeService %s %s -> ok", device, uuid)

    @dbus.service.method(IFACE, in_signature="o", out_signature="s")
    def RequestPinCode(self, device):
        # Legacy pre-SSP pairing; modern phones won't hit this path.
        pin = _read_static_pin()
        LOG.info("RequestPinCode %s -> %s", device, pin)
        _write_passkey(pin)
        return pin

    @dbus.service.method(IFACE, in_signature="o", out_signature="u")
    def RequestPasskey(self, device):
        # Shouldn't be reached with DisplayYesNo capability; respond defensively.
        LOG.warning("RequestPasskey %s (unexpected with DisplayYesNo)", device)
        return dbus.UInt32(0)

    @dbus.service.method(IFACE, in_signature="ouq", out_signature="")
    def DisplayPasskey(self, device, passkey, entered):
        s = "%06d" % int(passkey)
        LOG.info("DisplayPasskey %s %s entered=%s", device, s, entered)
        _write_passkey(s)

    @dbus.service.method(IFACE, in_signature="os", out_signature="")
    def DisplayPinCode(self, device, pincode):
        LOG.info("DisplayPinCode %s %s", device, pincode)
        _write_passkey(str(pincode))

    @dbus.service.method(IFACE, in_signature="ou", out_signature="")
    def RequestConfirmation(self, device, passkey):
        # Numeric-comparison flow: phone shows this code, user verifies it
        # matches the e-paper, taps Pair on phone. Pi auto-confirms.
        s = "%06d" % int(passkey)
        LOG.info("RequestConfirmation %s %s -> auto-accept", device, s)
        _write_passkey(s)

    @dbus.service.method(IFACE, in_signature="o", out_signature="")
    def RequestAuthorization(self, device):
        LOG.info("RequestAuthorization %s -> auto-accept", device)

    @dbus.service.method(IFACE, in_signature="", out_signature="")
    def Cancel(self):
        LOG.info("Cancel")
        _clear_passkey()


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()

    agent = RagnarAgent(bus, AGENT_PATH)  # noqa: F841 - holds D-Bus registration

    manager = dbus.Interface(
        bus.get_object("org.bluez", "/org/bluez"),
        "org.bluez.AgentManager1",
    )
    manager.RegisterAgent(AGENT_PATH, CAPABILITY)
    manager.RequestDefaultAgent(AGENT_PATH)
    LOG.info("Agent registered, capability=%s path=%s", CAPABILITY, AGENT_PATH)

    loop = GLib.MainLoop()

    def _shutdown(*_):
        LOG.info("Shutting down agent")
        try:
            manager.UnregisterAgent(AGENT_PATH)
        except Exception as exc:
            LOG.warning("UnregisterAgent failed: %s", exc)
        _clear_passkey()
        loop.quit()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)
    try:
        loop.run()
    finally:
        _clear_passkey()


if __name__ == "__main__":
    main()
