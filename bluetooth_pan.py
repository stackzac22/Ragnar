# bluetooth_pan.py
# Manages a Bluetooth PAN (NAP) so a phone can browse the Ragnar web UI
# while wardriving — no Wi-Fi or internet needed.
#
# The actual bring-up runs in a systemd service (ragnar-bt-pan.service)
# installed by scripts/install_bluetooth_pan.sh. This module is a thin
# Python wrapper that lets the webapp start/stop the service and read
# the pairing PIN for display.

import logging
import os
import subprocess

logger = logging.getLogger("BluetoothPan")

SERVICE_NAME = "ragnar-bt-pan.service"
# Live SSP passkey written by ragnar_bt_agent.py at pair time. Volatile —
# only present during an active pairing window.
LIVE_PASSKEY_FILE = "/run/ragnar-bt-pan/current-passkey"
# Static fallback PIN used only by legacy (pre-SSP 2.1) devices, which
# nobody actually owns any more. Kept for safety, not for the e-paper UX.
PIN_FILE = "/etc/ragnar/bt-pan.pin"
PAN_INTERFACE = "pan0"
PAN_IP = "172.20.5.1"
WEB_PORT_DEFAULT = 8000

INSTALLER_PATH_CANDIDATES = (
    "/home/ragnar/Ragnar/scripts/install_bluetooth_pan.sh",
    os.path.join(os.path.dirname(os.path.abspath(__file__)),
                 "scripts", "install_bluetooth_pan.sh"),
)


def _run(cmd, timeout=10):
    """Run a command and return (rc, stdout, stderr). Never raises."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return 1, "", str(e)


def is_installed():
    """True if the ragnar-bt-pan.service unit exists on the system."""
    rc, _, _ = _run(["systemctl", "cat", SERVICE_NAME])
    return rc == 0


def is_active():
    rc, out, _ = _run(["systemctl", "is-active", SERVICE_NAME])
    return out == "active"


def read_pin():
    """Return the *live* pairing passkey if a pair is currently in flight.

    The Python agent writes the SSP-derived passkey to LIVE_PASSKEY_FILE
    when BlueZ calls DisplayPasskey or RequestConfirmation, and clears it
    on completion / cancellation. Returns:
      * 6-digit code: a pair is in progress — confirm this matches the
                      number your phone shows, then tap Pair on the phone
      * None:         no active pairing (phone hasn't requested one yet,
                      or the bond already exists and reconnect is automatic)

    The static PIN_FILE is intentionally NOT used here — it only applies
    to pre-SSP 2.1 devices, and modern phones ignore it. Showing it would
    mislead the user into typing a code their phone never asked for.
    """
    try:
        with open(LIVE_PASSKEY_FILE, "r") as f:
            v = f.read().strip()
        if v.isdigit() and 4 <= len(v) <= 8:
            return v
    except FileNotFoundError:
        return None
    except Exception as e:
        logger.warning(f"Could not read live passkey: {e}")
    return None


def connected_peers():
    """Return the count of phones currently bridged to pan0.

    A bridged peer appears as `MAC dev bnep<N> master pan0` in the FDB.
    The bridge's own MAC also appears as `MAC dev pan0 master pan0 permanent`,
    so we must filter by the slave device name (`bnep*`) rather than just
    `master pan0` to avoid counting the bridge itself.
    """
    rc, out, _ = _run(["bridge", "fdb", "show", "br", PAN_INTERFACE])
    if rc != 0 or not out:
        return 0
    count = 0
    for line in out.splitlines():
        # Peer line: "aa:bb:cc:dd:ee:ff dev bnepN master pan0"
        # Bridge own line: "16:0a:... dev pan0 vlan 1 master pan0 permanent"
        if "dev bnep" in line and "master " + PAN_INTERFACE in line:
            count += 1
    return count


def _find_installer():
    for p in INSTALLER_PATH_CANDIDATES:
        if os.path.isfile(p):
            return p
    return None


def ensure_installed():
    """If the systemd unit is missing, run the installer via sudo.

    Returns a dict with `installed` (final state) and optionally `error`.
    Requires the bootstrap sudoers entry (which install_ragnar.sh / the
    first manual run of the installer creates).
    """
    if is_installed():
        return {"installed": True}
    installer = _find_installer()
    if not installer:
        return {"installed": False,
                "error": "install_bluetooth_pan.sh not found in Ragnar checkout"}
    logger.info(f"BT PAN not installed — running {installer} via sudo")
    rc, out, err = _run(["sudo", "-n", "/bin/bash", installer], timeout=180)
    if rc != 0:
        return {"installed": False,
                "error": (err or out or f"installer exit {rc}").strip()[:500]}
    # systemctl needs a daemon-reload moment; is_installed re-queries unit files
    return {"installed": is_installed()}


def start():
    """Start the systemd service. Returns dict with success/error."""
    if not is_installed():
        # Try to self-heal — auto-install on first wardriving start so the
        # user doesn't have to run a separate script.
        ensure = ensure_installed()
        if not ensure.get("installed"):
            return {"success": False,
                    "error": ensure.get("error") or
                             "ragnar-bt-pan.service not installed and "
                             "auto-install failed. Run "
                             "`sudo bash scripts/install_bluetooth_pan.sh`."}
    rc, out, err = _run(["sudo", "-n", "systemctl", "start", SERVICE_NAME], timeout=20)
    if rc != 0:
        return {"success": False, "error": err or out or f"systemctl exit {rc}"}
    return {"success": True}


def stop():
    """Stop the systemd service. Returns dict with success/error."""
    if not is_installed():
        return {"success": True, "note": "not installed; nothing to stop"}
    rc, out, err = _run(["sudo", "-n", "systemctl", "stop", SERVICE_NAME], timeout=20)
    if rc != 0:
        return {"success": False, "error": err or out or f"systemctl exit {rc}"}
    return {"success": True}


def get_status(web_port=WEB_PORT_DEFAULT):
    """Return a dict suitable for the web UI / display layer."""
    installed = is_installed()
    active = is_active() if installed else False
    pin = read_pin() if installed else None
    peers = connected_peers() if active else 0
    return {
        "installed": installed,
        "active": active,
        "pin": pin,
        "device_name": _device_name(),
        "pan_ip": PAN_IP,
        "web_url": f"http://{PAN_IP}:{web_port}" if active else None,
        "peers": peers,
    }


def _device_name():
    """Best-effort lookup of the BT adapter name (defaults to 'Ragnar')."""
    rc, out, _ = _run(["hciconfig", "hci0", "name"])
    if rc == 0 and out:
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("Name: "):
                return line[len("Name: "):].strip("'\"")
    return "Ragnar"
