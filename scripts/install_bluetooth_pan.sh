#!/bin/bash
# install_bluetooth_pan.sh
#
# Installs the Ragnar Bluetooth-PAN (NAP) service so a phone can pair with
# the Pi over Bluetooth and browse the Ragnar web UI without any Wi-Fi or
# internet. The runtime helper, systemd unit, and sudoers rules are written
# here; the Python wrapper lives in bluetooth_pan.py.

set -e

if [ "$EUID" -ne 0 ]; then
  echo "Must be run as root (use sudo)." >&2
  exit 1
fi

RAGNAR_USER="${RAGNAR_USER:-ragnar}"
RAGNAR_GROUP="${RAGNAR_GROUP:-ragnar}"
DEVICE_NAME="${RAGNAR_BT_NAME:-Ragnar}"

PIN_DIR=/etc/ragnar
PIN_FILE="$PIN_DIR/bt-pan.pin"
RUNTIME_SCRIPT=/usr/local/sbin/ragnar-bt-pan
AGENT_SCRIPT=/usr/local/sbin/ragnar_bt_agent.py
AGENT_SRC="$(dirname "$(readlink -f "$0")")/ragnar_bt_agent.py"
SERVICE_FILE=/etc/systemd/system/ragnar-bt-pan.service
SUDOERS_FILE=/etc/sudoers.d/ragnar-bt-pan

# ----------------------------------------------------------------------
# 1. Packages
# ----------------------------------------------------------------------
echo "[+] Installing packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
  bluez bluez-tools bridge-utils dnsmasq-base iproute2 \
  python3-dbus python3-gi

# ----------------------------------------------------------------------
# 2. PIN
# ----------------------------------------------------------------------
echo "[+] Generating pairing PIN..."
mkdir -p "$PIN_DIR"
chown root:"$RAGNAR_GROUP" "$PIN_DIR"
chmod 0750 "$PIN_DIR"

if [ ! -s "$PIN_FILE" ]; then
  # 6 random digits
  PIN=$(awk 'BEGIN{srand(); printf "%06d\n", int(rand()*1000000)}')
  echo "$PIN" > "$PIN_FILE"
fi
chown root:"$RAGNAR_GROUP" "$PIN_FILE"
chmod 0640 "$PIN_FILE"
PIN=$(cat "$PIN_FILE")
echo "    pairing PIN: $PIN"

# ----------------------------------------------------------------------
# 2a. Disable BlueZ audio plugins
#
# BlueZ on Pi OS ships with the audio plugins (a2dp, avrcp, hfp, hsp)
# enabled by default, so the controller advertises Hands-Free Audio
# Gateway / Audio Source / Audio Sink / A/V Remote Control UUIDs.
# Android (rightly) prefers an audio profile over NAP when both are
# offered, treats Ragnar as a headset, and never shows the
# "Internet access" toggle. Since Ragnar is not a media device, we
# strip these plugins from bluetoothd so only NAP remains for phones.
# ----------------------------------------------------------------------
BT_MAIN_CONF=/etc/bluetooth/main.conf
DISABLE_LIST="a2dp,avrcp,hfp,hsp"
echo "[+] Disabling BlueZ audio plugins ($DISABLE_LIST)..."
if [ -f "$BT_MAIN_CONF" ]; then
  # Strip any prior managed line first so re-runs are idempotent
  sed -i '/^# ragnar-bt-pan: disable audio plugins$/,/^DisablePlugins =/d' "$BT_MAIN_CONF" || true
  if grep -q '^\[General\]' "$BT_MAIN_CONF"; then
    awk -v block="# ragnar-bt-pan: disable audio plugins\nDisablePlugins = $DISABLE_LIST" '
      /^\[General\]/ && !done { print; print block; done=1; next }
      { print }
    ' "$BT_MAIN_CONF" > "$BT_MAIN_CONF.new" && mv "$BT_MAIN_CONF.new" "$BT_MAIN_CONF"
  else
    printf '\n[General]\n# ragnar-bt-pan: disable audio plugins\nDisablePlugins = %s\n' "$DISABLE_LIST" >> "$BT_MAIN_CONF"
  fi
  echo "[+] Restarting bluetoothd to drop audio profiles..."
  systemctl restart bluetooth.service
  sleep 1
else
  echo "    WARNING: $BT_MAIN_CONF not found; cannot disable audio plugins" >&2
fi

# ----------------------------------------------------------------------
# 2b. Deploy the Python pairing agent
# ----------------------------------------------------------------------
echo "[+] Installing Python pairing agent at $AGENT_SCRIPT..."
if [ -f "$AGENT_SRC" ]; then
  install -m 0755 "$AGENT_SRC" "$AGENT_SCRIPT"
else
  echo "    WARNING: $AGENT_SRC not found — pairing will fall back to static PIN" >&2
fi

# ----------------------------------------------------------------------
# 3. Runtime helper script (does the bring-up; systemd runs this)
# ----------------------------------------------------------------------
echo "[+] Writing runtime helper $RUNTIME_SCRIPT..."
cat > "$RUNTIME_SCRIPT" <<'RUNTIME_EOF'
#!/bin/bash
# /usr/local/sbin/ragnar-bt-pan
#
# Brings up a Bluetooth PAN (NAP) on pan0 (172.20.5.1/24), runs a PIN-based
# pairing agent, and serves DHCP via a dedicated dnsmasq instance.
# No NAT, no DNS upstream — phone gets an IP and can reach the Ragnar
# web UI at http://172.20.5.1:8000 but cannot route anywhere else.
#
# Invoked by ragnar-bt-pan.service.
set -e

PAN_IFACE=pan0
PAN_IP=172.20.5.1
PAN_NET=24
DHCP_START=172.20.5.10
DHCP_END=172.20.5.50

PIN_FILE=/etc/ragnar/bt-pan.pin
DEVICE_NAME="${RAGNAR_BT_NAME:-Ragnar}"

RUN_DIR=/run/ragnar-bt-pan
mkdir -p "$RUN_DIR"

PINDB="$RUN_DIR/pins"
DNSMASQ_CONF="$RUN_DIR/dnsmasq.conf"

cleanup() {
  echo "[ragnar-bt-pan] tearing down"
  jobs -p | xargs -r kill 2>/dev/null || true
  # bluetoothctl: stop advertising
  bluetoothctl <<EOF >/dev/null 2>&1 || true
discoverable off
pairable off
EOF
  ip link set "$PAN_IFACE" down 2>/dev/null || true
  ip link delete "$PAN_IFACE" 2>/dev/null || true
}
trap cleanup TERM INT EXIT

# ---- kernel + bridge ----------------------------------------------
modprobe bnep || true

if ! ip link show "$PAN_IFACE" >/dev/null 2>&1; then
  ip link add name "$PAN_IFACE" type bridge
fi
ip addr flush dev "$PAN_IFACE" || true
ip addr add "$PAN_IP/$PAN_NET" dev "$PAN_IFACE"
ip link set "$PAN_IFACE" up

# ---- PIN agent setup ----------------------------------------------
PIN=$(cat "$PIN_FILE" 2>/dev/null || true)
if ! [[ "$PIN" =~ ^[0-9]{4,8}$ ]]; then
  PIN=$(awk 'BEGIN{srand(); printf "%06d\n", int(rand()*1000000)}')
  echo "$PIN" > "$PIN_FILE"
  chmod 0640 "$PIN_FILE"
fi
# bt-agent --pin file syntax: "<bdaddr|*> <pin>"
umask 077
echo "* $PIN" > "$PINDB"

# ---- bluetooth adapter --------------------------------------------
hciconfig hci0 up || true
hciconfig hci0 name "$DEVICE_NAME" || true
hciconfig hci0 sspmode 1 || true
hciconfig hci0 piscan || true

bluetoothctl <<EOF >/dev/null 2>&1 || true
power on
agent off
discoverable on
pairable on
EOF

# Kill any stray helpers from previous runs
pkill -f 'bt-agent.*ragnar-bt-pan' 2>/dev/null || true
pkill -f 'ragnar_bt_agent' 2>/dev/null || true
pkill -f 'bt-network.*-s nap' 2>/dev/null || true

# ---- Custom Python pairing agent ----------------------------------
# Uses DisplayYesNo capability so SSP negotiates Numeric Comparison with
# modern phones, and writes the live per-pair passkey to
# /run/ragnar-bt-pan/current-passkey so the e-paper / web banner can
# show the correct code. Falls back to legacy bt-agent if Python agent
# is missing for some reason.
if [ -x /usr/local/sbin/ragnar_bt_agent.py ]; then
  /usr/local/sbin/ragnar_bt_agent.py &
else
  echo "[ragnar-bt-pan] Python agent missing, falling back to bt-agent (static PIN, may not work on modern phones)"
  bt-agent --capability=DisplayOnly --pin="$PINDB" &
fi
AGENT_PID=$!

# ---- PAN/NAP server -----------------------------------------------
sleep 0.5
bt-network -s nap "$PAN_IFACE" &
NETWORK_PID=$!

# Force Class of Device to "Networking → LAN/NAP" *after* bt-network has
# registered the NAP service. When bt-network starts, BlueZ OR-s in audio
# service bits from the still-loaded audio plugins, leaving the major
# class as Audio/Video — which makes Android display Ragnar as a headset
# with no "Internet access" toggle. Setting the class after the service
# is up overrides BlueZ's auto-computed value and sticks.
sleep 1
hciconfig hci0 class 0x020300 || true

# ---- dnsmasq (DHCP only, no DNS, bound to pan0) -------------------
cat > "$DNSMASQ_CONF" <<EOF
interface=$PAN_IFACE
bind-interfaces
dhcp-range=$DHCP_START,$DHCP_END,255.255.255.0,1h
no-resolv
port=0
log-dhcp
EOF
dnsmasq --conf-file="$DNSMASQ_CONF" --keep-in-foreground &
DNSMASQ_PID=$!

echo "[ragnar-bt-pan] up: name=$DEVICE_NAME ip=$PAN_IP/$PAN_NET pin=$PIN"

# Wait until any child exits — systemd then restarts us
wait -n $AGENT_PID $NETWORK_PID $DNSMASQ_PID
RUNTIME_EOF
chmod 0755 "$RUNTIME_SCRIPT"

# ----------------------------------------------------------------------
# 4. Systemd unit
# ----------------------------------------------------------------------
echo "[+] Writing $SERVICE_FILE..."
cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=Ragnar Bluetooth PAN (NAP) for phone web access
After=bluetooth.service network.target
Requires=bluetooth.service

[Service]
Type=simple
Environment=RAGNAR_BT_NAME=$DEVICE_NAME
ExecStart=$RUNTIME_SCRIPT
Restart=on-failure
RestartSec=3
KillMode=mixed
TimeoutStopSec=10

[Install]
WantedBy=multi-user.target
EOF

# ----------------------------------------------------------------------
# 5. Sudoers (let ragnar start/stop the service, nothing else)
# ----------------------------------------------------------------------
echo "[+] Writing sudoers rules $SUDOERS_FILE..."
RAGNAR_HOME="/home/$RAGNAR_USER/Ragnar"
cat > "$SUDOERS_FILE" <<EOF
# Ragnar Bluetooth PAN: allow the ragnar user to toggle the unit and to re-run
# the installer (self-heal if something on the system gets out of sync).
$RAGNAR_USER ALL=(root) NOPASSWD: /usr/bin/systemctl start ragnar-bt-pan.service
$RAGNAR_USER ALL=(root) NOPASSWD: /usr/bin/systemctl stop ragnar-bt-pan.service
$RAGNAR_USER ALL=(root) NOPASSWD: /usr/bin/systemctl restart ragnar-bt-pan.service
$RAGNAR_USER ALL=(root) NOPASSWD: /bin/bash $RAGNAR_HOME/scripts/install_bluetooth_pan.sh
EOF
chmod 0440 "$SUDOERS_FILE"

# ----------------------------------------------------------------------
# 6. Reload systemd. Do NOT enable on boot — wardriving controls lifecycle.
# ----------------------------------------------------------------------
systemctl daemon-reload

echo
echo "[OK] ragnar-bt-pan installed."
echo "    PIN:         $PIN  (stored in $PIN_FILE)"
echo "    Device name: $DEVICE_NAME"
echo "    Pi IP:       172.20.5.1  (after phone joins via Bluetooth PAN)"
echo "    Web URL:     http://172.20.5.1:8000"
echo
echo "    The service is NOT enabled on boot — it starts automatically when"
echo "    wardriving starts (and stops when wardriving stops). You can also"
echo "    flip it manually:"
echo "      sudo systemctl start  ragnar-bt-pan"
echo "      sudo systemctl stop   ragnar-bt-pan"
