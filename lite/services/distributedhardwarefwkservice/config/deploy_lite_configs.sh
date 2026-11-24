#!/bin/bash
# Deploy dhfwk lite configs to the product out dir (ipcamera_hispark_taurus_linux).
# GN copy targets in ../BUILD.gn (lite branch) do the same during build; this
# script is a manual convenience for incremental rootfs updates.
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUT_DIR="$1"
if [ -z "$OUT_DIR" ]; then
    OUT_DIR="$SCRIPT_DIR/../../../../../../out/hispark_taurus/ipcamera_hispark_taurus_linux"
fi

ROOTFS_DIR="$OUT_DIR/rootfs"

echo "Deploying distributed hardware lite configs to $ROOTFS_DIR ..."

# Deploy DHFWK component config (component_loader searches /vendor/etc first,
# then /etc; contracts C3: /etc/distributedhardware/...)
mkdir -p "$ROOTFS_DIR/etc/distributedhardware/"
cp "$SCRIPT_DIR/distributed_hardware_components_cfg.json" \
   "$ROOTFS_DIR/etc/distributedhardware/"

# Deploy dhfwk_daemon init cfg (init lite scans /system/etc/init/*.cfg via
# ParseCfgByPriority, services/init/lite/init.c)
mkdir -p "$ROOTFS_DIR/system/etc/init/"
cp "$SCRIPT_DIR/dhfwk_daemon.cfg" \
   "$ROOTFS_DIR/system/etc/init/"

echo "Done."
