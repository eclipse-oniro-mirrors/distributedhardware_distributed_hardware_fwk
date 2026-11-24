#!/bin/bash
# Copyright (c) 2026 Huawei Device Co., Ltd.
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

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
