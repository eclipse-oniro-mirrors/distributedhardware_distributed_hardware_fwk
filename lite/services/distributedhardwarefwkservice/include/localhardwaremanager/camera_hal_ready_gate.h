/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * DEF-20bB-1 (TASK-22, route A-adjusted): camera HAL readiness gate.
 *
 * Boot-window race, function-level proven on board (20bB):
 *   daemon LocalHardwareManager::Init -> DCameraHandler::Initialize ->
 *   camera_lite CameraManager::GetInstance constructs a process-lifetime
 *   singleton whose cameraMapCache_ is filled ONLY at construction
 *   (InitCameraServiceClient -> OnCameraServiceInitialized); GetCameraIds()
 *   is a pure cache read. media_server registers the CameraServer SA during
 *   SAMGR_Bootstrap BEFORE HalCameraInit (~3s+ later, media_main.cpp), so a
 *   first enumeration inside that window freezes 0 cameras until the daemon
 *   is restarted -- the EX2 3x1s query retry cannot pierce the cache.
 *
 * Fix shape (fwk lite domain only, camera_lite/camera/vendor untouched):
 * do not construct the client instance before the camera HAL is ready.
 * Readiness observable = the HAL-owner flag file /dev/.camera_hal_inited,
 * created by camera_lite services/impl/src/camera_service.cpp
 * MarkCameraHalInited() (af78fdc) after HalCameraInit() succeeds in the
 * owner process (media_server, D-PRIO-1). /dev is tmpfs -> per-boot flag,
 * no stale-flag risk across reboots. This is a read-only cross-repo
 * dependency; the gate is fail-open (on timeout the caller proceeds and the
 * legacy EX2 degradation applies), so a missing/renamed flag degrades to
 * the pre-fix behavior instead of blocking boot.
 *
 * The pure wait-loop core (WaitForReadyGate) is IO/log-free and injected
 * with probe/waitStep callables so host unit tests can replay the readiness
 * timing deterministically (immediate / ready-after-3s / timeout).
 */

#ifndef OHOS_DISTRIBUTED_HARDWARE_CAMERA_HAL_READY_GATE_H
#define OHOS_DISTRIBUTED_HARDWARE_CAMERA_HAL_READY_GATE_H

#include <cstdint>
#include <functional>

namespace OHOS {
namespace DistributedHardware {
// Cross-repo readiness contract: verbatim == camera_lite CAMERA_HAL_INIT_FLAG
// (services/impl/src/camera_service.cpp:28 @af78fdc). Pinned by host test.
constexpr const char *CAMERA_HAL_READY_FLAG = "/dev/.camera_hal_inited";
// Timeout cap ~15s covers the measured HAL init window (~3s+) with margin;
// 1s interval matches the EX2 probe cadence.
constexpr uint32_t CAMERA_HAL_READY_TIMEOUT_SEC = 15;
constexpr uint32_t CAMERA_HAL_READY_INTERVAL_SEC = 1;

struct ReadyGateResult {
    bool ready = false;   // true = readiness observed within the probe budget
    uint32_t probes = 0;  // probes consumed (board evidence / latency metric)
};

/*
 * Pure wait-loop core: probe readiness up to maxProbes times with waitStep
 * between failed probes (uniform cadence, total window = maxProbes x step).
 * Fail-open contract: on exhaustion returns {false, maxProbes}; the caller
 * decides the degradation. Null callables / zero budget return {false, 0}.
 */
ReadyGateResult WaitForReadyGate(const std::function<bool()> &probe,
    const std::function<void()> &waitStep, uint32_t maxProbes);

/*
 * Production wrapper: poll flagPath every intervalSec up to timeoutSec
 * (maxProbes = timeoutSec / intervalSec, min 1). Injectable for host tests
 * (tmp flag path + short cadence); production defaults = the constants above.
 */
ReadyGateResult WaitCameraHalReady(uint32_t timeoutSec = CAMERA_HAL_READY_TIMEOUT_SEC,
    uint32_t intervalSec = CAMERA_HAL_READY_INTERVAL_SEC,
    const char *flagPath = CAMERA_HAL_READY_FLAG);
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_HARDWARE_CAMERA_HAL_READY_GATE_H
