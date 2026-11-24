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
 * DEF-20bB-1 (TASK-22): camera HAL readiness gate implementation.
 * Kept free of fwk headers (log/context) on purpose: the pure core and the
 * flag-path wrapper are directly compilable with plain g++ on a Linux host
 * for the self-asserting unit test (lite/test/camera_hal_ready_gate_test.cpp,
 * T6-style). Anchor logging lives at the call site (local_hardware_manager).
 */

#include "camera_hal_ready_gate.h"

#include <unistd.h>

namespace OHOS {
namespace DistributedHardware {
ReadyGateResult WaitForReadyGate(const std::function<bool()> &probe,
    const std::function<void()> &waitStep, uint32_t maxProbes)
{
    ReadyGateResult result;
    if (probe == nullptr || waitStep == nullptr || maxProbes == 0) {
        return result;
    }
    for (uint32_t i = 0; i < maxProbes; ++i) {
        result.probes = i + 1;
        if (probe()) {
            result.ready = true;
            return result;
        }
        waitStep();
    }
    return result;
}

ReadyGateResult WaitCameraHalReady(uint32_t timeoutSec, uint32_t intervalSec, const char *flagPath)
{
    if (flagPath == nullptr) {
        return ReadyGateResult();
    }
    uint32_t maxProbes = (intervalSec == 0) ? timeoutSec : (timeoutSec / intervalSec);
    if (maxProbes == 0) {
        maxProbes = 1; // always probe at least once (flag may already exist)
    }
    return WaitForReadyGate(
        [flagPath]() { return access(flagPath, F_OK) == 0; },
        [intervalSec]() {
            if (intervalSec > 0) {
                sleep(intervalSec);
            }
        },
        maxProbes);
}
} // namespace DistributedHardware
} // namespace OHOS
