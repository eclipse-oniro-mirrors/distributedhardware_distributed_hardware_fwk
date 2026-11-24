/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <vector>
#include <unistd.h>

#include "distributed_hardware_manager_factory.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"
#include "componentloader/component_loader.h"
#include "device_type.h"
#include "idistributed_hardware_sink.h"

// Weak stub definition (stub period, TASK-2): libdistributedhardwarefwksvr.so
// references the frozen extern "C" sink-instance producer
// GetSinkHardwareHandler() (idistributed_hardware_sink.h) from
// ComponentManager::InitCompSink. The executable links with
// --no-allow-shlib-undefined, so this weak definition satisfies the SO
// reference until TASK-5 statically links the camera sink SDK (whose strong
// definition overrides it). Unreachable in this test (InitCompSink
// short-circuits on the empty static registry).
extern "C" __attribute__((weak)) OHOS::DistributedHardware::IDistributedHardwareSink *GetSinkHardwareHandler()
{
    return nullptr;
}

int main()
{
    DHLOGI("========== dhfwk_test: VerifyStart ==========");

    auto &factory = OHOS::DistributedHardware::DistributedHardwareManagerFactory::GetInstance();
    bool result = factory.InitLocalDevInfo();

    if (result) {
        DHLOGI("========== dhfwk_test: InitLocalDevInfo SUCCESS ==========");
    } else {
        DHLOGE("========== dhfwk_test: InitLocalDevInfo FAILED ==========");
    }

    {
        std::vector<OHOS::DistributedHardware::DHType> dhTypeVec;
        OHOS::DistributedHardware::ComponentLoader::GetInstance().GetAllCompTypes(dhTypeVec);
        for (auto &type : dhTypeVec) {
            DHLOGI("Found DHType: %{public}d", static_cast<int32_t>(type));
        }
    }

    sleep(3);
    DHLOGI("========== dhfwk_test: VerifyEnd ==========");
    return result ? 0 : 1;
}
