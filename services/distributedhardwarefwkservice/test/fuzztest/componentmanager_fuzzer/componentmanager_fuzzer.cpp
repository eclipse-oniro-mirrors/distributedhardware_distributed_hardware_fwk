/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "componentmanager_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "component_disable.h"
#include "component_enable.h"
#include "component_manager.h"
#include "constants.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"
#include "dh_data_sync_trigger_listener.h"
#include "dh_state_listener.h"
#include "event_handler.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
    const uint32_t DH_TYPE_SIZE = 10;
    const DHType dhTypeFuzz[DH_TYPE_SIZE] = {
        DHType::CAMERA, DHType::AUDIO, DHType::SCREEN, DHType::VIRMODEM_AUDIO,
        DHType::INPUT, DHType::A2D, DHType::GPS, DHType::HFP
    };
}
void ComponentManagerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    std::string networkId(reinterpret_cast<const char*>(data), size);
    std::string uuid(reinterpret_cast<const char*>(data), size);
    std::string dhId(reinterpret_cast<const char*>(data), size);
    DHType dhType = dhTypeFuzz[data[0] % DH_TYPE_SIZE];
    bool enableSource = false;
    sptr<IHDSinkStatusListener> sinkListener = nullptr;
    sptr<IHDSourceStatusListener> sourceListener = nullptr;
    FuzzedDataProvider fdp(data, size);
    int32_t callingUid = fdp.ConsumeIntegral<int32_t>();
    int32_t callingPid = fdp.ConsumeIntegral<int32_t>();
    DHDescriptor dhDescriptor {
        .id = std::string(reinterpret_cast<const char*>(data), size),
        .dhType = dhType
    };

    ComponentManager::GetInstance().Init();
    ComponentManager::GetInstance().Enable(networkId, uuid, dhId, dhType);
    ComponentManager::GetInstance().Disable(networkId, uuid, dhId, dhType);
    ComponentManager::GetInstance().CheckDemandStart(uuid, dhType, enableSource);
    ComponentManager::GetInstance().RegisterDHStatusListener(sinkListener, callingUid, callingPid);
    ComponentManager::GetInstance().UnregisterDHStatusListener(sinkListener, callingUid, callingPid);
    ComponentManager::GetInstance().RegisterDHStatusListener(networkId, sourceListener, callingUid, callingPid);
    ComponentManager::GetInstance().UnregisterDHStatusListener(networkId, sourceListener, callingUid, callingPid);
    ComponentManager::GetInstance().EnableSink(dhDescriptor, callingUid, callingPid);
    ComponentManager::GetInstance().DisableSink(dhDescriptor, callingUid, callingPid);
    ComponentManager::GetInstance().EnableSource(networkId, dhDescriptor, callingUid, callingPid);
    ComponentManager::GetInstance().DisableSource(networkId, dhDescriptor, callingUid, callingPid);
    ComponentManager::GetInstance().ForceDisableSink(dhDescriptor);
    ComponentManager::GetInstance().ForceDisableSource(networkId, dhDescriptor);
    ComponentManager::GetInstance().UnInit();
}

void OnDataSyncTriggerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    std::string networkId(reinterpret_cast<const char*>(data), size);
    DHDataSyncTriggerListener dhDataSyncTrigger;
    dhDataSyncTrigger.OnDataSyncTrigger(networkId);
}

void OnStateChangedFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    std::string networkId(reinterpret_cast<const char*>(data), size);
    std::string dhId(reinterpret_cast<const char*>(data), size);
    BusinessState state = BusinessState::UNKNOWN;
    DHStateListener dhData;
    dhData.OnStateChanged(networkId, dhId, state);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::ComponentManagerFuzzTest(data, size);
    OHOS::DistributedHardware::OnDataSyncTriggerFuzzTest(data, size);
    OHOS::DistributedHardware::OnStateChangedFuzzTest(data, size);
    return 0;
}

