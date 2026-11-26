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

#include "capabilityinfomanagerfour_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include "capability_info.h"
#include "capability_info_manager.h"
#include "constants.h"
#include "dh_context.h"
#include "dh_utils_tool.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
    const std::string VALID_DEVICE_ID = "validDeviceId_123";
    const std::string VALID_DH_ID = "validDhId_123456";
    const std::string OTHER_VALID_DEVICE_ID = "otherValidDevId_";
}

void CapabilityInfoManagerMemMapFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint16_t) + sizeof(uint32_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    uint16_t deviceType = fdp.ConsumeIntegral<uint16_t>();
    DHType dhType = static_cast<DHType>(fdp.ConsumeIntegral<uint32_t>());
    std::string dhId = fdp.ConsumeRandomLengthString();
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string deviceName = fdp.ConsumeRandomLengthString();
    std::string dhAttrs = fdp.ConsumeRandomLengthString();
    std::string dhSubtype = fdp.ConsumeRandomLengthString();

    auto mgr = CapabilityInfoManager::GetInstance();
    // Seed the memory map to cover the found, not-found and nullptr pointer branches.
    std::shared_ptr<CapabilityInfo> capInfo = std::make_shared<CapabilityInfo>(VALID_DH_ID, VALID_DEVICE_ID,
        deviceName, deviceType, DHType::CAMERA, dhAttrs, dhSubtype);
    mgr->globalCapInfoMap_[capInfo->GetKey()] = capInfo;
    std::shared_ptr<CapabilityInfo> otherCapInfo = std::make_shared<CapabilityInfo>(dhId, OTHER_VALID_DEVICE_ID,
        deviceName, deviceType, dhType, dhAttrs, dhSubtype);
    mgr->globalCapInfoMap_[otherCapInfo->GetKey()] = otherCapInfo;

    std::vector<std::shared_ptr<CapabilityInfo>> resInfos;
    // Cover the deviceId match, not match and invalid branches.
    mgr->GetCapabilitiesByDeviceId(VALID_DEVICE_ID, resInfos);
    mgr->GetCapabilitiesByDeviceId(OTHER_VALID_DEVICE_ID, resInfos);
    mgr->GetCapabilitiesByDeviceId(deviceId, resInfos);

    CapabilityInfoMap capabilityMap;
    // Cover the dhType match and not match branches.
    mgr->GetDataByDHType(dhType, capabilityMap);
    mgr->GetDataByDHType(DHType::CAMERA, capabilityMap);

    // Cover the found and not found branches.
    mgr->GetDhSubtype(VALID_DEVICE_ID, VALID_DH_ID);
    mgr->GetDhSubtype(deviceId, dhId);

    // Cover the nullptr pointer in map branch of GetDhSubtype.
    mgr->globalCapInfoMap_[otherCapInfo->GetKey()] = nullptr;
    mgr->GetDhSubtype(OTHER_VALID_DEVICE_ID, dhId);

    mgr->globalCapInfoMap_.clear();
}

void CapabilityInfoManagerCloudOnChangeFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string key = fdp.ConsumeRandomLengthString();

    // Cover the cloud data change branches.
    DistributedKv::DataOrigin origin;
    DistributedKv::KvStoreObserver::Keys keys;
    keys[DistributedKv::KvStoreObserver::ChangeOp::OP_INSERT].push_back(key);
    keys[DistributedKv::KvStoreObserver::ChangeOp::OP_UPDATE].push_back(key);
    keys[DistributedKv::KvStoreObserver::ChangeOp::OP_DELETE].push_back(key);
    CapabilityInfoManager::GetInstance()->OnChange(origin, std::move(keys));
}

void CapabilityInfoManagerEventHandlerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint32_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    uint32_t eventId = fdp.ConsumeIntegral<uint32_t>();

    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create(true);
    std::shared_ptr<CapabilityInfoManager> nullMgr;
    CapabilityInfoManager::CapabilityInfoManagerEventHandler nullHandler(runner, nullMgr);
    // Cover the event null branch.
    AppExecFwk::InnerEvent::Pointer nullEvent = AppExecFwk::InnerEvent::Get(eventId);
    nullEvent.reset();
    nullHandler.ProcessEvent(nullEvent);
    // Cover the self ptr lock failed branch.
    nullHandler.ProcessEvent(AppExecFwk::InnerEvent::Get(eventId));

    CapabilityInfoManager::CapabilityInfoManagerEventHandler handler(runner,
        CapabilityInfoManager::GetInstance());
    // Cover the db recover event branch.
    handler.ProcessEvent(AppExecFwk::InnerEvent::Get(EVENT_CAPABILITY_INFO_DB_RECOVER));
    // Cover the undefined event branch.
    handler.ProcessEvent(AppExecFwk::InnerEvent::Get(eventId));
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::CapabilityInfoManagerMemMapFuzzTest(data, size);
    OHOS::DistributedHardware::CapabilityInfoManagerCloudOnChangeFuzzTest(data, size);
    OHOS::DistributedHardware::CapabilityInfoManagerEventHandlerFuzzTest(data, size);
    return 0;
}
