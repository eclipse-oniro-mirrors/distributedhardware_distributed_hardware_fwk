/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "local_hardware_manager.h"

#include <unistd.h>

#include "anonymous_string.h"
#include "capability_info_manager.h"
#include "component_loader.h"
#include "constants.h"
#include "device_type.h"
#include "dh_context.h"
#include "dh_utils_hitrace.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"
#include "dh_utils_tool.h"
#include "meta_info_manager.h"
#include "plugin_listener_impl.h"
#include "version_manager.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
    constexpr int32_t QUERY_INTERVAL_TIME = 1000 * 1000; // 1s
    constexpr int32_t QUERY_RETRY_MAX_TIMES = 3;
}
#undef DH_LOG_TAG
#define DH_LOG_TAG "LocalHardwareManager"

IMPLEMENT_SINGLE_INSTANCE(LocalHardwareManager)

LocalHardwareManager::LocalHardwareManager() {}
LocalHardwareManager::~LocalHardwareManager() {}

void LocalHardwareManager::Init()
{
    DHLOGI("start");
    std::vector<DHType> allCompTypes = ComponentLoader::GetInstance().GetAllCompTypes();
    localDHItemsMap_.clear();
    int64_t allQueryStartTime = GetCurrentTime();
    for (auto dhType : allCompTypes) {
        int64_t singleQueryStartTime = GetCurrentTime();
        IHardwareHandler *hardwareHandler = nullptr;
        int32_t status = ComponentLoader::GetInstance().GetHardwareHandler(dhType, hardwareHandler);
        if (status != DH_FWK_SUCCESS || hardwareHandler == nullptr) {
            DHLOGE("GetHardwareHandler %{public}#X failed", dhType);
            continue;
        }
        if (hardwareHandler->Initialize() != DH_FWK_SUCCESS) {
            DHLOGE("Initialize %{public}#X failed", dhType);
            continue;
        }

        DHQueryTraceStart(dhType);
        QueryLocalHardware(dhType, hardwareHandler);
        DHTraceEnd();
        if (!hardwareHandler->IsSupportPlugin()) {
            DHLOGI("hardwareHandler is not support hot swap plugin, release!");
            ComponentLoader::GetInstance().ReleaseHardwareHandler(dhType);
            hardwareHandler = nullptr;
        } else {
            compToolFuncsMap_[dhType] = hardwareHandler;
            std::shared_ptr<PluginListener> listener = std::make_shared<PluginListenerImpl>(dhType);
            pluginListenerMap_[dhType] = listener;
            hardwareHandler->RegisterPluginListener(listener);
        }
        int64_t singleQueryEndTime = GetCurrentTime();
        DHLOGI("query %{public}#X hardware cost time: %{public}" PRIu64 " ms",
            dhType, singleQueryEndTime - singleQueryStartTime);
    }
    int64_t allQueryEndTime = GetCurrentTime();
    DHLOGI("query all local hardware cost time: %{public}" PRIu64 " ms", allQueryEndTime - allQueryStartTime);
    std::vector<std::shared_ptr<CapabilityInfo>> capabilityInfos;
    std::vector<std::shared_ptr<MetaCapabilityInfo>> metaCapInfos;
    for (const auto &localDHItems : localDHItemsMap_) {
        AddLocalCapabilityInfo(localDHItems.second, localDHItems.first, capabilityInfos);
        AddLocalMetaCapInfo(localDHItems.second, localDHItems.first, metaCapInfos);
    }
    CapabilityInfoManager::GetInstance()->AddCapability(capabilityInfos);
    MetaInfoManager::GetInstance()->AddMetaCapInfos(metaCapInfos);
}

void LocalHardwareManager::UnInit()
{
    DHLOGI("start");
    compToolFuncsMap_.clear();
    pluginListenerMap_.clear();
}

void LocalHardwareManager::QueryLocalHardware(const DHType dhType, IHardwareHandler *hardwareHandler)
{
    std::vector<DHItem> dhItems;
    int32_t retryTimes = QUERY_RETRY_MAX_TIMES;
    while (retryTimes > 0) {
        DHLOGI("Query hardwareHandler retry times left: %{public}d, dhType: %{public}#X", retryTimes, dhType);
        if (hardwareHandler == nullptr) {
            DHLOGE("hardwareHandler is null.");
            return;
        }
        dhItems = hardwareHandler->Query();
        if (dhItems.empty()) {
            DHLOGE("Query hardwareHandler and obtain empty, dhType: %{public}#X", dhType);
            usleep(QUERY_INTERVAL_TIME);
        } else {
            DHLOGI("Query hardwareHandler success, dhType: %{public}#X!, size: %{public}zu", dhType, dhItems.size());
            /*
             * Failed to delete data when the device restarts or other exception situation.
             * So check and remove the non-exist local capabilityInfo.
             */
            CheckNonExistCapabilityInfo(dhItems, dhType);
            localDHItemsMap_[dhType] = dhItems;
            break;
        }
        retryTimes--;
    }
}

void LocalHardwareManager::AddLocalCapabilityInfo(const std::vector<DHItem> &dhItems, const DHType dhType,
    std::vector<std::shared_ptr<CapabilityInfo>> &capabilityInfos)
{
    DHLOGI("start!");
    std::string deviceId = DHContext::GetInstance().GetDeviceInfo().deviceId;
    std::string devName = DHContext::GetInstance().GetDeviceInfo().deviceName;
    uint16_t devType = DHContext::GetInstance().GetDeviceInfo().deviceType;
    for (auto dhItem : dhItems) {
        std::shared_ptr<CapabilityInfo> dhCapabilityInfo = std::make_shared<CapabilityInfo>(
            dhItem.dhId, deviceId, devName, devType, dhType, dhItem.attrs, dhItem.subtype);
        capabilityInfos.push_back(dhCapabilityInfo);
    }
}

void LocalHardwareManager::AddLocalMetaCapInfo(const std::vector<DHItem> &dhItems, const DHType dhType,
    std::vector<std::shared_ptr<MetaCapabilityInfo>> &metaCapInfos)
{
    DHLOGI("start!");
    std::string deviceId = DHContext::GetInstance().GetDeviceInfo().deviceId;
    std::string udidHash = DHContext::GetInstance().GetDeviceInfo().udidHash;
    std::string devName = DHContext::GetInstance().GetDeviceInfo().deviceName;
    uint16_t devType = DHContext::GetInstance().GetDeviceInfo().deviceType;
    std::string strUUID = DHContext::GetInstance().GetDeviceInfo().uuid;
    CompVersion compversion;
    VersionManager::GetInstance().GetCompVersion(strUUID, dhType, compversion);
    for (auto dhItem : dhItems) {
        std::shared_ptr<MetaCapabilityInfo> dhMetaCapInfo = std::make_shared<MetaCapabilityInfo>(
            dhItem.dhId, deviceId, devName, devType, dhType, dhItem.attrs, dhItem.subtype, udidHash,
            compversion.sinkVersion);
        metaCapInfos.push_back(dhMetaCapInfo);
    }
}

void LocalHardwareManager::CheckNonExistCapabilityInfo(const std::vector<DHItem> &dhItems, const DHType dhType)
{
    DHLOGI("start");
    if (dhType != DHType::INPUT) {
        DHLOGI("This dhType is not input and no need check!");
        return;
    }
    CapabilityInfoMap allLocalCapabilityInfos;
    GetLocalCapabilityMapByPrefix(dhType, allLocalCapabilityInfos);
    for (auto capabilityInfo : allLocalCapabilityInfos) {
        std::shared_ptr<CapabilityInfo> capabilityValue = capabilityInfo.second;
        if (capabilityValue == nullptr) {
            DHLOGE("capabilityInfo value is nullptr");
            continue;
        }
        DHLOGI("The key in allLocalCapabilityInfos is %{public}s", capabilityValue->GetAnonymousKey().c_str());
        bool isExist = false;
        for (auto dhItem : dhItems) {
            DHLOGI("This data key is: %{public}s, dhItem: %{public}s", capabilityValue->GetAnonymousKey().c_str(),
                GetAnonyString(dhItem.dhId).c_str());
            if (capabilityValue->GetDHId() == dhItem.dhId) {
                DHLOGI("This data is exist, no need removed key: %{public}s",
                    capabilityValue->GetAnonymousKey().c_str());
                isExist = true;
                break;
            }
        }
        if (!isExist) {
            DHLOGI("This data is non-exist, it should be removed, key: %{public}s",
                capabilityValue->GetAnonymousKey().c_str());
            CapabilityInfoManager::GetInstance()->RemoveCapabilityInfoByKey(capabilityValue->GetKey());
        }
    }
    DHLOGI("end");
}

void LocalHardwareManager::GetLocalCapabilityMapByPrefix(const DHType dhType, CapabilityInfoMap &capabilityInfoMap)
{
    std::string localDeviceId = DHContext::GetInstance().GetDeviceInfo().deviceId;
    if (!IsIdLengthValid(localDeviceId)) {
        return;
    }
    if (DHTypePrefixMap.find(dhType) == DHTypePrefixMap.end()) {
        DHLOGE("DHTypePrefixMap can not find dhType: %{public}#X", dhType);
        return;
    }
    std::string prefix = DHTypePrefixMap.find(dhType)->second;
    std::string localCapabilityPrefix = localDeviceId + RESOURCE_SEPARATOR + prefix;
    CapabilityInfoManager::GetInstance()->GetDataByKeyPrefix(localCapabilityPrefix, capabilityInfoMap);
}
} // namespace DistributedHardware
} // namespace OHOS
