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

#include "dh_comm_tool.h"

#include "cJSON.h"
#include "device_manager.h"

#include "anonymous_string.h"
#include "component_manager.h"
#include "dh_context.h"
#include "dh_transport_obj.h"
#include "dh_utils_tool.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"
#include "local_hardware_manager.h"
#include "meta_capability_info.h"
#include "component_loader.h"
#include "task_executor.h"

namespace OHOS {
namespace DistributedHardware {
#undef DH_LOG_TAG
#define DH_LOG_TAG "DHCommTool"

// request remote dh send back full dh capabilities
constexpr int32_t DH_COMM_REQ_FULL_CAPS = 1;
// send back full dh attributes to the requester
constexpr int32_t DH_COMM_RSP_FULL_CAPS = 2;

DHCommTool::DHCommTool() : dhTransportPtr_(nullptr)
{
    DHLOGI("Ctor DHCommTool");
}

void DHCommTool::Init()
{
    DHLOGI("Init DHCommTool");
    dhTransportPtr_ = std::make_shared<DHTransport>(shared_from_this());
    dhTransportPtr_->Init();
}

void DHCommTool::UnInit()
{
    DHLOGI("UnInit DHCommTool");
    if (dhTransportPtr_ == nullptr) {
        DHLOGI("dhTransportPtr_ is null");
        return;
    }
    dhTransportPtr_->UnInit();
}

std::string DHCommTool::GetLocalFullCapsInfo(bool isSyncMeta)
{
    DHLOGI("get local cap info start");
    std::vector<std::shared_ptr<CapabilityInfo>> localFullCapInfos;
    // TASK-121d: refresh the cached DHItems right before answering, so the
    // peer (L2 DH framework) always sees the sink's CURRENT capability (e.g.
    // fps changed via /userdata/dcamera_fps since boot) instead of the stale
    // boot-time snapshot.
    LocalHardwareManager::GetInstance().RefreshLocalDHItems();
    DeviceInfo devInfo = GetLocalDeviceInfo();
    const auto& localDHItemsMap = LocalHardwareManager::GetInstance().GetLocalDHItemsMap();
    for (const auto& [dhType, dhItems] : localDHItemsMap) {
        for (const auto& dhItem : dhItems) {
            auto capInfo = std::make_shared<CapabilityInfo>(
                dhItem.dhId, devInfo.deviceId, devInfo.deviceName,
                devInfo.deviceType, dhType, dhItem.attrs, dhItem.subtype);
            localFullCapInfos.push_back(capInfo);
        }
    }
    FullCapsRsp capsRsp;
    capsRsp.networkId = GetLocalNetworkId();
    capsRsp.caps = localFullCapInfos;
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        DHLOGE("Create cJSON object failed.");
        return "";
    }
    ToJson(root, capsRsp, isSyncMeta);
    char *msg = cJSON_PrintUnformatted(root);
    if (msg == nullptr) {
        cJSON_Delete(root);
        return "";
    }
    std::string fullCapsMsg(msg);
    cJSON_free(msg);
    cJSON_Delete(root);
    return fullCapsMsg;
}

std::string DHCommTool::GetLocalFullMetaCapsInfo(bool isSyncMeta)
{
    DHLOGI("get local metaCap info start (lite)");
    LocalHardwareManager::GetInstance().RefreshLocalDHItems();
    DeviceInfo devInfo = GetLocalDeviceInfo();
    const auto& localDHItemsMap = LocalHardwareManager::GetInstance().GetLocalDHItemsMap();
    std::vector<std::shared_ptr<MetaCapabilityInfo>> localFullMetaCapInfos;
    for (const auto &entry : localDHItemsMap) {
        DHType dhType = entry.first;
        CompVersion compVersion;
        ComponentLoader::GetInstance().GetCompVersionByDHType(dhType, compVersion);
        for (const auto &dhItem : entry.second) {
            auto metaCapInfo = std::make_shared<MetaCapabilityInfo>(
                dhItem.dhId, devInfo.deviceId, devInfo.deviceName,
                devInfo.deviceType, dhType, dhItem.attrs, dhItem.subtype,
                devInfo.udidHash, compVersion);
            localFullMetaCapInfos.push_back(metaCapInfo);
        }
    }
    FullCapsRsp capsRsp;
    capsRsp.networkId = GetLocalNetworkId();
    capsRsp.metaCaps = localFullMetaCapInfos;
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        DHLOGE("Create cJSON object failed.");
        return "";
    }
    ToJson(root, capsRsp, isSyncMeta);
    char *fullMetaInfo = cJSON_PrintUnformatted(root);
    if (fullMetaInfo == nullptr) {
        cJSON_Delete(root);
        return "";
    }
    std::string fullMetaCaps(fullMetaInfo);
    cJSON_free(fullMetaInfo);
    cJSON_Delete(root);
    return fullMetaCaps;
}

void DHCommTool::GetAndSendLocalFullCaps(const std::string &reqNetworkId, bool isSyncMeta)
{
    DHLOGI("GetAndSendLocalFullCaps, reqNetworkId: %{public}s", GetAnonyString(reqNetworkId).c_str());
    if (dhTransportPtr_ == nullptr) {
        DHLOGE("transport is null");
        return;
    }
    std::string localFullInfo;
    // lite: use MetaCapabilityInfo path so sinkVersion is included in the response.
    localFullInfo = GetLocalFullMetaCapsInfo(true);
    if (localFullInfo.empty()) {
        DHLOGE("Get lcoal full device info failed.");
        return;
    }
    CommMsg commMsg;
    commMsg.code = DH_COMM_RSP_FULL_CAPS;
    commMsg.msg = localFullInfo;
    // lite now answers with metaCaps (GetLocalFullMetaCapsInfo), so the peer
    // must parse the payload as MetaCapabilityInfo to extract sinkVersion.
    commMsg.isSyncMeta = true;
    std::string payload = GetCommMsgString(commMsg);
    int32_t ret = dhTransportPtr_->Send(reqNetworkId, payload);
    if (ret != DH_FWK_SUCCESS) {
        DHLOGE("Send back Caps failed, ret: %{public}d", ret);
        return;
    }
    DHLOGI("Send back Caps success");
}

FullCapsRsp DHCommTool::ParseAndSaveRemoteDHCaps(const std::string &remoteCaps, bool isSyncMeta,
    const std::string &realNetworkId)
{
    FullCapsRsp capsRsp;
    DHLOGI("Receive remote device full capinfos, parse and save remote device capinfos.");
    cJSON *root = cJSON_Parse(remoteCaps.c_str());
    if (root == NULL) {
        DHLOGE("Parse remote Caps failed");
        return capsRsp;
    }

    FromJson(root, capsRsp, isSyncMeta);
    cJSON_Delete(root);
    FullCapsRsp invalidCaps;
    if (!ComponentManager::GetInstance().IsRequestSyncData(realNetworkId)) {
        DHLOGE("Ignore response, networkId: %{public}s no request sync", GetAnonyString(realNetworkId).c_str());
        return invalidCaps;
    }

    if (!IsSaveRemoteDHCaps(capsRsp, isSyncMeta, realNetworkId)) {
        DHLOGE("save remote device capabilityInfo failed");
        return invalidCaps;
    }
    return capsRsp;
}

bool DHCommTool::IsSaveRemoteDHCaps(const FullCapsRsp &capsRsp, bool isSyncMeta, const std::string &realNetworkId)
{
    (void)capsRsp;
    (void)isSyncMeta;
    (void)realNetworkId;
    return true;
}

std::string DHCommTool::SplitString(const std::string &capInfoPrefix)
{
    std::string prefix = "";
    size_t pos = capInfoPrefix.find(RESOURCE_SEPARATOR);
    if (pos != std::string::npos) {
        prefix = capInfoPrefix.substr(0, pos);
    }
    return prefix;
}

const std::shared_ptr<DHTransport> DHCommTool::GetDHTransportPtr()
{
    return this->dhTransportPtr_;
}

} // DistributedHardware
} // OHOS
