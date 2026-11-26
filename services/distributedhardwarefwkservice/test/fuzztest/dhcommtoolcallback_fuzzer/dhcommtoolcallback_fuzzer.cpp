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

#include "dhcommtoolcallback_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>

#include "capability_info.h"
#include "constants.h"
#include "dh_comm_tool.h"
#include "dh_context.h"
#include "dh_transport.h"
#include "dh_transport_obj.h"
#include "dh_utils_tool.h"
#include "distributed_hardware_log.h"
#include "meta_capability_info.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
    constexpr int32_t DH_COMM_REQ_FULL_CAPS = 1;
    constexpr int32_t DH_COMM_RSP_FULL_CAPS = 2;
    const std::string ONLINE_UDID = "onlineUdidTest123";
    const std::string ONLINE_UUID = "onlineUuidTest123";
    const std::string ONLINE_NETWORK_ID = "onlineNetworkId123";
}

void DHCommToolGetLocalFullCapsFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint8_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    bool isSyncMeta = (fdp.ConsumeIntegral<uint8_t>() % 2) == 0;
    std::string reqNetworkId = fdp.ConsumeRandomLengthString();

    std::shared_ptr<DHCommTool> dhCommTool = std::make_shared<DHCommTool>();
    // Cover the sync meta and common caps branches.
    dhCommTool->GetLocalFullCapsInfo(isSyncMeta);
    dhCommTool->GetLocalFullMetaCapsInfo(isSyncMeta);

    // Cover the transport nullptr branch of GetAndSendLocalFullCaps.
    dhCommTool->GetAndSendLocalFullCaps(reqNetworkId, isSyncMeta);
    dhCommTool->GetAndSendLocalFullCaps(reqNetworkId, false);

    // Cover the send failed branch of GetAndSendLocalFullCaps.
    dhCommTool->dhTransportPtr_ = std::make_shared<DHTransport>(dhCommTool);
    dhCommTool->GetAndSendLocalFullCaps(reqNetworkId, isSyncMeta);
    dhCommTool->GetAndSendLocalFullCaps(reqNetworkId, false);
    dhCommTool->dhTransportPtr_ = nullptr;

    // Cover the UnInit transport nullptr branch.
    dhCommTool->UnInit();
    dhCommTool->dhTransportPtr_ = std::make_shared<DHTransport>(dhCommTool);
    dhCommTool->UnInit();
    dhCommTool->dhTransportPtr_ = nullptr;
}

void DHCommToolIsSaveRemoteDHCapsFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint16_t) + sizeof(uint32_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    uint16_t deviceType = fdp.ConsumeIntegral<uint16_t>();
    DHType dhType = static_cast<DHType>(fdp.ConsumeIntegral<uint32_t>());
    std::string remoteNetworkId = fdp.ConsumeRandomLengthString();
    std::string dhId = fdp.ConsumeRandomLengthString();
    std::string dhAttrs = fdp.ConsumeRandomLengthString();
    std::string dhSubtype = fdp.ConsumeRandomLengthString();

    std::shared_ptr<DHCommTool> dhCommTool = std::make_shared<DHCommTool>();
    FullCapsRsp capsRsp;
    capsRsp.caps.push_back(std::make_shared<CapabilityInfo>(dhId, "devId_test_123", "devName_test", deviceType,
        dhType, dhAttrs, dhSubtype));
    capsRsp.metaCaps.push_back(std::make_shared<MetaCapabilityInfo>(dhId, "devId_test_123", "devName_test",
        deviceType, dhType, dhAttrs, dhSubtype, "udidHash_test",
        CompVersion { .sinkVersion = "1.0" }));
    // Cover the remote device not online branches.
    dhCommTool->IsSaveRemoteDHCaps(capsRsp, true, remoteNetworkId);
    dhCommTool->IsSaveRemoteDHCaps(capsRsp, false, remoteNetworkId);

    // Cover the udidHash and deviceId trustworthy branches with an online device.
    DHContext::GetInstance().AddOnlineDevice(ONLINE_UDID, ONLINE_UUID, ONLINE_NETWORK_ID);
    std::string remoteUdidHash = Sha256(ONLINE_UDID);
    std::string remoteDeviceId = Sha256(ONLINE_UUID);
    FullCapsRsp onlineCapsRsp;
    onlineCapsRsp.caps.push_back(std::make_shared<CapabilityInfo>(dhId, remoteDeviceId, "devName_test",
        deviceType, dhType, dhAttrs, dhSubtype));
    // Cover the udidHash not trustworthy branch.
    onlineCapsRsp.metaCaps.push_back(std::make_shared<MetaCapabilityInfo>(dhId, remoteDeviceId, "devName_test",
        deviceType, dhType, dhAttrs, dhSubtype, remoteDeviceId,
        CompVersion { .sinkVersion = "1.0" }));
    dhCommTool->IsSaveRemoteDHCaps(onlineCapsRsp, true, ONLINE_NETWORK_ID);
    dhCommTool->IsSaveRemoteDHCaps(onlineCapsRsp, false, ONLINE_NETWORK_ID);

    // Cover the udidHash and deviceId trustworthy branches.
    FullCapsRsp matchedCapsRsp;
    matchedCapsRsp.caps.push_back(std::make_shared<CapabilityInfo>(dhId, remoteDeviceId, "devName_test",
        deviceType, dhType, dhAttrs, dhSubtype));
    matchedCapsRsp.metaCaps.push_back(std::make_shared<MetaCapabilityInfo>(dhId, remoteDeviceId, "devName_test",
        deviceType, dhType, dhAttrs, dhSubtype, remoteUdidHash,
        CompVersion { .sinkVersion = "1.0" }));
    dhCommTool->IsSaveRemoteDHCaps(matchedCapsRsp, true, ONLINE_NETWORK_ID);
    dhCommTool->IsSaveRemoteDHCaps(matchedCapsRsp, false, ONLINE_NETWORK_ID);
    // Cover the nullptr cap item branches.
    matchedCapsRsp.caps.push_back(nullptr);
    matchedCapsRsp.metaCaps.push_back(nullptr);
    dhCommTool->IsSaveRemoteDHCaps(matchedCapsRsp, true, ONLINE_NETWORK_ID);
    dhCommTool->IsSaveRemoteDHCaps(matchedCapsRsp, false, ONLINE_NETWORK_ID);
    DHContext::GetInstance().RemoveOnlineDeviceIdEntryByNetworkId(ONLINE_NETWORK_ID);
}

void DHCommToolEventHandlerProcessEventFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t code = fdp.ConsumeIntegral<int32_t>();
    std::string msg = fdp.ConsumeRandomLengthString();
    std::string realNetworkId = fdp.ConsumeRandomLengthString();
    bool isSyncMeta = fdp.ConsumeBool();

    std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create(true);
    std::shared_ptr<DHCommTool> dhCommTool = std::make_shared<DHCommTool>();
    auto handler = std::make_shared<DHCommTool::DHCommToolEventHandler>(runner, dhCommTool);
    dhCommTool->dhTransportPtr_ = std::make_shared<DHTransport>(dhCommTool);

    // Cover the event null branch.
    AppExecFwk::InnerEvent::Pointer nullEvent = AppExecFwk::InnerEvent::Get(static_cast<uint32_t>(code));
    nullEvent.reset();
    handler->ProcessEvent(nullEvent);

    // Cover the commMsg nullptr branch.
    handler->ProcessEvent(AppExecFwk::InnerEvent::Get(static_cast<uint32_t>(code)));

    // Cover the request full caps, response full caps and undefined event branches.
    std::shared_ptr<CommMsg> commMsg = std::make_shared<CommMsg>();
    commMsg->code = code;
    commMsg->msg = msg;
    commMsg->realNetworkId = realNetworkId;
    commMsg->isSyncMeta = isSyncMeta;
    handler->ProcessEvent(AppExecFwk::InnerEvent::Get(static_cast<uint32_t>(code), commMsg));

    std::shared_ptr<CommMsg> reqMsg = std::make_shared<CommMsg>();
    reqMsg->code = DH_COMM_REQ_FULL_CAPS;
    reqMsg->msg = msg;
    reqMsg->realNetworkId = realNetworkId;
    reqMsg->isSyncMeta = isSyncMeta;
    handler->ProcessEvent(AppExecFwk::InnerEvent::Get(static_cast<uint32_t>(DH_COMM_REQ_FULL_CAPS), reqMsg));

    std::shared_ptr<CommMsg> rspMsg = std::make_shared<CommMsg>();
    rspMsg->code = DH_COMM_RSP_FULL_CAPS;
    rspMsg->msg = msg;
    rspMsg->realNetworkId = realNetworkId;
    rspMsg->isSyncMeta = isSyncMeta;
    handler->ProcessEvent(AppExecFwk::InnerEvent::Get(static_cast<uint32_t>(DH_COMM_RSP_FULL_CAPS), rspMsg));

    // Cover the sync meta false branches of the request and response events.
    reqMsg->isSyncMeta = false;
    handler->ProcessEvent(AppExecFwk::InnerEvent::Get(static_cast<uint32_t>(DH_COMM_REQ_FULL_CAPS), reqMsg));
    rspMsg->isSyncMeta = false;
    handler->ProcessEvent(AppExecFwk::InnerEvent::Get(static_cast<uint32_t>(DH_COMM_RSP_FULL_CAPS), rspMsg));

    // Cover the ParseAndSaveRemoteDHCaps isSyncMeta false branch directly.
    dhCommTool->ParseAndSaveRemoteDHCaps(msg, false, realNetworkId);
    dhCommTool->ParseAndSaveRemoteDHCaps(msg, true, realNetworkId);
    dhCommTool->dhTransportPtr_ = nullptr;
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::DHCommToolGetLocalFullCapsFuzzTest(data, size);
    OHOS::DistributedHardware::DHCommToolIsSaveRemoteDHCapsFuzzTest(data, size);
    OHOS::DistributedHardware::DHCommToolEventHandlerProcessEventFuzzTest(data, size);
    return 0;
}
