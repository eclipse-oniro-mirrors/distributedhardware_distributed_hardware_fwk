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

#include "dhtransportcallback_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>

#include "constants.h"
#include "dh_comm_tool.h"
#include "dh_transport.h"
#include "dh_utils_tool.h"
#include "distributed_hardware_log.h"
#include "socket.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
    const int32_t INVALID_QOS_COUNT = 1001;
}

void OnBind(int32_t socket, PeerSocketInfo info);
void OnShutdown(int32_t socket, ShutdownReason reason);
void OnBytes(int32_t socket, const void *data, uint32_t dataLen);
void OnMessage(int32_t socket, const void *data, uint32_t dataLen);
void OnStream(int32_t socket, const StreamData *data, const StreamData *ext, const StreamFrameInfo *param);
void OnFile(int32_t socket, FileEvent *event);
void OnQos(int32_t socket, QoSEvent eventId, const QosTV *qos, uint32_t qosCount);

void DhTransportListenerCallbackFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t) + sizeof(uint32_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t socketId = fdp.ConsumeIntegral<int32_t>();
    uint32_t dataLen = fdp.ConsumeIntegral<uint32_t>() % static_cast<uint32_t>(size);
    std::string payload = fdp.ConsumeRandomLengthString();

    // Cover the OnMessage, OnStream and OnFile callbacks.
    OnMessage(socketId, payload.c_str(), dataLen);
    StreamData streamData = {};
    StreamFrameInfo streamFrameInfo = {};
    OnStream(socketId, &streamData, &streamData, &streamFrameInfo);
    OnStream(socketId, nullptr, nullptr, nullptr);
    FileEvent fileEvent = {};
    OnFile(socketId, &fileEvent);
    OnFile(socketId, nullptr);

    // Cover the OnQos qosCount invalid and valid branches.
    QosTV qosTV = { QOS_TYPE_MIN_BW, 256 * 1024 };
    OnQos(socketId, QOS_SATISFIED, &qosTV, 0);
    OnQos(socketId, QOS_SATISFIED, &qosTV, 1);
    OnQos(socketId, QOS_SATISFIED, nullptr, INVALID_QOS_COUNT);
}

void DhTransportGetRemoteNetworkIdBySocketIdFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t socketId = fdp.ConsumeIntegral<int32_t>();
    std::string remoteNetworkId = fdp.ConsumeRandomLengthString();

    std::shared_ptr<DHCommTool> dhCommTool = std::make_shared<DHCommTool>();
    std::shared_ptr<DHTransport> dhTransportTest = std::make_shared<DHTransport>(dhCommTool);
    dhTransportTest->remoteDevSocketIds_[remoteNetworkId] = socketId;
    // Cover the socketId found branch.
    dhTransportTest->GetRemoteNetworkIdBySocketId(socketId);
    // Cover the socketId not found branch.
    dhTransportTest->GetRemoteNetworkIdBySocketId(socketId + 1);
    dhTransportTest->remoteDevSocketIds_.clear();
}

void DhTransportListenerDeepCallbackFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t socketId = fdp.ConsumeIntegral<int32_t>();
    std::string peerSocketName = fdp.ConsumeRandomLengthString();
    std::string remoteNetworkId = fdp.ConsumeRandomLengthString();
    std::string payload = fdp.ConsumeRandomLengthString();

    char *nameBuf = strdup(peerSocketName.c_str());
    char *networkIdBuf = strdup(remoteNetworkId.c_str());
    char *pkgNameBuf = strdup(DH_FWK_PKG_NAME);
    if (nameBuf == nullptr || networkIdBuf == nullptr || pkgNameBuf == nullptr) {
        free(nameBuf);
        free(networkIdBuf);
        free(pkgNameBuf);
        return;
    }
    PeerSocketInfo info = {
        .name = nameBuf,
        .networkId = networkIdBuf,
        .pkgName = pkgNameBuf,
        .dataType = DATA_TYPE_BYTES
    };

    std::shared_ptr<DHCommTool> dhCommTool = std::make_shared<DHCommTool>();
    std::shared_ptr<DHTransport> dhTransportTest = std::make_shared<DHTransport>(dhCommTool);
    dhCommTool->dhTransportPtr_ = dhTransportTest;
    // Cover the OnBind to OnSocketOpened path.
    OnBind(socketId, info);
    // Cover the OnBytes to OnBytesReceived path with the opened session.
    OnBytes(socketId, payload.c_str(), static_cast<uint32_t>(payload.size()));
    OnBytes(socketId, payload.c_str(), 0);
    // Cover the OnShutdown to OnSocketClosed path.
    OnShutdown(socketId, ShutdownReason::SHUTDOWN_REASON_UNKNOWN);
    dhCommTool->dhTransportPtr_ = nullptr;
    dhTransportTest->remoteDevSocketIds_.clear();
    dhTransportTest->UnInit();

    // Cover the transport ptr not got branches.
    OnBind(socketId, info);
    OnShutdown(socketId, ShutdownReason::SHUTDOWN_REASON_UNKNOWN);
    OnBytes(socketId, payload.c_str(), static_cast<uint32_t>(payload.size()));

    // Cover the DHCommTool ptr expired branches.
    dhTransportTest.reset();
    dhCommTool.reset();
    OnBind(socketId, info);
    OnShutdown(socketId, ShutdownReason::SHUTDOWN_REASON_UNKNOWN);
    OnBytes(socketId, payload.c_str(), static_cast<uint32_t>(payload.size()));
    OnMessage(socketId, payload.c_str(), static_cast<uint32_t>(payload.size()));
    free(nameBuf);
    free(networkIdBuf);
    free(pkgNameBuf);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::DhTransportListenerCallbackFuzzTest(data, size);
    OHOS::DistributedHardware::DhTransportGetRemoteNetworkIdBySocketIdFuzzTest(data, size);
    OHOS::DistributedHardware::DhTransportListenerDeepCallbackFuzzTest(data, size);
    return 0;
}
