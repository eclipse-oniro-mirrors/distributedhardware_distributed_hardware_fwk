/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "dhtransport_fuzzer.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unistd.h>

#include "constants.h"
#include "dh_transport.h"
#include "dh_comm_tool.h"
#include "socket.h"
#include "softbus_bus_center.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
    const int32_t SOCKETID = 1;
}
void DhTransportOnBytesReceivedFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    int32_t socketId = *(reinterpret_cast<const int32_t*>(data));
    std::shared_ptr<DHCommTool> dhCommTool = std::make_shared<DHCommTool>();
    std::shared_ptr<DHTransport> dhTransportTest = std::make_shared<DHTransport>(dhCommTool);
    std::string remoteNetworkId = "remoteNetworkId_test";
    dhTransportTest->remoteDevSocketIds_[remoteNetworkId] = socketId;
    dhTransportTest->OnBytesReceived(socketId, data, size);
    dhTransportTest->remoteDevSocketIds_.clear();
}

void DhTransportCreateClientSocketFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string remoteNetworkId(reinterpret_cast<const char*>(data), size);
    std::shared_ptr<DHCommTool> dhCommTool = std::make_shared<DHCommTool>();
    std::shared_ptr<DHTransport> dhTransportTest = std::make_shared<DHTransport>(dhCommTool);
    dhTransportTest->CreateServerSocket();
    dhTransportTest->CreateClientSocket(remoteNetworkId);
}

void DhTransportIsDeviceSessionOpenedFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    int32_t socketId = 0;
    std::string remoteNetworkId(reinterpret_cast<const char*>(data), size);
    std::shared_ptr<DHCommTool> dhCommTool = std::make_shared<DHCommTool>();
    std::shared_ptr<DHTransport> dhTransportTest = std::make_shared<DHTransport>(dhCommTool);
    dhTransportTest->remoteDevSocketIds_[remoteNetworkId] = SOCKETID;
    dhTransportTest->IsDeviceSessionOpened(remoteNetworkId, socketId);
    dhTransportTest->remoteDevSocketIds_.clear();
}

void DhTransportClearDeviceSocketOpenedFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string remoteNetworkId(reinterpret_cast<const char*>(data), size);
    std::shared_ptr<DHCommTool> dhCommTool = std::make_shared<DHCommTool>();
    std::shared_ptr<DHTransport> dhTransportTest = std::make_shared<DHTransport>(dhCommTool);
    dhTransportTest->ClearDeviceSocketOpened(remoteNetworkId);
}

void DhTransportStartSocketFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string remoteNetworkId(reinterpret_cast<const char*>(data), size);
    std::shared_ptr<DHCommTool> dhCommTool = std::make_shared<DHCommTool>();
    std::shared_ptr<DHTransport> dhTransportTest = std::make_shared<DHTransport>(dhCommTool);
    dhTransportTest->StartSocket(remoteNetworkId);
}

void DhTransportStopSocketFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string remoteNetworkId(reinterpret_cast<const char*>(data), size);
    std::shared_ptr<DHCommTool> dhCommTool = std::make_shared<DHCommTool>();
    std::shared_ptr<DHTransport> dhTransportTest = std::make_shared<DHTransport>(dhCommTool);
    dhTransportTest->remoteDevSocketIds_[remoteNetworkId] = SOCKETID;
    dhTransportTest->StopSocket(remoteNetworkId);
    dhTransportTest->remoteDevSocketIds_.clear();
}

void DhTransportSendFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    std::string remoteNetworkId(reinterpret_cast<const char*>(data), size);
    std::string payload(reinterpret_cast<const char*>(data), size);
    std::shared_ptr<DHCommTool> dhCommTool = std::make_shared<DHCommTool>();
    std::shared_ptr<DHTransport> dhTransportTest = std::make_shared<DHTransport>(dhCommTool);
    dhTransportTest->remoteDevSocketIds_[remoteNetworkId] = 1;
    dhTransportTest->Send(remoteNetworkId, payload);
    dhTransportTest->remoteDevSocketIds_.clear();
}

void DhTransportOnSocketOpenedFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t socketId = *(reinterpret_cast<const int32_t*>(data));
    std::string peerSocketName(reinterpret_cast<const char*>(data), size);
    std::string remoteNetworkId(reinterpret_cast<const char*>(data), size);
    PeerSocketInfo info = {
        .name = const_cast<char*>(peerSocketName.c_str()),
        .networkId = const_cast<char*>(remoteNetworkId.c_str()),
        .pkgName = const_cast<char*>(DH_FWK_PKG_NAME.c_str()),
        .dataType = DATA_TYPE_BYTES
    };
    std::shared_ptr<DHCommTool> dhCommTool = std::make_shared<DHCommTool>();
    std::shared_ptr<DHTransport> dhTransportTest = std::make_shared<DHTransport>(dhCommTool);
    dhTransportTest->OnSocketOpened(socketId, info);
}

void DhTransportOnSocketClosedFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t socketId = *(reinterpret_cast<const int32_t*>(data));
    ShutdownReason reason = ShutdownReason::SHUTDOWN_REASON_UNKNOWN;
    std::shared_ptr<DHCommTool> dhCommTool = std::make_shared<DHCommTool>();
    std::shared_ptr<DHTransport> dhTransportTest = std::make_shared<DHTransport>(dhCommTool);
    dhTransportTest->OnSocketClosed(socketId, reason);
    dhTransportTest->UnInit();
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::DhTransportOnBytesReceivedFuzzTest(data, size);
    OHOS::DistributedHardware::DhTransportCreateClientSocketFuzzTest(data, size);
    OHOS::DistributedHardware::DhTransportIsDeviceSessionOpenedFuzzTest(data, size);
    OHOS::DistributedHardware::DhTransportClearDeviceSocketOpenedFuzzTest(data, size);
    OHOS::DistributedHardware::DhTransportStartSocketFuzzTest(data, size);
    OHOS::DistributedHardware::DhTransportStopSocketFuzzTest(data, size);
    OHOS::DistributedHardware::DhTransportSendFuzzTest(data, size);
    OHOS::DistributedHardware::DhTransportOnSocketOpenedFuzzTest(data, size);
    OHOS::DistributedHardware::DhTransportOnSocketClosedFuzzTest(data, size);
    return 0;
}

