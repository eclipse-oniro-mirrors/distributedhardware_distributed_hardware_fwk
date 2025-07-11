/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_HARDWARE_TRANSPORT_H
#define OHOS_DISTRIBUTED_HARDWARE_TRANSPORT_H

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>

#include "socket.h"
#include "softbus_bus_center.h"

#include "dh_transport_obj.h"

namespace OHOS {
namespace DistributedHardware {
class DHCommTool;
class DHTransport {
public:
    explicit DHTransport(std::shared_ptr<DHCommTool> dhCommToolPtr);
    int32_t Init();
    int32_t UnInit();
    virtual ~DHTransport() = default;
    // open softbus channel with remote device by networkid.
    int32_t StartSocket(const std::string &remoteNetworkId);
    // stop softbus channel with remote device by networkid.
    int32_t StopSocket(const std::string &remoteNetworkId);
    int32_t Send(const std::string &remoteNetworkId, const std::string &payload);
    int32_t OnSocketOpened(int32_t socketId, const PeerSocketInfo &info);
    void OnSocketClosed(int32_t socketId, ShutdownReason reason);
    void OnBytesReceived(int32_t socketId, const void *data, uint32_t dataLen);

private:
    int32_t CreateServerSocket();
    int32_t CreateClientSocket(const std::string &remoteDevId);
    bool IsDeviceSessionOpened(const std::string &remoteDevId, int32_t &socketId);
    std::string GetRemoteNetworkIdBySocketId(int32_t socketId);
    void ClearDeviceSocketOpened(const std::string &remoteDevId);
    void HandleReceiveMessage(const std::string &payload);
    bool CheckCalleeAclRight(const std::shared_ptr<CommMsg> commMsg);

private:
    std::mutex rmtSocketIdMtx_;
    // record the socket id for the connection with remote devices, <remote networkId, socketId>
    std::map<std::string, int32_t> remoteDevSocketIds_;
    std::atomic<int32_t> localServerSocket_;
    std::string localSocketName_;
    std::atomic<bool> isSocketSvrCreateFlag_;
    std::weak_ptr<DHCommTool> dhCommToolWPtr_;
};
} // DistributedHardware
} // OHOS
#endif