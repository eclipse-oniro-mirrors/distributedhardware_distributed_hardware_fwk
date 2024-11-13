/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_SOFTBUS_CHANNEL_ADAPTER
#define OHOS_SOFTBUS_CHANNEL_ADAPTER

#include <map>
#include <mutex>
#include <set>

#include "transport/socket.h"
#include "transport/trans_type.h"
#include "av_trans_types.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"
#include "av_trans_constants.h"

namespace OHOS {
namespace DistributedHardware {
class ISoftbusChannelListener {
public:
    virtual ~ISoftbusChannelListener() = default;
    virtual void OnChannelEvent(const AVTransEvent &event) = 0;
    virtual void OnStreamReceived(const StreamData *data, const StreamData *ext) = 0;
};

class SoftbusChannelAdapter {
public:
    static SoftbusChannelAdapter& GetInstance();
    int32_t CreateChannelServer(const std::string &pkgName, const std::string &sessName);
    int32_t RemoveChannelServer(const std::string &pkgName, const std::string &sessName);

    int32_t OpenSoftbusChannel(const std::string &mySessName, const std::string &peerSessName,
        const std::string &peerDevId);
    int32_t CloseSoftbusChannel(const std::string &mySessName, const std::string &peerDevId);

    int32_t SendBytesData(const std::string &sessName, const std::string &peerDevId, const std::string &data);
    int32_t SendStreamData(const std::string &sessName, const std::string &peerDevId, const StreamData *data,
        const StreamData *ext);

    int32_t RegisterChannelListener(const std::string &sessName, const std::string &peerDevId,
        ISoftbusChannelListener *listener);
    int32_t UnRegisterChannelListener(const std::string &sessName, const std::string &peerDevId);

    int32_t StartDeviceTimeSync(const std::string &pkgName, const std::string &sessName,
        const std::string &peerDevId);
    int32_t StopDeviceTimeSync(const std::string &pkgName, const std::string &sessName,
        const std::string &peerDevId);

    void SendChannelEvent(const std::string &sessName, const AVTransEvent event);

    int32_t OnSoftbusChannelOpened(std::string peerSessionName, int32_t sessionId,
        std::string peerDevId, int32_t result);
    void OnSoftbusChannelClosed(int32_t sessionId, ShutdownReason reason);
    void OnSoftbusBytesReceived(int32_t sessionId, const void *data, uint32_t dataLen);
    void OnSoftbusTimeSyncResult(const TimeSyncResultInfo *info, int32_t result);
    void OnSoftbusStreamReceived(int32_t sessionId, const StreamData *data, const StreamData *ext,
        const StreamFrameInfo *frameInfo);

private:
    SoftbusChannelAdapter(const SoftbusChannelAdapter&) = delete;
    SoftbusChannelAdapter& operator= (const SoftbusChannelAdapter&) = delete;
    SoftbusChannelAdapter(SoftbusChannelAdapter&&) = delete;
    SoftbusChannelAdapter& operator= (SoftbusChannelAdapter&&) = delete;
    SoftbusChannelAdapter();
    ~SoftbusChannelAdapter();

    std::string GetSessionNameById(int32_t sessionId);
    int32_t GetSessIdBySessName(const std::string &sessName, const std::string &peerDevId);
    std::string GetPeerDevIdBySessId(int32_t sessionId);
    std::string GetOwnerFromSessName(const std::string &sessName);
    std::string TransName2PkgName(const std::string &ownerName);
    std::string FindSessNameByPeerSessName(const std::string peerSessionName);
    void SendEventChannelOPened(const std::string &mySessName, const std::string &peerDevId);

private:
    std::mutex timeSyncMtx_;
    std::mutex idMapMutex_;
    std::mutex listenerMtx_;
    std::mutex serverMapMtx_;

    ISocketListener sessListener_;
    std::map<std::string, int32_t> serverMap_;
    std::set<std::string> timeSyncSessNames_;
    std::map<std::string, int32_t> devId2SessIdMap_;
    std::map<std::string, ISoftbusChannelListener *> listenerMap_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_SOFTBUS_CHANNEL_ADAPTER
