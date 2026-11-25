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

#ifndef OHOS_DISTRIBUTED_HARDWARE_COMM_TOOL_H
#define OHOS_DISTRIBUTED_HARDWARE_COMM_TOOL_H

#include <cstdint>
#include <string>
#include <vector>
#include <memory>

#include "dh_transport.h"
#include "dh_transport_obj.h"

namespace OHOS {
namespace DistributedHardware {
class DHCommTool : public std::enable_shared_from_this<DHCommTool> {
public:
    DHCommTool();
    virtual ~DHCommTool() = default;
    void Init();
    void UnInit();
    void GetAndSendLocalFullCaps(const std::string &reqNetworkId, bool isSyncMeta);
    std::string GetLocalFullCapsInfo(bool isSyncMeta);
    std::string GetLocalFullMetaCapsInfo(bool isSyncMeta);
    FullCapsRsp ParseAndSaveRemoteDHCaps(const std::string &remoteCaps, bool isSyncMeta,
        const std::string &realNetworkId);

    const std::shared_ptr<DHTransport> GetDHTransportPtr();

private:
    std::string SplitString(const std::string &capInfoPrefix);
    bool IsSaveRemoteDHCaps(const FullCapsRsp &capsRsp, bool isSyncMeta, const std::string &realNetworkId);
private:
    std::shared_ptr<DHTransport> dhTransportPtr_;
};
} // DistributedHardware
} // OHOS
#endif
