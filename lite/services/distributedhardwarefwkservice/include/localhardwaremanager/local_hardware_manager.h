/*
 * Copyright (c) 2021-2026 Huawei Device Co., Ltd.
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

/*
 * lite shadow of include/localhardwaremanager/local_hardware_manager.h.
 * Verbatim new-baseline content plus ONE lite increment (same delta the old
 * fork applied to the shared header, kept out of the shared file per C7):
 * the GetLocalDHItemsMap() accessor consumed by the lite capability-report
 * chain (dh_comm_tool GetLocalFullCapsInfo -> localDHItemsMap_, BR1).
 */

#ifndef OHOS_DISTRIBUTED_HARDWARE_LOCAL_HARDWARE_MANAGER_H
#define OHOS_DISTRIBUTED_HARDWARE_LOCAL_HARDWARE_MANAGER_H

#include <map>
#include <memory>
#include <mutex>
#include <vector>

#include "capability_info.h"
#include "device_type.h"
#include "ihardware_handler.h"
#include "meta_capability_info.h"
#include "dhfwk_single_instance.h"

namespace OHOS {
namespace DistributedHardware {
class LocalHardwareManager {
    FWK_DECLARE_SINGLE_INSTANCE_BASE(LocalHardwareManager);

public:
    LocalHardwareManager();
    ~LocalHardwareManager();
    void Init();
    void UnInit();
    const std::unordered_map<DHType, std::vector<DHItem>>& GetLocalDHItemsMap() const;
    /*
     * TASK-121d: re-query every local hardware handler and refresh the cached
     * DHItems. Called before answering a remote FULL_CAPS request so runtime
     * config changes on the sink (e.g. the camera fps config file) are picked
     * up without a daemon restart or a device re-registration.
     */
    void RefreshLocalDHItems();

private:
    void QueryLocalHardware(const DHType dhType, IHardwareHandler *hardwareHandler);
    void InitSingleHardware(DHType dhType);
    void AddLocalCapabilityInfo(const std::vector<DHItem> &dhItems, const DHType dhType,
                                std::vector<std::shared_ptr<CapabilityInfo>> &capabilityInfos);
    void AddLocalMetaCapInfo(const std::vector<DHItem> &dhItems, const DHType dhType,
        std::vector<std::shared_ptr<MetaCapabilityInfo>> &metaCapInfos);
    void CheckNonExistCapabilityInfo(const std::vector<DHItem> &dhItems, const DHType dhType);
    void GetLocalCapabilityMapByPrefix(const DHType dhType, CapabilityInfoMap &capabilityInfoMap);

private:
    std::map<DHType, IHardwareHandler*> compToolFuncsMap_;
    std::map<DHType, std::shared_ptr<PluginListener>> pluginListenerMap_;
    std::unordered_map<DHType, std::vector<DHItem>> localDHItemsMap_;
    std::mutex localHardwareMgrMutex_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif
