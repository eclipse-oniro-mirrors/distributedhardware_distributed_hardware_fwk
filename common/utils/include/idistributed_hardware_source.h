/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_HARDWARE_IDISTRIBUTED_HARDWARE_SOURCE_H
#define OHOS_DISTRIBUTED_HARDWARE_IDISTRIBUTED_HARDWARE_SOURCE_H

#include <memory>
#include <string>

namespace OHOS {
namespace DistributedHardware {
const std::string COMPONENT_LOADER_GET_SOURCE_HANDLER = "GetSourceHardwareHandler";
class RegisterCallback {
public:
    virtual int32_t OnRegisterResult(const std::string &networkId, const std::string &dhId, int32_t status,
        const std::string &data) = 0;
};

class UnregisterCallback {
public:
    virtual int32_t OnUnregisterResult(const std::string &networkId, const std::string &dhId, int32_t status,
        const std::string &data) = 0;
};

struct EnableParam {
    std::string sourceVersion;
    std::string sourceAttrs;
    std::string sinkVersion;
    std::string sinkAttrs;
    std::string subtype;
};

enum class BusinessState : uint32_t {
    UNKNOWN,
    IDLE,
    RUNNING,
    PAUSING
};

struct WorkModeParam {
    int32_t fd;
    int32_t sharedMemLen;
    uint32_t scene;
    bool isAVsync;

    WorkModeParam(int32_t f, int32_t sm, uint32_t s, bool av)
        : fd(f), sharedMemLen(sm), scene(s), isAVsync(av)
    {}
};

class DistributedHardwareStateListener {
public:
    /**
     * @brief report the business state of local virtual driver
     *        corresponding the remote device with the device id and dhid.
     *
     * @param networkId the remote device networkId.
     * @param dhId the remote device peripheral dhId.
     * @param state business state.
     */
    virtual void OnStateChanged(const std::string &networkId, const std::string &dhId, const BusinessState state) = 0;
};

class DataSyncTriggerListener {
public:
    /**
     * @brief trigger local distributed hardware open session with remote device with uuid
     *
     * @param networkId the remote device networkId
     */
    virtual void OnDataSyncTrigger(const std::string &networkId) = 0;
};

class HdfDeathCallback {
public:
    /**
     * @brief Trigger callback when HDF driver exits abnormally
     *
     */
    virtual void OnHdfHostDied() = 0;
};


class IDistributedHardwareSource {
public:
    virtual int32_t InitSource(const std::string &params) = 0;
    virtual int32_t ReleaseSource() = 0;
    virtual int32_t RegisterDistributedHardware(const std::string &networkId, const std::string &dhId,
        const EnableParam &param, std::shared_ptr<RegisterCallback> callback) = 0;
    virtual int32_t UnregisterDistributedHardware(const std::string &networkId, const std::string &dhId,
        std::shared_ptr<UnregisterCallback> callback) = 0;
    virtual int32_t ConfigDistributedHardware(const std::string &networkId, const std::string &dhId,
        const std::string &key, const std::string &value) = 0;
    virtual void RegisterDistributedHardwareStateListener(
        std::shared_ptr<DistributedHardwareStateListener> listener) = 0;
    virtual void UnregisterDistributedHardwareStateListener() = 0;
    virtual void RegisterDataSyncTriggerListener(std::shared_ptr<DataSyncTriggerListener> listener) = 0;
    virtual void UnregisterDataSyncTriggerListener() = 0;
    virtual int32_t LoadDistributedHDF(std::shared_ptr<HdfDeathCallback> callback)
    {
        (void)callback;
        return 0;
    }
    virtual int32_t UnLoadDistributedHDF()
    {
        return 0;
    }
    virtual int32_t UpdateDistributedHardwareWorkMode(const std::string &networkId, const std::string &dhId,
        const WorkModeParam &param)
    {
        (void)networkId;
        (void)dhId;
        (void)param;
        return 0;
    }
};
extern "C" __attribute__((visibility("default"))) IDistributedHardwareSource* GetSourceHardwareHandler();
} // namespace DistributedHardware
} // namespace OHOS
#endif
