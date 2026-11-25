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

// lite variant of include/accessmanager/access_manager.h.
// Baseline drift @fae6ed46: the device_manager lite SDK is a pure-C vtable API
// (DmDeviceManagerGetInstance + DeviceManagerVtable + C callback structs), the
// native_cpp C++ SDK (DeviceManager::GetInstance()/DmStateCallback) is an empty
// group on lite. The shared access_manager cannot be compiled against the C
// SDK, so lite brings its own copy: same public surface consumed by
// dhfwk_daemon_main (GetInstance/Init/OnDeviceOnline/.../CheckTrustedDeviceOnline)
// but the DM access face is adapted to the C vtable with static trampolines
// (ctx = this). See D-DM1 in the TASK-2 report.

#ifndef OHOS_DISTRIBUTED_HARDWARE_ACCESS_MANAGER_H
#define OHOS_DISTRIBUTED_HARDWARE_ACCESS_MANAGER_H

#include <cstdint>
#include <string>
#include <memory>
#include <mutex>
#include <vector>

#include "device_manager_callback.h"
#include "dm_device_info.h"

namespace OHOS {
namespace DistributedHardware {
class AccessManager {
public:
    AccessManager(const AccessManager &) = delete;
    AccessManager &operator = (const AccessManager &) = delete;
    AccessManager(AccessManager &&) = delete;
    AccessManager &operator = (AccessManager &&) = delete;
    AccessManager() = default;
    virtual ~AccessManager();
    static std::shared_ptr<AccessManager> GetInstance();
    int32_t Init();
    int32_t UnInit();
    bool IsDeviceOnline(const std::string &uuid);
    void OnRemoteDied();
    void OnDeviceOnline(const DmDeviceInfo &deviceInfo);
    void OnDeviceOffline(const DmDeviceInfo &deviceInfo);
    void OnDeviceReady(const DmDeviceInfo &deviceInfo);
    void OnDeviceChanged(const DmDeviceInfo &deviceInfo);
    /* Send device online event which is already online */
    void CheckTrustedDeviceOnline();

private:
    int32_t RegisterDevStateCallback();
    int32_t UnRegisterDevStateCallback();
    int32_t InitDeviceManager();
    int32_t UnInitDeviceManager();

    // C vtable trampolines: ctx carries the AccessManager instance pointer.
    static void OnRemoteDiedCb(void *ctx);
    static void OnDeviceOnlineCb(void *ctx, const DmDeviceInfo *deviceInfo);
    static void OnDeviceOfflineCb(void *ctx, const DmDeviceInfo *deviceInfo);
    static void OnDeviceReadyCb(void *ctx, const DmDeviceInfo *deviceInfo);
    static void OnDeviceChangedCb(void *ctx, const DmDeviceInfo *deviceInfo);

    std::mutex accessMutex_;
    DmInitCallbackVtable initVtable_ { &AccessManager::OnRemoteDiedCb };
    DmInitCallback initCb_ { &initVtable_, nullptr };
    DeviceStateCallbackVtable devStateVtable_ {
        &AccessManager::OnDeviceOnlineCb,
        &AccessManager::OnDeviceOfflineCb,
        &AccessManager::OnDeviceChangedCb,
        &AccessManager::OnDeviceReadyCb
    };
    DeviceStateCallback devStateCb_ { &devStateVtable_, nullptr };
};
} // namespace DistributedHardware
} // namespace OHOS
#endif
