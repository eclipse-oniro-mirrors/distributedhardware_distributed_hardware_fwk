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

/*
 * lite variant of src/accessmanager/access_manager.cpp. Deltas versus the
 * standard source (baseline drift @fae6ed46, D-DM1):
 * 1. DeviceManager access is adapted to the DM lite pure-C vtable SDK
 *    (DmDeviceManagerGetInstance); the native_cpp C++ SDK is an empty group
 *    on lite. C callbacks reach the instance through static trampolines
 *    (ctx = AccessManager*), so the class no longer derives from the C++
 *    DmInitCallback/DeviceStateCallback bases.
 * 2. GetTrustedDeviceList consumes DmVec_DmDeviceInfo (C container); only the
 *    fields the lite IPC transports are used (extraData is not transported,
 *    so osType falls back to the "" parse result).
 * 3. GetUUIDByDm/GetUDIDByDm keep their frozen utils signatures; on the
 *    current DM lite SDK they return "" (TASK-1 decision) — the runtime
 *    uuid/udid supply source is escalated via D-DM1 (candidate: softbus
 *    GetNodeKeyInfo NODE_KEY_UUID/NODE_KEY_UDID). No device_manager change
 *    is made here (D-DM1 branch 3: escalate only).
 */

#include "access_manager.h"

#include <cstring>
#include <new>
#include <unistd.h>
#include <vector>

#include "device_manager.h"

#include "anonymous_string.h"
#include "constants.h"
#include "dh_context.h"
#include "dh_utils_tool.h"
#include "device_param_mgr.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"
#include "distributed_hardware_manager_factory.h"

namespace OHOS {
namespace DistributedHardware {
#undef DH_LOG_TAG
#define DH_LOG_TAG "AccessManager"

namespace {
    constexpr int32_t OLD_HO_DEVICE_TYPE = -1;
    constexpr int32_t NEW_HO_DEVICE_TYPE = 11;
    constexpr int32_t DH_RETRY_INIT_DM_COUNT = 6;
    constexpr int32_t DH_RETRY_INIT_DM_INTERVAL_US = 1000 * 500;

    DeviceManager *GetDmLiteInstance()
    {
        DeviceManager *dm = DmDeviceManagerGetInstance();
        if (dm == nullptr || dm->vtable == nullptr) {
            DHLOGE("DM lite instance or vtable is unavailable");
            return nullptr;
        }
        return dm;
    }

    std::string ExtraDataToString(const DmString &extraData)
    {
        const char *cstr = DmStringCstr(&extraData);
        return (cstr != nullptr) ? std::string(cstr) : std::string();
    }
}

AccessManager::~AccessManager()
{
    UnInit();
}

std::shared_ptr<AccessManager> AccessManager::GetInstance()
{
    static std::shared_ptr<AccessManager> instance = std::make_shared<AccessManager>();
    return instance;
}

int32_t AccessManager::Init()
{
    DHLOGI("start");
    initCb_.ctx = this;
    devStateCb_.ctx = this;
    if (InitDeviceManager() != DH_FWK_SUCCESS) {
        DHLOGE("InitDeviceManager failed");
        return ERR_DH_FWK_ACCESS_INIT_DM_FAILED;
    }
    if (RegisterDevStateCallback() != DH_FWK_SUCCESS) {
        DHLOGE("RegisterDevStateCallback failed");
        return ERR_DH_FWK_ACCESS_REGISTER_DM_FAILED;
    }
    return DH_FWK_SUCCESS;
}

int32_t AccessManager::UnInit()
{
    DHLOGI("start");
    if (UnInitDeviceManager() != DH_FWK_SUCCESS) {
        DHLOGE("UnInitDeviceManager failed");
        return ERR_DH_FWK_ACCESS_UNINIT_DM_FAILED;
    }

    if (UnRegisterDevStateCallback() != DH_FWK_SUCCESS) {
        DHLOGE("UnRegisterDevStateCallback failed");
        return ERR_DH_FWK_ACCESS_UNREGISTER_DM_FAILED;
    }
    return DH_FWK_SUCCESS;
}

int32_t AccessManager::InitDeviceManager()
{
    DHLOGI("start");
    DeviceManager *dm = GetDmLiteInstance();
    if (dm == nullptr || dm->vtable->InitDeviceManager == nullptr) {
        return ERR_DH_FWK_ACCESS_INIT_DM_FAILED;
    }
    DmString pkgName = DmStringCreate(DH_FWK_PKG_NAME);
    int32_t ret = dm->vtable->InitDeviceManager(&pkgName, &initCb_);
    DmStringDestroy(&pkgName);
    return ret;
}

int32_t AccessManager::UnInitDeviceManager()
{
    DHLOGI("start");
    DeviceManager *dm = GetDmLiteInstance();
    if (dm == nullptr || dm->vtable->UnInitDeviceManager == nullptr) {
        return ERR_DH_FWK_ACCESS_UNINIT_DM_FAILED;
    }
    DmString pkgName = DmStringCreate(DH_FWK_PKG_NAME);
    int32_t ret = dm->vtable->UnInitDeviceManager(&pkgName);
    DmStringDestroy(&pkgName);
    return ret;
}

int32_t AccessManager::RegisterDevStateCallback()
{
    DeviceManager *dm = GetDmLiteInstance();
    if (dm == nullptr || dm->vtable->RegisterDevStateCallback == nullptr) {
        return ERR_DH_FWK_ACCESS_REGISTER_DM_FAILED;
    }
    DmString pkgName = DmStringCreate(DH_FWK_PKG_NAME);
    DmString extra = DmStringCreateEmpty();
    int32_t ret = dm->vtable->RegisterDevStateCallback(&pkgName, &extra, &devStateCb_);
    DmStringDestroy(&pkgName);
    DmStringDestroy(&extra);
    return ret;
}

int32_t AccessManager::UnRegisterDevStateCallback()
{
    DeviceManager *dm = GetDmLiteInstance();
    if (dm == nullptr || dm->vtable->UnRegisterDevStateCallback == nullptr) {
        return ERR_DH_FWK_ACCESS_UNREGISTER_DM_FAILED;
    }
    DmString pkgName = DmStringCreate(DH_FWK_PKG_NAME);
    int32_t ret = dm->vtable->UnRegisterDevStateCallback(&pkgName);
    DmStringDestroy(&pkgName);
    return ret;
}

void AccessManager::OnRemoteDiedCb(void *ctx)
{
    if (ctx == nullptr) {
        return;
    }
    static_cast<AccessManager *>(ctx)->OnRemoteDied();
}

void AccessManager::OnDeviceOnlineCb(void *ctx, const DmDeviceInfo *deviceInfo)
{
    if (ctx == nullptr || deviceInfo == nullptr) {
        return;
    }
    static_cast<AccessManager *>(ctx)->OnDeviceOnline(*deviceInfo);
}

void AccessManager::OnDeviceOfflineCb(void *ctx, const DmDeviceInfo *deviceInfo)
{
    if (ctx == nullptr || deviceInfo == nullptr) {
        return;
    }
    static_cast<AccessManager *>(ctx)->OnDeviceOffline(*deviceInfo);
}

void AccessManager::OnDeviceReadyCb(void *ctx, const DmDeviceInfo *deviceInfo)
{
    if (ctx == nullptr || deviceInfo == nullptr) {
        return;
    }
    static_cast<AccessManager *>(ctx)->OnDeviceReady(*deviceInfo);
}

void AccessManager::OnDeviceChangedCb(void *ctx, const DmDeviceInfo *deviceInfo)
{
    if (ctx == nullptr || deviceInfo == nullptr) {
        return;
    }
    static_cast<AccessManager *>(ctx)->OnDeviceChanged(*deviceInfo);
}

void AccessManager::OnRemoteDied()
{
    for (int32_t tryCount = 0; tryCount < DH_RETRY_INIT_DM_COUNT; ++tryCount) {
        usleep(DH_RETRY_INIT_DM_INTERVAL_US);
        if (Init() == DH_FWK_SUCCESS) {
            DHLOGI("DeviceManager onDied, try to init success, tryCount = %{public}d", tryCount);
            return;
        }
        DHLOGW("DeviceManager onDied, try to init failed, tryCount = %{public}d", tryCount);
    }
    DHLOGE("DeviceManager onDied, try to init has reached the maximum, but still failed");
    return;
}

void AccessManager::OnDeviceOnline(const DmDeviceInfo &deviceInfo)
{
    DHLOGI("Dhfwk receive online device notify");
    std::lock_guard<std::mutex> lock(accessMutex_);
    auto deviceName = std::string(deviceInfo.deviceName, strnlen(deviceInfo.deviceName, DM_MAX_DEVICE_NAME_LEN));
    auto networkId = std::string(deviceInfo.networkId, strnlen(deviceInfo.networkId, DM_MAX_DEVICE_ID_LEN));
    if (!IsIdLengthValid(networkId)) {
        DHLOGE("Param networkId is invalid");
        return;
    }
    auto uuid = GetUUIDByDm(networkId);
    if (!IsIdLengthValid(uuid)) {
        DHLOGE("Param uuid is invalid");
        return;
    }
    auto udid = GetUDIDByDm(networkId);
    if (!IsIdLengthValid(udid)) {
        DHLOGE("Param udid is invalid");
        return;
    }
    int32_t osType = GetDeviceSystemType(ExtraDataToString(deviceInfo.extraData));
    DHLOGI("Online device deviceName: %{public}s, networkId: %{public}s, uuid: %{public}s, udid: %{public}s, "
        "deviceTypeId: %{public}d, osType: %{public}d", GetAnonyString(deviceName).c_str(),
        GetAnonyString(networkId).c_str(), GetAnonyString(uuid).c_str(), GetAnonyString(udid).c_str(),
        deviceInfo.deviceTypeId, osType);

    auto ret = DistributedHardwareManagerFactory::GetInstance().SendOnLineEvent(networkId, uuid, udid,
        deviceInfo.deviceTypeId, osType);
    DHLOGI("Online event result: %{public}d, networkId: %{public}s", ret, GetAnonyString(networkId).c_str());
}

void AccessManager::OnDeviceOffline(const DmDeviceInfo &deviceInfo)
{
    DHLOGI("Dhfwk receive offline device notify");
    std::lock_guard<std::mutex> lock(accessMutex_);
    auto deviceName = std::string(deviceInfo.deviceName, strnlen(deviceInfo.deviceName, DM_MAX_DEVICE_NAME_LEN));
    auto networkId = std::string(deviceInfo.networkId, strnlen(deviceInfo.networkId, DM_MAX_DEVICE_ID_LEN));
    if (!IsIdLengthValid(networkId)) {
        DHLOGE("Param networkId is invalid");
        return;
    }
    std::string uuid = DHContext::GetInstance().GetUUIDByNetworkId(networkId);
    if (!IsIdLengthValid(uuid)) {
        DHLOGE("Param uuid is invalid");
        return;
    }
    std::string udid = DHContext::GetInstance().GetUDIDByNetworkId(networkId);
    if (!IsIdLengthValid(udid)) {
        DHLOGE("Param udid is invalid");
        return;
    }
    DHLOGI("Offline device deviceName: %{public}s, networkId: %{public}s, uuid: %{public}s, udid: %{public}s, "
        "deviceTypeId: %{public}d", GetAnonyString(deviceName).c_str(), GetAnonyString(networkId).c_str(),
        GetAnonyString(uuid).c_str(), GetAnonyString(udid).c_str(), deviceInfo.deviceTypeId);

    auto ret = DistributedHardwareManagerFactory::GetInstance().SendOffLineEvent(networkId, uuid, udid,
        deviceInfo.deviceTypeId);
    DHLOGI("Offline event result: %{public}d, networkId: %{public}s", ret, GetAnonyString(networkId).c_str());
}

void AccessManager::OnDeviceReady(const DmDeviceInfo &deviceInfo)
{
    DHLOGI("Dhfwk receive device ready notify");
    std::lock_guard<std::mutex> lock(accessMutex_);
    auto deviceName = std::string(deviceInfo.deviceName, strnlen(deviceInfo.deviceName, DM_MAX_DEVICE_NAME_LEN));
    auto networkId = std::string(deviceInfo.networkId, strnlen(deviceInfo.networkId, DM_MAX_DEVICE_ID_LEN));
    if (!IsIdLengthValid(networkId)) {
        DHLOGE("Param networkId is invalid");
        return;
    }
    DHLOGI("Ready device deviceName: %{public}s, networkId: %{public}s", GetAnonyString(deviceName).c_str(),
        GetAnonyString(networkId).c_str());

    if (!DeviceParamMgr::GetInstance().GetDeviceSyncDataMode()) {
        DHLOGI("local device is not e2e device, no need sync data.");
        return;
    }
    DHLOGI("Current user is enterprise space, need active sync data.");

    int32_t osType = GetDeviceSystemType(ExtraDataToString(deviceInfo.extraData));
    if (osType != OLD_HO_DEVICE_TYPE && osType != NEW_HO_DEVICE_TYPE) {
        DHLOGI("remote is single frame device, need sync data.");
        DistributedHardwareManagerFactory::GetInstance().ActiveSyncDataByNetworkId(networkId);
        return;
    }
}

void AccessManager::OnDeviceChanged(const DmDeviceInfo &deviceInfo)
{
    (void)deviceInfo;
    return;
}

void AccessManager::CheckTrustedDeviceOnline()
{
    DeviceManager *dm = GetDmLiteInstance();
    if (dm == nullptr || dm->vtable->GetTrustedDeviceList == nullptr) {
        DHLOGE("GetTrustedDeviceList is unavailable on the DM lite SDK");
        return;
    }
    DmString pkgName = DmStringCreate(DH_FWK_PKG_NAME);
    DmString extra = DmStringCreateEmpty();
    DmVec_DmDeviceInfo dmList;
    (void)DmVec_DmDeviceInfo_Init(&dmList);
    int32_t ret = dm->vtable->GetTrustedDeviceList(&pkgName, &extra, &dmList);
    DmStringDestroy(&pkgName);
    DmStringDestroy(&extra);
    if (ret != DH_FWK_SUCCESS) {
        DHLOGE("GetTrustedDeviceList failed, ret = %{public}d", ret);
        DmVec_DmDeviceInfo_Destroy(&dmList);
        return;
    }
    int32_t count = DmVec_DmDeviceInfo_Size(&dmList);
    if (count <= 0 || count > MAX_ONLINE_DEVICE_SIZE) {
        DHLOGE("DeviceList size is invalid!");
        DmVec_DmDeviceInfo_Destroy(&dmList);
        return;
    }
    for (int32_t i = 0; i < count; i++) {
        const DmDeviceInfo *info = DmVec_DmDeviceInfo_At(&dmList, i);
        if (info == nullptr) {
            continue;
        }
        const auto networkId = std::string(info->networkId, strnlen(info->networkId, DM_MAX_DEVICE_ID_LEN));
        const auto uuid = GetUUIDByDm(networkId);
        const auto udid = GetUDIDByDm(networkId);
        int32_t osType = GetDeviceSystemType(ExtraDataToString(info->extraData));
        DHLOGI("Send trusted device online, networkId = %{public}s, uuid = %{public}s, udid = %{public}s, "
            "osType = %{public}d", GetAnonyString(networkId).c_str(), GetAnonyString(uuid).c_str(),
            GetAnonyString(udid).c_str(), osType);
        DistributedHardwareManagerFactory::GetInstance().SendOnLineEvent(networkId, uuid, udid,
            info->deviceTypeId, osType);
    }
    DmVec_DmDeviceInfo_Destroy(&dmList);
}

} // namespace DistributedHardware
} // namespace OHOS
