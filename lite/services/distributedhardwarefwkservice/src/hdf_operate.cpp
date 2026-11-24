/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "hdf_operate.h"

#include <dlfcn.h>

#include "component_loader.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"
#include "task_board.h"
#include "task_executor.h"
#include "task_factory.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "HdfOperator"

namespace OHOS {
namespace DistributedHardware {
int32_t HdfOperator::UnLoadDistributedHDF()
{
    DHLOGI("UnLoad hdf impl begin, dhType = %{public}#X!", dhType_);
    std::unique_lock<std::mutex> loadRefLocker(hdfLoadRefMutex_);
    if (hdfLoadRef_ <= 0) {
        DHLOGI("The hdf impl has been unloaded, dhType = %{public}#X!", dhType_);
        return DH_FWK_SUCCESS;
    }
    if (hdfLoadRef_ > 1) {
        hdfLoadRef_--;
        DHLOGI("The hdf impl has been loaded, just dec ref, dhType = %{public}#X!", dhType_);
        return DH_FWK_SUCCESS;
    }
    auto ret = sourcePtr_->UnLoadDistributedHDF();
    if (ret != DH_FWK_SUCCESS) {
        DHLOGE("Source handler unload hdf failed, dhType = %{public}#X, ret = %{public}d.", dhType_, ret);
        return ret;
    }
    hdfLoadRef_--;
    DHLOGI("UnLoad hdf impl end, dhType = %{public}#X!", dhType_);
    return DH_FWK_SUCCESS;
}

void HdfOperator::ResetRefCount()
{
    DHLOGI("Reset reference count, dhType = %{public}#X!", dhType_);
    std::unique_lock<std::mutex> loadRefLocker(hdfLoadRefMutex_);
    hdfLoadRef_ = 0;
}

bool HdfOperator::IsNeedErase()
{
    std::unique_lock<std::mutex> loadRefLocker(hdfLoadRefMutex_);
    return hdfLoadRef_ <= 0;
}

FWK_IMPLEMENT_SINGLE_INSTANCE(HdfOperateManager);


void HdfOperateManager::ResetRefCount(DHType dhType)
{
    DHLOGI("Reset ref count begin, dhType = %{public}#X!", dhType);
    std::unique_lock<std::mutex> hdfOperateMapLocker(hdfOperateMapMutex_);
    auto itHdfOperate = hdfOperateMap_.find(dhType);
    if (itHdfOperate == hdfOperateMap_.end()) {
        DHLOGI("The hdf operate has not been created yet, dhType = %{public}#X!", dhType);
        return;
    }
    auto hdfOperate = itHdfOperate->second;
    hdfOperate->ResetRefCount();
    DHLOGI("reset ref count end, dhType = %{public}#X!", dhType);
}

int32_t HdfOperateManager::RigidGetSourcePtr(DHType dhType, IDistributedHardwareSource *&sourcePtr)
{
    DHLOGI("Rigid get source ptr begin, dhType = %{public}#X!", dhType);
    std::lock_guard<std::mutex> locker(sourceHandlerDataMapMutex_);
    auto itSourceHandlerData = sourceHandlerDataMap_.find(dhType);
    if (itSourceHandlerData != sourceHandlerDataMap_.end()) {
        auto &sourceHandlerData = itSourceHandlerData->second;
        sourcePtr = sourceHandlerData.sourcePtr;
        sourceHandlerData.refCount++;
        DHLOGI("Source ptr already exists, only increase reference count, dhType = %{public}#X!", dhType);
        return DH_FWK_SUCCESS;
    }
    // D2/DD-4 (TASK-3 merged): the hardcoded compSourceLoc dlopen fallback is
    // removed on lite — L1 never enables the distributed source path (the
    // EnableSource task branch is explicitly skipped with the frozen anchor in
    // enable_task.cpp, and the camera source entry is stripped from
    // distributed_hardware_components_cfg.json). Only previously registered
    // entries (map hit above) can return a source pointer.
    (void)sourcePtr;
    DHLOGE("No source ptr registered and the dlopen fallback is removed on lite (D2), dhType = %{public}#X.",
        dhType);
    return ERR_DH_FWK_NO_HDF_SUPPORT;
}

int32_t HdfOperateManager::RigidReleaseSourcePtr(DHType dhType)
{
    DHLOGI("Rigid release source ptr begin, dhType = %{public}#X!", dhType);
    std::lock_guard<std::mutex> locker(sourceHandlerDataMapMutex_);
    auto itSourceHandlerData = sourceHandlerDataMap_.find(dhType);
    if (itSourceHandlerData == sourceHandlerDataMap_.end()) {
        DHLOGI("The source ptr has not been obtained yet, dhType = %{public}#X!", dhType);
        return DH_FWK_SUCCESS;
    }
    auto &sourceHandlerData = itSourceHandlerData->second;
    if (sourceHandlerData.refCount > 1) {
        sourceHandlerData.refCount--;
        DHLOGI("Source ptr is still in use, only reducing reference count, dhType = %{public}#X!", dhType);
        return DH_FWK_SUCCESS;
    }
    if (dlclose(sourceHandlerData.sourceHandler) != 0) {
        DHLOGE("dlclose failed, failed reason: %{public}s, dhType: %{public}" PRIu32, dlerror(), (uint32_t)dhType);
        return ERR_DH_FWK_LOADER_DLCLOSE_FAIL;
    }
    sourceHandlerDataMap_.erase(itSourceHandlerData);
    DHLOGI("Rigid release source ptr end, dhType = %{public}#X!", dhType);
    return DH_FWK_SUCCESS;
}

bool HdfOperateManager::IsAnyHdfInuse()
{
    return hdfInuseRefCount_.load(std::memory_order_acquire) > 0;
}


void HdfDeathCallbackImpl::OnHdfHostDied()
{
    DHLOGI("On hdf died, dhType = %{public}#X!", dhType_);
    HdfOperateManager::GetInstance().ResetRefCount(dhType_);
}
} // namespace DistributedHardware
} // namespace OHOS
