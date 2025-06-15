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

#include "daudio_hdf_operate.h"

#include <hdf_io_service_if.h>
#include <hdf_base.h>

#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"

#undef DH_LOG_TAG
#define DH_LOG_TAG "DaudioHdfOperate"

namespace OHOS {
namespace DistributedHardware {
IMPLEMENT_SINGLE_INSTANCE(DaudioHdfOperate);
int32_t DaudioHdfOperate::LoadDaudioHDFImpl()
{
    DHLOGI("Load daudio hdf impl begin!");
    std::unique_lock<std::mutex> loadRefLocker(hdfLoadRefMutex_);
    if (hdfLoadRef_ > 0) {
        hdfLoadRef_++;
        DHLOGI("The daudio hdf impl has been loaded, just inc ref!");
        return DH_FWK_SUCCESS;
    }
    int32_t ret = LoadDevice();
    if (ret != DH_FWK_SUCCESS) {
        DHLOGE("LoadDevice failed, ret: %{public}d.", ret);
        return ret;
    }
    ret = RegisterHdfListener();
    if (ret != DH_FWK_SUCCESS) {
        DHLOGE("RegisterHdfListener failed, ret: %{public}d.", ret);
        UnLoadDevice();
        return ret;
    }
    hdfLoadRef_++;
    DHLOGI("Load daudio hdf impl end!");
    return DH_FWK_SUCCESS;
}

int32_t DaudioHdfOperate::UnLoadDaudioHDFImpl()
{
    DHLOGI("UnLoad daudio hdf impl begin!");
    std::unique_lock<std::mutex> loadRefLocker(hdfLoadRefMutex_);
    if (hdfLoadRef_ == 0) {
        DHLOGI("The daudio hdf impl has been unloaded!");
        return DH_FWK_SUCCESS;
    }
    if (hdfLoadRef_ > 1) {
        hdfLoadRef_--;
        DHLOGI("The daudio hdf impl has been loaded, just dec ref!");
        return DH_FWK_SUCCESS;
    }
    int32_t ret = UnRegisterHdfListener();
    if (ret != DH_FWK_SUCCESS) {
        DHLOGE("UnRegisterHdfListener failed, ret: %{public}d.", ret);
    }
    ret = UnLoadDevice();
    if (ret != DH_FWK_SUCCESS) {
        DHLOGE("UnLoadDevice failed, ret: %{public}d.", ret);
    }
    hdfLoadRef_--;
    DHLOGI("UnLoad daudio hdf impl end!");
    return DH_FWK_SUCCESS;
}

void DaudioHdfOperate::ResetRefCount()
{
    DHLOGI("Reset reference count for daudio.");
    std::unique_lock<std::mutex> loadRefLocker(hdfLoadRefMutex_);
    hdfLoadRef_ = 0;
}

int32_t DaudioHdfOperate::WaitLoadService(const std::string& servName)
{
    std::unique_lock<std::mutex> lock(hdfOperateMutex_);
    if (servName == AUDIO_SERVICE_NAME) {
        DHLOGD("WaitLoadService start service %s, status %hu", servName.c_str(), this->audioServStatus_.load());
        hdfOperateCon_.wait_for(lock, std::chrono::milliseconds(AUDIO_WAIT_TIME), [this] {
            return (this->audioServStatus_.load() == OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_START);
        });

        if (this->audioServStatus_.load() != OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_START) {
            DHLOGE("Wait load service %{public}s failed, status %{public}hu", servName.c_str(),
                this->audioServStatus_.load());
            return ERR_DH_FWK_LOAD_HDF_TIMEOUT;
        }
    }

    if (servName == AUDIOEXT_SERVICE_NAME) {
        DHLOGD("WaitLoadService start service %s, status %hu", servName.c_str(), this->audioextServStatus_.load());
        hdfOperateCon_.wait_for(lock, std::chrono::milliseconds(AUDIO_WAIT_TIME), [this] {
            return (this->audioextServStatus_.load() == OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_START);
        });

        if (this->audioextServStatus_.load() != OHOS::HDI::ServiceManager::V1_0::SERVIE_STATUS_START) {
            DHLOGE("Wait load service %{public}s failed, status %{public}hu", servName.c_str(),
                this->audioextServStatus_.load());
            return ERR_DH_FWK_LOAD_HDF_TIMEOUT;
        }
    }
    return DH_FWK_SUCCESS;
}

OHOS::sptr<IServStatListener> DaudioHdfOperate::MakeServStatListener()
{
    return OHOS::sptr<IServStatListener>(
        new DAudioHdfServStatListener(DAudioHdfServStatListener::StatusCallback([&](const ServiceStatus& status) {
            DHLOGI("Load audio service status callback, serviceName: %{public}s, status: %{public}d",
                status.serviceName.c_str(), status.status);
            std::unique_lock<std::mutex> lock(hdfOperateMutex_);
            if (status.serviceName == AUDIO_SERVICE_NAME) {
                audioServStatus_.store(status.status);
                hdfOperateCon_.notify_one();
            } else if (status.serviceName == AUDIOEXT_SERVICE_NAME) {
                audioextServStatus_.store(status.status);
                hdfOperateCon_.notify_one();
            }
        }))
    );
}

int32_t DaudioHdfOperate::LoadDevice()
{
    DHLOGI("LoadDevice for daudio begin!");
    servMgr_ = IServiceManager::Get();
    devmgr_ = IDeviceManager::Get();
    if (servMgr_ == nullptr || devmgr_ == nullptr) {
        DHLOGE("get hdi service manager or device manager failed!");
        return ERR_DH_FWK_POINTER_IS_NULL;
    }
    OHOS::sptr<IServStatListener> listener = MakeServStatListener();
    if (servMgr_->RegisterServiceStatusListener(listener, DEVICE_CLASS_AUDIO) != HDF_SUCCESS) {
        DHLOGE("Failed to register the service status listener.");
        return ERR_DH_FWK_REGISTER_HDF_LISTENER_FAIL;
    }
    int32_t ret = devmgr_->LoadDevice(AUDIO_SERVICE_NAME);
    if (ret != HDF_SUCCESS && ret != HDF_ERR_DEVICE_BUSY) {
        DHLOGE("Load audio service failed!");
        servMgr_->UnregisterServiceStatusListener(listener);
        return ERR_DH_FWK_LOAD_HDF_FAIL;
    }
    if (WaitLoadService(AUDIO_SERVICE_NAME) != DH_FWK_SUCCESS) {
        DHLOGE("Wait load audio service failed!");
        servMgr_->UnregisterServiceStatusListener(listener);
        return ERR_DH_FWK_LOAD_HDF_TIMEOUT;
    }
    ret = devmgr_->LoadDevice(AUDIOEXT_SERVICE_NAME);
    if (ret != HDF_SUCCESS && ret != HDF_ERR_DEVICE_BUSY) {
        DHLOGE("Load audio provider service failed!");
        devmgr_->UnloadDevice(AUDIO_SERVICE_NAME);
        servMgr_->UnregisterServiceStatusListener(listener);
        return ERR_DH_FWK_LOAD_HDF_FAIL;
    }
    if (WaitLoadService(AUDIOEXT_SERVICE_NAME) != DH_FWK_SUCCESS) {
        DHLOGE("Wait load audio provider service failed!");
        devmgr_->UnloadDevice(AUDIO_SERVICE_NAME);
        servMgr_->UnregisterServiceStatusListener(listener);
        return ERR_DH_FWK_LOAD_HDF_TIMEOUT;
    }
    if (servMgr_->UnregisterServiceStatusListener(listener) != HDF_SUCCESS) {
        DHLOGE("Failed to unregister the service status listener.");
    }
    DHLOGI("LoadDevice for daudio end!");
    return DH_FWK_SUCCESS;
}

int32_t DaudioHdfOperate::UnLoadDevice()
{
    DHLOGI("UnLoadDevice for daudio begin!");
    if (devmgr_ == nullptr) {
        DHLOGE("hdi device manager is nullptr!");
        return ERR_DH_FWK_POINTER_IS_NULL;
    }
    int32_t ret = devmgr_->UnloadDevice(AUDIO_SERVICE_NAME);
    if (ret != HDF_SUCCESS) {
        DHLOGE("Unload audio service failed, ret: %{public}d", ret);
    }
    ret = devmgr_->UnloadDevice(AUDIOEXT_SERVICE_NAME);
    if (ret != HDF_SUCCESS) {
        DHLOGE("Unload device failed, ret: %{public}d", ret);
    }
    audioServStatus_.store(AUDIO_INVALID_VALUE);
    audioextServStatus_.store(AUDIO_INVALID_VALUE);
    DHLOGI("UnLoadDevice for daudio end!");
    return DH_FWK_SUCCESS;
}

int32_t DaudioHdfOperate::RegisterHdfListener()
{
    DHLOGI("RegisterHdfListener for daudio begin!");
    audioSrvHdf_ = IDAudioManager::Get(AUDIOEXT_SERVICE_NAME.c_str(), false);
    if (audioSrvHdf_ == nullptr) {
        DHLOGE("Get hdi daudio manager failed.");
        return ERR_DH_FWK_POINTER_IS_NULL;
    }
    if (fwkDAudioHdfCallback_ == nullptr) {
        fwkDAudioHdfCallback_ = new FwkDAudioHdfCallback();
        if (fwkDAudioHdfCallback_ == nullptr) {
            DHLOGE("Create FwkDAudioHdfCallback failed.");
            return ERR_DH_FWK_POINTER_IS_NULL;
        }
    }
    int32_t ret = audioSrvHdf_->RegisterAudioHdfListener("DHFWK", fwkDAudioHdfCallback_);
    if (ret != DH_FWK_SUCCESS) {
        DHLOGE("Call hdf proxy RegisterAudioHdfListener failed, ret: %{public}d.", ret);
        return ret;
    }
    DHLOGI("RegisterHdfListener for daudio end!");
    return DH_FWK_SUCCESS;
}

int32_t DaudioHdfOperate::UnRegisterHdfListener()
{
    DHLOGI("UnRegisterHdfListener for daudio begin!");
    if (audioSrvHdf_ == nullptr) {
        DHLOGE("hdi daudio manager is nullptr!");
        return ERR_DH_FWK_POINTER_IS_NULL;
    }
    int32_t ret = audioSrvHdf_->UnRegisterAudioHdfListener("DHFWK");
    if (ret != DH_FWK_SUCCESS) {
        DHLOGE("Call hdf proxy UnRegisterAudioHdfListener failed, ret: %{public}d.", ret);
        return ret;
    }
    DHLOGI("UnRegisterHdfListener for daudio end!");
    return DH_FWK_SUCCESS;
}

void DAudioHdfServStatListener::OnReceive(const ServiceStatus& status)
{
    DHLOGI("Service status on receive.");
    if (status.serviceName == AUDIO_SERVICE_NAME || status.serviceName == AUDIOEXT_SERVICE_NAME) {
        callback_(status);
    }
}

int32_t FwkDAudioHdfCallback::NotifyEvent(int32_t devId, const DAudioEvent& event)
{
    (void)devId;
    (void)event;
    return DH_FWK_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS