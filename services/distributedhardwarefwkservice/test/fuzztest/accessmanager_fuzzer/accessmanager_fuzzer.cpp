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

#include "accessmanager_fuzzer.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>
#include <string>
#include <unistd.h>

#include "access_manager.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_manager_factory.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
    constexpr uint32_t SLEEP_TIME_US = 10 * 1000;
}

void OnDeviceOnlineFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0 || size >= DM_MAX_DEVICE_ID_LEN)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string networkId = fdp.ConsumeRandomLengthString();
    DmDeviceInfo deviceInfo;
    int32_t ret = memcpy_s(deviceInfo.networkId, DM_MAX_DEVICE_ID_LEN, networkId.c_str(), size);
    if (ret != EOK) {
        return;
    }
    AccessManager::GetInstance()->OnDeviceOnline(deviceInfo);
    usleep(SLEEP_TIME_US);
}

void OnDeviceOfflineFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0 || size >= DM_MAX_DEVICE_ID_LEN)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string networkId = fdp.ConsumeRandomLengthString();
    DmDeviceInfo deviceInfo;
    int32_t ret = memcpy_s(deviceInfo.networkId, DM_MAX_DEVICE_ID_LEN, networkId.c_str(), size);
    if (ret != EOK) {
        return;
    }
    AccessManager::GetInstance()->OnDeviceOffline(deviceInfo);
    usleep(SLEEP_TIME_US);
}

void OnDeviceReadyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0 || size >= DM_MAX_DEVICE_ID_LEN)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string networkId = fdp.ConsumeRandomLengthString();
    DmDeviceInfo deviceInfo;
    int32_t ret = memcpy_s(deviceInfo.networkId, DM_MAX_DEVICE_ID_LEN, networkId.c_str(), size);
    if (ret != EOK) {
        return;
    }
    AccessManager::GetInstance()->OnDeviceReady(deviceInfo);

    usleep(SLEEP_TIME_US);
}

void OnDeviceChangedFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0 || size >= DM_MAX_DEVICE_ID_LEN)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string networkId = fdp.ConsumeRandomLengthString();
    DmDeviceInfo deviceInfo;
    int32_t ret = memcpy_s(deviceInfo.networkId, DM_MAX_DEVICE_ID_LEN, networkId.c_str(), size);
    if (ret != EOK) {
        return;
    }
    AccessManager::GetInstance()->OnDeviceChanged(deviceInfo);
    usleep(SLEEP_TIME_US);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::OnDeviceOnlineFuzzTest(data, size);
    OHOS::DistributedHardware::OnDeviceOfflineFuzzTest(data, size);
    OHOS::DistributedHardware::OnDeviceReadyFuzzTest(data, size);
    OHOS::DistributedHardware::OnDeviceChangedFuzzTest(data, size);
    return 0;
}

