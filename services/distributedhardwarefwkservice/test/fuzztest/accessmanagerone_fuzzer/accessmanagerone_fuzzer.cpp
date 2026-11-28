/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "accessmanagerone_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <vector>

#include "access_manager.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_manager_factory.h"

namespace OHOS {
namespace DistributedHardware {
void UnInitFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    AccessManager::GetInstance()->Init();
    AccessManager::GetInstance()->UnInit();
}

void CheckTrustedDeviceOnlineFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    AccessManager::GetInstance()->Init();
    AccessManager::GetInstance()->CheckTrustedDeviceOnline();
}

void DumpFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::vector<std::string> argsStr;
    const uint32_t maxArgCount = 8;
    uint32_t argCount = fdp.ConsumeIntegralInRange<uint32_t>(0, maxArgCount);
    for (uint32_t i = 0; i < argCount; ++i) {
        argsStr.push_back(fdp.ConsumeRandomLengthString());
    }
    std::string result;
    AccessManager::GetInstance()->Init();
    AccessManager::GetInstance()->Dump(argsStr, result);
}

void DeviceManagerPrivateFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    AccessManager::GetInstance()->Init();
    AccessManager::GetInstance()->RegisterDevStateCallback();
    AccessManager::GetInstance()->UnRegisterDevStateCallback();
    AccessManager::GetInstance()->InitDeviceManager();
    AccessManager::GetInstance()->UnInitDeviceManager();
}
} // namespace DistributedHardware
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::UnInitFuzzTest(data, size);
    OHOS::DistributedHardware::CheckTrustedDeviceOnlineFuzzTest(data, size);
    OHOS::DistributedHardware::DumpFuzzTest(data, size);
    OHOS::DistributedHardware::DeviceManagerPrivateFuzzTest(data, size);
    return 0;
}
