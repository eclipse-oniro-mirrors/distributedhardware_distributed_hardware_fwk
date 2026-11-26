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

#include "dhfwksamanager_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>

#include "dhfwk_sa_manager.h"
#include "ipublisher_listener.h"
#include "distributed_hardware_errno.h"

namespace OHOS {
namespace DistributedHardware {
void AddPublisherListenerToCacheFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    uint32_t topicRaw = fdp.ConsumeIntegral<uint32_t>();
    DHTopic topic = static_cast<DHTopic>(topicRaw);
    sptr<IPublisherListener> listener(new (std::nothrow) FuzzPublisherListenerStub());
    if (listener == nullptr) {
        return;
    }
    DHFWKSAManager::GetInstance().AddPublisherListenerToCache(topic, listener);
    DHFWKSAManager::GetInstance().RemovePublisherListenerFromCache(topic, listener);
}

void AddAVTransControlCenterCbToCacheFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t engineId = fdp.ConsumeIntegral<int32_t>();
    sptr<IAvTransControlCenterCallback> callback(new (std::nothrow) FuzzAVTransControlCenterCallback());
    if (callback == nullptr) {
        return;
    }
    DHFWKSAManager::GetInstance().AddAVTransControlCenterCbToCache(engineId, callback);
    DHFWKSAManager::GetInstance().RemoveAVTransControlCenterCbFromCache(engineId);
}

void RestoreListenerFuzzTest(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
    DHFWKSAManager::GetInstance().RestoreListener();
}

void RegisterAbilityListenerFuzzTest(const uint8_t *data, size_t size)
{
    (void)data;
    (void)size;
    DHFWKSAManager::GetInstance().RegisterAbilityListener();
    DHFWKSAManager::GetInstance().GetDHFWKProxy();
}
} // namespace DistributedHardware
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::AddPublisherListenerToCacheFuzzTest(data, size);
    OHOS::DistributedHardware::AddAVTransControlCenterCbToCacheFuzzTest(data, size);
    OHOS::DistributedHardware::RestoreListenerFuzzTest(data, size);
    OHOS::DistributedHardware::RegisterAbilityListenerFuzzTest(data, size);
    return 0;
}
