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

#include "accesslistenerproxy_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>

#include "device_type.h"
#include "distributed_hardware_errno.h"
#include "iaccess_listener.h"

namespace OHOS {
namespace DistributedHardware {
void OnRequestHardwareAccessFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint32_t) + sizeof(uint16_t) + 1)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string requestId = fdp.ConsumeRandomLengthString();
    AuthDeviceInfo info;
    info.networkId = fdp.ConsumeRandomLengthString();
    info.deviceName = fdp.ConsumeRandomLengthString();
    info.deviceType = fdp.ConsumeIntegral<uint16_t>();
    uint32_t dhTypeRaw = fdp.ConsumeIntegral<uint32_t>();
    DHType dhType = static_cast<DHType>(dhTypeRaw);
    std::string pkgName = fdp.ConsumeRandomLengthString();

    sptr<IRemoteObject> remote(new (std::nothrow) FuzzAccessListenerStub());
    if (remote == nullptr) {
        return;
    }
    AccessListenerProxy proxy(remote);
    proxy.OnRequestHardwareAccess(requestId, info, dhType, pkgName);
}
} // namespace DistributedHardware
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::OnRequestHardwareAccessFuzzTest(data, size);
    return 0;
}
