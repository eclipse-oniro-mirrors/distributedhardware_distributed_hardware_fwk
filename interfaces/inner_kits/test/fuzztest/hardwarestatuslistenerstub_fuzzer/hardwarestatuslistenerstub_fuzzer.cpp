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

#include "hardwarestatuslistenerstub_fuzzer.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <thread>
#include <unistd.h>

#include "constants.h"
#include "dhardware_descriptor.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"
#include "hardware_status_listener_stub.h"
#include "publisher_listener_stub.h"

namespace OHOS {
namespace DistributedHardware {
void HDSinkStatusOnRemoteRequestFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint32_t))) {
        return;
    }
    MessageParcel parcel;
    parcel.WriteInterfaceToken(FuzzHDSinkStatusListenerStub().GetDescriptor());
    uint32_t dhType = *(reinterpret_cast<const uint32_t*>(data));
    parcel.WriteUint32(dhType);
    std::string id(reinterpret_cast<const char*>(data + 4), size - 4);
    parcel.WriteString(id);
    MessageParcel reply;
    MessageOption option;

    uint32_t code = 0;
    if (size >= sizeof(uint32_t)) {
        code = *(reinterpret_cast<const uint32_t*>(data));
    }

    FuzzHDSinkStatusListenerStub stub;

    stub.OnRemoteRequest(code, parcel, reply, option);

}
void HDSourceStatusOnRemoteRequestFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint32_t))) {
        return;
    }

    MessageParcel parcel;
    parcel.WriteInterfaceToken(FuzzHDSinkStatusListenerStub().GetDescriptor());
    uint32_t dhType = *(reinterpret_cast<const uint32_t*>(data));
    parcel.WriteUint32(dhType);
    std::string id(reinterpret_cast<const char*>(data + 4), size - 4);
    parcel.WriteString(id);
    MessageParcel reply;
    MessageOption option;

    uint32_t code = 0;
    if (size >= sizeof(uint32_t)) {
        code = *(reinterpret_cast<const uint32_t*>(data));
    }
    FuzzHDSourceStatusListenerStub stub;

    stub.OnRemoteRequest(code, parcel, reply, option);
}
} // namespace DistributedHardware
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::HDSinkStatusOnRemoteRequestFuzzTest(data, size);
    OHOS::DistributedHardware::HDSourceStatusOnRemoteRequestFuzzTest(data, size);
    return 0;
}