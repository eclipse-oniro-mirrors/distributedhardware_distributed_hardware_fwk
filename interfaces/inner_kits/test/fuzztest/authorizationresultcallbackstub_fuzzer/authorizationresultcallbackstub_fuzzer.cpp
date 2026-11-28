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

#include "authorizationresultcallbackstub_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>

#include "authorization_result_callback_stub.h"
#include "iauthorization_result_callback.h"
#include "distributed_hardware_errno.h"

namespace OHOS {
namespace DistributedHardware {
void OnRemoteRequestFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint32_t) + 1)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    uint32_t code = fdp.ConsumeIntegral<uint32_t>();
    MessageParcel parcel;
    parcel.WriteInterfaceToken(FuzzAuthorizationResultCallbackStub().GetDescriptor());
    std::string networkId = fdp.ConsumeRandomLengthString();
    parcel.WriteString(networkId);
    std::string requestId = fdp.ConsumeRandomLengthString();
    parcel.WriteString(requestId);
    MessageParcel reply;
    MessageOption option;

    FuzzAuthorizationResultCallbackStub stub;
    stub.OnRemoteRequest(code, parcel, reply, option);
}
} // namespace DistributedHardware
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::OnRemoteRequestFuzzTest(data, size);
    return 0;
}
