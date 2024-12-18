/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "onsoftbustimesyncresult_fuzzer.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <thread>
#include <unistd.h>

#include "softbus_channel_adapter.h"

namespace OHOS {
namespace DistributedHardware {

void OnSoftbusTimeSyncResultFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    int32_t result = *(reinterpret_cast<const int32_t*>(data));
    TimeSyncResultInfo info = {};
    FuzzedDataProvider fdp(data, size);
    info.result.millisecond = fdp.ConsumeIntegral<int32_t>();
    info.result.microsecond = fdp.ConsumeIntegral<int32_t>();

    SoftbusChannelAdapter::GetInstance().OnSoftbusTimeSyncResult(&info, result);
}
} // namespace DistributedHardware
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::OnSoftbusTimeSyncResultFuzzTest(data, size);
    return 0;
}