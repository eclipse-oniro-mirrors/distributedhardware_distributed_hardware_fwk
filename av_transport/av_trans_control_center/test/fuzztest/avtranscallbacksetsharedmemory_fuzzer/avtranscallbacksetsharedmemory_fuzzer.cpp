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

#include "avtranscallbacksetsharedmemory_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>
#include "av_trans_control_center_callback.h"
#include "av_sync_utils.h"

namespace OHOS {
namespace DistributedHardware {
void AVTransCallbackSetSharedMemoryFuzzTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t fd = fdp.ConsumeIntegral<int32_t>();
    int32_t len = fdp.ConsumeIntegral<int32_t>();
    std::string name(reinterpret_cast<const char*>(data), size);
    AVTransSharedMemory memory = AVTransSharedMemory{ fd, len, name };
    sptr<AVTransControlCenterCallback> controlCenterCallback(new (std::nothrow) AVTransControlCenterCallback());
    if (controlCenterCallback == nullptr) {
        return;
    }
    controlCenterCallback->SetSharedMemory(memory);
}
} // namespace DistributedHardware
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::AVTransCallbackSetSharedMemoryFuzzTest(data, size);
    return 0;
}