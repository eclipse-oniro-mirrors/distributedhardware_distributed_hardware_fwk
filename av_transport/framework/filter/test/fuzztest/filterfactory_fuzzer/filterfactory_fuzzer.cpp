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

#include <string>
#include "filter_factory.h"
#include "filterfactory_fuzzer.h"

namespace OHOS {
namespace DistributedHardware {
namespace Pipeline {
void FilterFactoryFuzzerTest(const uint8_t *data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    std::string filterName(reinterpret_cast<const char*>(data), size - 1);
    FilterType type = static_cast<FilterType>(data[size - 1]);
    auto filter = FilterFactory::Instance().CreateFilterPriv(filterName, type);
}
} // namespace Pipeline
} // namespace DistributedHardware
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::Pipeline::FilterFactoryFuzzerTest(data, size);
    return 0;
}