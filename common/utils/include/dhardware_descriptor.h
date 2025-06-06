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

#ifndef OHOS_DISTRIBUTED_HARDWARE_DESCRIPTOR_H
#define OHOS_DISTRIBUTED_HARDWARE_DESCRIPTOR_H

#include <string>
#include <unordered_map>

#include "device_type.h"

namespace OHOS {
namespace DistributedHardware {

struct DHDescriptor {
    std::string id;
    DHType dhType;
};

enum class EnableStep : uint32_t {
    ENABLE_SOURCE = 1,
    DISABLE_SOURCE = 2,
    ENABLE_SINK = 3,
    DISABLE_SINK = 4
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_HARDWARE_DESCRIPTOR_H
