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

#include "mock_meta_enable_task.h"

#include <chrono>
#include <thread>

#include "distributed_hardware_errno.h"

namespace OHOS {
namespace DistributedHardware {
MockMetaEnableTask::MockMetaEnableTask(const std::string &networkId, const std::string &uuid, const std::string &udid,
    const std::string &dhId, const DHType dhType) : MetaEnableTask(networkId, uuid, udid, dhId, dhType)
{}

int32_t MockMetaEnableTask::Enable()
{
    using namespace std::chrono_literals;
    std::this_thread::sleep_for(100ms);
    return DH_FWK_SUCCESS;
}
} // namespace DistributedHardware
} // namespace OHOS
