/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_HARDWARE_MOCK_DISABLE_TASK_H
#define OHOS_DISTRIBUTED_HARDWARE_MOCK_DISABLE_TASK_H

#include "disable_task.h"

namespace OHOS {
namespace DistributedHardware {
class MockDisableTask : public DisableTask {
public:
    MockDisableTask() = delete;
    MockDisableTask(const std::string &networkId, const std::string &uuid, const std::string &udid,
        const std::string &dhId, const DHType dhType);

private:
    /* synchronous function for unregister distributed hardware, return on asynchronous unregister finish */
    int32_t UnRegisterHardware();
};
} // namespace DistributedHardware
} // namespace OHOS
#endif
