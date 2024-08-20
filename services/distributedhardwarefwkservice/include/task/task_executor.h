/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_HARDWARE_TASK_EXECUTOR_H
#define OHOS_DISTRIBUTED_HARDWARE_TASK_EXECUTOR_H

#include <condition_variable>
#include <mutex>
#include <queue>

#include "task.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedHardware {
class TaskExecutor {
DECLARE_SINGLE_INSTANCE_BASE(TaskExecutor);
public:
    explicit TaskExecutor();
    ~TaskExecutor();
    void PushTask(const std::shared_ptr<Task> task);

private:
    std::shared_ptr<Task> PopTask();
    void TriggerTask();

private:
    std::queue<std::shared_ptr<Task>> taskQueue_;
    std::mutex taskQueueMtx_;
    std::condition_variable condVar_;
    bool taskThreadFlag_;
};
} // namespace DistributedHardware
} // namespace OHOS
#endif
