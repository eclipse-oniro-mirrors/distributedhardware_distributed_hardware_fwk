/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "task_board.h"

#include "anonymous_string.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"

namespace OHOS {
namespace DistributedHardware {
#undef DH_LOG_TAG
#define DH_LOG_TAG "TaskBoard"

constexpr int32_t TASK_TIMEOUT_MS = 5000;

IMPLEMENT_SINGLE_INSTANCE(TaskBoard);

int32_t TaskBoard::WaitForALLTaskFinish()
{
    // wait for all task finish until timeout
    std::unique_lock<std::mutex> lock(tasksMtx_);
    auto status = conVar_.wait_for(lock, std::chrono::milliseconds(TASK_TIMEOUT_MS),
        [this]() { return tasks_.empty(); });
    if (!status) {
        DHLOGE("wait for all task finish timeout");
        return ERR_DH_FWK_TASK_TIMEOUT;
    }
    DHLOGI("all task finished");

    return DH_FWK_SUCCESS;
}

bool TaskBoard::IsAllTaskFinish()
{
    std::lock_guard<std::mutex> lock(tasksMtx_);
    return this->tasks_.empty();
}

void TaskBoard::AddTask(std::shared_ptr<Task> task)
{
    if (task == nullptr) {
        DHLOGE("task is null, error");
        return;
    }

    std::lock_guard<std::mutex> lock(tasksMtx_);
    DHLOGI("Add task, id: %{public}s", task->GetId().c_str());
    if (this->tasks_.find(task->GetId()) != this->tasks_.end()) {
        DHLOGE("Task id duplicate, id: %{public}s", task->GetId().c_str());
        return;
    }
    this->tasks_.emplace(task->GetId(), task);
}

bool TaskBoard::IsAllDisableTaskFinish()
{
    std::lock_guard<std::mutex> lock(tasksMtx_);
    int32_t disableCount = 0;
    for (auto iter = tasks_.begin(); iter != tasks_.end(); iter++) {
        if (iter->second->GetTaskType() == TaskType::DISABLE || iter->second->GetTaskType() == TaskType::META_DISABLE) {
            disableCount++;
        }
    }
    DHLOGI("DisableTask count: %{public}d", disableCount);
    if (disableCount == 0) {
        return true;
    }
    return false;
}

void TaskBoard::RemoveTask(std::string taskId)
{
    std::lock_guard<std::mutex> lock(tasksMtx_);
    DHLOGI("Remove task, id: %{public}s", taskId.c_str());
    RemoveTaskInner(taskId);
    if (tasks_.empty()) {
        conVar_.notify_one();
    }
}

void TaskBoard::RemoveTaskInner(std::string taskId)
{
    if (tasks_.find(taskId) == tasks_.end()) {
        DHLOGE("Can not find removed task");
        return;
    }

    tasks_.erase(taskId);
}

void TaskBoard::DumpAllTasks(std::vector<TaskDump> &taskInfos)
{
    std::lock_guard<std::mutex> lock(tasksMtx_);
    for (auto t : tasks_) {
        TaskDump taskInfo = {
            .id = t.second->GetId(),
            .taskType = t.second->GetTaskType(),
            .taskParm = {
                .networkId = t.second->GetNetworkId(),
                .uuid = t.second->GetUUID(),
                .dhId = t.second->GetDhId(),
                .dhType = t.second->GetDhType(),
            },
            .taskSteps = t.second->GetTaskSteps()
        };
        taskInfos.emplace_back(taskInfo);
    }
}

void TaskBoard::SaveEnabledDevice(const std::string &enabledDeviceKey, const TaskParam &taskParam)
{
    std::lock_guard<std::mutex> lock(enabledDevicesMutex_);
    DHLOGI("SaveEnabledDevice key is %{public}s", GetAnonyString(enabledDeviceKey).c_str());
    enabledDevices_[enabledDeviceKey] = taskParam;
}

void TaskBoard::RemoveEnabledDevice(const std::string &enabledDeviceKey)
{
    std::lock_guard<std::mutex> lock(enabledDevicesMutex_);
    DHLOGI("RemoveEnabledDevice key is %{public}s", GetAnonyString(enabledDeviceKey).c_str());
    enabledDevices_.erase(enabledDeviceKey);
}

const std::unordered_map<std::string, TaskParam> TaskBoard::GetEnabledDevice()
{
    std::lock_guard<std::mutex> lock(enabledDevicesMutex_);
    if (enabledDevices_.empty()) {
        DHLOGI("enabledDevices is empty!");
    }
    return enabledDevices_;
}

bool TaskBoard::IsEnabledDevice(const std::string &enabledDeviceKey)
{
    std::lock_guard<std::mutex> lock(enabledDevicesMutex_);
    bool flag = false;
    for (auto iter = enabledDevices_.begin(); iter != enabledDevices_.end(); iter++) {
        if (iter->first == enabledDeviceKey) {
            flag = true;
            break;
        }
    }
    return flag;
}
} // namespace DistributedHardware
} // namespace OHOS
