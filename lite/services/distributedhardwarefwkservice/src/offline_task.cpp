/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "offline_task.h"

#include <pthread.h>
#include <thread>


#include "anonymous_string.h"
#include "dh_utils_tool.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"
#include "distributed_hardware_manager_factory.h"
#include "task_board.h"
#include "task_executor.h"
#include "task_factory.h"
#include "component_loader.h"
#include "dh_context.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
    constexpr uint16_t PHONE_TYPE = 14;
    constexpr const char *OFFLINE_TASK_INNER = "OffLineTask";
    constexpr int32_t USLEEP_TIME = 1000 * 100;
    constexpr int32_t RETRY_MAX_TIMES = 30;
}
#undef DH_LOG_TAG
#define DH_LOG_TAG "OffLineTask"

OffLineTask::OffLineTask(const std::string &networkId, const std::string &uuid, const std::string &udid,
    const std::string &dhId, const DHType dhType) : Task(networkId, uuid, udid, dhId, dhType)
{
    this->SetTaskType(TaskType::OFF_LINE);
    this->SetTaskSteps({TaskStep::DISABLE_SINK, TaskStep::WAIT_UNREGISTGER_COMPLETE});
    DHLOGD("OffLineTask id: %{public}s, networkId: %{public}s, uuid: %{public}s, udid: %{public}s",
        GetId().c_str(), GetAnonyString(GetNetworkId()).c_str(), GetAnonyString(GetUUID()).c_str(),
        GetAnonyString(GetUDID()).c_str());
}

OffLineTask::~OffLineTask()
{
    DHLOGD("id = %{public}s, uuid = %{public}s", GetId().c_str(), GetAnonyString(GetUUID()).c_str());
}

void OffLineTask::DoTask()
{
    std::thread([this]() { this->DoTaskInner(); }).detach();
}

void OffLineTask::DoTaskInner()
{
    int32_t ret = pthread_setname_np(pthread_self(), OFFLINE_TASK_INNER);
    if (ret != DH_FWK_SUCCESS) {
        DHLOGE("DoTaskInner setname failed.");
    }
    DHLOGD("start offline task, id = %{public}s, uuid = %{public}s", GetId().c_str(),
        GetAnonyString(GetUUID()).c_str());
    this->SetTaskState(TaskState::RUNNING);
    for (const auto& step : this->GetTaskSteps()) {
        switch (step) {
            case TaskStep::DISABLE_SINK: {
                CreateDisableSinkTask();
                break;
            }
            case TaskStep::WAIT_UNREGISTGER_COMPLETE: {
                WaitDisableTaskFinish();
                break;
            }
            default: {
                break;
            }
        }
    }

    this->SetTaskState(TaskState::SUCCESS);
    DHLOGI("Finish OffLine task, remove it, id: %{public}s", GetId().c_str());
    TaskBoard::GetInstance().RemoveTask(this->GetId());
    int32_t retryCount = 0;
    if (DHContext::GetInstance().GetRealTimeOnlineDeviceCount() == 0 &&
        DHContext::GetInstance().GetIsomerismConnectCount() == 0) {
        while (!TaskBoard::GetInstance().IsAllDisableTaskFinish() && retryCount < RETRY_MAX_TIMES) {
            retryCount++;
            usleep(USLEEP_TIME);
            DHLOGI("judge disable task is finished, retryCount = %{public}d", retryCount);
        }
        DHLOGI("all devices are offline and all disable tasks are finished, start to free the resource");
        DistributedHardwareManagerFactory::GetInstance().UnInit();
    }
}


void OffLineTask::CreateDisableSinkTask()
{
    DHLOGI("CreateDisableSinkTask start");
    DeviceInfo localDeviceInfo = GetLocalDeviceInfo();
    std::vector<DHType> allCompTypes;
    ComponentLoader::GetInstance().GetAllCompTypes(allCompTypes);
    for (auto dhType : allCompTypes) {
        TaskParam taskParam;
        taskParam.networkId = localDeviceInfo.networkId;
        taskParam.uuid = localDeviceInfo.uuid;
        taskParam.udid = localDeviceInfo.udid;
        taskParam.dhId = "";
        taskParam.dhType = dhType;
        auto task = TaskFactory::GetInstance().CreateTask(TaskType::DISABLE, taskParam, shared_from_this());
        TaskExecutor::GetInstance().PushTask(task);
    }
}

void OffLineTask::WaitDisableTaskFinish()
{
    DHLOGI("start wait disable task finish");
    std::unique_lock<std::mutex> waitLock(unFinishTaskMtx_);
    finishCondVar_.wait(waitLock, [&] { return this->unFinishChildrenTasks_.empty(); });
    DHLOGI("all disable task finish");
    DHContext::GetInstance().RemoveOnlineDeviceIdEntryByNetworkId(GetNetworkId());
}


void OffLineTask::NotifyFatherFinish(std::string taskId)
{
    std::lock_guard<std::mutex> lock(unFinishTaskMtx_);
    this->unFinishChildrenTasks_.erase(taskId);
    if (unFinishChildrenTasks_.empty()) {
        finishCondVar_.notify_all();
    }
}

void OffLineTask::AddChildrenTask(std::shared_ptr<Task> childrenTask)
{
    std::lock_guard<std::mutex> lock(unFinishTaskMtx_);
    this->unFinishChildrenTasks_.insert(childrenTask->GetId());
}

} // namespace DistributedHardware
} // namespace OHOS
