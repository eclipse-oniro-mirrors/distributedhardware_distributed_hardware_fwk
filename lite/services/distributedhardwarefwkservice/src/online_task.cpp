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

#include "online_task.h"

#include "anonymous_string.h"
#include "dh_utils_tool.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"
#include "dh_context.h"
#include "task_board.h"
#include "task_executor.h"
#include "task_factory.h"
#include "component_loader.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
    constexpr uint16_t PHONE_TYPE = 14;
    constexpr uint32_t WAIT_SYNC_TIME_MS = 13 * 1000;
}
#undef DH_LOG_TAG
#define DH_LOG_TAG "OnLineTask"

OnLineTask::OnLineTask(const std::string &networkId, const std::string &uuid, const std::string &udid,
    const std::string &dhId, const DHType dhType) : Task(networkId, uuid, udid, dhId, dhType)
{
    SetTaskType(TaskType::ON_LINE);
    SetTaskSteps(std::vector<TaskStep> { TaskStep::ENABLE_SINK });
    DHLOGD("OnLineTask id: %{public}s, networkId: %{public}s, uuid: %{public}s, udid: %{public}s",
        GetId().c_str(), GetAnonyString(networkId).c_str(), GetAnonyString(uuid).c_str(),
        GetAnonyString(udid).c_str());
}

OnLineTask::~OnLineTask()
{
    DHLOGD("id = %{public}s, uuid = %{public}s", GetId().c_str(), GetAnonyString(GetUUID()).c_str());
}

void OnLineTask::DoTask()
{
    DHLOGD("start online task, id = %{public}s, networkId: %{public}s, uuid: %{public}s, udid: %{public}s",
        GetId().c_str(), GetAnonyString(GetNetworkId()).c_str(), GetAnonyString(GetUUID()).c_str(),
        GetAnonyString(GetUDID()).c_str());
    this->SetTaskState(TaskState::RUNNING);
    for (const auto& step : this->GetTaskSteps()) {
        switch (step) {
            case TaskStep::SYNC_ONLINE_INFO: {
                break;
            }
            case TaskStep::REGISTER_ONLINE_DISTRIBUTED_HARDWARE: {
                break;
            }
            case TaskStep::ENABLE_SINK: {
                CreateEnableSinkTask();
                break;
            }
            case TaskStep::META_ENABLE_TASK: {
                break;
            }
            default: {
                break;
            }
        }
    }
    SetTaskState(TaskState::SUCCESS);
    DHLOGI("finish online task, remove it, id = %{public}s.", GetId().c_str());
    TaskBoard::GetInstance().RemoveTask(this->GetId());
}


void OnLineTask::CreateEnableSinkTask()
{
    DeviceInfo localDeviceInfo = GetLocalDeviceInfo();
    DHLOGI("CreateEnableSinkTask, uuid: %{public}s", GetAnonyString(localDeviceInfo.uuid).c_str());
    std::vector<DHType> dhTypes;
    ComponentLoader::GetInstance().GetAllCompTypes(dhTypes);
    if (dhTypes.empty()) {
        DHLOGE("Can not get local component types from config.");
        return;
    }
    for (const auto &dhType : dhTypes) {
        TaskParam taskParam;
        taskParam.networkId = localDeviceInfo.networkId;
        taskParam.uuid = localDeviceInfo.uuid;
        taskParam.udid = localDeviceInfo.udid;
        taskParam.dhId = "";
        taskParam.dhType = dhType;
        auto task = TaskFactory::GetInstance().CreateTask(TaskType::ENABLE, taskParam, shared_from_this());
        TaskExecutor::GetInstance().PushTask(task);
    }
}

void OnLineTask::CreateMetaEnableTask()
{
    if (!DHContext::GetInstance().IsDoubleFwkDevice(GetNetworkId())) {
        DHLOGE("online device is not double frame device or networkId not find.");
        return;
    }
    uint16_t deviceType = DHContext::GetInstance().GetDeviceTypeByNetworkId(GetNetworkId());
    if (deviceType != PHONE_TYPE) {
        DHLOGE("online device not phone, deviceType = %{public}d", deviceType);
        return;
    }
    DHLOGI("CreateMetaEnableTask, networkId: %{public}s, uuid: %{public}s, udid: %{public}s",
        GetAnonyString(GetNetworkId()).c_str(), GetAnonyString(GetUUID()).c_str(), GetAnonyString(GetUDID()).c_str());
    TaskParam taskParam = {
        .networkId = GetNetworkId(),
        .uuid = GetUUID(),
        .udid = GetUDID(),
        .dhId = "Modem_1234",
        .dhType = DHType::MODEM
    };
    auto task = TaskFactory::GetInstance().CreateTask(TaskType::META_ENABLE, taskParam, shared_from_this());
    TaskExecutor::GetInstance().PushTask(task);
}
} // namespace DistributedHardware
} // namespace OHOS
