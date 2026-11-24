/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

/*
 * lite variant of utils/src/device_param_mgr.cpp.
 * lite has no os_account and no enterprise space: QueryUserBelongToSpace
 * and QueryDeviceSpaceMode always return false, so GetDeviceSyncDataMode
 * degenerates to the E2E sync switch (isDeviceE2ESync_).
 */

#include "device_param_mgr.h"

#include <cstring>

#include <parameter.h>

#include "distributed_hardware_log.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
    constexpr int32_t BUF_LENTH = 128;
    const char *SYNC_TYPE_E2E = "1";
    const char *DATA_SYNC_PARAM = "persist.distributed_scene.sys_settings_data_sync";
}
FWK_IMPLEMENT_SINGLE_INSTANCE(DeviceParamMgr);
void DeviceParamMgr::QueryDeviceDataSyncMode()
{
    char paramBuf[BUF_LENTH] = {0};
    int32_t ret = GetParameter(DATA_SYNC_PARAM, "", paramBuf, BUF_LENTH);
    DHLOGI("The device paramBuf: %{public}s", paramBuf);
    if (ret > 0 && strncmp(paramBuf, SYNC_TYPE_E2E, strlen(SYNC_TYPE_E2E)) == 0) {
        DHLOGI("Determining the e2e device succeeded.");
        isDeviceE2ESync_.store(true);
        return;
    }
    DHLOGW("Determining is not e2e device");
}

bool DeviceParamMgr::QueryUserBelongToSpace()
{
    DHLOGI("User is not an enterprise user.");
    return false;
}

bool DeviceParamMgr::QueryDeviceSpaceMode()
{
    DHLOGI("Enterprise space close");
    return false;
}

bool DeviceParamMgr::GetDeviceSyncDataMode()
{
    if (!isDeviceE2ESync_.load()) {
        return false;
    }
    if (QueryDeviceSpaceMode() && !QueryUserBelongToSpace()) {
        return false;
    }
    return true;
}
}
}
