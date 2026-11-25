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

#include "component_monitor.h"

#include <cinttypes>


#include "anonymous_string.h"
#include "component_loader.h"
#include "component_manager.h"
#include "device_type.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"

namespace OHOS {
namespace DistributedHardware {

ComponentMonitor::ComponentMonitor()
{
    DHLOGI("Ctor ComponentMonitor (lite)");
}

ComponentMonitor::~ComponentMonitor()
{
    DHLOGI("Dtor ComponentMonitor (lite)");
}
} // namespace DistributedHardware
} // namespace OHOS
