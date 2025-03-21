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

#ifndef OHOS_MOCK_IDISTRIBUTED_HARDWARE_SOURCE_H
#define OHOS_MOCK_IDISTRIBUTED_HARDWARE_SOURCE_H

#include <gmock/gmock.h>
#include <string>

#include "idistributed_hardware_source.h"
namespace OHOS {
namespace DistributedHardware {
class MockIDistributedHardwareSource : public IDistributedHardwareSource {
public:
    virtual ~MockIDistributedHardwareSource() {}
    MOCK_METHOD(int32_t, InitSource, (const std::string &));
    MOCK_METHOD(int32_t, ReleaseSource, ());
    MOCK_METHOD(int32_t, RegisterDistributedHardware, (const std::string &, const std::string &,
        const EnableParam &, std::shared_ptr<RegisterCallback>));
    MOCK_METHOD(int32_t, UnregisterDistributedHardware, (const std::string &, const std::string &,
        std::shared_ptr<UnregisterCallback>));
    MOCK_METHOD(int32_t, ConfigDistributedHardware, (const std::string &, const std::string &, const std::string &,
        const std::string &));
    MOCK_METHOD(void, RegisterDistributedHardwareStateListener, (std::shared_ptr<DistributedHardwareStateListener>));
    MOCK_METHOD(void, UnregisterDistributedHardwareStateListener, ());
    MOCK_METHOD(void, RegisterDataSyncTriggerListener, (std::shared_ptr<DataSyncTriggerListener>));
    MOCK_METHOD(void, UnregisterDataSyncTriggerListener, ());
};
} // namespace DistributedHardware
} // namespace OHOS
#endif
