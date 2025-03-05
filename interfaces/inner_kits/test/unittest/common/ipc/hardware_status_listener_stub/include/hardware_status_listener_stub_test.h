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

#ifndef OHOS_HARDWARE_STATUS_LISTENER_STUB_TEST_H
#define OHOS_HARDWARE_STATUS_LISTENER_STUB_TEST_H

#include <atomic>
#include <functional>
#include <mutex>

#include <gtest/gtest.h>

#include "distributed_hardware_errno.h"
#include "iremote_stub.h"
#include "idistributed_hardware.h"
#include "hardware_status_listener_stub.h"

namespace OHOS {
namespace DistributedHardware {
class HardwareStatusListenerStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    virtual void SetUp();
    virtual void TearDown();

    std::shared_ptr<HDSinkStatusListenerStub> sinkListenerStub_ = nullptr;
    std::shared_ptr<HDSourceStatusListenerStub> sourceListenerStub_ = nullptr;
};

class MockHDSinkStatusListenerStub : public HDSinkStatusListenerStub {
public:
    void OnEnable(const DHDescriptor &dhDescriptor)
    {
        (void)dhDescriptor;
    }
    void OnDisable(const DHDescriptor &dhDescriptor)
    {
        (void)dhDescriptor;
    }
};

class MockHDSourceStatusListenerStub : public HDSourceStatusListenerStub {
public:
void OnEnable(const std::string &networkId, const DHDescriptor &dhDescriptor)
{
    (void)networkId;
    (void)dhDescriptor;
}
void OnDisable(const std::string &networkId, const DHDescriptor &dhDescriptor)
{
    (void)networkId;
    (void)dhDescriptor;
}
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_HARDWARE_STATUS_LISTENER_STUB_TEST_H