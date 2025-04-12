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

#include "disable_task_test.h"

#include "ffrt.h"

#include "dh_utils_tool.h"
#include "distributed_hardware_errno.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
namespace {

const std::string DEV_ID_1 = "bb536a637105409e904d4da83790a4a8";
const std::string DEV_NETWORK_ID_1 = "nt36a637105409e904d4da83790a4a8";
const std::string DEV_DID_1 = "2144a637105409e904d4da83790a4a8";

const TaskParam TASK_PARAM_1 = {
    .networkId = DEV_NETWORK_ID_1,
    .uuid = DEV_ID_1,
    .udid = DEV_DID_1,
    .dhId = "",
    .dhType = DHType::UNKNOWN
};

}

void DisableTaskTest::SetUpTestCase()
{}

void DisableTaskTest::TearDownTestCase()
{}

void DisableTaskTest::SetUp()
{
    auto componentManager = IComponentManager::GetOrCtreateInstance();
    componentManager_ = std::static_pointer_cast<MockComponentManager>(componentManager);
    auto dhContext = IDHContext::GetOrCreateInstance();
    dhContext_ = std::static_pointer_cast<MockDHContext>(dhContext);
}

void DisableTaskTest::TearDown()
{
    IComponentManager::ReleaseInstance();
    componentManager_ = nullptr;
    IDHContext::ReleaseInstance();
    dhContext_ = nullptr;
}

/**
 * @tc.name: UnRegisterHardware_001
 * @tc.desc: Verify the UnRegisterHardware function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DisableTaskTest, UnRegisterHardware_001, TestSize.Level0)
{
    auto disableTask = std::make_shared<DisableTask>(TASK_PARAM_1.networkId, TASK_PARAM_1.uuid, TASK_PARAM_1.udid,
        TASK_PARAM_1.dhId, TASK_PARAM_1.dhType);
    EXPECT_CALL(*componentManager_, ForceDisableSource(_, _)).Times(1).WillRepeatedly(Return(0));
    ASSERT_EQ(disableTask->UnRegisterHardware(), DH_FWK_SUCCESS);
}

/**
 * @tc.name: UnRegisterHardware_002
 * @tc.desc: Verify the UnRegisterHardware function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DisableTaskTest, UnRegisterHardware_002, TestSize.Level0)
{
    auto disableTask = std::make_shared<DisableTask>(TASK_PARAM_1.networkId, TASK_PARAM_1.uuid, TASK_PARAM_1.udid,
        TASK_PARAM_1.dhId, TASK_PARAM_1.dhType);
    EXPECT_CALL(*componentManager_, ForceDisableSource(_, _)).Times(1).WillRepeatedly(Return(1));
    ASSERT_EQ(disableTask->UnRegisterHardware(), 1);
}

/**
 * @tc.name: UnRegisterHardware_003
 * @tc.desc: Verify the UnRegisterHardware function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DisableTaskTest, UnRegisterHardware_003, TestSize.Level0)
{
    auto disableTask = std::make_shared<DisableTask>(TASK_PARAM_1.networkId, TASK_PARAM_1.uuid, GetLocalUdid(),
        TASK_PARAM_1.dhId, TASK_PARAM_1.dhType);
    EXPECT_CALL(*dhContext_, GetRealTimeOnlineDeviceCount()).Times(1).WillRepeatedly(Return(0));
    EXPECT_CALL(*dhContext_, GetIsomerismConnectCount()).Times(1).WillRepeatedly(Return(0));
    EXPECT_CALL(*componentManager_, ForceDisableSink(_)).Times(1).WillRepeatedly(Return(0));
    ASSERT_EQ(disableTask->UnRegisterHardware(), DH_FWK_SUCCESS);
}

/**
 * @tc.name: UnRegisterHardware_004
 * @tc.desc: Verify the UnRegisterHardware function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DisableTaskTest, UnRegisterHardware_004, TestSize.Level0)
{
    auto disableTask = std::make_shared<DisableTask>(TASK_PARAM_1.networkId, TASK_PARAM_1.uuid, GetLocalUdid(),
        TASK_PARAM_1.dhId, TASK_PARAM_1.dhType);
    EXPECT_CALL(*dhContext_, GetRealTimeOnlineDeviceCount()).Times(1).WillRepeatedly(Return(0));
    EXPECT_CALL(*dhContext_, GetIsomerismConnectCount()).Times(1).WillRepeatedly(Return(0));
    EXPECT_CALL(*componentManager_, ForceDisableSink(_)).Times(1).WillRepeatedly(Return(1));
    ASSERT_EQ(disableTask->UnRegisterHardware(), 1);
}

/**
 * @tc.name: UnRegisterHardware_005
 * @tc.desc: Verify the UnRegisterHardware function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DisableTaskTest, UnRegisterHardware_005, TestSize.Level0)
{
    auto disableTask = std::make_shared<DisableTask>(TASK_PARAM_1.networkId, TASK_PARAM_1.uuid, GetLocalUdid(),
        TASK_PARAM_1.dhId, TASK_PARAM_1.dhType);
    EXPECT_CALL(*dhContext_, GetRealTimeOnlineDeviceCount()).Times(1).WillRepeatedly(Return(1));
    ASSERT_EQ(disableTask->UnRegisterHardware(), DH_FWK_SUCCESS);
}

/**
 * @tc.name: UnRegisterHardware_006
 * @tc.desc: Verify the UnRegisterHardware function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DisableTaskTest, UnRegisterHardware_006, TestSize.Level0)
{
    auto disableTask = std::make_shared<DisableTask>(TASK_PARAM_1.networkId, TASK_PARAM_1.uuid, GetLocalUdid(),
        TASK_PARAM_1.dhId, TASK_PARAM_1.dhType);
    EXPECT_CALL(*dhContext_, GetRealTimeOnlineDeviceCount()).Times(1).WillRepeatedly(Return(0));
    EXPECT_CALL(*dhContext_, GetIsomerismConnectCount()).Times(1).WillRepeatedly(Return(1));
    ASSERT_EQ(disableTask->UnRegisterHardware(), DH_FWK_SUCCESS);
}

/**
 * @tc.name: UnRegisterHardware_007
 * @tc.desc: Verify the UnRegisterHardware function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DisableTaskTest, UnRegisterHardware_007, TestSize.Level0)
{
    auto disableTask = std::make_shared<DisableTask>(TASK_PARAM_1.networkId, TASK_PARAM_1.uuid, TASK_PARAM_1.udid,
        TASK_PARAM_1.dhId, TASK_PARAM_1.dhType);
    disableTask->callingUid_ = 1;
    disableTask->callingPid_ = 1;
    disableTask->effectSink_ = true;
    disableTask->effectSource_ = true;
    EXPECT_CALL(*componentManager_, DisableSink(_, _, _)).Times(1).WillRepeatedly(Return(1));
    EXPECT_CALL(*componentManager_, DisableSource(_, _, _, _)).Times(1).WillRepeatedly(Return(1));
    ASSERT_EQ(disableTask->UnRegisterHardware(), 1);
}

/**
 * @tc.name: UnRegisterHardware_008
 * @tc.desc: Verify the UnRegisterHardware function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DisableTaskTest, UnRegisterHardware_008, TestSize.Level0)
{
    auto disableTask = std::make_shared<DisableTask>(TASK_PARAM_1.networkId, TASK_PARAM_1.uuid, TASK_PARAM_1.udid,
        TASK_PARAM_1.dhId, TASK_PARAM_1.dhType);
    disableTask->callingUid_ = 1;
    disableTask->callingPid_ = 1;
    disableTask->effectSink_ = true;
    disableTask->effectSource_ = true;
    EXPECT_CALL(*componentManager_, DisableSink(_, _, _)).Times(1).WillRepeatedly(Return(0));
    EXPECT_CALL(*componentManager_, DisableSource(_, _, _, _)).Times(1).WillRepeatedly(Return(0));
    ASSERT_EQ(disableTask->UnRegisterHardware(), DH_FWK_SUCCESS);
}

/**
 * @tc.name: UnRegisterHardware_009
 * @tc.desc: Verify the UnRegisterHardware function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DisableTaskTest, UnRegisterHardware_009, TestSize.Level0)
{
    auto disableTask = std::make_shared<DisableTask>(TASK_PARAM_1.networkId, TASK_PARAM_1.uuid, TASK_PARAM_1.udid,
        TASK_PARAM_1.dhId, TASK_PARAM_1.dhType);
    disableTask->callingUid_ = 1;
    disableTask->callingPid_ = 1;
    ASSERT_EQ(disableTask->UnRegisterHardware(), DH_FWK_SUCCESS);
}
} // namespace DistributedHardware
} // namespace OHOS