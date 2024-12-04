/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "output_controller_test.h"

#include "output_controller.h"
#include "av_trans_errno.h"

namespace OHOS {
namespace DistributedHardware {
const std::string PLUGINNAME = "dsoftbus_output_plugin";
constexpr uint32_t SLEEP_TIME_US = 1000 * 1000;
void OutputControllerTest::SetUpTestCase(void) {}

void OutputControllerTest::TearDownTestCase(void) {}

void OutputControllerTest::SetUp(void) {}

void OutputControllerTest::TearDown(void) {}

const int32_t TEST_QUEUE_MAX_SIZE = 100;

HWTEST_F(OutputControllerTest, SetParameter_001, TestSize.Level0)
{
    auto controller = std::make_shared<OutputController>();
    std::string value = "dscreen_output_test";
    Status ret = controller->SetParameter(Tag::USER_FRAME_NUMBER, value);
    EXPECT_EQ(Status::OK, ret);

    std::shared_ptr<Plugin::Buffer> data = std::make_shared<Plugin::Buffer>(BufferMetaType::AUDIO);
    controller->PushData(data);

    controller->status_.store(OutputController::ControlStatus::START);
    controller->mode_.store(OutputController::ControlMode::SYNC);

    for (int32_t i = 0; i <= TEST_QUEUE_MAX_SIZE; i++) {
        controller->dataQueue_.push(data);
    }
    controller->PushData(data);
}

HWTEST_F(OutputControllerTest, SetParameter_002, TestSize.Level0)
{
    auto controller = std::make_shared<OutputController>();
    std::string value = "dscreen_output_test";
    Status ret = controller->SetParameter(Tag::USER_SHARED_MEMORY_FD, value);
    EXPECT_EQ(Status::OK, ret);
}

HWTEST_F(OutputControllerTest, SetParameter_003, TestSize.Level0)
{
    auto controller = std::make_shared<OutputController>();
    std::string value = "dscreen_output_test";
    Status ret = controller->SetParameter(Tag::USER_TIME_SYNC_RESULT, value);
    EXPECT_EQ(Status::OK, ret);
}

HWTEST_F(OutputControllerTest, GetParameter_001, TestSize.Level0)
{
    auto controller = std::make_shared<OutputController>();
    std::string value = "dscreen_output_test";
    controller->SetParameter(Tag::USER_FRAME_NUMBER, value);
    ValueType val;
    Status ret = controller->GetParameter(Tag::USER_FRAME_NUMBER, val);
    EXPECT_EQ(Status::OK, ret);
}

HWTEST_F(OutputControllerTest, GetParameter_002, TestSize.Level0)
{
    auto controller = std::make_shared<OutputController>();
    ValueType val;
    Status ret = controller->GetParameter(Tag::USER_FRAME_NUMBER, val);
    EXPECT_EQ(Status::ERROR_NOT_EXISTED, ret);
}

HWTEST_F(OutputControllerTest, StartControl_001, testing::ext::TestSize.Level1)
{
    auto controller = std::make_shared<OutputController>();
    OutputController::ControlStatus ret = controller->StartControl();
    EXPECT_EQ(OutputController::ControlStatus::START, ret);

    controller->SetControlStatus(OutputController::ControlStatus::START);
    ret = controller->StartControl();
    usleep(SLEEP_TIME_US);
    EXPECT_EQ(OutputController::ControlStatus::STARTED, ret);
}

HWTEST_F(OutputControllerTest, StopControl_001, testing::ext::TestSize.Level1)
{
    auto controller = std::make_shared<OutputController>();
    OutputController::ControlStatus ret = controller->StopControl();
    EXPECT_EQ(OutputController::ControlStatus::STOP, ret);

    controller->SetControlStatus(OutputController::ControlStatus::STOP);
    ret = controller->StopControl();
    EXPECT_EQ(OutputController::ControlStatus::STOPPED, ret);
}

HWTEST_F(OutputControllerTest, ReleaseControl_001, testing::ext::TestSize.Level1)
{
    auto controller = std::make_shared<OutputController>();
    OutputController::ControlStatus ret = controller->ReleaseControl();
    EXPECT_EQ(OutputController::ControlStatus::RELEASED, ret);
}

HWTEST_F(OutputControllerTest, ControlOutput_001, testing::ext::TestSize.Level1)
{
    auto controller = std::make_shared<OutputController>();
    std::shared_ptr<Plugin::Buffer> data = std::make_shared<AVBuffer>();
    controller->SetAllowControlState(false);
    int32_t ret = controller->ControlOutput(data);
    EXPECT_EQ(OUTPUT_FRAME, ret);

    controller->SetAllowControlState(true);
    data->pts = 100;
    ret = controller->ControlOutput(data);
    EXPECT_EQ(OUTPUT_FRAME, ret);

    controller->isTimeInit_.store(true);
    ret = controller->ControlOutput(data);
    EXPECT_EQ(OUTPUT_FRAME, ret);

    controller->isBaselineInit_.store(true);
    ret = controller->ControlOutput(data);
    EXPECT_EQ(OUTPUT_FRAME, ret);

    controller->CheckSyncInfo(data);

    controller->SetControlMode(OutputController::ControlMode::SMOOTH);
    controller->CheckSyncInfo(data);

    controller->PrepareControl();
    controller->SetControlMode(OutputController::ControlMode::SYNC);
    controller->CalProcessTime(data);
}

HWTEST_F(OutputControllerTest, CheckIsClockInvalid_001, testing::ext::TestSize.Level1)
{
    auto controller = std::make_shared<OutputController>();
    std::shared_ptr<Plugin::Buffer> data;
    bool ret = controller->CheckIsClockInvalid(data);
    EXPECT_EQ(false, ret);

    controller->SetControlMode(OutputController::ControlMode::SYNC);
    ret = controller->CheckIsClockInvalid(data);
    EXPECT_EQ(true, ret);
}

HWTEST_F(OutputControllerTest, AcquireSyncClockTime_001, testing::ext::TestSize.Level1)
{
    auto controller = std::make_shared<OutputController>();
    std::shared_ptr<Plugin::Buffer> data;
    int32_t ret = controller->AcquireSyncClockTime(data);
    EXPECT_EQ(ERR_DH_AVT_INVALID_PARAM, ret);
}

HWTEST_F(OutputControllerTest, WaitRereadClockFailed_001, testing::ext::TestSize.Level1)
{
    auto controller = std::make_shared<OutputController>();
    std::shared_ptr<Plugin::Buffer> data;
    controller->statistician_ = std::make_shared<TimeStatistician>();
    bool ret = controller->WaitRereadClockFailed(data);
    EXPECT_EQ(false, ret);

    data = std::make_shared<Plugin::Buffer>(BufferMetaType::AUDIO);
    for (int32_t i = 0; i <= TEST_QUEUE_MAX_SIZE; i++) {
        controller->dataQueue_.push(data);
    }
    ret = controller->WaitRereadClockFailed(data);
    EXPECT_EQ(true, ret);

    controller->enterTime_ = 2;
    controller->leaveTime_ = 1;
    int64_t timeStamp = 2;
    controller->CalSleepTime(timeStamp);

    controller->adjustSleepFactor_ = -2;
    controller->CalSleepTime(timeStamp);
}

HWTEST_F(OutputControllerTest, CheckIsProcessInDynamicBalance_001, testing::ext::TestSize.Level1)
{
    auto controller = std::make_shared<OutputController>();
    std::shared_ptr<Plugin::Buffer> data;
    controller->SetControlMode(OutputController::ControlMode::SYNC);
    bool ret = controller->CheckIsProcessInDynamicBalance(data);
    EXPECT_EQ(true, ret);

    controller->SetControlMode(OutputController::ControlMode::SMOOTH);
    controller->SetProcessDynamicBalanceState(false);
    ret = controller->CheckIsProcessInDynamicBalance(data);
    EXPECT_EQ(true, ret);
}

HWTEST_F(OutputControllerTest, CheckIsProcessInDynamicBalanceOnce_001, testing::ext::TestSize.Level1)
{
    auto controller = std::make_shared<OutputController>();
    std::shared_ptr<Plugin::Buffer> data;
    bool ret = controller->CheckIsProcessInDynamicBalanceOnce(data);
    EXPECT_EQ(false, ret);
}

HWTEST_F(OutputControllerTest, PostOutputEvent_001, testing::ext::TestSize.Level1)
{
    auto controller = std::make_shared<OutputController>();
    std::shared_ptr<Plugin::Buffer> data;
    int32_t ret = controller->PostOutputEvent(data);
    EXPECT_EQ(HANDLE_FAILED, ret);

    data = std::make_shared<AVBuffer>();
    controller->SyncClock(data);

    controller->sleep_ = 1;
    controller->SyncClock(data);

    controller->sleep_ = -1;
    controller->SyncClock(data);

    controller->statistician_ = std::make_shared<TimeStatistician>();
    data = std::make_shared<Plugin::Buffer>(BufferMetaType::AUDIO);
    data->pts = 1;
    controller->sleep_ = 1;
    controller->clockTime_.store(1);
    controller->HandleSmoothTime(data);

    controller->statistician_->averTimeStampInterval_ = 1;
    controller->waitClockFactor_ = 2;
    controller->HandleSmoothTime(data);
}

HWTEST_F(OutputControllerTest, NotifyOutput_001, testing::ext::TestSize.Level1)
{
    auto controller = std::make_shared<OutputController>();
    std::shared_ptr<Plugin::Buffer> data;
    controller->UnregisterListener();
    int32_t ret = controller->NotifyOutput(data);
    EXPECT_EQ(NOTIFY_FAILED, ret);

    int32_t result = 0;
    controller->HandleControlResult(data, result);

    result = 1;
    data = std::make_shared<Plugin::Buffer>(BufferMetaType::AUDIO);
    controller->dataQueue_.push(data);
    controller->HandleControlResult(data, result);

    result = 2;
    controller->HandleControlResult(data, result);

    result = 3;
    controller->HandleControlResult(data, result);
}
} // namespace DistributedHardware
} // namespace OHOS