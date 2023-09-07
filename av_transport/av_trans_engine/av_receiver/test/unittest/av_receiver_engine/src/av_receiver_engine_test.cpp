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

#include "av_receiver_engine_test.h"

#include "pipeline/factory/filter_factory.h"
#include "plugin_video_tags.h"

using namespace testing::ext;
using namespace OHOS::DistributedHardware;
using namespace std;

namespace OHOS {
namespace DistributedHardware {
const std::string FILTERNAME = "avreceivererengine";

void AvReceiverEngineTest::SetUp()
{
}

void AvReceiverEngineTest::TearDown()
{
}

void AvReceiverEngineTest::SetUpTestCase()
{
}

void AvReceiverEngineTest::TearDownTestCase()
{
}

HWTEST_F(AvReceiverEngineTest, Initialize_001, testing::ext::TestSize.Level1)
{
    std::string ownerName = "001";
    std::string peerDevId = "pEid";
    auto receiver = std::make_shared<AVReceiverEngine>(ownerName, peerDevId);
    receiver->initialized_ = true;
    int32_t ret = receiver->Initialize();
    EXPECT_EQ(DH_AVT_SUCCESS, ret);
}

HWTEST_F(AvReceiverEngineTest, Initialize_002, testing::ext::TestSize.Level1)
{
    std::string ownerName = "001";
    std::string peerDevId = "pEid";
    auto receiver = std::make_shared<AVReceiverEngine>(ownerName, peerDevId);
    receiver->avInput_ = nullptr;
    int32_t ret = receiver->Initialize();
    EXPECT_EQ(ERR_DH_AVT_INIT_FAILED, ret);
}

HWTEST_F(AvReceiverEngineTest, Initialize_003, testing::ext::TestSize.Level1)
{
    std::string ownerName = "001";
    std::string peerDevId = "pEid";
    auto receiver = std::make_shared<AVReceiverEngine>(ownerName, peerDevId);
    receiver->sessionName_ = "";
    int32_t ret = receiver->Initialize();
    EXPECT_EQ(ERR_DH_AVT_INIT_FAILED, ret);
}

HWTEST_F(AvReceiverEngineTest, CreateControlChannel_001, testing::ext::TestSize.Level1)
{
    std::string ownerName = "001";
    std::string peerDevId = "pEid";
    auto receiver = std::make_shared<AVReceiverEngine>(ownerName, peerDevId);
    std::vector<std::string> dstDevIds;
    int32_t ret = receiver->CreateControlChannel(dstDevIds, ChannelAttribute{TransStrategy::LOW_LATANCY_STRATEGY});
    EXPECT_EQ(ERR_DH_AVT_NULL_POINTER, ret);
}

HWTEST_F(AvReceiverEngineTest, CreateControlChannel_002, testing::ext::TestSize.Level1)
{
    std::string ownerName = "001";
    std::string peerDevId = "pEid";
    auto receiver = std::make_shared<AVReceiverEngine>(ownerName, peerDevId);
    std::vector<std::string> dstDevIds = {peerDevId};
    int32_t ret = receiver->CreateControlChannel(dstDevIds, ChannelAttribute{TransStrategy::LOW_LATANCY_STRATEGY});
    EXPECT_EQ(ERR_DH_AVT_CREATE_CHANNEL_FAILED, ret);
}

HWTEST_F(AvReceiverEngineTest, CreateControlChannel_003, testing::ext::TestSize.Level1)
{
    std::string ownerName = "001";
    std::string peerDevId = "pEid";
    auto receiver = std::make_shared<AVReceiverEngine>(ownerName, peerDevId);
    std::vector<std::string> dstDevIds = {peerDevId};
    int32_t ret = receiver->CreateControlChannel(dstDevIds, ChannelAttribute{TransStrategy::LOW_LATANCY_STRATEGY});
    EXPECT_EQ(ERR_DH_AVT_CREATE_CHANNEL_FAILED, ret);
}

HWTEST_F(AvReceiverEngineTest, Start_001, testing::ext::TestSize.Level1)
{
    std::string ownerName = "001";
    std::string peerDevId = "pEid";
    auto receiver = std::make_shared<AVReceiverEngine>(ownerName, peerDevId);
    receiver->currentState_ = StateId::IDLE;
    receiver->pipeline_ = std::make_shared<OHOS::Media::Pipeline::PipelineCore>();
    int32_t ret = receiver->Start();
    EXPECT_EQ(ERR_DH_AVT_START_FAILED, ret);
}

HWTEST_F(AvReceiverEngineTest, Start_002, testing::ext::TestSize.Level1)
{
    std::string ownerName = "001";
    std::string peerDevId = "pEid";
    auto receiver = std::make_shared<AVReceiverEngine>(ownerName, peerDevId);
    receiver->currentState_ = StateId::CH_CREATED;
    receiver->pipeline_ = std::make_shared<OHOS::Media::Pipeline::PipelineCore>();
    int32_t ret = receiver->Start();
    receiver->Stop();
    EXPECT_EQ(DH_AVT_SUCCESS, ret);
}

HWTEST_F(AvReceiverEngineTest, Stop_001, testing::ext::TestSize.Level1)
{
    std::string ownerName = "001";
    std::string peerDevId = "pEid";
    auto receiver = std::make_shared<AVReceiverEngine>(ownerName, peerDevId);
    receiver->currentState_ = StateId::CH_CREATED;
    receiver->pipeline_ = std::make_shared<OHOS::Media::Pipeline::PipelineCore>();
    receiver->Start();
    int32_t ret = receiver->Stop();
    EXPECT_EQ(DH_AVT_SUCCESS, ret);
}

HWTEST_F(AvReceiverEngineTest, SetParameter_001, testing::ext::TestSize.Level1)
{
    std::string ownerName = "001";
    std::string peerDevId = "pEid";
    std::string value = "value";
    auto receiver = std::make_shared<AVReceiverEngine>(ownerName, peerDevId);
    int32_t ret = receiver->SetParameter(AVTransTag::INVALID, value);
    EXPECT_EQ(ERR_DH_AVT_SETUP_FAILED, ret);
}

HWTEST_F(AvReceiverEngineTest, SetParameter_002, testing::ext::TestSize.Level1)
{
    std::string ownerName = "001";
    std::string peerDevId = "pEid";
    std::string value = "value";
    auto receiver = std::make_shared<AVReceiverEngine>(ownerName, peerDevId);
    receiver->avInput_ = FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, "avinput");
    int32_t ret = receiver->SetParameter(AVTransTag::INVALID, value);
    EXPECT_EQ(ERR_DH_AVT_SETUP_FAILED, ret);
}

HWTEST_F(AvReceiverEngineTest, SetParameter_003, testing::ext::TestSize.Level1)
{
    std::string ownerName = "001";
    std::string peerDevId = "pEid";
    std::string value = "value";
    auto receiver = std::make_shared<AVReceiverEngine>(ownerName, peerDevId);
    receiver->avInput_ = FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, "avinput");
    receiver->avOutput_ = FilterFactory::Instance().CreateFilterWithType<AVOutputFilter>(AVOUTPUT_NAME, "avoutput");
    int32_t ret = receiver->SetParameter(AVTransTag::INVALID, value);
    EXPECT_EQ(ERR_DH_AVT_SETUP_FAILED, ret);
}

HWTEST_F(AvReceiverEngineTest, SetParameter_004, testing::ext::TestSize.Level1)
{
    std::string ownerName = "001";
    std::string peerDevId = "pEid";
    std::string value = "123";
    auto receiver = std::make_shared<AVReceiverEngine>(ownerName, peerDevId);
    receiver->avInput_ = FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, "avinput");
    receiver->avOutput_ = FilterFactory::Instance().CreateFilterWithType<AVOutputFilter>(AVOUTPUT_NAME, "avoutput");

    std::shared_ptr<OHOS::Media::Pipeline::PipelineCore> pipeline_ = nullptr;
    receiver->pipeline_ = std::make_shared<OHOS::Media::Pipeline::PipelineCore>();
    int32_t ret = receiver->SetParameter(AVTransTag::VIDEO_WIDTH, value);
    EXPECT_EQ(ERR_DH_AVT_INVALID_PARAM, ret);
}

HWTEST_F(AvReceiverEngineTest, PreparePipeline_001, testing::ext::TestSize.Level1)
{
    std::string ownerName = "001";
    std::string peerDevId = "pEid";
    std::string configParam = "value";
    auto receiver = std::make_shared<AVReceiverEngine>(ownerName, peerDevId);
    receiver->currentState_ = StateId::STARTED;
    int32_t ret = receiver->PreparePipeline(configParam);
    EXPECT_EQ(ERR_DH_AVT_PREPARE_FAILED, ret);
}

HWTEST_F(AvReceiverEngineTest, PreparePipeline_002, testing::ext::TestSize.Level1)
{
    std::string ownerName = "001";
    std::string peerDevId = "pEid";
    std::string configParam = "value";
    auto receiver = std::make_shared<AVReceiverEngine>(ownerName, peerDevId);
    receiver->currentState_ = StateId::INITIALIZED;
    int32_t ret = receiver->PreparePipeline(configParam);
    EXPECT_EQ(ERR_DH_AVT_PREPARE_FAILED, ret);
}

HWTEST_F(AvReceiverEngineTest, PreparePipeline_003, testing::ext::TestSize.Level1)
{
    std::string ownerName = "001";
    std::string peerDevId = "pEid";
    std::string configParam = "value";
    auto receiver = std::make_shared<AVReceiverEngine>(ownerName, peerDevId);
    receiver->currentState_ = StateId::INITIALIZED;
    receiver->avInput_ = FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, "avinput");
    int32_t ret = receiver->PreparePipeline(configParam);
    EXPECT_EQ(ERR_DH_AVT_PREPARE_FAILED, ret);
}

HWTEST_F(AvReceiverEngineTest, PreparePipeline_004, testing::ext::TestSize.Level1)
{
    std::string ownerName = "001";
    std::string peerDevId = "pEid";
    std::string configParam = "value";
    auto receiver = std::make_shared<AVReceiverEngine>(ownerName, peerDevId);
    receiver->currentState_ = StateId::INITIALIZED;
    std::shared_ptr<AVOutputFilter> avOutput_ = nullptr;
    avOutput_ = FilterFactory::Instance().CreateFilterWithType<AVOutputFilter>(AVOUTPUT_NAME, "avoutput");
    int32_t ret = receiver->PreparePipeline(configParam);
    EXPECT_EQ(ERR_DH_AVT_PREPARE_FAILED, ret);
}

HWTEST_F(AvReceiverEngineTest, SendMessage_001, testing::ext::TestSize.Level1)
{
    std::string ownerName = "001";
    std::string peerDevId = "pEid";
    std::string configParam = "value";
    auto receiver = std::make_shared<AVReceiverEngine>(ownerName, peerDevId);
    int32_t ret = receiver->SendMessage(nullptr);
    EXPECT_EQ(ERR_DH_AVT_INVALID_PARAM, ret);
}
} // namespace DistributedHardware
} // namespace OHOS