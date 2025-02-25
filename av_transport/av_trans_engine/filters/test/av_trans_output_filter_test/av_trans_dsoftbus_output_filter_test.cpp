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

#include "av_trans_dsoftbus_output_filter_test.h"
#include "av_trans_audio_encoder_filter.h"
#include "av_trans_constants.h"
using namespace testing::ext;
using namespace OHOS::DistributedHardware;
using namespace std;

namespace OHOS {
namespace DistributedHardware {
constexpr int32_t DEFAULT_BUFFER_NUM = 8;
const std::string INPUT_BUFFER_QUEUE_NAME = "AVTransAudioInputBufferQueue";

void AvTransportAudioOutputFilterTest::SetUp()
{
    dSoftbusOutputTest_ = std::make_shared<Pipeline::DSoftbusOutputFilter>("builtin.daudio.output",
        Pipeline::FilterType::FILTERTYPE_SSINK);
}

void AvTransportAudioOutputFilterTest::TearDown()
{
}

void AvTransportAudioOutputFilterTest::SetUpTestCase()
{
}

void AvTransportAudioOutputFilterTest::TearDownTestCase()
{
}

HWTEST_F(AvTransportAudioOutputFilterTest, Init_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(dSoftbusOutputTest_ != nullptr);
    std::string receiverId = std::string("AVreceiverEngineTest");
    dSoftbusOutputTest_->Init(nullptr, nullptr);
}

HWTEST_F(AvTransportAudioOutputFilterTest, DoInitAfterLink_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(dSoftbusOutputTest_ != nullptr);
    Status ret = dSoftbusOutputTest_->DoInitAfterLink();
    EXPECT_EQ(Status::OK, ret);
}

HWTEST_F(AvTransportAudioOutputFilterTest, PrepareInputBuffer_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(dSoftbusOutputTest_ != nullptr);
    dSoftbusOutputTest_->PrepareInputBuffer();
}

HWTEST_F(AvTransportAudioOutputFilterTest, DoPrepare_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(dSoftbusOutputTest_ != nullptr);
    Status ret = dSoftbusOutputTest_->DoPrepare();
    EXPECT_NE(Status::OK, ret);
}

HWTEST_F(AvTransportAudioOutputFilterTest, DoStart_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(dSoftbusOutputTest_ != nullptr);
    Status ret = dSoftbusOutputTest_->DoStart();
    EXPECT_EQ(Status::ERROR_INVALID_OPERATION, ret);
}

HWTEST_F(AvTransportAudioOutputFilterTest, DoPause_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(dSoftbusOutputTest_ != nullptr);
    Status ret = dSoftbusOutputTest_->DoPause();
    EXPECT_EQ(Status::OK, ret);
}

HWTEST_F(AvTransportAudioOutputFilterTest, DoPauseDragging_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(dSoftbusOutputTest_ != nullptr);
    Status ret = dSoftbusOutputTest_->DoPauseDragging();
    EXPECT_EQ(Status::OK, ret);
}

HWTEST_F(AvTransportAudioOutputFilterTest, DoResume_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(dSoftbusOutputTest_ != nullptr);
    Status ret = dSoftbusOutputTest_->DoResume();
    EXPECT_EQ(Status::OK, ret);
}

HWTEST_F(AvTransportAudioOutputFilterTest, DoResumeDragging_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(dSoftbusOutputTest_ != nullptr);
    Status ret = dSoftbusOutputTest_->DoResumeDragging();
    EXPECT_EQ(Status::OK, ret);
}

HWTEST_F(AvTransportAudioOutputFilterTest, DoStop_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(dSoftbusOutputTest_ != nullptr);
    Status ret = dSoftbusOutputTest_->DoStop();
    EXPECT_EQ(Status::ERROR_NULL_POINTER, ret);
}

HWTEST_F(AvTransportAudioOutputFilterTest, DoFlush_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(dSoftbusOutputTest_ != nullptr);
    Status ret = dSoftbusOutputTest_->DoFlush();
    EXPECT_EQ(Status::OK, ret);
}

HWTEST_F(AvTransportAudioOutputFilterTest, DoRelease_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(dSoftbusOutputTest_ != nullptr);
    Status ret = dSoftbusOutputTest_->DoRelease();
    EXPECT_EQ(Status::OK, ret);
}

HWTEST_F(AvTransportAudioOutputFilterTest, DoProcessInputBuffer_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(dSoftbusOutputTest_ != nullptr);
    dSoftbusOutputTest_->PrepareInputBuffer();
    Status ret = dSoftbusOutputTest_->DoProcessInputBuffer(1, true);
    EXPECT_EQ(Status::ERROR_INVALID_OPERATION, ret);
    
    dSoftbusOutputTest_->outputBufQue_ = Media::AVBufferQueue::Create(DEFAULT_BUFFER_NUM,
        Media::MemoryType::VIRTUAL_MEMORY, INPUT_BUFFER_QUEUE_NAME);
    ret = dSoftbusOutputTest_->DoProcessInputBuffer(1, true);
    EXPECT_EQ(Status::ERROR_INVALID_OPERATION, ret);
}

HWTEST_F(AvTransportAudioOutputFilterTest, DoProcessOutputBuffer_001, testing::ext::TestSize.Level1)
{
    Status ret = dSoftbusOutputTest_->DoProcessOutputBuffer(1, true, true, 2, 3);
    EXPECT_EQ(Status::OK, ret);
}

HWTEST_F(AvTransportAudioOutputFilterTest, ProcessAndSendBuffer_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(dSoftbusOutputTest_ != nullptr);
    std::shared_ptr<Media::AVBuffer> audioData = std::make_shared<Media::AVBuffer>();
    Status ret = dSoftbusOutputTest_->ProcessAndSendBuffer(audioData);
    EXPECT_EQ(Status::ERROR_NULL_POINTER, ret);
}

HWTEST_F(AvTransportAudioOutputFilterTest, SetParameterAndGetParameter_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = nullptr;
    std::shared_ptr<Media::Meta> meta2 = std::make_shared<Media::Meta>();
    dSoftbusOutputTest_->SetParameter(meta2);
    dSoftbusOutputTest_->GetParameter(meta);
    EXPECT_EQ(meta, meta2);
}

HWTEST_F(AvTransportAudioOutputFilterTest, LinkNext_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(dSoftbusOutputTest_ != nullptr);
    std::shared_ptr<Pipeline::AudioEncoderFilter> avAudioEncoderTest_ =
        std::make_shared<Pipeline::AudioEncoderFilter>("builtin.recorder.audioencoderfilter",
            Pipeline::FilterType::FILTERTYPE_AENC);
    Status ret = dSoftbusOutputTest_->LinkNext(avAudioEncoderTest_, Pipeline::StreamType::STREAMTYPE_RAW_AUDIO);
    EXPECT_EQ(Status::ERROR_NULL_POINTER, ret);
}

HWTEST_F(AvTransportAudioOutputFilterTest, UpdateNext_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Pipeline::AudioEncoderFilter> filter =
        std::make_shared<Pipeline::AudioEncoderFilter>("builtin.recorder.audioencoderfilter2",
            Pipeline::FilterType::FILTERTYPE_AENC);
    Status ret = dSoftbusOutputTest_->UpdateNext(filter, Pipeline::StreamType::STREAMTYPE_RAW_AUDIO);
    EXPECT_EQ(Status::OK, ret);
}

HWTEST_F(AvTransportAudioOutputFilterTest, UnLinkNext_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Pipeline::AudioEncoderFilter> filter =
        std::make_shared<Pipeline::AudioEncoderFilter>("builtin.recorder.audioencoderfilter2",
            Pipeline::FilterType::FILTERTYPE_AENC);
    Status ret = dSoftbusOutputTest_->UnLinkNext(filter, Pipeline::StreamType::STREAMTYPE_RAW_AUDIO);
    EXPECT_EQ(Status::OK, ret);
}

HWTEST_F(AvTransportAudioOutputFilterTest, OnLinked_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(dSoftbusOutputTest_ != nullptr);
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    Status ret = dSoftbusOutputTest_->OnLinked(Pipeline::StreamType::STREAMTYPE_RAW_AUDIO, meta, nullptr);
    EXPECT_EQ(Status::OK, ret);
}

HWTEST_F(AvTransportAudioOutputFilterTest, OnUpdated_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(dSoftbusOutputTest_ != nullptr);
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    Status ret = dSoftbusOutputTest_->OnUpdated(Pipeline::StreamType::STREAMTYPE_RAW_AUDIO, meta, nullptr);
    EXPECT_EQ(Status::OK, ret);
}

HWTEST_F(AvTransportAudioOutputFilterTest, OnUnLinked_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<Pipeline::AudioEncoderFilter> filter =
        std::make_shared<Pipeline::AudioEncoderFilter>("builtin.recorder.audioencoderfilter2",
            Pipeline::FilterType::FILTERTYPE_AENC);
    Status ret = dSoftbusOutputTest_->OnUnLinked(Pipeline::StreamType::STREAMTYPE_RAW_AUDIO, nullptr);
    EXPECT_EQ(Status::OK, ret);
}

} // namespace DistributedHardware
} // namespace OHOS