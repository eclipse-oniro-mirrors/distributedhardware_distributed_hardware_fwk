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

#include "av_transport_input_filter_test.h"

#include "av_trans_constants.h"
#include "pipeline/filters/common/plugin_utils.h"
#include "pipeline/factory/filter_factory.h"
#include "plugin/common/plugin_attr_desc.h"
#include "pipeline/core/filter_base.h"
#include "pipeline/core/filter.h"

using namespace testing::ext;
using namespace OHOS::DistributedHardware;
using namespace std;

namespace OHOS {
namespace DistributedHardware {
const std::string FILTERNAME = "avinput";

void AvTransportInputFilterTest::SetUp()
{
}

void AvTransportInputFilterTest::TearDown()
{
}

void AvTransportInputFilterTest::SetUpTestCase()
{
}

void AvTransportInputFilterTest::TearDownTestCase()
{
}

HWTEST_F(AvTransportInputFilterTest, SetParameter_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    int32_t key = -1;
    Any value = VideoBitStreamFormat::ANNEXB;
    if (avInputTest_ == nullptr) {
        return;
    }
    ErrorCode ret = avInputTest_->SetParameter(key, value);
    EXPECT_EQ(ErrorCode::ERROR_INVALID_PARAMETER_VALUE, ret);
}

HWTEST_F(AvTransportInputFilterTest, SetParameter_002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    int32_t key = static_cast<int32_t>(Plugin::Tag::MIME);
    Any value = MEDIA_MIME_VIDEO_H264;
    if (avInputTest_ == nullptr) {
        return;
    }
    ErrorCode ret = avInputTest_->SetParameter(key, value);
    EXPECT_EQ(ErrorCode::SUCCESS, ret);

    avInputTest_->plugin_ =
        PluginManager::Instance().CreateGenericPlugin<AvTransInput, AvTransInputPlugin>("AVTransDaudioInputPlugin");
    ret = avInputTest_->SetParameter(key, value);
    EXPECT_EQ(ErrorCode::SUCCESS, ret);
}

HWTEST_F(AvTransportInputFilterTest, GetParameter_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    int32_t key = -1;
    Any value = VideoBitStreamFormat::ANNEXB;
    ErrorCode ret = avInputTest_->GetParameter(key, value);
    EXPECT_EQ(ErrorCode::ERROR_INVALID_PARAMETER_VALUE, ret);
}

HWTEST_F(AvTransportInputFilterTest, GetParameter_002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    int32_t key = static_cast<int32_t>(Plugin::Tag::MIME);
    Any value = VideoBitStreamFormat::ANNEXB;
    ErrorCode ret = avInputTest_->GetParameter(key, value);
    EXPECT_EQ(ErrorCode::SUCCESS, ret);
}

HWTEST_F(AvTransportInputFilterTest, Prepare_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    ErrorCode ret = avInputTest_->Prepare();
    EXPECT_EQ(ErrorCode::ERROR_INVALID_STATE, ret);
}

HWTEST_F(AvTransportInputFilterTest, Prepare_002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    avInputTest_->state_ = FilterState::INITIALIZED;
    ErrorCode ret = avInputTest_->Prepare();
    EXPECT_EQ(ErrorCode::ERROR_INVALID_PARAMETER_VALUE, ret);
}

HWTEST_F(AvTransportInputFilterTest, Start_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    ErrorCode ret = avInputTest_->Start();
    EXPECT_EQ(ErrorCode::ERROR_INVALID_STATE, ret);

    avInputTest_->state_ = FilterState::READY;
    ret = avInputTest_->Start();
    EXPECT_EQ(ErrorCode::ERROR_NULL_POINTER, ret);

    avInputTest_->state_ = FilterState::PAUSED;
    ret = avInputTest_->Start();
    EXPECT_EQ(ErrorCode::ERROR_NULL_POINTER, ret);
}

HWTEST_F(AvTransportInputFilterTest, Start_002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    avInputTest_->state_ = FilterState::READY;
    avInputTest_->plugin_ =
        PluginManager::Instance().CreateGenericPlugin<AvTransInput, AvTransInputPlugin>("AVTransDaudioInputPlugin");
    ErrorCode ret = avInputTest_->Start();
    EXPECT_EQ(ErrorCode::ERROR_INVALID_OPERATION, ret);
}

HWTEST_F(AvTransportInputFilterTest, Stop_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    ErrorCode ret = avInputTest_->Stop();
    EXPECT_EQ(ErrorCode::ERROR_NULL_POINTER, ret);
    avInputTest_->plugin_ =
        PluginManager::Instance().CreateGenericPlugin<AvTransInput, AvTransInputPlugin>("AVTransDaudioInputPlugin");

    avInputTest_->state_ = FilterState::READY;
    ret = avInputTest_->Stop();
    EXPECT_EQ(ErrorCode::SUCCESS, ret);

    avInputTest_->state_ = FilterState::PAUSED;
    ret = avInputTest_->Stop();
    EXPECT_EQ(ErrorCode::SUCCESS, ret);
}

HWTEST_F(AvTransportInputFilterTest, Stop_002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
    FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    avInputTest_->state_ = FilterState::RUNNING;
    avInputTest_->plugin_ =
        PluginManager::Instance().CreateGenericPlugin<AvTransInput, AvTransInputPlugin>("AVTransDaudioInputPlugin");
    ErrorCode ret = avInputTest_->Stop();
    EXPECT_EQ(ErrorCode::SUCCESS, ret);
}

HWTEST_F(AvTransportInputFilterTest, Pause_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    ErrorCode ret = avInputTest_->Pause();
    EXPECT_EQ(ErrorCode::ERROR_INVALID_STATE, ret);

    avInputTest_->state_ = FilterState::PAUSED;
    ret = avInputTest_->Pause();
    EXPECT_EQ(ErrorCode::SUCCESS, ret);
}

HWTEST_F(AvTransportInputFilterTest, Pause_002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    avInputTest_->state_ = FilterState::READY;
    ErrorCode ret = avInputTest_->Pause();
    EXPECT_EQ(ErrorCode::ERROR_NULL_POINTER, ret);

    avInputTest_->state_ = FilterState::RUNNING;
    ret = avInputTest_->Pause();
    EXPECT_EQ(ErrorCode::ERROR_NULL_POINTER, ret);
}

HWTEST_F(AvTransportInputFilterTest, Pause_003, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    avInputTest_->state_ = FilterState::RUNNING;
    avInputTest_->plugin_ =
        PluginManager::Instance().CreateGenericPlugin<AvTransInput, AvTransInputPlugin>("AVTransDaudioInputPlugin");
    ErrorCode ret = avInputTest_->Pause();
    EXPECT_EQ(ErrorCode::SUCCESS, ret);
}

HWTEST_F(AvTransportInputFilterTest, Resume_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    ErrorCode ret = avInputTest_->Resume();
    EXPECT_EQ(ErrorCode::ERROR_NULL_POINTER, ret);
}

HWTEST_F(AvTransportInputFilterTest, Resume_002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    avInputTest_->plugin_ =
        PluginManager::Instance().CreateGenericPlugin<AvTransInput, AvTransInputPlugin>("AVTransDaudioInputPlugin");
    ErrorCode ret = avInputTest_->Resume();
    EXPECT_EQ(ErrorCode::SUCCESS, ret);
}

HWTEST_F(AvTransportInputFilterTest, FindPlugin_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    ErrorCode ret = avInputTest_->FindPlugin();
    EXPECT_EQ(ErrorCode::ERROR_INVALID_PARAMETER_VALUE, ret);

    int32_t key = static_cast<int32_t>(Plugin::Tag::MIME);
    Any value = MEDIA_MIME_VIDEO_H264;
    avInputTest_->SetParameter(key, value);
    ret = avInputTest_->FindPlugin();
    EXPECT_EQ(ErrorCode::ERROR_INVALID_PARAMETER_VALUE, ret);

    value = MEDIA_MIME_VIDEO_RAW;
    avInputTest_->SetParameter(key, value);
    ret = avInputTest_->FindPlugin();
    EXPECT_NE(ErrorCode::ERROR_UNSUPPORTED_FORMAT, ret);
}

HWTEST_F(AvTransportInputFilterTest, DoNegotiate_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    CapabilitySet outCaps;
    bool ret = avInputTest_->DoNegotiate(outCaps);
    EXPECT_EQ(false, ret);

    Capability capability;
    outCaps.push_back(capability);
    ret = avInputTest_->DoNegotiate(outCaps);
    EXPECT_EQ(false, ret);
}

HWTEST_F(AvTransportInputFilterTest, CreatePlugin_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    std::shared_ptr<PluginInfo> selectedInfo = nullptr;
    ErrorCode ret = avInputTest_->CreatePlugin(selectedInfo);
    EXPECT_EQ(ErrorCode::ERROR_INVALID_PARAMETER_VALUE, ret);

    selectedInfo = std::make_shared<PluginInfo>();
    selectedInfo->name = "";
    ret = avInputTest_->CreatePlugin(selectedInfo);
    EXPECT_EQ(ErrorCode::ERROR_INVALID_PARAMETER_VALUE, ret);
}

HWTEST_F(AvTransportInputFilterTest, CreatePlugin_002, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    std::shared_ptr<PluginInfo> selectedInfo = std::make_shared<PluginInfo>();
    avInputTest_->plugin_ = nullptr;
    selectedInfo->name = "name";
    ErrorCode ret = avInputTest_->CreatePlugin(selectedInfo);
    EXPECT_EQ(ErrorCode::ERROR_INVALID_PARAMETER_VALUE, ret);

    selectedInfo->name = "AVTransDaudioInputPlugin";
    ret = avInputTest_->CreatePlugin(selectedInfo);
    EXPECT_EQ(ErrorCode::SUCCESS, ret);

    if (avInputTest_->pluginInfo_ == nullptr) {
        return;
    }
    avInputTest_->pluginInfo_->name = "name";
    avInputTest_->CreatePlugin(selectedInfo);
    EXPECT_EQ(ErrorCode::SUCCESS, ret);

    avInputTest_->CreatePlugin(selectedInfo);
    EXPECT_EQ(ErrorCode::SUCCESS, ret);
}

HWTEST_F(AvTransportInputFilterTest, ConfigMeta_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    Plugin::Meta meta;
    ErrorCode ret = avInputTest_->ConfigMeta(meta);
    EXPECT_EQ(ErrorCode::ERROR_NOT_EXISTED, ret);

    int32_t key = static_cast<int32_t>(Plugin::Tag::MIME);
    Any value = MEDIA_MIME_VIDEO_H264;
    avInputTest_->SetParameter(key, value);
    ret = avInputTest_->ConfigMeta(meta);
    EXPECT_EQ(ErrorCode::ERROR_NOT_EXISTED, ret);

    key = static_cast<int32_t>(Plugin::Tag::MEDIA_TYPE);
    avInputTest_->SetParameter(key, value);
    ret = avInputTest_->ConfigMeta(meta);
    EXPECT_EQ(ErrorCode::ERROR_NOT_EXISTED, ret);
}

HWTEST_F(AvTransportInputFilterTest, ConfigVideoMeta_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    Plugin::Meta meta;
    ErrorCode ret = avInputTest_->ConfigVideoMeta(meta);
    EXPECT_EQ(ErrorCode::SUCCESS, ret);

    int32_t key = static_cast<int32_t>(Plugin::Tag::VIDEO_WIDTH);
    int value = 100;
    avInputTest_->SetParameter(key, value);
    ret = avInputTest_->ConfigVideoMeta(meta);
    EXPECT_EQ(ErrorCode::SUCCESS, ret);

    key = static_cast<int32_t>(Plugin::Tag::VIDEO_HEIGHT);
    avInputTest_->SetParameter(key, value);
    ret = avInputTest_->ConfigVideoMeta(meta);
    EXPECT_EQ(ErrorCode::SUCCESS, ret);

    key = static_cast<int32_t>(Plugin::Tag::MEDIA_BITRATE);
    avInputTest_->SetParameter(key, value);
    ret = avInputTest_->ConfigVideoMeta(meta);
    EXPECT_EQ(ErrorCode::SUCCESS, ret);

    key = static_cast<int32_t>(Plugin::Tag::VIDEO_FRAME_RATE);
    avInputTest_->SetParameter(key, value);
    ret = avInputTest_->ConfigVideoMeta(meta);
    EXPECT_EQ(ErrorCode::SUCCESS, ret);

    key = static_cast<int32_t>(Plugin::Tag::VIDEO_BIT_STREAM_FORMAT);
    avInputTest_->SetParameter(key, value);
    ret = avInputTest_->ConfigVideoMeta(meta);
    EXPECT_EQ(ErrorCode::SUCCESS, ret);

    key = static_cast<int32_t>(Plugin::Tag::VIDEO_PIXEL_FORMAT);
    avInputTest_->SetParameter(key, value);
    ret = avInputTest_->ConfigVideoMeta(meta);
    EXPECT_EQ(ErrorCode::SUCCESS, ret);
}

HWTEST_F(AvTransportInputFilterTest, TransAudioChannelLayout_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    int layoutPtr = 3;
    OHOS::Media::Plugin::AudioChannelLayout ret = avInputTest_->TransAudioChannelLayout(layoutPtr);
    EXPECT_EQ(OHOS::Media::Plugin::AudioChannelLayout::UNKNOWN, ret);

    layoutPtr = 1;
    ret = avInputTest_->TransAudioChannelLayout(layoutPtr);
    EXPECT_EQ(OHOS::Media::Plugin::AudioChannelLayout::MONO, ret);
}

HWTEST_F(AvTransportInputFilterTest, TransAudioSampleFormat_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    int layoutPtr = 5;
    OHOS::Media::Plugin::AudioSampleFormat ret = avInputTest_->TransAudioSampleFormat(layoutPtr);
    EXPECT_EQ(OHOS::Media::Plugin::AudioSampleFormat::NONE, ret);

    layoutPtr = 1;
    ret = avInputTest_->TransAudioSampleFormat(layoutPtr);
    EXPECT_EQ(OHOS::Media::Plugin::AudioSampleFormat::S16, ret);
}

HWTEST_F(AvTransportInputFilterTest, ConfigAudioMeta_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    Plugin::Meta meta;
    int32_t key = static_cast<int32_t>(Plugin::Tag::AUDIO_CHANNELS);
    uint32_t value = 100;
    avInputTest_->SetParameter(key, value);
    ErrorCode ret = avInputTest_->ConfigAudioMeta(meta);
    EXPECT_EQ(ErrorCode::SUCCESS, ret);

    key = static_cast<int32_t>(Plugin::Tag::AUDIO_SAMPLE_RATE);
    avInputTest_->SetParameter(key, value);
    ret = avInputTest_->ConfigAudioMeta(meta);
    EXPECT_EQ(ErrorCode::SUCCESS, ret);

    key = static_cast<int32_t>(Plugin::Tag::MEDIA_BITRATE);
    avInputTest_->SetParameter(key, value);
    ret = avInputTest_->ConfigAudioMeta(meta);
    EXPECT_EQ(ErrorCode::SUCCESS, ret);

    key = static_cast<int32_t>(Plugin::Tag::AUDIO_SAMPLE_FORMAT);
    avInputTest_->SetParameter(key, value);
    ret = avInputTest_->ConfigAudioMeta(meta);
    EXPECT_EQ(ErrorCode::SUCCESS, ret);

    key = static_cast<int32_t>(Plugin::Tag::AUDIO_CHANNEL_LAYOUT);
    avInputTest_->SetParameter(key, value);
    ret = avInputTest_->ConfigAudioMeta(meta);
    EXPECT_EQ(ErrorCode::SUCCESS, ret);

    key = static_cast<int32_t>(Plugin::Tag::AUDIO_SAMPLE_PER_FRAME);
    avInputTest_->SetParameter(key, value);
    ret = avInputTest_->ConfigAudioMeta(meta);
    EXPECT_EQ(ErrorCode::SUCCESS, ret);

    key = static_cast<int32_t>(Plugin::Tag::AUDIO_AAC_LEVEL);
    avInputTest_->SetParameter(key, value);
    ret = avInputTest_->ConfigAudioMeta(meta);
    EXPECT_EQ(ErrorCode::SUCCESS, ret);
}

HWTEST_F(AvTransportInputFilterTest, ConfigDownStream_001, testing::ext::TestSize.Level1)
{
    auto avInputTest_ = FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    Plugin::Meta meta;
    ErrorCode ret = avInputTest_->ConfigDownStream(meta);
    EXPECT_EQ(ErrorCode::ERROR_INVALID_PARAMETER_VALUE, ret);
}

HWTEST_F(AvTransportInputFilterTest, InitPlugin_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    avInputTest_->plugin_ = nullptr;
    ErrorCode ret = avInputTest_->InitPlugin();
    EXPECT_EQ(ErrorCode::ERROR_INVALID_PARAMETER_VALUE, ret);

    avInputTest_->plugin_ =
        PluginManager::Instance().CreateGenericPlugin<AvTransInput, AvTransInputPlugin>("AVTransDaudioInputPlugin");
    ret = avInputTest_->InitPlugin();
    EXPECT_EQ(ErrorCode::SUCCESS, ret);
}

HWTEST_F(AvTransportInputFilterTest, ConfigPlugin_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    ErrorCode ret = avInputTest_->ConfigPlugin();
    EXPECT_EQ(ErrorCode::ERROR_NULL_POINTER, ret);

    avInputTest_->plugin_ =
        PluginManager::Instance().CreateGenericPlugin<AvTransInput, AvTransInputPlugin>("AVTransDaudioInputPlugin");
    ret = avInputTest_->ConfigPlugin();
    EXPECT_EQ(ErrorCode::SUCCESS, ret);
}

HWTEST_F(AvTransportInputFilterTest, SetPluginParams_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    ErrorCode ret = avInputTest_->SetPluginParams();
    EXPECT_EQ(ErrorCode::ERROR_NULL_POINTER, ret);
}

HWTEST_F(AvTransportInputFilterTest, SetPluginParams_002, testing::ext::TestSize.Level1)
{
    auto avInputTest_ = FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    avInputTest_->plugin_ =
        PluginManager::Instance().CreateGenericPlugin<AvTransInput, AvTransInputPlugin>("AVTransDaudioInputPlugin");
    avInputTest_->paramsMap_.clear();
    ErrorCode ret = avInputTest_->SetPluginParams();
    EXPECT_EQ(ErrorCode::SUCCESS, ret);

    int32_t key = static_cast<int32_t>(Plugin::Tag::MEDIA_DESCRIPTION);
    uint32_t value = 100;
    avInputTest_->SetParameter(key, value);
    ret = avInputTest_->SetPluginParams();
    EXPECT_EQ(ErrorCode::SUCCESS, ret);

    key = static_cast<int32_t>(Plugin::Tag::SECTION_USER_SPECIFIC_START);
    avInputTest_->SetParameter(key, value);
    ret = avInputTest_->SetPluginParams();
    EXPECT_EQ(ErrorCode::SUCCESS, ret);

    key = static_cast<int32_t>(Plugin::Tag::SECTION_VIDEO_SPECIFIC_START);
    avInputTest_->SetParameter(key, value);
    ret = avInputTest_->SetPluginParams();
    EXPECT_EQ(ErrorCode::SUCCESS, ret);
}

HWTEST_F(AvTransportInputFilterTest, PreparePlugin_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    ErrorCode ret = avInputTest_->PreparePlugin();
    EXPECT_EQ(ErrorCode::ERROR_NULL_POINTER, ret);

    avInputTest_->plugin_ =
        PluginManager::Instance().CreateGenericPlugin<AvTransInput, AvTransInputPlugin>("AVTransDaudioInputPlugin");
    ret = avInputTest_->PreparePlugin();
    EXPECT_NE(ErrorCode::SUCCESS, ret);
}

HWTEST_F(AvTransportInputFilterTest, PushData_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    std::string inPort;
    AVBufferPtr buffer;
    int64_t offset = 0;
    ErrorCode ret = avInputTest_->PushData(inPort, buffer, offset);
    EXPECT_EQ(ErrorCode::ERROR_INVALID_PARAMETER_VALUE, ret);
}

HWTEST_F(AvTransportInputFilterTest, SetEventCallBack_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    avInputTest_->plugin_ = nullptr;
    ErrorCode ret = avInputTest_->SetEventCallBack();
    EXPECT_EQ(ErrorCode::ERROR_NULL_POINTER, ret);

    avInputTest_->plugin_ =
        PluginManager::Instance().CreateGenericPlugin<AvTransInput, AvTransInputPlugin>("AVTransDaudioInputPlugin");
    ret = avInputTest_->SetEventCallBack();
    EXPECT_EQ(ErrorCode::SUCCESS, ret);
}

HWTEST_F(AvTransportInputFilterTest, SetDataCallBack_001, testing::ext::TestSize.Level1)
{
    std::shared_ptr<AVInputFilter> avInputTest_ =
        FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, FILTERNAME);
    if (avInputTest_ == nullptr) {
        return;
    }
    std::shared_ptr<Plugin::Buffer> buffer = nullptr;
    avInputTest_->OnDataCallback(buffer);
    avInputTest_->plugin_ = nullptr;
    ErrorCode ret = avInputTest_->SetDataCallBack();
    EXPECT_EQ(ErrorCode::ERROR_NULL_POINTER, ret);

    buffer = std::make_shared<AVBuffer>();
    avInputTest_->OnDataCallback(buffer);
    avInputTest_->plugin_ =
        PluginManager::Instance().CreateGenericPlugin<AvTransInput, AvTransInputPlugin>("AVTransDaudioInputPlugin");
    ret = avInputTest_->SetDataCallBack();
    EXPECT_EQ(ErrorCode::SUCCESS, ret);
}
} // namespace DistributedHardware
} // namespace OHOS