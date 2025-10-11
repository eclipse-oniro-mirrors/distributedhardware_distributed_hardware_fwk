/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "histreamer_ability_parser_test.h"

#include <vector>
#include <gtest/gtest.h>

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
static const std::uint16_t UINT16_ONE = 1;

static const std::string TEST_STR = "test string";
static const std::string KEY = "key";
static const std::string NAME = "name";
static const std::string MIME = "mime";
static const std::string INS = "ins";
static const std::string OUTS = "outs";
static const std::string AUDIO_ENCODER_NAME = "ffmpegAuEnc_aac";
static const std::string AUDIO_ENCODERIN_MIME = "audio/raw";
static const std::string AUDIO_ENCODEROUT_MIME = "audio/mp4a-latm";
static const std::string AD_MPEG_VER = "ad_mpeg_ver";
static const std::uint32_t AD_MPEG_VER_VALUE = 4;
static const std::string AUDIO_AAC_PROFILE = "aac_profile";
static const std::uint32_t AUDIO_AAC_PROFILE_VALUE = 0;
static const std::string AUDIO_AAC_STREAM_FORMAT = "aac_stm_fmt";

static const std::string AUDIO_DECODER_NAME = "ffmpegAuDec_aac";
static const std::string AUDIO_DECODERIN_MIME = "audio/mp4a-latm";
static const std::string AUDIO_DECODEROUT_MIME = "audio/raw";
static const std::string AUDIO_CHANNEL_LAYOUT = "channel_layout";
static const std::string AUDIO_SAMPLE_FORMAT = "sample_fmt";

static const std::string VIDEO_ENCODER_NAME = "HdiCodecAdapter.OMX.rk.video_encoder.hevc";
static const std::string VIDEO_ENCODERIN_MIME = "video/raw";
static const std::string VIDEO_ENCODEROUT_MIME = "video/hevc";

static const std::string VIDEO_DECODER_NAME = "HdiCodecAdapter.OMX.rk.video_decoder.hevc";
static const std::string VIDEO_DECODERIN_MIME = "video/hevc";
static const std::string VIDEO_DECODEROUT_MIME = "video/raw";

static const std::string SAMPLE_RATE = "sample_rate";
static const std::string VIDEO_PIXEL_FMT = "pixel_fmt";
static const std::string VIDEO_BIT_STREAM_FMT = "vd_bit_stream_fmt";

void HistreamerAbilityParserTest::SetUpTestCase(void) {}

void HistreamerAbilityParserTest::TearDownTestCase(void) {}

void HistreamerAbilityParserTest::SetUp() {}

void HistreamerAbilityParserTest::TearDown() {}

/**
 * @tc.name: FromJson_AudioEncoderIn
 * @tc.desc: Verify the FromJson(const cJSON *jsonObj, AudioEncoderIn &audioEncoderIn) function
 * @tc.type: FUNC
 * @tc.require: issuelI7MJPJ
 */
HWTEST_F(HistreamerAbilityParserTest, FromJson_AudioEncoderIn_001, TestSize.Level1)
{
    cJSON *json = nullptr;
    AudioEncoderIn audioEncoderIn;
    FromJson(json, audioEncoderIn);
    EXPECT_TRUE(audioEncoderIn.mime.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_AudioEncoderIn_002, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    ASSERT_TRUE(json != nullptr);
    cJSON_AddNumberToObject(json, MIME.c_str(), (double)(UINT16_ONE));
    AudioEncoderIn audioEncoderIn;
    FromJson(json, audioEncoderIn);
    cJSON_Delete(json);
    EXPECT_TRUE(audioEncoderIn.mime.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_AudioEncoderIn_003, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    ASSERT_TRUE(json != nullptr);
    cJSON_AddStringToObject(json, MIME.c_str(), "mime_test");
    AudioEncoderIn audioEncoderIn;
    FromJson(json, audioEncoderIn);
    cJSON_Delete(json);
    EXPECT_FALSE(audioEncoderIn.mime.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_AudioEncoderIn_004, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    ASSERT_TRUE(json != nullptr);
    cJSON_AddStringToObject(json, MIME.c_str(), "mime_test");
    cJSON_AddStringToObject(json, SAMPLE_RATE.c_str(), "sample_rate_test");
    AudioEncoderIn audioEncoderIn;
    FromJson(json, audioEncoderIn);
    cJSON_Delete(json);
    EXPECT_FALSE(audioEncoderIn.mime.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_AudioEncoderIn_005, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    ASSERT_TRUE(json != nullptr);
    cJSON *jsonArr = cJSON_CreateArray();
    if (jsonArr == nullptr) {
        cJSON_Delete(json);
        return;
    }
    cJSON_AddItemToArray(jsonArr, cJSON_CreateNumber(1));

    cJSON_AddStringToObject(json, MIME.c_str(), "mime_test");
    cJSON_AddItemToObject(json, SAMPLE_RATE.c_str(), jsonArr);
    AudioEncoderIn audioEncoderIn;
    FromJson(json, audioEncoderIn);
    cJSON_Delete(json);
    EXPECT_FALSE(audioEncoderIn.mime.empty());
}


HWTEST_F(HistreamerAbilityParserTest, FromJson_AudioEncoderIn_006, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    ASSERT_TRUE(json != nullptr);
    cJSON *jsonArr = cJSON_CreateArray();
    if (jsonArr == nullptr) {
        cJSON_Delete(json);
        return;
    }
    cJSON_AddItemToArray(jsonArr, cJSON_CreateString("sample_rate_test"));

    cJSON_AddStringToObject(json, MIME.c_str(), "mime_test");
    cJSON_AddItemToObject(json, SAMPLE_RATE.c_str(), jsonArr);
    AudioEncoderIn audioEncoderIn;
    FromJson(json, audioEncoderIn);
    cJSON_Delete(json);
    EXPECT_TRUE(audioEncoderIn.sample_rate.empty());
}

/**
 * @tc.name: FromJson_AudioEncoderOut
 * @tc.desc: Verify the FromJson(const cJSON *jsonObj, AudioEncoderOut &audioEncoderOut) function
 * @tc.type: FUNC
 * @tc.require: issuelI7MJPJ
 */
HWTEST_F(HistreamerAbilityParserTest, FromJson_AudioEncoderOut_001, TestSize.Level1)
{
    cJSON *json = nullptr;
    AudioEncoderOut audioEncoderOut;
    FromJson(json, audioEncoderOut);
    EXPECT_TRUE(audioEncoderOut.mime.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_AudioEncoderOut_002, TestSize.Level1)
{
    cJSON *json = cJSON_CreateObject();
    ASSERT_TRUE(json != nullptr);
    cJSON_AddNumberToObject(json, MIME.c_str(), (double)(UINT16_ONE));
    AudioEncoderOut audioEncoderOut;
    FromJson(json, audioEncoderOut);
    EXPECT_TRUE(audioEncoderOut.mime.empty());

    cJSON_ReplaceItemInObject(json, MIME.c_str(), cJSON_CreateString(AUDIO_ENCODEROUT_MIME.c_str()));
    cJSON_AddStringToObject(json, AD_MPEG_VER.c_str(), TEST_STR.c_str());
    FromJson(json, audioEncoderOut);
    EXPECT_EQ(AUDIO_ENCODEROUT_MIME, audioEncoderOut.mime);

    cJSON_ReplaceItemInObject(json, AD_MPEG_VER.c_str(), cJSON_CreateNumber((double)AD_MPEG_VER_VALUE));
    cJSON_AddStringToObject(json, AUDIO_AAC_PROFILE.c_str(), TEST_STR.c_str());
    FromJson(json, audioEncoderOut);
    EXPECT_EQ(AD_MPEG_VER_VALUE, (uint32_t)audioEncoderOut.ad_mpeg_ver);

    cJSON_ReplaceItemInObject(json, AUDIO_AAC_PROFILE.c_str(), cJSON_CreateNumber((double)AUDIO_AAC_PROFILE_VALUE));
    cJSON_AddStringToObject(json, AUDIO_AAC_STREAM_FORMAT.c_str(), TEST_STR.c_str());
    FromJson(json, audioEncoderOut);
    cJSON_Delete(json);
    EXPECT_EQ(AUDIO_AAC_PROFILE_VALUE, (uint32_t)audioEncoderOut.aac_profile);
}

/**
 * @tc.name: FromJson_AudioEncoder
 * @tc.desc: Verify the FromJson(const cJSON *jsonObj, AudioEncoder &audioEncoder) function
 * @tc.type: FUNC
 * @tc.require: issuelI7MJPJ
 */

HWTEST_F(HistreamerAbilityParserTest, FromJson_AudioEncoder_001, TestSize.Level1)
{
    cJSON *json = nullptr;
    AudioEncoder audioEncoder;
    FromJson(json, audioEncoder);
    EXPECT_TRUE(audioEncoder.name.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_AudioEncoder_002, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    cJSON_AddNumberToObject(jsonObject, NAME.c_str(), (double)(UINT16_ONE));
    AudioEncoder audioEncoder;
    FromJson(jsonObject, audioEncoder);
    EXPECT_TRUE(audioEncoder.name.empty());

    cJSON_ReplaceItemInObject(jsonObject, NAME.c_str(), cJSON_CreateString(AUDIO_ENCODER_NAME.c_str()));
    FromJson(jsonObject, audioEncoder);
    EXPECT_EQ(AUDIO_ENCODER_NAME, audioEncoder.name);
    EXPECT_TRUE(audioEncoder.ins.empty());

    AudioEncoderIn audioEncoderIn;
    audioEncoderIn.mime = AUDIO_ENCODERIN_MIME;
    audioEncoderIn.sample_rate = { 96000, 88200, 64000, 48000, 44100, 32000 };
    audioEncoder.ins.push_back(audioEncoderIn);
    FromJson(jsonObject, audioEncoder);
    cJSON_Delete(jsonObject);
    EXPECT_FALSE(audioEncoder.ins.empty());
    EXPECT_TRUE(audioEncoder.outs.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_AudioEncoder_003, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    cJSON_AddStringToObject(jsonObject, NAME.c_str(), "name_test");
    cJSON *jsonArr = cJSON_CreateArray();
    if (jsonArr == nullptr) {
        cJSON_Delete(jsonObject);
        return;
    }
    cJSON_AddItemToArray(jsonArr, cJSON_CreateNumber(1));
    cJSON_AddItemToObject(jsonObject, INS.c_str(), jsonArr);
    AudioEncoder audioEncoder;
    FromJson(jsonObject, audioEncoder);
    cJSON_Delete(jsonObject);
    EXPECT_TRUE(audioEncoder.outs.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_AudioEncoder_004, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    cJSON_AddStringToObject(jsonObject, NAME.c_str(), "name_test");
    cJSON *jsonArr1 = cJSON_CreateArray();
    if (jsonArr1 == nullptr) {
        cJSON_Delete(jsonObject);
        return;
    }
    cJSON_AddItemToArray(jsonArr1, cJSON_CreateNumber(1));
    cJSON_AddItemToObject(jsonObject, INS.c_str(), jsonArr1);

    cJSON *jsonArr2 = cJSON_CreateArray();
    if (jsonArr2 == nullptr) {
        cJSON_Delete(jsonObject);
        cJSON_Delete(jsonArr1);
        return;
    }
    cJSON_AddItemToArray(jsonArr2, cJSON_CreateNumber(1));
    cJSON_AddItemToObject(jsonObject, OUTS.c_str(), jsonArr2);
    AudioEncoder audioEncoder;
    FromJson(jsonObject, audioEncoder);
    cJSON_Delete(jsonObject);
    EXPECT_FALSE(audioEncoder.outs.empty());
}

/**
 * @tc.name: FromJson_audioDecoderIn
 * @tc.desc: Verify the FromJson(const cJSON *jsonObj, AudioDecoderIn &audioDecoderIn) function
 * @tc.type: FUNC
 * @tc.require: issuelI7MJPJ
 */

HWTEST_F(HistreamerAbilityParserTest, FromJson_audioDecoderIn_001, TestSize.Level1)
{
    cJSON *jsonObject = nullptr;
    AudioDecoderIn audioDecoderIn;
    FromJson(jsonObject, audioDecoderIn);
    EXPECT_TRUE(audioDecoderIn.mime.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_audioDecoderIn_002, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    AudioDecoderIn audioDecoderIn;
    cJSON_AddNumberToObject(jsonObject, MIME.c_str(), (double)(UINT16_ONE));
    FromJson(jsonObject, audioDecoderIn);
    EXPECT_TRUE(audioDecoderIn.mime.empty());

    cJSON_ReplaceItemInObject(jsonObject, MIME.c_str(), cJSON_CreateString(AUDIO_DECODERIN_MIME.c_str()));
    FromJson(jsonObject, audioDecoderIn);
    cJSON_Delete(jsonObject);
    EXPECT_EQ(AUDIO_DECODERIN_MIME, audioDecoderIn.mime);
    EXPECT_TRUE(audioDecoderIn.channel_layout.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_audioDecoderIn_003, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    AudioDecoderIn audioDecoderIn;
    cJSON_AddStringToObject(jsonObject, MIME.c_str(), "mime_test");
    cJSON *jsonArr = cJSON_CreateArray();
    if (jsonArr == nullptr) {
        cJSON_Delete(jsonObject);
        return;
    }
    cJSON_AddItemToArray(jsonArr, cJSON_CreateNumber(1));
    cJSON_AddItemToObject(jsonObject, AUDIO_CHANNEL_LAYOUT.c_str(), jsonArr);
    FromJson(jsonObject, audioDecoderIn);
    cJSON_Delete(jsonObject);
    EXPECT_FALSE(audioDecoderIn.channel_layout.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_audioDecoderIn_004, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    AudioDecoderIn audioDecoderIn;
    cJSON_AddStringToObject(jsonObject, MIME.c_str(), "mime_test");
    cJSON *jsonArr = cJSON_CreateArray();
    if (jsonArr == nullptr) {
        cJSON_Delete(jsonObject);
        return;
    }
    cJSON_AddItemToArray(jsonArr, cJSON_CreateString("audio_channel_layout_test"));
    cJSON_AddItemToObject(jsonObject, AUDIO_CHANNEL_LAYOUT.c_str(), jsonArr);
    FromJson(jsonObject, audioDecoderIn);
    cJSON_Delete(jsonObject);
    EXPECT_TRUE(audioDecoderIn.channel_layout.empty());
}

/**
 * @tc.name: FromJson_audioDecoderOut
 * @tc.desc: Verify the FromJson(const cJSON *jsonObj, AudioDecoderOut &audioDecoderOut) function
 * @tc.type: FUNC
 * @tc.require: issuelI7MJPJ
 */

HWTEST_F(HistreamerAbilityParserTest, FromJson_audioDecoderOut_001, TestSize.Level1)
{
    cJSON *jsonObject = nullptr;
    AudioDecoderOut audioDecoderOut;
    FromJson(jsonObject, audioDecoderOut);
    EXPECT_TRUE(audioDecoderOut.mime.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_audioDecoderOut_002, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    AudioDecoderOut audioDecoderOut;
    cJSON_AddNumberToObject(jsonObject, MIME.c_str(), (double)(UINT16_ONE));
    FromJson(jsonObject, audioDecoderOut);
    EXPECT_TRUE(audioDecoderOut.mime.empty());

    cJSON_ReplaceItemInObject(jsonObject, MIME.c_str(), cJSON_CreateString(AUDIO_DECODEROUT_MIME.c_str()));
    FromJson(jsonObject, audioDecoderOut);
    cJSON_Delete(jsonObject);
    EXPECT_EQ(AUDIO_DECODEROUT_MIME, audioDecoderOut.mime);
    EXPECT_TRUE(audioDecoderOut.sample_fmt.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_audioDecoderOut_003, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    AudioDecoderOut audioDecoderOut;
    cJSON_AddStringToObject(jsonObject, MIME.c_str(), "mime_test");
    cJSON *jsonArr = cJSON_CreateArray();
    if (jsonArr == nullptr) {
        cJSON_Delete(jsonObject);
        return;
    }
    cJSON_AddItemToArray(jsonArr, cJSON_CreateNumber(1));
    cJSON_AddItemToObject(jsonObject, AUDIO_SAMPLE_FORMAT.c_str(), jsonArr);
    FromJson(jsonObject, audioDecoderOut);
    cJSON_Delete(jsonObject);
    EXPECT_FALSE(audioDecoderOut.sample_fmt.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_audioDecoderOut_004, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    AudioDecoderOut audioDecoderOut;
    cJSON_AddStringToObject(jsonObject, MIME.c_str(), "mime_test");
    cJSON *jsonArr = cJSON_CreateArray();
    if (jsonArr == nullptr) {
        cJSON_Delete(jsonObject);
        return;
    }
    cJSON_AddItemToArray(jsonArr, cJSON_CreateString("audio_sample_format_test"));
    cJSON_AddItemToObject(jsonObject, AUDIO_SAMPLE_FORMAT.c_str(), jsonArr);
    FromJson(jsonObject, audioDecoderOut);
    cJSON_Delete(jsonObject);
    EXPECT_TRUE(audioDecoderOut.sample_fmt.empty());
}

/**
 * @tc.name: FromJson_audioDecoder
 * @tc.desc: Verify the FromJson(const cJSON *jsonObj, AudioDecoder &audioDecoder) function
 * @tc.type: FUNC
 * @tc.require: issuelI7MJPJ
 */

HWTEST_F(HistreamerAbilityParserTest, FromJson_audioDecoder_001, TestSize.Level1)
{
    cJSON *jsonObject = nullptr;
    AudioDecoder audioDecoder;
    FromJson(jsonObject, audioDecoder);
    EXPECT_TRUE(audioDecoder.name.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_audioDecoder_002, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    AudioDecoder audioDecoder;
    cJSON_AddNumberToObject(jsonObject, NAME.c_str(), (double)(UINT16_ONE));
    FromJson(jsonObject, audioDecoder);
    EXPECT_TRUE(audioDecoder.name.empty());

    cJSON_ReplaceItemInObject(jsonObject, NAME.c_str(), cJSON_CreateString(AUDIO_DECODER_NAME.c_str()));
    FromJson(jsonObject, audioDecoder);
    EXPECT_EQ(AUDIO_DECODER_NAME, audioDecoder.name);
    EXPECT_TRUE(audioDecoder.ins.empty());

    AudioDecoderIn audioDecoderIn;
    audioDecoderIn.mime = AUDIO_DECODERIN_MIME;
    audioDecoderIn.channel_layout = {
        AudioChannelLayout::CH_2POINT1,
        AudioChannelLayout::CH_2_1,
        AudioChannelLayout::SURROUND,
    };
    audioDecoder.ins.push_back(audioDecoderIn);
    FromJson(jsonObject, audioDecoder);
    cJSON_Delete(jsonObject);
    EXPECT_FALSE(audioDecoder.ins.empty());
    EXPECT_TRUE(audioDecoder.outs.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_audioDecoder_003, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    AudioDecoder audioDecoder;
    cJSON_AddStringToObject(jsonObject, NAME.c_str(), "name_test");
    cJSON *jsonArr1 = cJSON_CreateArray();
    if (jsonArr1 == nullptr) {
        cJSON_Delete(jsonObject);
        return;
    }
    cJSON_AddItemToArray(jsonArr1, cJSON_CreateNumber(1));
    cJSON_AddItemToObject(jsonObject, INS.c_str(), jsonArr1);

    cJSON *jsonArr2 = cJSON_CreateArray();
    if (jsonArr2 == nullptr) {
        cJSON_Delete(jsonObject);
        cJSON_Delete(jsonArr1);
        return;
    }
    cJSON_AddItemToArray(jsonArr2, cJSON_CreateNumber(1));
    cJSON_AddItemToObject(jsonObject, OUTS.c_str(), jsonArr2);
    FromJson(jsonObject, audioDecoder);
    cJSON_Delete(jsonObject);
    EXPECT_FALSE(audioDecoder.outs.empty());
}

/**
 * @tc.name: FromJson_videoEncoderIn
 * @tc.desc: Verify the FromJson(const cJSON *jsonObj, VideoEncoderIn &videoEncoderIn) function
 * @tc.type: FUNC
 * @tc.require: issuelI7MJPJ
 */

HWTEST_F(HistreamerAbilityParserTest, FromJson_videoEncoderIn_001, TestSize.Level1)
{
    cJSON *jsonObject = nullptr;
    VideoEncoderIn videoEncoderIn;
    FromJson(jsonObject, videoEncoderIn);
    EXPECT_TRUE(videoEncoderIn.mime.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_videoEncoderIn_002, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    VideoEncoderIn videoEncoderIn;
    cJSON_AddNumberToObject(jsonObject, MIME.c_str(), (double)(UINT16_ONE));
    FromJson(jsonObject, videoEncoderIn);
    EXPECT_TRUE(videoEncoderIn.mime.empty());

    cJSON_ReplaceItemInObject(jsonObject, MIME.c_str(), cJSON_CreateString(VIDEO_ENCODERIN_MIME.c_str()));
    FromJson(jsonObject, videoEncoderIn);
    cJSON_Delete(jsonObject);
    EXPECT_EQ(VIDEO_ENCODERIN_MIME, videoEncoderIn.mime);
    EXPECT_TRUE(videoEncoderIn.pixel_fmt.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_videoEncoderIn_003, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    VideoEncoderIn videoEncoderIn;
    cJSON_AddStringToObject(jsonObject, MIME.c_str(), "mime_test");
    cJSON *jsonArr = cJSON_CreateArray();
    if (jsonArr == nullptr) {
        cJSON_Delete(jsonObject);
        return;
    }
    cJSON_AddItemToArray(jsonArr, cJSON_CreateNumber(1));
    cJSON_AddItemToObject(jsonObject, VIDEO_PIXEL_FMT.c_str(), jsonArr);
    FromJson(jsonObject, videoEncoderIn);
    cJSON_Delete(jsonObject);
    EXPECT_FALSE(videoEncoderIn.pixel_fmt.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_videoEncoderIn_004, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    VideoEncoderIn videoEncoderIn;
    cJSON_AddStringToObject(jsonObject, MIME.c_str(), "mime_test");
    cJSON *jsonArr = cJSON_CreateArray();
    if (jsonArr == nullptr) {
        cJSON_Delete(jsonObject);
        return;
    }
    cJSON_AddItemToArray(jsonArr, cJSON_CreateString("video_pixel_fmt_test"));
    cJSON_AddItemToObject(jsonObject, VIDEO_PIXEL_FMT.c_str(), jsonArr);
    FromJson(jsonObject, videoEncoderIn);
    cJSON_Delete(jsonObject);
    EXPECT_TRUE(videoEncoderIn.pixel_fmt.empty());
}

/**
 * @tc.name: FromJson_videoEncoderOut
 * @tc.desc: Verify the FromJson(const cJSON *jsonObj, VideoEncoderOut &videoEncoderOut) function
 * @tc.type: FUNC
 * @tc.require: issuelI7MJPJ
 */

HWTEST_F(HistreamerAbilityParserTest, FromJson_videoEncoderOut_001, TestSize.Level1)
{
    cJSON *jsonObject = nullptr;
    VideoEncoderOut videoEncoderOut;
    FromJson(jsonObject, videoEncoderOut);
    EXPECT_TRUE(videoEncoderOut.mime.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_videoEncoderOut_002, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    VideoEncoderOut videoEncoderOut;
    cJSON_AddNumberToObject(jsonObject, MIME.c_str(), (double)(UINT16_ONE));
    FromJson(jsonObject, videoEncoderOut);
    cJSON_Delete(jsonObject);
    EXPECT_TRUE(videoEncoderOut.mime.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_videoEncoderOut_003, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    VideoEncoderOut videoEncoderOut;
    cJSON_AddStringToObject(jsonObject, MIME.c_str(), "MIME_test");
    FromJson(jsonObject, videoEncoderOut);
    cJSON_Delete(jsonObject);
    EXPECT_FALSE(videoEncoderOut.mime.empty());
}

/**
 * @tc.name: FromJson_VideoEncoder
 * @tc.desc: Verify the FromJson(const cJSON *jsonObj, VideoEncoder &videoEncoder) function
 * @tc.type: FUNC
 * @tc.require: issuelI7MJPJ
 */

HWTEST_F(HistreamerAbilityParserTest, FromJson_VideoEncoder_001, TestSize.Level1)
{
    cJSON *jsonObject = nullptr;
    VideoEncoder videoEncoder;
    FromJson(jsonObject, videoEncoder);
    EXPECT_TRUE(videoEncoder.name.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_VideoEncoder_002, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    VideoEncoder videoEncoder;
    cJSON_AddNumberToObject(jsonObject, NAME.c_str(), (double)(UINT16_ONE));
    FromJson(jsonObject, videoEncoder);
    EXPECT_TRUE(videoEncoder.name.empty());

    cJSON_ReplaceItemInObject(jsonObject, NAME.c_str(), cJSON_CreateString(VIDEO_ENCODER_NAME.c_str()));
    FromJson(jsonObject, videoEncoder);
    EXPECT_EQ(VIDEO_ENCODER_NAME, videoEncoder.name);
    EXPECT_TRUE(videoEncoder.ins.empty());

    VideoEncoderIn videoEncoderIn;
    videoEncoderIn.mime = VIDEO_ENCODERIN_MIME;
    videoEncoderIn.pixel_fmt = {
        VideoPixelFormat::YUV410P,
        VideoPixelFormat::RGBA,
    };
    videoEncoder.ins.push_back(videoEncoderIn);
    FromJson(jsonObject, videoEncoder);

    cJSON_Delete(jsonObject);
    EXPECT_FALSE(videoEncoder.ins.empty());
    EXPECT_TRUE(videoEncoder.outs.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_VideoEncoder_003, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    VideoEncoder videoEncoder;
    cJSON_AddStringToObject(jsonObject, NAME.c_str(), "name_test");
    cJSON *jsonArr1 = cJSON_CreateArray();
    if (jsonArr1 == nullptr) {
        cJSON_Delete(jsonObject);
        return;
    }
    cJSON_AddItemToArray(jsonArr1, cJSON_CreateNumber(1));
    cJSON_AddItemToObject(jsonObject, INS.c_str(), jsonArr1);

    cJSON *jsonArr2 = cJSON_CreateArray();
    if (jsonArr2 == nullptr) {
        cJSON_Delete(jsonObject);
        cJSON_Delete(jsonArr1);
        return;
    }
    cJSON_AddItemToArray(jsonArr2, cJSON_CreateNumber(1));
    cJSON_AddItemToObject(jsonObject, OUTS.c_str(), jsonArr2);
    FromJson(jsonObject, videoEncoder);
    cJSON_Delete(jsonObject);
    EXPECT_FALSE(videoEncoder.outs.empty());
}

/**
 * @tc.name: FromJson_VideoDecoderIn
 * @tc.desc: Verify the FromJson(const cJSON *jsonObj, VideoDecoderIn &videoDecoderIn) function
 * @tc.type: FUNC
 * @tc.require: issuelI7MJPJ
 */

HWTEST_F(HistreamerAbilityParserTest, FromJson_VideoDecoderIn_001, TestSize.Level1)
{
    cJSON *jsonObject = nullptr;
    VideoDecoderIn videoDecoderIn;
    FromJson(jsonObject, videoDecoderIn);
    EXPECT_TRUE(videoDecoderIn.mime.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_VideoDecoderIn_002, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    VideoDecoderIn videoDecoderIn;
    cJSON_AddNumberToObject(jsonObject, MIME.c_str(), (double)(UINT16_ONE));
    FromJson(jsonObject, videoDecoderIn);
    EXPECT_TRUE(videoDecoderIn.mime.empty());

    cJSON_ReplaceItemInObject(jsonObject, MIME.c_str(), cJSON_CreateString(VIDEO_DECODERIN_MIME.c_str()));
    FromJson(jsonObject, videoDecoderIn);
    cJSON_Delete(jsonObject);
    EXPECT_EQ(VIDEO_DECODERIN_MIME, videoDecoderIn.mime);
    EXPECT_TRUE(videoDecoderIn.vd_bit_stream_fmt.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_VideoDecoderIn_003, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    VideoDecoderIn videoDecoderIn;
    cJSON_AddStringToObject(jsonObject, MIME.c_str(), "mime_test");
    cJSON *jsonArr = cJSON_CreateArray();
    if (jsonArr == nullptr) {
        cJSON_Delete(jsonObject);
        return;
    }
    cJSON_AddItemToArray(jsonArr, cJSON_CreateNumber(1));
    cJSON_AddItemToObject(jsonObject, VIDEO_BIT_STREAM_FMT.c_str(), jsonArr);
    FromJson(jsonObject, videoDecoderIn);
    cJSON_Delete(jsonObject);
    EXPECT_FALSE(videoDecoderIn.vd_bit_stream_fmt.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_VideoDecoderIn_004, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    VideoDecoderIn videoDecoderIn;
    cJSON_AddStringToObject(jsonObject, MIME.c_str(), "mime_test");
    cJSON *jsonArr = cJSON_CreateArray();
    if (jsonArr == nullptr) {
        cJSON_Delete(jsonObject);
        return;
    }
    cJSON_AddItemToArray(jsonArr, cJSON_CreateString("video_bit_stream_fmt_test"));
    cJSON_AddItemToObject(jsonObject, VIDEO_BIT_STREAM_FMT.c_str(), jsonArr);
    FromJson(jsonObject, videoDecoderIn);
    cJSON_Delete(jsonObject);
    EXPECT_TRUE(videoDecoderIn.vd_bit_stream_fmt.empty());
}

/**
 * @tc.name: FromJson_VideoDecoderOut
 * @tc.desc: Verify the FromJson(const cJSON *jsonObj, VideoDecoderOut &videoDecoderOut) function
 * @tc.type: FUNC
 * @tc.require: issuelI7MJPJ
 */

HWTEST_F(HistreamerAbilityParserTest, FromJson_VideoDecoderOut_001, TestSize.Level1)
{
    cJSON *jsonObject = nullptr;
    VideoDecoderOut videoDecoderOut;
    FromJson(jsonObject, videoDecoderOut);
    EXPECT_TRUE(videoDecoderOut.mime.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_VideoDecoderOut_002, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    VideoDecoderOut videoDecoderOut;
    cJSON_AddNumberToObject(jsonObject, MIME.c_str(), (double)(UINT16_ONE));
    FromJson(jsonObject, videoDecoderOut);
    EXPECT_TRUE(videoDecoderOut.mime.empty());

    cJSON_ReplaceItemInObject(jsonObject, MIME.c_str(), cJSON_CreateString(VIDEO_DECODEROUT_MIME.c_str()));
    FromJson(jsonObject, videoDecoderOut);
    cJSON_Delete(jsonObject);
    EXPECT_EQ(VIDEO_DECODEROUT_MIME, videoDecoderOut.mime);
    EXPECT_TRUE(videoDecoderOut.pixel_fmt.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_VideoDecoderOut_003, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    VideoDecoderOut videoDecoderOut;
    cJSON_AddStringToObject(jsonObject, MIME.c_str(), "mime_test");
    cJSON *jsonArr = cJSON_CreateArray();
    if (jsonArr == nullptr) {
        cJSON_Delete(jsonObject);
        return;
    }
    cJSON_AddItemToArray(jsonArr, cJSON_CreateNumber(1));
    cJSON_AddItemToObject(jsonObject, VIDEO_PIXEL_FMT.c_str(), jsonArr);
    FromJson(jsonObject, videoDecoderOut);
    cJSON_Delete(jsonObject);
    EXPECT_FALSE(videoDecoderOut.pixel_fmt.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_VideoDecoderOut_004, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    VideoDecoderOut videoDecoderOut;
    cJSON_AddStringToObject(jsonObject, MIME.c_str(), "mime_test");
    cJSON *jsonArr = cJSON_CreateArray();
    if (jsonArr == nullptr) {
        cJSON_Delete(jsonObject);
        return;
    }
    cJSON_AddItemToArray(jsonArr, cJSON_CreateString("video_pixel_fmt_test"));
    cJSON_AddItemToObject(jsonObject, VIDEO_PIXEL_FMT.c_str(), jsonArr);
    FromJson(jsonObject, videoDecoderOut);
    cJSON_Delete(jsonObject);
    EXPECT_TRUE(videoDecoderOut.pixel_fmt.empty());
}

/**
 * @tc.name: FromJson_VideoDecoder
 * @tc.desc: Verify the FromJson(const cJSON *jsonObj, VideoDecoder &videoDecoder) function
 * @tc.type: FUNC
 * @tc.require: issuelI7MJPJ
 */
HWTEST_F(HistreamerAbilityParserTest, FromJson_VideoDecoder_001, TestSize.Level1)
{
    cJSON *jsonObject = nullptr;
    VideoDecoder videoDecoder;
    FromJson(jsonObject, videoDecoder);
    EXPECT_TRUE(videoDecoder.name.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_VideoDecoder_002, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    VideoDecoder videoDecoder;
    cJSON_AddNumberToObject(jsonObject, NAME.c_str(), (double)(UINT16_ONE));
    FromJson(jsonObject, videoDecoder);
    EXPECT_TRUE(videoDecoder.name.empty());

    cJSON_ReplaceItemInObject(jsonObject, NAME.c_str(), cJSON_CreateString(VIDEO_DECODER_NAME.c_str()));
    FromJson(jsonObject, videoDecoder);
    EXPECT_EQ(VIDEO_DECODER_NAME, videoDecoder.name);
    EXPECT_TRUE(videoDecoder.ins.empty());

    VideoDecoderIn videoDecoderIn;
    videoDecoderIn.mime = VIDEO_DECODERIN_MIME;
    videoDecoderIn.vd_bit_stream_fmt = {
        VideoBitStreamFormat::AVC1,
        VideoBitStreamFormat::HEVC,
    };
    videoDecoder.ins.push_back(videoDecoderIn);
    FromJson(jsonObject, videoDecoder);
    cJSON_Delete(jsonObject);
    EXPECT_FALSE(videoDecoder.ins.empty());
    EXPECT_TRUE(videoDecoder.outs.empty());
}

HWTEST_F(HistreamerAbilityParserTest, FromJson_VideoDecoder_003, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    VideoDecoder videoDecoder;
    cJSON_AddStringToObject(jsonObject, NAME.c_str(), "name_test");
    cJSON *jsonArr1 = cJSON_CreateArray();
    if (jsonArr1 == nullptr) {
        cJSON_Delete(jsonObject);
        return;
    }
    cJSON_AddItemToArray(jsonArr1, cJSON_CreateNumber(1));
    cJSON_AddItemToObject(jsonObject, INS.c_str(), jsonArr1);

    cJSON *jsonArr2 = cJSON_CreateArray();
    if (jsonArr2 == nullptr) {
        cJSON_Delete(jsonObject);
        cJSON_Delete(jsonArr1);
        return;
    }
    cJSON_AddItemToArray(jsonArr2, cJSON_CreateNumber(1));
    cJSON_AddItemToObject(jsonObject, OUTS.c_str(), jsonArr2);

    FromJson(jsonObject, videoDecoder);
    EXPECT_FALSE(videoDecoder.name.empty());
}

/**
 * @tc.name: histreamer_ability_parser_test_013
 * @tc.desc: Verify the FromJson<AudioEncoder> function
 * @tc.type: FUNC
 * @tc.require: issuelI7MJPJ
 */
HWTEST_F(HistreamerAbilityParserTest, histreamer_ability_parser_test_013, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    AudioEncoder audioEncoder;
    cJSON_AddStringToObject(jsonObject, NAME.c_str(), AUDIO_ENCODER_NAME.c_str());
    audioEncoder.name = AUDIO_ENCODER_NAME;
    std::vector<AudioEncoder>audioEncoders;
    
    FromJson(VIDEO_PIXEL_FMT, jsonObject, audioEncoders);
    EXPECT_TRUE(audioEncoders.empty());

    FromJson(NAME, jsonObject, audioEncoders);
    cJSON_Delete(jsonObject);
    EXPECT_FALSE(audioEncoders.empty());
}

/**
 * @tc.name: histreamer_ability_parser_test_014
 * @tc.desc: Verify the FromJson<AudioDecoder> function
 * @tc.type: FUNC
 * @tc.require: issuelI7MJPJ
 */
HWTEST_F(HistreamerAbilityParserTest, histreamer_ability_parser_test_014, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    AudioDecoder audioDecoder;
    cJSON_AddStringToObject(jsonObject, NAME.c_str(), AUDIO_DECODER_NAME.c_str());
    audioDecoder.name = AUDIO_DECODER_NAME;
    std::vector<AudioDecoder>audioDecoders;

    FromJson(VIDEO_PIXEL_FMT, jsonObject, audioDecoders);
    EXPECT_TRUE(audioDecoders.empty());

    FromJson(NAME, jsonObject, audioDecoders);
    cJSON_Delete(jsonObject);
    EXPECT_FALSE(audioDecoders.empty());
}

/**
 * @tc.name: histreamer_ability_parser_test_015
 * @tc.desc: Verify the FromJson<VideoEncoder> function
 * @tc.type: FUNC
 * @tc.require: issuelI7MJPJ
 */
HWTEST_F(HistreamerAbilityParserTest, histreamer_ability_parser_test_015, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    VideoEncoder videoEncoder;
    cJSON_AddStringToObject(jsonObject, NAME.c_str(), VIDEO_ENCODER_NAME.c_str());
    videoEncoder.name = VIDEO_ENCODER_NAME;
    std::vector<VideoEncoder>videoEncoders;

    FromJson(AUDIO_AAC_PROFILE, jsonObject, videoEncoders);
    EXPECT_TRUE(videoEncoders.empty());

    FromJson(NAME, jsonObject, videoEncoders);
    cJSON_Delete(jsonObject);
    EXPECT_FALSE(videoEncoders.empty());
}

/**
 * @tc.name: histreamer_ability_parser_test_016
 * @tc.desc: Verify the FromJson<VideoDecoder> function
 * @tc.type: FUNC
 * @tc.require: issuelI7MJPJ
 */
HWTEST_F(HistreamerAbilityParserTest, histreamer_ability_parser_test_016, TestSize.Level1)
{
    cJSON *jsonObject = cJSON_CreateObject();
    ASSERT_TRUE(jsonObject != nullptr);
    VideoDecoder videoDecoder;
    cJSON_AddStringToObject(jsonObject, NAME.c_str(), VIDEO_DECODER_NAME.c_str());
    videoDecoder.name = VIDEO_DECODER_NAME;
    std::vector<VideoDecoder>videoDecoders;

    FromJson(AUDIO_AAC_PROFILE, jsonObject, videoDecoders);
    EXPECT_TRUE(videoDecoders.empty());

    FromJson(NAME, jsonObject, videoDecoders);
    cJSON_Delete(jsonObject);
    EXPECT_FALSE(videoDecoders.empty());
}
} // namespace DistributedHardware
} // namespace OHOS
