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

#include "av_receiver_engine.h"

#include "pipeline/factory/filter_factory.h"
#include "plugin_video_tags.h"

namespace OHOS {
namespace DistributedHardware {

using namespace OHOS::Media;
using namespace OHOS::Media::Plugin;
using namespace OHOS::Media::Pipeline;
using AVBuffer = OHOS::Media::Plugin::Buffer;

#undef DH_LOG_TAG
#define DH_LOG_TAG "AVReceiverEngine"

AVReceiverEngine::AVReceiverEngine(const std::string &ownerName, const std::string &peerDevId)
    : ownerName_(ownerName), peerDevId_(peerDevId)
{
    AVTRANS_LOGI("AVReceiverEngine ctor.");
    sessionName_ = ownerName_ + "_" + RECEIVER_CONTROL_SESSION_NAME_SUFFIX;
}

AVReceiverEngine::~AVReceiverEngine()
{
    AVTRANS_LOGI("AVReceiverEngine dctor.");
    Release();

    dhFwkKit_ = nullptr;
    pipeline_ = nullptr;
    avInput_ = nullptr;
    avOutput_ = nullptr;
    audioDecoder_ = nullptr;
    videoDecoder_ = nullptr;
    ctlCtrCallback_ = nullptr;
}

int32_t AVReceiverEngine::Initialize()
{
    TRUE_RETURN_V_MSG_E(isInitialized_.load(), DH_AVT_SUCCESS, "sender engine has been initialized");

    int32_t ret = InitPipeline();
    TRUE_RETURN_V_MSG_E(ret != DH_AVT_SUCCESS, ERR_DH_AVT_INIT_FAILED, "init pipeline failed");

    ret = InitControlCenter();
    TRUE_RETURN_V_MSG_E(ret != DH_AVT_SUCCESS, ERR_DH_AVT_INIT_FAILED, "init av control center failed");

    ret = SoftbusChannelAdapter::GetInstance().RegisterChannelListener(sessionName_, peerDevId_, this);
    TRUE_RETURN_V_MSG_E(ret != DH_AVT_SUCCESS, ERR_DH_AVT_INIT_FAILED, "register receiver channel callback failed");
    RegRespFunMap();
    isInitialized_ = true;
    SetCurrentState(StateId::INITIALIZED);
    return DH_AVT_SUCCESS;
}

int32_t AVReceiverEngine::InitPipeline()
{
    AVTRANS_LOGI("InitPipeline enter.");
    FilterFactory::Instance().Init();
    avInput_ = FilterFactory::Instance().CreateFilterWithType<AVInputFilter>(AVINPUT_NAME, "avinput");
    TRUE_RETURN_V_MSG_E(avInput_ == nullptr, ERR_DH_AVT_NULL_POINTER, "create av input filter failed");

    avOutput_ = FilterFactory::Instance().CreateFilterWithType<AVOutputFilter>(AVOUTPUT_NAME, "avoutput");
    TRUE_RETURN_V_MSG_E(avOutput_ == nullptr, ERR_DH_AVT_NULL_POINTER, "create av output filter failed");

    videoDecoder_ = FilterFactory::Instance().CreateFilterWithType<VideoDecoderFilter>(VDECODER_NAME, "videoDec");
    TRUE_RETURN_V_MSG_E(videoDecoder_ == nullptr, ERR_DH_AVT_NULL_POINTER, "create av video decoder filter failed");

    audioDecoder_ = FilterFactory::Instance().CreateFilterWithType<AudioDecoderFilter>(ADECODER_NAME, "audioDec");
    TRUE_RETURN_V_MSG_E(audioDecoder_ == nullptr, ERR_DH_AVT_NULL_POINTER, "create av audio decoder filter failed");

    ErrorCode ret;
    pipeline_ = std::make_shared<OHOS::Media::Pipeline::PipelineCore>();
    pipeline_->Init(this, nullptr);
    if ((ownerName_ == OWNER_NAME_D_SCREEN) || (ownerName_ == OWNER_NAME_D_CAMERA)) {
        ret = pipeline_->AddFilters({avInput_.get(), videoDecoder_.get(), avOutput_.get()});
        if (ret == ErrorCode::SUCCESS) {
            ret = pipeline_->LinkFilters({avInput_.get(), videoDecoder_.get(), avOutput_.get()});
        }
    } else if ((ownerName_ == OWNER_NAME_D_MIC) || (ownerName_ == OWNER_NAME_D_SPEAKER) ||
               (ownerName_ == OWNER_NAME_D_VIRMODEM_MIC) || (ownerName_ == OWNER_NAME_D_VIRMODEM_SPEAKER)) {
        ret = pipeline_->AddFilters({avInput_.get(), avOutput_.get()});
        if (ret == ErrorCode::SUCCESS) {
            ret = pipeline_->LinkFilters({avInput_.get(), avOutput_.get()});
        }
    } else {
        AVTRANS_LOGI("unsupport ownerName:%{public}s", ownerName_.c_str());
        return ERR_DH_AVT_INVALID_PARAM_VALUE;
    }
    if (ret != ErrorCode::SUCCESS) {
        pipeline_->RemoveFilterChain(avInput_.get());
    }
    return (ret == ErrorCode::SUCCESS) ? DH_AVT_SUCCESS : ERR_DH_AVT_INVALID_OPERATION;
}

int32_t AVReceiverEngine::InitControlCenter()
{
    dhFwkKit_ = std::make_shared<DistributedHardwareFwkKit>();
    int32_t ret = dhFwkKit_->InitializeAVCenter(TransRole::AV_RECEIVER, engineId_);
    TRUE_RETURN_V_MSG_E(ret != DH_AVT_SUCCESS, ERR_DH_AVT_CTRL_CENTER_INIT_FAIL, "init av trans control center failed");

    ctlCtrCallback_ = sptr<AVTransControlCenterCallback>(new (std::nothrow) AVTransControlCenterCallback());
    TRUE_RETURN_V_MSG_E(ctlCtrCallback_ == nullptr, ERR_DH_AVT_REGISTER_CALLBACK_FAIL,
        "new control center callback failed");

    std::shared_ptr<IAVReceiverEngine> engine = std::shared_ptr<AVReceiverEngine>(shared_from_this());
    ctlCtrCallback_->SetReceiverEngine(engine);

    ret = dhFwkKit_->RegisterCtlCenterCallback(engineId_, ctlCtrCallback_);
    TRUE_RETURN_V_MSG_E(ret != DH_AVT_SUCCESS, ERR_DH_AVT_REGISTER_CALLBACK_FAIL,
        "register control center callback failed");

    return DH_AVT_SUCCESS;
}

int32_t AVReceiverEngine::CreateControlChannel(const std::vector<std::string> &dstDevIds,
    const ChannelAttribute &attribution)
{
    (void)attribution;
    AVTRANS_LOGI("CreateControlChannel enter.");
    TRUE_RETURN_V_MSG_E(dstDevIds.empty(), ERR_DH_AVT_NULL_POINTER, "dst deviceId vector is empty");

    peerDevId_ = dstDevIds[0];
    int32_t ret = SoftbusChannelAdapter::GetInstance().RegisterChannelListener(sessionName_, peerDevId_, this);
    TRUE_RETURN_V_MSG_E(ret != DH_AVT_SUCCESS, ERR_DH_AVT_CREATE_CHANNEL_FAILED,
        "register receiver control channel callback failed");

    std::string peerSessName = ownerName_ + "_" + SENDER_CONTROL_SESSION_NAME_SUFFIX;
    ret = SoftbusChannelAdapter::GetInstance().OpenSoftbusChannel(sessionName_, peerSessName, peerDevId_);
    TRUE_RETURN_V(ret == ERR_DH_AVT_SESSION_HAS_OPENED, ERR_DH_AVT_CHANNEL_ALREADY_CREATED);
    TRUE_RETURN_V_MSG_E(ret != DH_AVT_SUCCESS, ERR_DH_AVT_CREATE_CHANNEL_FAILED,
        "create receiver control channel failed");
    return DH_AVT_SUCCESS;
}

int32_t AVReceiverEngine::PreparePipeline(const std::string &configParam)
{
    AVTRANS_LOGI("PreparePipeline enter.");

    StateId currentState = GetCurrentState();
    bool isErrState = ((currentState != StateId::INITIALIZED) && (currentState != StateId::CH_CREATED));
    TRUE_RETURN_V_MSG_E(isErrState, ERR_DH_AVT_PREPARE_FAILED,
        "current state=%{public}" PRId32 " is invalid.", currentState);

    TRUE_RETURN_V_MSG_E((avInput_ == nullptr) || (avOutput_ == nullptr), ERR_DH_AVT_PREPARE_FAILED,
        "av input or output filter is null");

    ErrorCode ret = avInput_->SetParameter(static_cast<int32_t>(Plugin::Tag::MEDIA_TYPE),
        TransName2MediaType(ownerName_));
    TRUE_RETURN_V(ret != ErrorCode::SUCCESS, ERR_DH_AVT_SET_PARAM_FAILED);

    ret = avInput_->SetParameter(static_cast<int32_t>(Plugin::Tag::VIDEO_BIT_STREAM_FORMAT),
        VideoBitStreamFormat::ANNEXB);
    TRUE_RETURN_V(ret != ErrorCode::SUCCESS, ERR_DH_AVT_SET_PARAM_FAILED);

    ret = avInput_->SetParameter(static_cast<int32_t>(Plugin::Tag::MEDIA_DESCRIPTION),
        BuildChannelDescription(ownerName_, peerDevId_));
    TRUE_RETURN_V(ret != ErrorCode::SUCCESS, ERR_DH_AVT_SET_PARAM_FAILED);

    if (pipeline_ == nullptr) {
        AVTRANS_LOGE("pipeline is nullptr.");
        return ERR_DH_AVT_SET_PARAM_FAILED;
    }
    ret = pipeline_->Prepare();
    TRUE_RETURN_V(ret != ErrorCode::SUCCESS, ERR_DH_AVT_PREPARE_FAILED);

    SetCurrentState(StateId::CH_CREATED);
    return DH_AVT_SUCCESS;
}

int32_t AVReceiverEngine::Start()
{
    AVTRANS_LOGI("Start enter.");

    bool isErrState = (GetCurrentState() != StateId::CH_CREATED);
    TRUE_RETURN_V_MSG_E(isErrState, ERR_DH_AVT_START_FAILED, "current state=%{public}" PRId32 " is invalid.",
        GetCurrentState());

    if (pipeline_ == nullptr) {
        AVTRANS_LOGE("pipeline is nullptr.");
        return ERR_DH_AVT_START_FAILED;
    }
    ErrorCode ret = pipeline_->Start();
    TRUE_RETURN_V(ret != ErrorCode::SUCCESS, ERR_DH_AVT_START_FAILED);
    SetCurrentState(StateId::STARTED);
    return DH_AVT_SUCCESS;
}

int32_t AVReceiverEngine::Stop()
{
    AVTRANS_LOGI("Stop enter.");
    if (pipeline_ == nullptr) {
        AVTRANS_LOGE("pipeline is nullptr.");
        return ERR_DH_AVT_START_FAILED;
    }
    ErrorCode ret = pipeline_->Stop();
    TRUE_RETURN_V(ret != ErrorCode::SUCCESS, ERR_DH_AVT_STOP_FAILED);
    SetCurrentState(StateId::STOPPED);
    return DH_AVT_SUCCESS;
}

int32_t AVReceiverEngine::Release()
{
    AVTRANS_LOGI("Release enter.");
    TRUE_RETURN_V(GetCurrentState() == StateId::IDLE, DH_AVT_SUCCESS);
    if (pipeline_ != nullptr) {
        pipeline_->Stop();
    }
    if (dhFwkKit_ != nullptr) {
        dhFwkKit_->ReleaseAVCenter(engineId_);
    }
    SoftbusChannelAdapter::GetInstance().CloseSoftbusChannel(sessionName_, peerDevId_);
    SoftbusChannelAdapter::GetInstance().UnRegisterChannelListener(sessionName_, peerDevId_);
    isInitialized_ = false;
    pipeline_ = nullptr;
    dhFwkKit_ = nullptr;
    avInput_ = nullptr;
    avOutput_ = nullptr;
    audioDecoder_ = nullptr;
    videoDecoder_ = nullptr;
    ctlCtrCallback_ = nullptr;
    SetCurrentState(StateId::IDLE);
    return DH_AVT_SUCCESS;
}

void AVReceiverEngine::SetParameterInner(AVTransTag tag, const std::string &value)
{
    switch (tag) {
        case AVTransTag::VIDEO_CODEC_TYPE:
            SetVideoCodecType(value);
            break;
        case AVTransTag::AUDIO_CODEC_TYPE:
            SetAudioCodecType(value);
            break;
        case AVTransTag::AUDIO_CHANNEL_MASK:
            SetAudioChannelMask(value);
            break;
        case AVTransTag::AUDIO_SAMPLE_RATE:
            SetAudioSampleRate(value);
            break;
        case AVTransTag::AUDIO_CHANNEL_LAYOUT:
            SetAudioChannelLayout(value);
            break;
        case AVTransTag::AUDIO_SAMPLE_FORMAT:
            SetAudioSampleFormat(value);
            break;
        case AVTransTag::AUDIO_FRAME_SIZE:
            SetAudioFrameSize(value);
            break;
        case AVTransTag::TIME_SYNC_RESULT:
            SetSyncResult(value);
            break;
        case AVTransTag::START_AV_SYNC:
            SetStartAvSync(value);
            break;
        case AVTransTag::STOP_AV_SYNC:
            SetStopAvSync(value);
            break;
        case AVTransTag::SHARED_MEMORY_FD:
            SetSharedMemoryFd(value);
            break;
        case AVTransTag::ENGINE_READY:
            SetEngineReady(value);
            break;
        default:
            break;
    }
}

int32_t AVReceiverEngine::SetParameter(AVTransTag tag, const std::string &value)
{
    bool isFilterNull = (avInput_ == nullptr) || (avOutput_ == nullptr) || (pipeline_ == nullptr);
    TRUE_RETURN_V_MSG_E(isFilterNull, ERR_DH_AVT_SETUP_FAILED, "filter or pipeline is null, set parameter failed.");
    AVTRANS_LOGI("AVTransTag=%{public}u.", tag);
    switch (tag) {
        case AVTransTag::VIDEO_WIDTH:
            SetVideoWidth(value);
            break;
        case AVTransTag::VIDEO_HEIGHT:
            SetVideoHeight(value);
            break;
        case AVTransTag::VIDEO_FRAME_RATE:
            SetVideoFrameRate(value);
            break;
        case AVTransTag::AUDIO_BIT_RATE:
            SetAudioBitRate(value);
            break;
        case AVTransTag::VIDEO_BIT_RATE:
            SetVideoBitRate(value);
            break;
        case AVTransTag::VIDEO_CODEC_TYPE:
        case AVTransTag::AUDIO_CODEC_TYPE:
        case AVTransTag::AUDIO_CHANNEL_MASK:
        case AVTransTag::AUDIO_SAMPLE_RATE:
        case AVTransTag::AUDIO_CHANNEL_LAYOUT:
        case AVTransTag::AUDIO_SAMPLE_FORMAT:
        case AVTransTag::AUDIO_FRAME_SIZE:
        case AVTransTag::TIME_SYNC_RESULT:
        case AVTransTag::START_AV_SYNC:
        case AVTransTag::STOP_AV_SYNC:
        case AVTransTag::SHARED_MEMORY_FD:
        case AVTransTag::ENGINE_READY:
            SetParameterInner(tag, value);
            break;
        default:
            AVTRANS_LOGE("AVTransTag %{public}u is undefined.", tag);
            return ERR_DH_AVT_INVALID_PARAM;
    }
    return DH_AVT_SUCCESS;
}

void AVReceiverEngine::RegRespFunMap()
{
    funcMap_[AVTransTag::VIDEO_WIDTH] = &AVReceiverEngine::SetVideoWidth;
    funcMap_[AVTransTag::VIDEO_HEIGHT] = &AVReceiverEngine::SetVideoHeight;
    funcMap_[AVTransTag::VIDEO_FRAME_RATE] = &AVReceiverEngine::SetVideoFrameRate;
    funcMap_[AVTransTag::AUDIO_BIT_RATE] = &AVReceiverEngine::SetAudioBitRate;
    funcMap_[AVTransTag::VIDEO_BIT_RATE] = &AVReceiverEngine::SetVideoBitRate;
    funcMap_[AVTransTag::VIDEO_CODEC_TYPE] = &AVReceiverEngine::SetVideoCodecType;
    funcMap_[AVTransTag::AUDIO_CODEC_TYPE] = &AVReceiverEngine::SetAudioCodecType;
    funcMap_[AVTransTag::AUDIO_CHANNEL_MASK] = &AVReceiverEngine::SetAudioChannelMask;
    funcMap_[AVTransTag::AUDIO_SAMPLE_RATE] = &AVReceiverEngine::SetAudioSampleRate;
    funcMap_[AVTransTag::AUDIO_CHANNEL_LAYOUT] = &AVReceiverEngine::SetAudioChannelLayout;
    funcMap_[AVTransTag::AUDIO_SAMPLE_FORMAT] = &AVReceiverEngine::SetAudioSampleFormat;
    funcMap_[AVTransTag::AUDIO_FRAME_SIZE] = &AVReceiverEngine::SetAudioFrameSize;
    funcMap_[AVTransTag::TIME_SYNC_RESULT] = &AVReceiverEngine::SetSyncResult;
    funcMap_[AVTransTag::START_AV_SYNC] = &AVReceiverEngine::SetStartAvSync;
    funcMap_[AVTransTag::STOP_AV_SYNC] = &AVReceiverEngine::SetStopAvSync;
    funcMap_[AVTransTag::SHARED_MEMORY_FD] = &AVReceiverEngine::SetSharedMemoryFd;
    funcMap_[AVTransTag::ENGINE_READY] = &AVReceiverEngine::SetEngineReady;
}

void AVReceiverEngine::SetVideoWidth(const std::string &value)
{
    if (avInput_ == nullptr) {
        AVTRANS_LOGE("avInput_ is nullptr.");
        return;
    }
    int intValue = 0;
    if (ConvertToInt(value, intValue)) {
        avInput_->SetParameter(static_cast<int32_t>(Plugin::Tag::VIDEO_WIDTH), intValue);
        AVTRANS_LOGI("SetParameter VIDEO_WIDTH success, video width = %{public}s", value.c_str());
    } else {
        AVTRANS_LOGI("SetParameter VIDEO_WIDTH failed, value conversion failed.");
    }
}

void AVReceiverEngine::SetVideoHeight(const std::string &value)
{
    if (avInput_ == nullptr) {
        AVTRANS_LOGE("avInput_ is nullptr.");
        return;
    }
    int intValue = 0;
    if (ConvertToInt(value, intValue)) {
        avInput_->SetParameter(static_cast<int32_t>(Plugin::Tag::VIDEO_HEIGHT), intValue);
        AVTRANS_LOGI("SetParameter VIDEO_HEIGHT success, video height = %{public}s", value.c_str());
    } else {
        AVTRANS_LOGI("SetParameter VIDEO_HEIGHT failed, value conversion failed.");
    }
}

void AVReceiverEngine::SetVideoFrameRate(const std::string &value)
{
    if (avInput_ == nullptr || avOutput_ == nullptr) {
        AVTRANS_LOGE("avInput_ or avOutput_ is nullptr.");
        return;
    }
    int intValue = 0;
    if (ConvertToInt(value, intValue)) {
        avInput_->SetParameter(static_cast<int32_t>(Plugin::Tag::VIDEO_FRAME_RATE), intValue);
        avOutput_->SetParameter(static_cast<int32_t>(Plugin::Tag::VIDEO_FRAME_RATE), intValue);
        AVTRANS_LOGI("SetParameter VIDEO_FRAME_RATE success, frame rate = %{public}s", value.c_str());
    } else {
        AVTRANS_LOGI("SetParameter VIDEO_FRAME_RATE failed, value conversion failed.");
    }
}

void AVReceiverEngine::SetAudioBitRate(const std::string &value)
{
    if (avInput_ == nullptr) {
        AVTRANS_LOGE("avInput_ is nullptr.");
        return;
    }
    int intValue = 0;
    if (ConvertToInt(value, intValue)) {
        avInput_->SetParameter(static_cast<int32_t>(Plugin::Tag::MEDIA_BITRATE), intValue);
        AVTRANS_LOGI("SetParameter MEDIA_BITRATE success, bit rate = %{public}s", value.c_str());
    } else {
        AVTRANS_LOGI("SetParameter MEDIA_BITRATE failed, value conversion failed.");
    }
}

void AVReceiverEngine::SetVideoBitRate(const std::string &value)
{
    if (avInput_ == nullptr) {
        AVTRANS_LOGE("avInput_ is nullptr.");
        return;
    }
    int intValue = 0;
    if (ConvertToInt(value, intValue)) {
        avInput_->SetParameter(static_cast<int32_t>(Plugin::Tag::MEDIA_BITRATE), intValue);
        AVTRANS_LOGI("SetParameter MEDIA_BITRATE success, bit rate = %{public}s", value.c_str());
    } else {
        AVTRANS_LOGI("SetParameter MEDIA_BITRATE failed, value conversion failed.");
    }
}

void AVReceiverEngine::SetVideoCodecType(const std::string &value)
{
    if (avInput_ == nullptr || avOutput_ == nullptr) {
        AVTRANS_LOGE("avInput_ or avOutput_ is nullptr.");
        return;
    }
    if (value == MIME_VIDEO_H264) {
        std::string mime = MEDIA_MIME_VIDEO_H264;
        avInput_->SetParameter(static_cast<int32_t>(Plugin::Tag::MIME), mime);
        mime = MEDIA_MIME_VIDEO_RAW;
        avOutput_->SetParameter(static_cast<int32_t>(Plugin::Tag::MIME), mime);
        AVTRANS_LOGI("SetParameter VIDEO_CODEC_TYPE = H264 success");
    } else if (value == MIME_VIDEO_H265) {
        std::string mime = MEDIA_MIME_VIDEO_H265;
        avInput_->SetParameter(static_cast<int32_t>(Plugin::Tag::MIME), mime);
        mime = MEDIA_MIME_VIDEO_RAW;
        avOutput_->SetParameter(static_cast<int32_t>(Plugin::Tag::MIME), mime);
        AVTRANS_LOGI("SetParameter VIDEO_CODEC_TYPE = H265 success");
    } else {
        AVTRANS_LOGE("SetParameter VIDEO_CODEC_TYPE failed, input value invalid.");
    }
}

void AVReceiverEngine::SetAudioCodecType(const std::string &value)
{
    if (avInput_ == nullptr || avOutput_ == nullptr) {
        AVTRANS_LOGE("avInput_ or avOutput_ is nullptr.");
        return;
    }
    std::string mime = MEDIA_MIME_AUDIO_AAC;
    avInput_->SetParameter(static_cast<int32_t>(Plugin::Tag::MIME), mime);
    mime = MEDIA_MIME_AUDIO_RAW;
    avOutput_->SetParameter(static_cast<int32_t>(Plugin::Tag::MIME), mime);
    AVTRANS_LOGI("SetParameter AUDIO_CODEC_TYPE = AAC success");
}

void AVReceiverEngine::SetAudioChannelMask(const std::string &value)
{
    if (avInput_ == nullptr || avOutput_ == nullptr) {
        AVTRANS_LOGE("avInput_ or avOutput_ is nullptr.");
        return;
    }
    int intValue = 0;
    if (ConvertToInt(value, intValue)) {
        avInput_->SetParameter(static_cast<int32_t>(Plugin::Tag::AUDIO_CHANNELS), intValue);
        avOutput_->SetParameter(static_cast<int32_t>(Plugin::Tag::AUDIO_CHANNELS), intValue);
        AVTRANS_LOGI("SetParameter AUDIO_CHANNELS success, audio channels = %{public}s", value.c_str());
    } else {
        AVTRANS_LOGI("SetParameter AUDIO_CHANNEL_LAYOUT failed, value conversion failed.");
    }
}

void AVReceiverEngine::SetAudioSampleRate(const std::string &value)
{
    if (avInput_ == nullptr || avOutput_ == nullptr) {
        AVTRANS_LOGE("avInput_ or avOutput_ is nullptr.");
        return;
    }
    int intValue = 0;
    if (ConvertToInt(value, intValue)) {
        avInput_->SetParameter(static_cast<int32_t>(Plugin::Tag::AUDIO_SAMPLE_RATE), intValue);
        avOutput_->SetParameter(static_cast<int32_t>(Plugin::Tag::AUDIO_SAMPLE_RATE), intValue);
        AVTRANS_LOGI("SetParameter AUDIO_SAMPLE_RATE success, audio sample rate = %{public}s", value.c_str());
    } else {
        AVTRANS_LOGI("SetParameter AUDIO_SAMPLE_RATE failed, value conversion failed.");
    }
}

void AVReceiverEngine::SetAudioChannelLayout(const std::string &value)
{
    if (avInput_ == nullptr || avOutput_ == nullptr) {
        AVTRANS_LOGE("avInput_ or avOutput_ is nullptr.");
        return;
    }
    int intValue = 0;
    if (ConvertToInt(value, intValue)) {
        avInput_->SetParameter(static_cast<int32_t>(Plugin::Tag::AUDIO_CHANNEL_LAYOUT), intValue);
        avOutput_->SetParameter(static_cast<int32_t>(Plugin::Tag::AUDIO_CHANNEL_LAYOUT), intValue);
        AVTRANS_LOGI("SetParameter AUDIO_CHANNEL_LAYOUT success, audio channel layout = %{public}s", value.c_str());
    } else {
        AVTRANS_LOGI("SetParameter AUDIO_CHANNEL_LAYOUT failed, value conversion failed.");
    }
}

void AVReceiverEngine::SetAudioSampleFormat(const std::string &value)
{
    if (avInput_ == nullptr) {
        AVTRANS_LOGE("avInput_ is nullptr.");
        return;
    }
    int intValue = 0;
    if (ConvertToInt(value, intValue)) {
        avInput_->SetParameter(static_cast<int32_t>(Plugin::Tag::AUDIO_SAMPLE_FORMAT), intValue);
        AVTRANS_LOGI("SetParameter AUDIO_SAMPLE_FORMAT success, audio sample format = %{public}s", value.c_str());
    } else {
        AVTRANS_LOGI("SetParameter AUDIO_SAMPLE_FORMAT failed, value conversion failed.");
    }
}

void AVReceiverEngine::SetAudioFrameSize(const std::string &value)
{
    if (avInput_ == nullptr) {
        AVTRANS_LOGE("avInput_ is nullptr.");
        return;
    }
    int intValue = 0;
    if (ConvertToInt(value, intValue)) {
        avInput_->SetParameter(static_cast<int32_t>(Plugin::Tag::AUDIO_SAMPLE_PER_FRAME), intValue);
        AVTRANS_LOGI("SetParameter AUDIO_SAMPLE_PER_FRAME success, audio sample per frame = %{public}s", value.c_str());
    } else {
        AVTRANS_LOGI("SetParameter AUDIO_SAMPLE_PER_FRAME failed, value conversion failed.");
    }
}

void AVReceiverEngine::SetSyncResult(const std::string &value)
{
    if (avOutput_ == nullptr) {
        AVTRANS_LOGE("avOutput_ is nullptr.");
        return;
    }
    avOutput_->SetParameter(static_cast<int32_t>(Plugin::Tag::USER_TIME_SYNC_RESULT), value);
    AVTRANS_LOGI("SetParameter USER_TIME_SYNC_RESULT success, time sync result = %{public}s", value.c_str());
}

void AVReceiverEngine::SetStartAvSync(const std::string &value)
{
    if (avOutput_ == nullptr) {
        AVTRANS_LOGE("avOutput_ is nullptr.");
        return;
    }
    avOutput_->SetParameter(static_cast<int32_t>(Plugin::Tag::USER_AV_SYNC_GROUP_INFO), value);
    AVTRANS_LOGI("SetParameter START_AV_SYNC success.");
}

void AVReceiverEngine::SetStopAvSync(const std::string &value)
{
    if (avOutput_ == nullptr) {
        AVTRANS_LOGE("avOutput_ is nullptr.");
        return;
    }
    avOutput_->SetParameter(static_cast<int32_t>(Plugin::Tag::USER_AV_SYNC_GROUP_INFO), value);
    AVTRANS_LOGI("SetParameter STOP_AV_SYNC success.");
}

void AVReceiverEngine::SetSharedMemoryFd(const std::string &value)
{
    if (avOutput_ == nullptr) {
        AVTRANS_LOGE("avOutput_ is nullptr.");
        return;
    }
    avOutput_->SetParameter(static_cast<int32_t>(Plugin::Tag::USER_SHARED_MEMORY_FD), value);
    AVTRANS_LOGI("SetParameter USER_SHARED_MEMORY_FD success, shared memory info = %{public}s", value.c_str());
}

void AVReceiverEngine::SetEngineReady(const std::string &value)
{
    int32_t ret = PreparePipeline(value);
    TRUE_LOG_MSG(ret != DH_AVT_SUCCESS, "SetParameter ENGINE_READY failed");
}

int32_t AVReceiverEngine::SendMessage(const std::shared_ptr<AVTransMessage> &message)
{
    TRUE_RETURN_V_MSG_E(message == nullptr, ERR_DH_AVT_INVALID_PARAM, "input message is nullptr.");
    std::string msgData = message->MarshalMessage();
    return SoftbusChannelAdapter::GetInstance().SendBytesData(sessionName_, message->dstDevId_, msgData);
}

int32_t AVReceiverEngine::RegisterReceiverCallback(const std::shared_ptr<IAVReceiverEngineCallback> &callback)
{
    AVTRANS_LOGI("RegisterReceiverCallback enter.");
    if (callback == nullptr) {
        AVTRANS_LOGE("RegisterReceiverCallback failed, receiver engine callback is nullptr.");
        return ERR_DH_AVT_INVALID_PARAM;
    }
    receiverCallback_ = callback;
    return DH_AVT_SUCCESS;
}

bool AVReceiverEngine::StartDumpMediaData()
{
    if (avInput_ == nullptr) {
        AVTRANS_LOGE("avInput_ is nullptr.");
        return false;
    }
    avInput_->SetParameter(static_cast<int32_t>(Plugin::Tag::SECTION_USER_SPECIFIC_START), true);
    return true;
}

bool AVReceiverEngine::StopDumpMediaData()
{
    if (avInput_ == nullptr) {
        AVTRANS_LOGE("avInput_ is nullptr.");
        return false;
    }
    avInput_->SetParameter(static_cast<int32_t>(Plugin::Tag::SECTION_USER_SPECIFIC_START), false);
    return true;
}

bool AVReceiverEngine::ReStartDumpMediaData()
{
    if (avInput_ == nullptr) {
        AVTRANS_LOGE("avInput_ is nullptr.");
        return false;
    }
    avInput_->SetParameter(static_cast<int32_t>(Plugin::Tag::SECTION_VIDEO_SPECIFIC_START), true);
    return true;
}

int32_t AVReceiverEngine::HandleOutputBuffer(std::shared_ptr<AVBuffer> &hisBuffer)
{
    StateId currentState = GetCurrentState();
    bool isErrState = (currentState != StateId::STARTED) && (currentState != StateId::PLAYING);
    TRUE_RETURN_V_MSG_E(isErrState, ERR_DH_AVT_OUTPUT_DATA_FAILED,
        "current state=%{public}" PRId32 " is invalid.", currentState);

    std::shared_ptr<AVTransBuffer> transBuffer = HiSBuffer2TransBuffer(hisBuffer);
    TRUE_RETURN_V(transBuffer == nullptr, ERR_DH_AVT_OUTPUT_DATA_FAILED);

    SetCurrentState(StateId::PLAYING);
    TRUE_RETURN_V(receiverCallback_ == nullptr, ERR_DH_AVT_OUTPUT_DATA_FAILED);
    return receiverCallback_->OnDataAvailable(transBuffer);
}

void AVReceiverEngine::OnChannelEvent(const AVTransEvent &event)
{
    AVTRANS_LOGI("OnChannelEvent enter. event type:%{public}" PRId32, event.type);
    TRUE_RETURN(receiverCallback_ == nullptr, "receiver callback is nullptr.");

    switch (event.type) {
        case EventType::EVENT_CHANNEL_OPENED: {
            SetCurrentState(StateId::CH_CREATED);
            receiverCallback_->OnReceiverEvent(event);
            break;
        }
        case EventType::EVENT_CHANNEL_OPEN_FAIL: {
            SetCurrentState(StateId::INITIALIZED);
            receiverCallback_->OnReceiverEvent(event);
            break;
        }
        case EventType::EVENT_CHANNEL_CLOSED: {
            StateId currentState = GetCurrentState();
            if ((currentState != StateId::IDLE) && (currentState != StateId::INITIALIZED)) {
                SetCurrentState(StateId::INITIALIZED);
                receiverCallback_->OnReceiverEvent(event);
            }
            break;
        }
        case EventType::EVENT_DATA_RECEIVED: {
            auto avMessage = std::make_shared<AVTransMessage>();
            TRUE_RETURN(!avMessage->UnmarshalMessage(event.content, event.peerDevId), "unmarshal message failed");
            receiverCallback_->OnMessageReceived(avMessage);
            break;
        }
        default:
            AVTRANS_LOGE("Invalid event type.");
    }
}

void AVReceiverEngine::OnStreamReceived(const StreamData *data, const StreamData *ext)
{
    (void)data;
    (void)ext;
}

void AVReceiverEngine::OnEvent(const OHOS::Media::Event &event)
{
    AVTRANS_LOGI("OnEvent enter. event type:%{public}s", GetEventName(event.type));
    TRUE_RETURN(receiverCallback_ == nullptr, "receiver callback is nullptr.");

    switch (event.type) {
        case OHOS::Media::EventType::EVENT_BUFFER_PROGRESS: {
            if (Plugin::Any::IsSameTypeWith<std::shared_ptr<AVBuffer>>(event.param)) {
                auto hisBuffer = Plugin::AnyCast<std::shared_ptr<AVBuffer>>(event.param);
                TRUE_RETURN(hisBuffer == nullptr, "hisBuffer is null");
                HandleOutputBuffer(hisBuffer);
            }
            break;
        }
        case OHOS::Media::EventType::EVENT_PLUGIN_EVENT: {
            Plugin::PluginEvent plugEvt = Plugin::AnyCast<Plugin::PluginEvent>(event.param);
            bool isPlaying = (GetCurrentState() == StateId::PLAYING);
            receiverCallback_->OnReceiverEvent(AVTransEvent{CastEventType(plugEvt.type, isPlaying), "", peerDevId_});
            break;
        }
        default:
            AVTRANS_LOGE("Invalid event type.");
    }
}
} // namespace DistributedHardware
} // namespace OHOS