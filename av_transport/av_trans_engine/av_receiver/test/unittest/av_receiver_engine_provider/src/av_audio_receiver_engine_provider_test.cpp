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

#include "av_audio_receiver_engine_provider_test.h"

#include "av_audio_receiver_engine.h"

using namespace testing::ext;
using namespace OHOS::DistributedHardware;
using namespace std;

namespace OHOS {
namespace DistributedHardware {

void AvAudioReceiverEngineProviderTest::SetUp()
{
}

void AvAudioReceiverEngineProviderTest::TearDown()
{
}

void AvAudioReceiverEngineProviderTest::SetUpTestCase()
{
}

void AvAudioReceiverEngineProviderTest::TearDownTestCase()
{
}

class IAVReceiverEngineProvider : public IAVEngineProviderCallback {
public:
    virtual int32_t OnProviderEvent(const AVTransEvent &event)
    {
        (void)event;
        return DH_AVT_SUCCESS;
    }
};

HWTEST_F(AvAudioReceiverEngineProviderTest, CreateAVReceiverEngine_001, testing::ext::TestSize.Level1)
{
    std::string peerDevId = "peerDevId";
    std::string ownerName = "ownerName";
    auto avReceiveProTest_ = std::make_shared<AVAudioReceiverEngineProvider>(ownerName);
    auto avReceiverEngine = avReceiveProTest_->CreateAVReceiverEngine(peerDevId);
    EXPECT_EQ(nullptr, avReceiverEngine);
}

HWTEST_F(AvAudioReceiverEngineProviderTest, GetAVReceiverEngineList_001, testing::ext::TestSize.Level1)
{
    std::string peerDevId = "peerDevId";
    std::string ownerName = "ownerName";
    auto avReceiveProTest_ = std::make_shared<AVAudioReceiverEngineProvider>(ownerName);
    auto avReceiverEngine = avReceiveProTest_->CreateAVReceiverEngine(peerDevId);
    std::vector<std::shared_ptr<IAVReceiverEngine>> receiverEngineList = avReceiveProTest_->GetAVReceiverEngineList();
    bool bRet = (receiverEngineList.empty()) ? false : true;
    EXPECT_NE(true, bRet);
}

HWTEST_F(AvAudioReceiverEngineProviderTest, GetAVReceiverEngineList_002, testing::ext::TestSize.Level1)
{
    std::string peerDevId = "peerDevId";
    std::string ownerName = "ownerName";
    auto avReceiveProTest_ = std::make_shared<AVAudioReceiverEngineProvider>(ownerName);
    auto avReceiverEngine = avReceiveProTest_->CreateAVReceiverEngine(peerDevId);
    auto receiver = std::make_shared<AVAudioReceiverEngine>(ownerName, peerDevId);
    avReceiveProTest_->receiverEngineList_.push_back(receiver);
    std::vector<std::shared_ptr<IAVReceiverEngine>> receiverEngineList = avReceiveProTest_->GetAVReceiverEngineList();
    bool bRet = (receiverEngineList.empty()) ? false : true;
    EXPECT_EQ(true, bRet);
}

HWTEST_F(AvAudioReceiverEngineProviderTest, RegisterProviderCallback_001, testing::ext::TestSize.Level1)
{
    std::string ownerName = "ownerName";
    auto avReceiveProTest_ = std::make_shared<AVAudioReceiverEngineProvider>(ownerName);
    std::shared_ptr<IAVEngineProviderCallback> callback = nullptr;
    int32_t ret = avReceiveProTest_->RegisterProviderCallback(callback);
    EXPECT_EQ(DH_AVT_SUCCESS, ret);

    AVTransEvent event;
    event.type = EventType::EVENT_CHANNEL_OPENED;
    avReceiveProTest_->OnChannelEvent(event);

    callback = make_shared<IAVReceiverEngineProvider>();
    avReceiveProTest_->RegisterProviderCallback(callback);
    avReceiveProTest_->OnChannelEvent(event);

    event.type = EventType::EVENT_CHANNEL_CLOSED;
    avReceiveProTest_->OnChannelEvent(event);

    event.type = EventType::EVENT_START_SUCCESS;
    avReceiveProTest_->OnChannelEvent(event);
}

HWTEST_F(AvAudioReceiverEngineProviderTest, TransName2PkgName_001, testing::ext::TestSize.Level1)
{
    std::string ownerName = "ownerName";
    auto avReceiveProTest_ = std::make_shared<AVAudioReceiverEngineProvider>(ownerName);
    std::shared_ptr<IAVEngineProviderCallback> callback = nullptr;
    int32_t ret = avReceiveProTest_->RegisterProviderCallback(callback);
    EXPECT_EQ(DH_AVT_SUCCESS, ret);

    AVTransEvent event;
    event.type = EventType::EVENT_CHANNEL_OPENED;
    avReceiveProTest_->OnChannelEvent(event);

    callback = make_shared<IAVReceiverEngineProvider>();
    avReceiveProTest_->RegisterProviderCallback(callback);
    avReceiveProTest_->OnChannelEvent(event);

    std::string test = "TEST";
    std::string result = avReceiveProTest_->TransName2PkgName(test);
    EXPECT_EQ(EMPTY_STRING, result);
}
} // namespace DistributedHardware
} // namespace OHOS