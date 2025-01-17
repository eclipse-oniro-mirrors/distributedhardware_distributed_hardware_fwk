/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "distributed_hardware_proxy_test.h"

using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DistributedHardwareProxyTest::SetUpTestCase()
{
}

void DistributedHardwareProxyTest::TearDownTestCase()
{
}

void DistributedHardwareProxyTest::SetUp() {}

void DistributedHardwareProxyTest::TearDown() {}

int32_t DistributedHardwareProxyTest::TestDistributedHardwareStub::RegisterPublisherListener(const DHTopic topic,
    const sptr<IPublisherListener> listener)
{
    (void)topic;
    (void)listener;
    return DH_FWK_SUCCESS;
}

int32_t DistributedHardwareProxyTest::TestDistributedHardwareStub::UnregisterPublisherListener(const DHTopic topic,
    const sptr<IPublisherListener> listener)
{
    (void)topic;
    (void)listener;
    return DH_FWK_SUCCESS;
}

int32_t DistributedHardwareProxyTest::TestDistributedHardwareStub::PublishMessage(const DHTopic topic,
    const std::string &msg)
{
    (void)topic;
    (void)msg;
    return DH_FWK_SUCCESS;
}

std::string DistributedHardwareProxyTest::TestDistributedHardwareStub::QueryLocalSysSpec(QueryLocalSysSpecType spec)
{
    (void)spec;
    return "";
}

int32_t DistributedHardwareProxyTest::TestDistributedHardwareStub::InitializeAVCenter(const TransRole &transRole,
    int32_t &engineId)
{
    (void)transRole;
    (void)engineId;
    return DH_FWK_SUCCESS;
}

int32_t DistributedHardwareProxyTest::TestDistributedHardwareStub::ReleaseAVCenter(int32_t engineId)
{
    (void)engineId;
    return DH_FWK_SUCCESS;
}

int32_t DistributedHardwareProxyTest::TestDistributedHardwareStub::CreateControlChannel(int32_t engineId,
    const std::string &peerDevId)
{
    (void)engineId;
    (void)peerDevId;
    return DH_FWK_SUCCESS;
}

int32_t DistributedHardwareProxyTest::TestDistributedHardwareStub::NotifyAVCenter(int32_t engineId,
    const AVTransEvent &event)
{
    (void)engineId;
    (void)event;
    return DH_FWK_SUCCESS;
}

int32_t DistributedHardwareProxyTest::TestDistributedHardwareStub::RegisterCtlCenterCallback(int32_t engineId,
    const sptr<IAVTransControlCenterCallback> callback)
{
    (void)engineId;
    (void)callback;
    return DH_FWK_SUCCESS;
}

int32_t DistributedHardwareProxyTest::TestDistributedHardwareStub::NotifySourceRemoteSinkStarted(std::string &deviceId)
{
    (void)deviceId;
    return DH_FWK_SUCCESS;
}

int32_t DistributedHardwareProxyTest::TestDistributedHardwareStub::PauseDistributedHardware(DHType dhType,
    const std::string &networkId)
{
    (void)dhType;
    (void)networkId;
    return DH_FWK_SUCCESS;
}

int32_t DistributedHardwareProxyTest::TestDistributedHardwareStub::ResumeDistributedHardware(DHType dhType,
    const std::string &networkId)
{
    (void)dhType;
    (void)networkId;
    return DH_FWK_SUCCESS;
}

int32_t DistributedHardwareProxyTest::TestDistributedHardwareStub::StopDistributedHardware(DHType dhType,
    const std::string &networkId)
{
    (void)dhType;
    (void)networkId;
    return DH_FWK_SUCCESS;
}

/**
 * @tc.name: RegisterPublisherListener_001
 * @tc.desc: Verify the RegisterPublisherListener function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareProxyTest, RegisterPublisherListener_001, TestSize.Level0)
{
    DHTopic topic = DHTopic::TOPIC_MIN;
    sptr<IPublisherListener> listener = nullptr;
    sptr<IRemoteObject> dhStubPtr(new TestDistributedHardwareStub());
    ASSERT_TRUE(dhStubPtr != nullptr);
    DistributedHardwareProxy dhProxy(dhStubPtr);
    auto ret = dhProxy.RegisterPublisherListener(topic, listener);
    EXPECT_EQ(ERR_DH_FWK_PUBLISHER_LISTENER_IS_NULL, ret);

    sptr<IPublisherListener> listener1(new MockIPublisherListener());
    ASSERT_TRUE(listener1 != nullptr);
    ret = dhProxy.RegisterPublisherListener(topic, listener1);
    EXPECT_EQ(ERR_DH_FWK_PARA_INVALID, ret);

    topic = DHTopic::TOPIC_MAX;
    ret = dhProxy.RegisterPublisherListener(topic, listener1);
    EXPECT_EQ(ERR_DH_FWK_PARA_INVALID, ret);
}

/**
 * @tc.name: RegisterAbilityListener_002
 * @tc.desc: Verify the RegisterAbilityListener function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareProxyTest, RegisterPublisherListener_002, TestSize.Level0)
{
    DHTopic topic = DHTopic::TOPIC_LOW_LATENCY;
    sptr<IPublisherListener> listener(new MockIPublisherListener());
    ASSERT_TRUE(listener != nullptr);
    sptr<IRemoteObject> dhStubPtr(new TestDistributedHardwareStub());
    ASSERT_TRUE(dhStubPtr != nullptr);
    DistributedHardwareProxy dhProxy(dhStubPtr);
    auto ret = dhProxy.RegisterPublisherListener(topic, listener);
    EXPECT_EQ(ERR_DH_FWK_SERVICE_WRITE_INFO_FAIL, ret);
}

/**
 * @tc.name: UnregisterPublisherListener_001
 * @tc.desc: Verify the UnregisterPublisherListener function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareProxyTest, UnregisterPublisherListener_001, TestSize.Level0)
{
    DHTopic topic = DHTopic::TOPIC_MIN;
    sptr<IPublisherListener> listener = nullptr;
    sptr<IRemoteObject> dhStubPtr(new TestDistributedHardwareStub());
    ASSERT_TRUE(dhStubPtr != nullptr);
    DistributedHardwareProxy dhProxy(dhStubPtr);
    auto ret = dhProxy.UnregisterPublisherListener(topic, listener);
    EXPECT_EQ(ERR_DH_FWK_PUBLISHER_LISTENER_IS_NULL, ret);

    sptr<IPublisherListener> listener1(new MockIPublisherListener());
    ASSERT_TRUE(listener1 != nullptr);
    ret = dhProxy.UnregisterPublisherListener(topic, listener1);
    EXPECT_EQ(ERR_DH_FWK_PARA_INVALID, ret);

    topic = DHTopic::TOPIC_MAX;
    ret = dhProxy.RegisterPublisherListener(topic, listener1);
    EXPECT_EQ(ERR_DH_FWK_PARA_INVALID, ret);
}

/**
 * @tc.name: UnregisterPublisherListener_002
 * @tc.desc: Verify the UnregisterPublisherListener function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareProxyTest, UnregisterPublisherListener_003, TestSize.Level0)
{
    DHTopic topic = DHTopic::TOPIC_LOW_LATENCY;
    sptr<IPublisherListener> listener(new MockIPublisherListener());
    sptr<IRemoteObject> dhStubPtr(new TestDistributedHardwareStub());
    ASSERT_TRUE(dhStubPtr != nullptr);
    DistributedHardwareProxy dhProxy(dhStubPtr);
    int32_t ret = dhProxy.UnregisterPublisherListener(topic, listener);
    EXPECT_EQ(ERR_DH_FWK_SERVICE_WRITE_INFO_FAIL, ret);
}

/**
 * @tc.name: PublishMessage_001
 * @tc.desc: Verify the PublishMessage function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareProxyTest, PublishMessage_001, TestSize.Level0)
{
    DHTopic topic = DHTopic::TOPIC_MIN;
    std::string msg = "";
    sptr<IRemoteObject> dhStubPtr(new TestDistributedHardwareStub());
    ASSERT_TRUE(dhStubPtr != nullptr);
    DistributedHardwareProxy dhProxy(dhStubPtr);
    auto ret = dhProxy.PublishMessage(topic, msg);
    EXPECT_EQ(ERR_DH_FWK_PARA_INVALID, ret);

    topic = DHTopic::TOPIC_MAX;
    ret = dhProxy.PublishMessage(topic, msg);
    EXPECT_EQ(ERR_DH_FWK_PARA_INVALID, ret);
}

/**
 * @tc.name: PublishMessage_002
 * @tc.desc: Verify the PublishMessage function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareProxyTest, PublishMessage_002, TestSize.Level0)
{
    DHTopic topic = DHTopic::TOPIC_LOW_LATENCY;
    std::string msg = "";
    sptr<IRemoteObject> dhStubPtr(new TestDistributedHardwareStub());
    ASSERT_TRUE(dhStubPtr != nullptr);
    DistributedHardwareProxy dhProxy(dhStubPtr);
    auto ret = dhProxy.PublishMessage(topic, msg);
    EXPECT_EQ(ERR_DH_FWK_SERVICE_MSG_INVALID, ret);

    msg = "msg_test";
    ret = dhProxy.PublishMessage(topic, msg);
    EXPECT_EQ(ERR_DH_FWK_SERVICE_IPC_SEND_REQUEST_FAIL, ret);
}

/**
 * @tc.name: QueryLocalSysSpec_001
 * @tc.desc: Verify the QueryLocalSysSpec function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareProxyTest, QueryLocalSysSpec_001, TestSize.Level0)
{
    QueryLocalSysSpecType spec = QueryLocalSysSpecType::MIN;
    sptr<IRemoteObject> dhStubPtr(new TestDistributedHardwareStub());
    ASSERT_TRUE(dhStubPtr != nullptr);
    DistributedHardwareProxy dhProxy(dhStubPtr);
    auto ret = dhProxy.QueryLocalSysSpec(spec);
    EXPECT_EQ("", ret);

    spec = QueryLocalSysSpecType::MAX;
    ret = dhProxy.QueryLocalSysSpec(spec);
    EXPECT_EQ("", ret);
}

HWTEST_F(DistributedHardwareProxyTest, QueryLocalSysSpec_002, TestSize.Level0)
{
    QueryLocalSysSpecType spec = QueryLocalSysSpecType::HISTREAMER_AUDIO_ENCODER;
    sptr<IRemoteObject> dhStubPtr(new TestDistributedHardwareStub());
    ASSERT_TRUE(dhStubPtr != nullptr);
    DistributedHardwareProxy dhProxy(dhStubPtr);
    auto ret = dhProxy.QueryLocalSysSpec(spec);
    EXPECT_EQ("", ret);
}

/**
 * @tc.name: InitializeAVCenter_001
 * @tc.desc: Verify the InitializeAVCenter function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareProxyTest, InitializeAVCenter_001, TestSize.Level0)
{
    TransRole transRole = TransRole::UNKNOWN;
    int32_t engineId = 0;
    sptr<IRemoteObject> dhStubPtr(new TestDistributedHardwareStub());
    ASSERT_TRUE(dhStubPtr != nullptr);
    DistributedHardwareProxy dhProxy(dhStubPtr);
    auto ret = dhProxy.InitializeAVCenter(transRole, engineId);
    EXPECT_EQ(ERR_DH_AVT_SERVICE_IPC_SEND_REQUEST_FAIL, ret);
}

/**
 * @tc.name: ReleaseAVCenter_001
 * @tc.desc: Verify the ReleaseAVCenter function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareProxyTest, ReleaseAVCenter_001, TestSize.Level0)
{
    int32_t engineId = 0;
    sptr<IRemoteObject> dhStubPtr(new TestDistributedHardwareStub());
    ASSERT_TRUE(dhStubPtr != nullptr);
    DistributedHardwareProxy dhProxy(dhStubPtr);
    auto ret = dhProxy.ReleaseAVCenter(engineId);
    EXPECT_EQ(ERR_DH_AVT_SERVICE_IPC_SEND_REQUEST_FAIL, ret);
}

/**
 * @tc.name: CreateControlChannel_001
 * @tc.desc: Verify the CreateControlChannel function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareProxyTest, CreateControlChannel_001, TestSize.Level0)
{
    int32_t engineId = 0;
    std::string peerDevId = "peerDevId_test";
    sptr<IRemoteObject> dhStubPtr(new TestDistributedHardwareStub());
    ASSERT_TRUE(dhStubPtr != nullptr);
    DistributedHardwareProxy dhProxy(dhStubPtr);
    auto ret = dhProxy.CreateControlChannel(engineId, peerDevId);
    EXPECT_EQ(ERR_DH_AVT_SERVICE_IPC_SEND_REQUEST_FAIL, ret);
}

/**
 * @tc.name: NotifyAVCenter_001
 * @tc.desc: Verify the NotifyAVCenter function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareProxyTest, NotifyAVCenter_001, TestSize.Level0)
{
    int32_t engineId = 0;
    AVTransEvent event;
    sptr<IRemoteObject> dhStubPtr(new TestDistributedHardwareStub());
    ASSERT_TRUE(dhStubPtr != nullptr);
    DistributedHardwareProxy dhProxy(dhStubPtr);
    auto ret = dhProxy.NotifyAVCenter(engineId, event);
    EXPECT_EQ(ERR_DH_AVT_SERVICE_IPC_SEND_REQUEST_FAIL, ret);
}

/**
 * @tc.name: RegisterCtlCenterCallback_001
 * @tc.desc: Verify the RegisterCtlCenterCallback function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareProxyTest, RegisterCtlCenterCallback_001, TestSize.Level0)
{
    int32_t engineId = 0;
    sptr<IAVTransControlCenterCallback> callback = nullptr;
    sptr<IRemoteObject> dhStubPtr(new TestDistributedHardwareStub());
    ASSERT_TRUE(dhStubPtr != nullptr);
    DistributedHardwareProxy dhProxy(dhStubPtr);
    auto ret = dhProxy.RegisterCtlCenterCallback(engineId, callback);
    EXPECT_EQ(ERR_DH_FWK_AVTRANS_CALLBACK_IS_NULL, ret);
}

/**
 * @tc.name: NotifySourceRemoteSinkStarted_001
 * @tc.desc: Verify the NotifySourceRemoteSinkStarted function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareProxyTest, NotifySourceRemoteSinkStarted_001, TestSize.Level0)
{
    std::string deviceId = "devid_test";
    sptr<IRemoteObject> dhStubPtr(new TestDistributedHardwareStub());
    ASSERT_TRUE(dhStubPtr != nullptr);
    DistributedHardwareProxy dhProxy(dhStubPtr);
    auto ret = dhProxy.NotifySourceRemoteSinkStarted(deviceId);
    EXPECT_EQ(ERR_DH_AVT_SERVICE_IPC_SEND_REQUEST_FAIL, ret);
}

/**
 * @tc.name: PauseDistributedHardware_001
 * @tc.desc: Verify the PauseDistributedHardware function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareProxyTest, PauseDistributedHardware_001, TestSize.Level0)
{
    DHType dhType = DHType::CAMERA;
    std::string networkId = "";
    sptr<IRemoteObject> dhStubPtr(new TestDistributedHardwareStub());
    ASSERT_TRUE(dhStubPtr != nullptr);
    DistributedHardwareProxy dhProxy(dhStubPtr);
    auto ret = dhProxy.PauseDistributedHardware(dhType, networkId);
    EXPECT_EQ(ERR_DH_FWK_PARA_INVALID, ret);

    networkId = "123456789";
    ret = dhProxy.PauseDistributedHardware(dhType, networkId);
    EXPECT_EQ(ERR_DH_AVT_SERVICE_IPC_SEND_REQUEST_FAIL, ret);
}

/**
 * @tc.name: ResumeDistributedHardware_001
 * @tc.desc: Verify the ResumeDistributedHardware function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareProxyTest, ResumeDistributedHardware_001, TestSize.Level0)
{
    DHType dhType = DHType::CAMERA;
    std::string networkId = "";
    sptr<IRemoteObject> dhStubPtr(new TestDistributedHardwareStub());
    ASSERT_TRUE(dhStubPtr != nullptr);
    DistributedHardwareProxy dhProxy(dhStubPtr);
    auto ret = dhProxy.ResumeDistributedHardware(dhType, networkId);
    EXPECT_EQ(ERR_DH_FWK_PARA_INVALID, ret);

    networkId = "123456789";
    ret = dhProxy.ResumeDistributedHardware(dhType, networkId);
    EXPECT_EQ(ERR_DH_AVT_SERVICE_IPC_SEND_REQUEST_FAIL, ret);
}

/**
 * @tc.name: StopDistributedHardware_001
 * @tc.desc: Verify the StopDistributedHardware function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareProxyTest, StopDistributedHardware_001, TestSize.Level0)
{
    DHType dhType = DHType::CAMERA;
    std::string networkId = "";
    sptr<IRemoteObject> dhStubPtr(new TestDistributedHardwareStub());
    ASSERT_TRUE(dhStubPtr != nullptr);
    DistributedHardwareProxy dhProxy(dhStubPtr);
    auto ret = dhProxy.StopDistributedHardware(dhType, networkId);
    EXPECT_EQ(ERR_DH_FWK_PARA_INVALID, ret);

    networkId = "123456789";
    ret = dhProxy.StopDistributedHardware(dhType, networkId);
    EXPECT_EQ(ERR_DH_AVT_SERVICE_IPC_SEND_REQUEST_FAIL, ret);
}
} // namespace DistributedHardware
} // namespace OHOS
