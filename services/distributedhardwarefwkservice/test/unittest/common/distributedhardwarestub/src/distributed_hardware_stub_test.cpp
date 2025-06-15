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

#include "distributed_hardware_stub_test.h"

#include <memory>

#include "iremote_stub.h"
#include "dhardware_ipc_interface_code.h"

using namespace OHOS::Security::AccessToken;
using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
void DistributedHardwareStubTest::SetUpTestCase(void) {}

void DistributedHardwareStubTest::TearDownTestCase(void) {}

void DistributedHardwareStubTest::SetUp()
{
    stubTest_ = std::make_shared<MockDistributedHardwareStub>();
    auto token = AccessTokenKitInterface::GetOrCreateAccessTokenKit();
    token_ = std::static_pointer_cast<AccessTokenKitMock>(token);
    ASSERT_TRUE(token_ != nullptr);
    EXPECT_CALL(*token_, VerifyAccessToken(_, _)).WillRepeatedly(Return(PERMISSION_DENIED));
}

void DistributedHardwareStubTest::TearDown()
{
    stubTest_ = nullptr;
    AccessTokenKitInterface::ReleaseAccessTokenKit();
    token_ = nullptr;
}

/**
 * @tc.name: OnRemoteRequest_001
 * @tc.desc: Verify the OnRemoteRequest function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_001, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_NE(DH_FWK_SUCCESS, stubTest_->OnRemoteRequest(code, data, reply, option));
}

/**
 * @tc.name: OnRemoteRequest_002
 * @tc.desc: Verify the OnRemoteRequest function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_002, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    EXPECT_EQ(ERR_INVALID_DATA, stubTest_->OnRemoteRequest(code, data, reply, option));
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_003, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::REG_PUBLISHER_LISTNER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    uint32_t topicInt = (uint32_t)DHTopic::TOPIC_MIN;
    data.WriteUint32(topicInt);
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_004, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::PUBLISH_MESSAGE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    uint32_t topicInt = (uint32_t)DHTopic::TOPIC_MIN;
    data.WriteUint32(topicInt);
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_005, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::INIT_CTL_CEN);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    uint32_t transRole = static_cast<uint32_t>(TransRole::UNKNOWN);
    data.WriteUint32(transRole);
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_006, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::RELEASE_CTL_CEN);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    int32_t engineId = 1;
    data.WriteInt32(engineId);
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_007, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::CREATE_CTL_CEN_CHANNEL);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    int32_t engineId = 1;
    std::string peerDevId = "peerDevId_test";
    data.WriteInt32(engineId);
    data.WriteString(peerDevId);
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_008, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::NOTIFY_AV_EVENT);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    int32_t engineId = 1;
    std::string peerDevId = "peerDevId_test";
    uint32_t type = 1;
    std::string content = "content_test";
    data.WriteInt32(engineId);
    data.WriteString(peerDevId);
    data.WriteUint32(type);
    data.WriteString(content);
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_009, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::QUERY_LOCAL_SYS_SPEC);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    uint32_t specInt = static_cast<uint32_t>(QueryLocalSysSpecType::MIN);
    data.WriteUint32(specInt);
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_010, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::NOTIFY_SOURCE_DEVICE_REMOTE_DMSDP_STARTED);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    std::string deviceId = "deviceId_test";
    data.WriteString(deviceId);
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_011, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::PAUSE_DISTRIBUTED_HARDWARE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_IS_SYSTEM_HAP_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_012, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::RESUME_DISTRIBUTED_HARDWARE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_IS_SYSTEM_HAP_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_013, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::STOP_DISTRIBUTED_HARDWARE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_IS_SYSTEM_HAP_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_014, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::UNREG_PUBLISHER_LISTENER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    uint32_t topicInt = (uint32_t)DHTopic::TOPIC_MIN;
    data.WriteUint32(topicInt);
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_015, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::REGISTER_CTL_CEN_CALLBACK);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_016, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::GET_DISTRIBUTED_HARDWARE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    data.WriteString("netWorkId_test");
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_017, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::REG_DH_SINK_STATUS_LISTNER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_018, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::UNREG_DH_SINK_STATUS_LISTNER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_019, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::REG_DH_SOURCE_STATUS_LISTNER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_020, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::UNREG_DH_SOURCE_STATUS_LISTNER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_021, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::ENABLE_SINK);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    data.WriteInt32(1);
    data.WriteInt32(static_cast<int32_t>(DHType::AUDIO));
    data.WriteString("id_test");
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_022, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::DISABLE_SINK);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    data.WriteInt32(1);
    data.WriteInt32(static_cast<int32_t>(DHType::AUDIO));
    data.WriteString("id_test");
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_023, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::ENABLE_SOURCE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    data.WriteInt32(1);
    data.WriteInt32(static_cast<int32_t>(DHType::AUDIO));
    data.WriteString("id_test");
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_024, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::DISABLE_SOURCE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    data.WriteInt32(1);
    data.WriteInt32(static_cast<int32_t>(DHType::AUDIO));
    data.WriteString("id_test");
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_025, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t code = static_cast<uint32_t>(0xffff);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    data.WriteInt32(1);
    data.WriteInt32(static_cast<int32_t>(DHType::AUDIO));
    data.WriteString("id_test");
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(DH_FWK_SUCCESS, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_026, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    ASSERT_TRUE(token_ != nullptr);
    EXPECT_CALL(*token_, VerifyAccessToken(_, _)).WillRepeatedly(Return(PERMISSION_GRANTED));

    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::REG_PUBLISHER_LISTNER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    uint32_t topicInt = (uint32_t)DHTopic::TOPIC_START_DSCREEN;
    data.WriteUint32(topicInt);

    sptr<IRemoteObject> listener(new MockIPublisherListener());
    data.WriteRemoteObject(listener);
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(DH_FWK_SUCCESS, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_027, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    ASSERT_TRUE(token_ != nullptr);
    EXPECT_CALL(*token_, VerifyAccessToken(_, _)).WillRepeatedly(Return(PERMISSION_GRANTED));

    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::UNREG_PUBLISHER_LISTENER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    uint32_t topicInt = (uint32_t)DHTopic::TOPIC_START_DSCREEN;
    data.WriteUint32(topicInt);

    sptr<IRemoteObject> listener(new MockIPublisherListener());
    data.WriteRemoteObject(listener);
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(DH_FWK_SUCCESS, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_028, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    ASSERT_TRUE(token_ != nullptr);
    EXPECT_CALL(*token_, VerifyAccessToken(_, _)).WillRepeatedly(Return(PERMISSION_GRANTED));

    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::GET_DISTRIBUTED_HARDWARE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    data.WriteString("netWorkId_test");
    EnableStep enableStep = EnableStep::ENABLE_SOURCE;
    data.WriteUint32(static_cast<uint32_t>(enableStep));
    sptr<IRemoteObject> callback(new MockGetDhDescriptorsCallbackStub());
    data.WriteRemoteObject(callback);
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(DH_FWK_SUCCESS, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_029, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    ASSERT_TRUE(token_ != nullptr);
    EXPECT_CALL(*token_, VerifyAccessToken(_, _)).WillRepeatedly(Return(PERMISSION_GRANTED));

    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::REG_DH_SINK_STATUS_LISTNER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    sptr<IRemoteObject> listener(new MockHDSinkStatusListenerStub());
    data.WriteRemoteObject(listener);
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(DH_FWK_SUCCESS, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_030, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    ASSERT_TRUE(token_ != nullptr);
    EXPECT_CALL(*token_, VerifyAccessToken(_, _)).WillRepeatedly(Return(PERMISSION_GRANTED));

    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::UNREG_DH_SINK_STATUS_LISTNER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    sptr<IRemoteObject> listener(new MockHDSinkStatusListenerStub());
    data.WriteRemoteObject(listener);
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(DH_FWK_SUCCESS, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_031, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    ASSERT_TRUE(token_ != nullptr);
    EXPECT_CALL(*token_, VerifyAccessToken(_, _)).WillRepeatedly(Return(PERMISSION_GRANTED));

    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::REG_DH_SOURCE_STATUS_LISTNER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    data.WriteString("networkId_test");
    sptr<IRemoteObject> listener(new MockHDSourceStatusListenerStub());
    data.WriteRemoteObject(listener);
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(DH_FWK_SUCCESS, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_032, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    ASSERT_TRUE(token_ != nullptr);
    EXPECT_CALL(*token_, VerifyAccessToken(_, _)).WillRepeatedly(Return(PERMISSION_GRANTED));

    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::UNREG_DH_SOURCE_STATUS_LISTNER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    data.WriteString("networkId_test");
    sptr<IRemoteObject> listener(new MockHDSourceStatusListenerStub());
    data.WriteRemoteObject(listener);
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(DH_FWK_SUCCESS, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_033, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    ASSERT_TRUE(token_ != nullptr);
    EXPECT_CALL(*token_, VerifyAccessToken(_, _)).WillRepeatedly(Return(PERMISSION_GRANTED));

    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::ENABLE_SINK);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    size_t descriptorCount = 1;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    data.WriteInt32(descriptorCount);
    data.WriteInt32(static_cast<int32_t>(DHType::AUDIO));
    data.WriteString("id_test");
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(DH_FWK_SUCCESS, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_034, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    ASSERT_TRUE(token_ != nullptr);
    EXPECT_CALL(*token_, VerifyAccessToken(_, _)).WillRepeatedly(Return(PERMISSION_GRANTED));

    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::DISABLE_SINK);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    size_t descriptorCount = 1;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    data.WriteInt32(descriptorCount);
    data.WriteInt32(static_cast<int32_t>(DHType::AUDIO));
    data.WriteString("id_test");
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(DH_FWK_SUCCESS, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_035, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    ASSERT_TRUE(token_ != nullptr);
    EXPECT_CALL(*token_, VerifyAccessToken(_, _)).WillRepeatedly(Return(PERMISSION_GRANTED));

    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::ENABLE_SOURCE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    size_t descriptorCount = 1;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    data.WriteInt32(descriptorCount);
    data.WriteInt32(static_cast<int32_t>(DHType::AUDIO));
    data.WriteString("id_test");
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(DH_FWK_SUCCESS, ret);
}

HWTEST_F(DistributedHardwareStubTest, OnRemoteRequest_036, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    ASSERT_TRUE(token_ != nullptr);
    EXPECT_CALL(*token_, VerifyAccessToken(_, _)).WillRepeatedly(Return(PERMISSION_GRANTED));

    uint32_t code = static_cast<uint32_t>(DHMsgInterfaceCode::DISABLE_SOURCE);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    size_t descriptorCount = 1;
    data.WriteInterfaceToken(stubTest_->GetDescriptor());
    data.WriteInt32(descriptorCount);
    data.WriteInt32(static_cast<int32_t>(DHType::AUDIO));
    data.WriteString("id_test");
    auto ret = stubTest_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(DH_FWK_SUCCESS, ret);
}

/**
 * @tc.name: RegisterPublisherListenerInner_001
 * @tc.desc: Verify the RegisterPublisherListenerInner function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareStubTest, RegisterPublisherListenerInner_001, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(DH_FWK_SUCCESS, stubTest_->RegisterPublisherListenerInner(data, reply));
}

/**
 * @tc.name: UnregisterPublisherListenerInner_001
 * @tc.desc: Verify the UnregisterPublisherListenerInner function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareStubTest, UnregisterPublisherListenerInner_001, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(DH_FWK_SUCCESS, stubTest_->UnregisterPublisherListenerInner(data, reply));
}

/**
 * @tc.name: PublishMessageInner_001
 * @tc.desc: Verify the PublishMessageInner function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareStubTest, PublishMessageInner_001, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    MessageParcel data;
    MessageParcel reply;
    EXPECT_NE(DH_FWK_SUCCESS, stubTest_->PublishMessageInner(data, reply));
}

/**
 * @tc.name: ValidTopic_001
 * @tc.desc: Verify the ValidTopic function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareStubTest, ValidTopic_001, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t topic = static_cast<uint32_t>(DHTopic::TOPIC_MIN);
    EXPECT_EQ(false, stubTest_->ValidTopic(topic));

    uint32_t topic1 = static_cast<uint32_t>(DHTopic::TOPIC_MAX);
    EXPECT_EQ(false, stubTest_->ValidTopic(topic1));

    uint32_t topic2 = static_cast<uint32_t>(DHTopic::TOPIC_START_DSCREEN);
    EXPECT_EQ(true, stubTest_->ValidTopic(topic2));
}

/**
 * @tc.name: ValidQueryLocalSpec_001
 * @tc.desc: Verify the ValidQueryLocalSpec function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareStubTest, ValidQueryLocalSpec_001, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t spec = 1;
    EXPECT_EQ(true, stubTest_->ValidQueryLocalSpec(spec));
}

/**
 * @tc.name: ValidQueryLocalSpec_002
 * @tc.desc: Verify the ValidQueryLocalSpec function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareStubTest, ValidQueryLocalSpec_002, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    uint32_t spec = 0;
    EXPECT_EQ(false, stubTest_->ValidQueryLocalSpec(spec));
    spec = 5;
    EXPECT_EQ(false, stubTest_->ValidQueryLocalSpec(spec));
}

/**
 * @tc.name: LoadDistributedHDFInner_001
 * @tc.desc: Verify the LoadDistributedHDFInner function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareStubTest, LoadDistributedHDFInner_001, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    ASSERT_TRUE(token_ != nullptr);
    EXPECT_CALL(*token_, VerifyAccessToken(_, _)).WillRepeatedly(Return(PERMISSION_GRANTED));
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(DH_FWK_SUCCESS, stubTest_->LoadDistributedHDFInner(data, reply));
}

/**
 * @tc.name: UnLoadDistributedHDFInner_001
 * @tc.desc: Verify the UnLoadDistributedHDFInner function
 * @tc.type: FUNC
 * @tc.require: AR000GHSJM
 */
HWTEST_F(DistributedHardwareStubTest, UnLoadDistributedHDFInner_001, TestSize.Level1)
{
    ASSERT_TRUE(stubTest_ != nullptr);
    ASSERT_TRUE(token_ != nullptr);
    EXPECT_CALL(*token_, VerifyAccessToken(_, _)).WillRepeatedly(Return(PERMISSION_GRANTED));
    MessageParcel data;
    MessageParcel reply;
    EXPECT_EQ(DH_FWK_SUCCESS, stubTest_->UnLoadDistributedHDFInner(data, reply));
}
} // namespace DistributedHardware
} // namespace OHOS
