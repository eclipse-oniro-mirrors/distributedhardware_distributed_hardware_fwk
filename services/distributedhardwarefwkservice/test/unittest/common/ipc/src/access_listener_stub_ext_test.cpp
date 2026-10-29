/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <memory>
#include <string>

#include "access_listener_stub.h"
#include "iaccess_listener.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"
#include "device_type.h"

using namespace testing::ext;
using namespace testing;
using namespace OHOS;
using namespace OHOS::DistributedHardware;

class MockAccessListenerStubExt : public AccessListenerStub {
public:
    MOCK_METHOD4(OnRequestHardwareAccess, void(const std::string&, AuthDeviceInfo, DHType, const std::string&));
};

class AccessListenerStubExtTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<MockAccessListenerStubExt> stub_ = nullptr;
};

void AccessListenerStubExtTest::SetUpTestCase(void) {}
void AccessListenerStubExtTest::TearDownTestCase(void) {}

void AccessListenerStubExtTest::SetUp()
{
    stub_ = std::make_shared<MockAccessListenerStubExt>();
    ASSERT_TRUE(stub_ != nullptr);
}

void AccessListenerStubExtTest::TearDown()
{
    stub_ = nullptr;
}

HWTEST_F(AccessListenerStubExtTest, OnRemoteRequest_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"ohos.DistributedHardware.WrongToken");
    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IAccessListener::Message::ON_REQUEST_HARDWARE_ACCESS), data, reply, option);
    EXPECT_EQ(ret, ERR_INVALID_DATA);
}

HWTEST_F(AccessListenerStubExtTest, OnRemoteRequest_002, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IAccessListener::GetDescriptor());
    std::string requestId = "req_001";
    data.WriteString(requestId);
    data.WriteString("network_id_123");
    data.WriteString("device_name_test");
    data.WriteUint16(1);
    data.WriteUint32(static_cast<uint32_t>(DHType::CAMERA));
    data.WriteString("com.test.pkg");
    EXPECT_CALL(*stub_, OnRequestHardwareAccess(requestId, _, DHType::CAMERA, "com.test.pkg")).Times(1);
    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IAccessListener::Message::ON_REQUEST_HARDWARE_ACCESS), data, reply, option);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
}

HWTEST_F(AccessListenerStubExtTest, OnRemoteRequest_003, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IAccessListener::GetDescriptor());
    int32_t ret = stub_->OnRemoteRequest(9999, data, reply, option);
    EXPECT_NE(ret, DH_FWK_SUCCESS);
}

HWTEST_F(AccessListenerStubExtTest, OnRemoteRequest_004, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IAccessListener::GetDescriptor());
    EXPECT_CALL(*stub_, OnRequestHardwareAccess(_, _, _, _)).Times(1);
    int32_t ret = stub_->OnRemoteRequest(0, data, reply, option);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
}

HWTEST_F(AccessListenerStubExtTest, OnRemoteRequest_005, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IAccessListener::GetDescriptor());
    std::string requestId = "req_audio_001";
    data.WriteString(requestId);
    data.WriteString("net_audio_456");
    data.WriteString("audio_device");
    data.WriteUint16(2);
    data.WriteUint32(static_cast<uint32_t>(DHType::AUDIO));
    data.WriteString("com.audio.test");
    EXPECT_CALL(*stub_, OnRequestHardwareAccess(requestId, _, DHType::AUDIO, "com.audio.test")).Times(1);
    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IAccessListener::Message::ON_REQUEST_HARDWARE_ACCESS), data, reply, option);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
}

HWTEST_F(AccessListenerStubExtTest, OnRemoteRequest_006, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IAccessListener::GetDescriptor());
    std::string requestId = "req_screen_001";
    data.WriteString(requestId);
    data.WriteString("net_screen_789");
    data.WriteString("screen_device");
    data.WriteUint16(3);
    data.WriteUint32(static_cast<uint32_t>(DHType::SCREEN));
    data.WriteString("com.screen.test");
    EXPECT_CALL(*stub_, OnRequestHardwareAccess(requestId, _, DHType::SCREEN, "com.screen.test")).Times(1);
    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IAccessListener::Message::ON_REQUEST_HARDWARE_ACCESS), data, reply, option);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
}

HWTEST_F(AccessListenerStubExtTest, OnRemoteRequest_007, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IAccessListener::GetDescriptor());
    data.WriteString("");
    data.WriteString("");
    data.WriteString("");
    data.WriteUint16(0);
    data.WriteUint32(static_cast<uint32_t>(DHType::UNKNOWN));
    data.WriteString("");
    EXPECT_CALL(*stub_, OnRequestHardwareAccess("", _, DHType::UNKNOWN, "")).Times(1);
    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IAccessListener::Message::ON_REQUEST_HARDWARE_ACCESS), data, reply, option);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
}

HWTEST_F(AccessListenerStubExtTest, OnRemoteRequest_008, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IAccessListener::GetDescriptor());
    std::string requestId = "req_gps_001";
    data.WriteString(requestId);
    data.WriteString("net_gps_001");
    data.WriteString("gps_device");
    data.WriteUint16(4);
    data.WriteUint32(static_cast<uint32_t>(DHType::GPS));
    data.WriteString("com.gps.test");
    EXPECT_CALL(*stub_, OnRequestHardwareAccess(requestId, _, DHType::GPS, "com.gps.test")).Times(1);
    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IAccessListener::Message::ON_REQUEST_HARDWARE_ACCESS), data, reply, option);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
}

HWTEST_F(AccessListenerStubExtTest, OnRemoteRequest_009, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IAccessListener::GetDescriptor());
    std::string requestId = "req_input_001";
    data.WriteString(requestId);
    data.WriteString("net_input_001");
    data.WriteString("input_device");
    data.WriteUint16(5);
    data.WriteUint32(static_cast<uint32_t>(DHType::INPUT));
    data.WriteString("com.input.test");
    EXPECT_CALL(*stub_, OnRequestHardwareAccess(requestId, _, DHType::INPUT, "com.input.test")).Times(1);
    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IAccessListener::Message::ON_REQUEST_HARDWARE_ACCESS), data, reply, option);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
}

HWTEST_F(AccessListenerStubExtTest, OnRemoteRequest_010, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IAccessListener::GetDescriptor());
    std::string requestId = "req_hfp_001";
    data.WriteString(requestId);
    data.WriteString("net_hfp_001");
    data.WriteString("hfp_device");
    data.WriteUint16(6);
    data.WriteUint32(static_cast<uint32_t>(DHType::HFP));
    data.WriteString("com.hfp.test");
    EXPECT_CALL(*stub_, OnRequestHardwareAccess(requestId, _, DHType::HFP, "com.hfp.test")).Times(1);
    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IAccessListener::Message::ON_REQUEST_HARDWARE_ACCESS), data, reply, option);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
}

HWTEST_F(AccessListenerStubExtTest, OnRemoteRequest_011, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IAccessListener::GetDescriptor());
    std::string requestId = "req_a2d_001";
    data.WriteString(requestId);
    data.WriteString("net_a2d_001");
    data.WriteString("a2d_device");
    data.WriteUint16(7);
    data.WriteUint32(static_cast<uint32_t>(DHType::A2D));
    data.WriteString("com.a2d.test");
    EXPECT_CALL(*stub_, OnRequestHardwareAccess(requestId, _, DHType::A2D, "com.a2d.test")).Times(1);
    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IAccessListener::Message::ON_REQUEST_HARDWARE_ACCESS), data, reply, option);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
}

HWTEST_F(AccessListenerStubExtTest, OnRemoteRequest_012, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IAccessListener::GetDescriptor());
    std::string requestId = "req_virmodem_001";
    data.WriteString(requestId);
    data.WriteString("net_virmodem_001");
    data.WriteString("virmodem_device");
    data.WriteUint16(8);
    data.WriteUint32(static_cast<uint32_t>(DHType::VIRMODEM_AUDIO));
    data.WriteString("com.virmodem.test");
    EXPECT_CALL(*stub_, OnRequestHardwareAccess(requestId, _, DHType::VIRMODEM_AUDIO, "com.virmodem.test")).Times(1);
    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IAccessListener::Message::ON_REQUEST_HARDWARE_ACCESS), data, reply, option);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
}

HWTEST_F(AccessListenerStubExtTest, OnRemoteRequest_013, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IAccessListener::GetDescriptor());
    std::string requestId = "req_modem_001";
    data.WriteString(requestId);
    data.WriteString("net_modem_001");
    data.WriteString("modem_device");
    data.WriteUint16(9);
    data.WriteUint32(static_cast<uint32_t>(DHType::MODEM));
    data.WriteString("com.modem.test");
    EXPECT_CALL(*stub_, OnRequestHardwareAccess(requestId, _, DHType::MODEM, "com.modem.test")).Times(1);
    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IAccessListener::Message::ON_REQUEST_HARDWARE_ACCESS), data, reply, option);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
}

HWTEST_F(AccessListenerStubExtTest, OnRemoteRequest_014, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IAccessListener::GetDescriptor());
    std::string requestId = "req_maxdh_001";
    data.WriteString(requestId);
    data.WriteString("net_maxdh_001");
    data.WriteString("maxdh_device");
    data.WriteUint16(10);
    data.WriteUint32(static_cast<uint32_t>(DHType::MAX_DH));
    data.WriteString("com.maxdh.test");
    EXPECT_CALL(*stub_, OnRequestHardwareAccess(requestId, _, DHType::MAX_DH, "com.maxdh.test")).Times(1);
    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IAccessListener::Message::ON_REQUEST_HARDWARE_ACCESS), data, reply, option);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
}

HWTEST_F(AccessListenerStubExtTest, OnRemoteRequest_015, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IAccessListener::GetDescriptor());
    EXPECT_CALL(*stub_, OnRequestHardwareAccess(_, _, _, _)).Times(1);
    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IAccessListener::Message::ON_REQUEST_HARDWARE_ACCESS), data, reply, option);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
}

HWTEST_F(AccessListenerStubExtTest, OnRemoteRequest_016, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IAccessListener::GetDescriptor());
    std::string largeRequestId(1024, 'r');
    data.WriteString(largeRequestId);
    data.WriteString("net_large");
    data.WriteString("large_device");
    data.WriteUint16(99);
    data.WriteUint32(static_cast<uint32_t>(DHType::CAMERA));
    data.WriteString("com.large.pkg");
    EXPECT_CALL(*stub_, OnRequestHardwareAccess(largeRequestId, _, DHType::CAMERA, "com.large.pkg")).Times(1);
    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IAccessListener::Message::ON_REQUEST_HARDWARE_ACCESS), data, reply, option);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
}

HWTEST_F(AccessListenerStubExtTest, OnRemoteRequest_017, TestSize.Level1)
{
    for (int i = 0; i < 3; i++) {
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;
        data.WriteInterfaceToken(IAccessListener::GetDescriptor());
        std::string requestId = "req_seq_" + std::to_string(i);
        data.WriteString(requestId);
        data.WriteString("net_seq");
        data.WriteString("seq_device");
        data.WriteUint16(static_cast<uint16_t>(i));
        data.WriteUint32(static_cast<uint32_t>(DHType::CAMERA));
        data.WriteString("com.seq.test");
        EXPECT_CALL(*stub_, OnRequestHardwareAccess(requestId, _, DHType::CAMERA, "com.seq.test")).Times(1);
        int32_t ret = stub_->OnRemoteRequest(
            static_cast<uint32_t>(IAccessListener::Message::ON_REQUEST_HARDWARE_ACCESS), data, reply, option);
        EXPECT_EQ(ret, DH_FWK_SUCCESS);
        Mock::VerifyAndClearExpectations(stub_.get());
    }
}

HWTEST_F(AccessListenerStubExtTest, ReadDeviceInfo_001, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IAccessListener::GetDescriptor());
    std::string requestId = "req_read_001";
    std::string networkId = "network_id_read_test";
    std::string deviceName = "device_name_read_test";
    uint16_t deviceType = 42;
    data.WriteString(requestId);
    data.WriteString(networkId);
    data.WriteString(deviceName);
    data.WriteUint16(deviceType);
    data.WriteUint32(static_cast<uint32_t>(DHType::CAMERA));
    data.WriteString("com.read.test");
    AuthDeviceInfo capturedInfo;
    EXPECT_CALL(*stub_, OnRequestHardwareAccess(requestId, _, DHType::CAMERA, "com.read.test"))
        .WillOnce(SaveArg<1>(&capturedInfo));
    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IAccessListener::Message::ON_REQUEST_HARDWARE_ACCESS), data, reply, option);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
    EXPECT_EQ(capturedInfo.networkId, networkId);
    EXPECT_EQ(capturedInfo.deviceName, deviceName);
    EXPECT_EQ(capturedInfo.deviceType, deviceType);
}

HWTEST_F(AccessListenerStubExtTest, ReadDeviceInfo_002, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IAccessListener::GetDescriptor());
    data.WriteString("req_read_002");
    data.WriteString("");
    data.WriteString("");
    data.WriteUint16(0);
    data.WriteUint32(static_cast<uint32_t>(DHType::UNKNOWN));
    data.WriteString("");
    AuthDeviceInfo capturedInfo;
    EXPECT_CALL(*stub_, OnRequestHardwareAccess("req_read_002", _, DHType::UNKNOWN, ""))
        .WillOnce(SaveArg<1>(&capturedInfo));
    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IAccessListener::Message::ON_REQUEST_HARDWARE_ACCESS), data, reply, option);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
    EXPECT_EQ(capturedInfo.networkId, "");
    EXPECT_EQ(capturedInfo.deviceName, "");
    EXPECT_EQ(capturedInfo.deviceType, 0);
}

HWTEST_F(AccessListenerStubExtTest, ReadDeviceInfo_003, TestSize.Level1)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(IAccessListener::GetDescriptor());
    data.WriteString("req_read_003");
    data.WriteString("net_max");
    data.WriteString("dev_max");
    data.WriteUint16(UINT16_MAX);
    data.WriteUint32(static_cast<uint32_t>(DHType::SCREEN));
    data.WriteString("com.max.test");
    AuthDeviceInfo capturedInfo;
    EXPECT_CALL(*stub_, OnRequestHardwareAccess("req_read_003", _, DHType::SCREEN, "com.max.test"))
        .WillOnce(SaveArg<1>(&capturedInfo));
    int32_t ret = stub_->OnRemoteRequest(
        static_cast<uint32_t>(IAccessListener::Message::ON_REQUEST_HARDWARE_ACCESS), data, reply, option);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
    EXPECT_EQ(capturedInfo.deviceType, UINT16_MAX);
}
