/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#include "component_manager_test_new.h"

#include <chrono>
#include <thread>

#include "component_loader.h"
#include "component_privacy.h"
#include "constants.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"
#include "capability_info_manager.h"
#include "local_capability_info_manager.h"
#include "meta_info_manager.h"
#include "version_info_manager.h"
#include "version_manager.h"
#include "dh_context.h"
#include "dh_utils_tool.h"
#include "idistributed_modem_ext.h"
#include "get_dh_descriptors_callback_stub.h"
#include "ihardware_status_listener.h"
#include "iauthorization_result_callback.h"
#include "iaccess_listener.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedHardware {
#undef DH_LOG_TAG
#define DH_LOG_TAG "ComponentManagerTestNew"

namespace {
const DeviceInfo VALUABLE_DEVICE_INFO(
    "networkId-1",
    "uuid-1",
    "deviceId-1",
    "udid-1",
    "udidHash-1",
    "deviceName: com.ohos.helloworld",
    1
);
constexpr int32_t CURRENT_DEVICE_UID = 10010;
constexpr int32_t CAMERA_UID = CURRENT_DEVICE_UID;
constexpr int32_t CAMERA_PID = 4083;
constexpr int32_t AUDIO_UID = CURRENT_DEVICE_UID;
constexpr int32_t AUDIO_PID = 4085;
const CompVersion VERSION = { .sinkVersion = "1.0", .sourceVersion = "1.0" };
const DHDescriptor CAMERA_DESCRIPTOR = { .id = "camera_1", .dhType = DHType::CAMERA };
const DHDescriptor AUDIO_DESCRIPTOR = { .id = "audio_1", .dhType = DHType::AUDIO };

class TestCallback : public GetDhDescriptorsCallbackStub {
public:
    void OnSuccess(const std::string &networkId, const std::vector<DHDescriptor> &descriptors,
        EnableStep enableStep) override
    {
        (void)networkId;
        (void)descriptors;
        (void)enableStep;
    }
    void OnError(const std::string &networkId, int32_t error) override
    {
        (void)networkId;
        (void)error;
    }
};

class MockAuthorizationResultCallbackStub : public IRemoteStub<IAuthorizationResultCallback> {
public:
    MOCK_METHOD(void, OnAuthorizationResult, (const std::string &networkId, const std::string &requestId), (override));
};

class MockDHModemExt : public IDistributedModemExt {
public:
    MOCK_METHOD(int32_t, Enable, (const std::string &networkId, IDistributedHardwareSource *sourcePtr));
    MOCK_METHOD(int32_t, Disable, (const std::string &networkId, IDistributedHardwareSource *sourcePtr));
};

std::shared_ptr<IDistributedHardwareSink> CreateDHSinkPtrWithSetExpectation()
{
    auto sinkPtr = std::make_shared<MockIDistributedHardwareSink>();
    EXPECT_CALL(*sinkPtr, InitSink(_)).WillRepeatedly(Return(DH_FWK_SUCCESS));
    EXPECT_CALL(*sinkPtr, ReleaseSink()).WillRepeatedly(Return(DH_FWK_SUCCESS));
    EXPECT_CALL(*sinkPtr, RegisterPrivacyResources(_)).WillRepeatedly(Return(DH_FWK_SUCCESS));
    return sinkPtr;
}

std::shared_ptr<IDistributedHardwareSource> CreateDHSourcePtrWithSetExpectation()
{
    auto sourcePtr = std::make_shared<MockIDistributedHardwareSource>();
    EXPECT_CALL(*sourcePtr, InitSource(_)).WillRepeatedly(Return(DH_FWK_SUCCESS));
    EXPECT_CALL(*sourcePtr, ReleaseSource()).WillRepeatedly(Return(DH_FWK_SUCCESS));
    EXPECT_CALL(*sourcePtr, RegisterDistributedHardwareStateListener(_)).Times(AtLeast(1));
    EXPECT_CALL(*sourcePtr, RegisterDataSyncTriggerListener(_)).Times(AtLeast(1));
    EXPECT_CALL(*sourcePtr, UnregisterDistributedHardwareStateListener()).Times(AtLeast(1));
    EXPECT_CALL(*sourcePtr, UnregisterDataSyncTriggerListener()).Times(AtLeast(1));
    return sourcePtr;
}
}

void ComponentManagerTestNew::SetUpTestCase(void)
{}

void ComponentManagerTestNew::TearDownTestCase(void)
{}

void ComponentManagerTestNew::SetUp()
{
    auto capabilityInfoManager = ICapabilityInfoManager::GetOrCreateInstance();
    capabilityInfoManager_ = std::static_pointer_cast<MockCapabilityInfoManager>(capabilityInfoManager);
    auto componentLoader = IComponentLoader::GetOrCreateInstance();
    componentLoader_ = std::static_pointer_cast<MockComponentLoader>(componentLoader);
    auto dhContext = IDHContext::GetOrCreateInstance();
    dhContext_ = std::static_pointer_cast<MockDHContext>(dhContext);
    auto utilTool = IDHUtilTool::GetOrCreateInstance();
    utilTool_ = std::static_pointer_cast<MockDHUtilTool>(utilTool);
    auto metaInfoManager = IMetaInfoManager::GetOrCreateInstance();
    metaInfoManager_ = std::static_pointer_cast<MockMetaInfoManager>(metaInfoManager);
    auto versionManager = IVersionManager::GetOrCreateInstance();
    versionManager_ = std::static_pointer_cast<MockVersionManager>(versionManager);
    auto deviceManager = IDeviceManager::GetOrCreateInstance();
    deviceManager_ = std::static_pointer_cast<MockDeviceManager>(deviceManager);

    ComponentManager::GetInstance().compSource_.clear();
    ComponentManager::GetInstance().compSink_.clear();
    ComponentManager::GetInstance().dhBizStates_.clear();
    ComponentManager::GetInstance().dhSinkStatus_.clear();
    ComponentManager::GetInstance().dhSourceStatus_.clear();
    ComponentManager::GetInstance().syncDeviceInfoMap_.clear();
    ComponentManager::GetInstance().needRefreshTaskParams_.clear();
    ComponentManager::GetInstance().accessListenerMap_.clear();
}

void ComponentManagerTestNew::TearDown()
{
    ICapabilityInfoManager::ReleaseInstance();
    IComponentLoader::ReleaseInstance();
    IDHContext::ReleaseInstance();
    IDHUtilTool::ReleaseInstance();
    IMetaInfoManager::ReleaseInstance();
    IVersionManager::ReleaseInstance();
    IDeviceManager::ReleaseInstance();
    capabilityInfoManager_ = nullptr;
    componentLoader_ = nullptr;
    dhContext_ = nullptr;
    metaInfoManager_ = nullptr;
    versionManager_ = nullptr;
    utilTool_ = nullptr;
    deviceManager_ = nullptr;

    ComponentManager::GetInstance().compSource_.clear();
    ComponentManager::GetInstance().compSink_.clear();
    ComponentManager::GetInstance().dhBizStates_.clear();
    ComponentManager::GetInstance().dhSinkStatus_.clear();
    ComponentManager::GetInstance().dhSourceStatus_.clear();
    ComponentManager::GetInstance().syncDeviceInfoMap_.clear();
    ComponentManager::GetInstance().needRefreshTaskParams_.clear();
    ComponentManager::GetInstance().accessListenerMap_.clear();
}

HWTEST_F(ComponentManagerTestNew, AddTokenIdToSinkAttrs_001, TestSize.Level1)
{
    EnableParam param;
    param.sinkAttrs = "";
    std::string customParams = "";
    ComponentManager::GetInstance().AddTokenIdToSinkAttrs(customParams, param);
    EXPECT_EQ(param.sinkAttrs, "");
}

HWTEST_F(ComponentManagerTestNew, AddTokenIdToSinkAttrs_002, TestSize.Level1)
{
    EnableParam param;
    param.sinkAttrs = "{\"key\":\"value\"}";
    std::string customParams = "invalid_json{{{";
    ComponentManager::GetInstance().AddTokenIdToSinkAttrs(customParams, param);
    EXPECT_EQ(param.sinkAttrs, "{\"key\":\"value\"}");
}

HWTEST_F(ComponentManagerTestNew, AddTokenIdToSinkAttrs_003, TestSize.Level1)
{
    EnableParam param;
    param.sinkAttrs = "{\"key\":\"value\"}";
    std::string customParams = "{\"noTokenId\":\"abc\"}";
    ComponentManager::GetInstance().AddTokenIdToSinkAttrs(customParams, param);
    EXPECT_EQ(param.sinkAttrs, "{\"key\":\"value\"}");
}

HWTEST_F(ComponentManagerTestNew, AddTokenIdToSinkAttrs_004, TestSize.Level1)
{
    EnableParam param;
    param.sinkAttrs = "{\"key\":\"value\"}";
    std::string customParams = "{\"tokenId\":\"not_a_number\"}";
    ComponentManager::GetInstance().AddTokenIdToSinkAttrs(customParams, param);
    EXPECT_EQ(param.sinkAttrs, "{\"key\":\"value\"}");
}

HWTEST_F(ComponentManagerTestNew, AddTokenIdToSinkAttrs_005, TestSize.Level1)
{
    EnableParam param;
    param.sinkAttrs = "";
    std::string customParams = "{\"tokenId\":12345}";
    ComponentManager::GetInstance().AddTokenIdToSinkAttrs(customParams, param);
    EXPECT_NE(param.sinkAttrs, "");
}

HWTEST_F(ComponentManagerTestNew, AddTokenIdToSinkAttrs_006, TestSize.Level1)
{
    EnableParam param;
    param.sinkAttrs = "{\"existingKey\":\"existingValue\"}";
    std::string customParams = "{\"tokenId\":12345}";
    ComponentManager::GetInstance().AddTokenIdToSinkAttrs(customParams, param);
    EXPECT_NE(param.sinkAttrs, "");
    EXPECT_TRUE(param.sinkAttrs.find("tokenId") != std::string::npos);
    EXPECT_TRUE(param.sinkAttrs.find("existingKey") != std::string::npos);
}

HWTEST_F(ComponentManagerTestNew, AddTokenIdToSinkAttrs_007, TestSize.Level1)
{
    EnableParam param;
    param.sinkAttrs = "{\"key\":\"value\"}";
    std::string customParams = "{\"tokenId\":0}";
    ComponentManager::GetInstance().AddTokenIdToSinkAttrs(customParams, param);
    EXPECT_NE(param.sinkAttrs, "");
    EXPECT_TRUE(param.sinkAttrs.find("tokenId") != std::string::npos);
}

HWTEST_F(ComponentManagerTestNew, AddTokenIdToSinkAttrs_008, TestSize.Level2)
{
    EnableParam param;
    param.sinkAttrs = "invalid_sink_attrs{{{";
    std::string customParams = "{\"tokenId\":12345}";
    ComponentManager::GetInstance().AddTokenIdToSinkAttrs(customParams, param);
    EXPECT_EQ(param.sinkAttrs, "invalid_sink_attrs{{{");
}

HWTEST_F(ComponentManagerTestNew, IsFeatureMatched_001, TestSize.Level1)
{
    std::vector<std::string> sourceFeatureFilters = { "featureA" };
    std::vector<std::string> sinkSupportedFeatures = { "featureA" };
    auto ret = ComponentManager::GetInstance().IsFeatureMatched(sourceFeatureFilters, sinkSupportedFeatures);
    EXPECT_EQ(ret, true);
}

HWTEST_F(ComponentManagerTestNew, IsFeatureMatched_002, TestSize.Level1)
{
    std::vector<std::string> sourceFeatureFilters = { "featureA" };
    std::vector<std::string> sinkSupportedFeatures = { "featureB" };
    auto ret = ComponentManager::GetInstance().IsFeatureMatched(sourceFeatureFilters, sinkSupportedFeatures);
    EXPECT_EQ(ret, false);
}

HWTEST_F(ComponentManagerTestNew, IsFeatureMatched_003, TestSize.Level1)
{
    std::vector<std::string> sourceFeatureFilters = {};
    std::vector<std::string> sinkSupportedFeatures = { "featureA" };
    auto ret = ComponentManager::GetInstance().IsFeatureMatched(sourceFeatureFilters, sinkSupportedFeatures);
    EXPECT_EQ(ret, false);
}

HWTEST_F(ComponentManagerTestNew, IsFeatureMatched_004, TestSize.Level1)
{
    std::vector<std::string> sourceFeatureFilters = { "featureA", "featureB" };
    std::vector<std::string> sinkSupportedFeatures = { "featureB", "featureC" };
    auto ret = ComponentManager::GetInstance().IsFeatureMatched(sourceFeatureFilters, sinkSupportedFeatures);
    EXPECT_EQ(ret, true);
}

HWTEST_F(ComponentManagerTestNew, IsFeatureMatched_005, TestSize.Level1)
{
    std::vector<std::string> sourceFeatureFilters = { "featureA" };
    std::vector<std::string> sinkSupportedFeatures = {};
    auto ret = ComponentManager::GetInstance().IsFeatureMatched(sourceFeatureFilters, sinkSupportedFeatures);
    EXPECT_EQ(ret, false);
}

HWTEST_F(ComponentManagerTestNew, RegisterSyncDataRequest_001, TestSize.Level1)
{
    ComponentManager::GetInstance().syncDeviceInfoMap_.clear();
    ComponentManager::GetInstance().RegisterSyncDataRequest("");
    EXPECT_EQ(ComponentManager::GetInstance().syncDeviceInfoMap_.empty(), true);
}

HWTEST_F(ComponentManagerTestNew, RegisterSyncDataRequest_002, TestSize.Level1)
{
    ComponentManager::GetInstance().syncDeviceInfoMap_.clear();
    std::string networkId = "networkId_test_12345678";
    ComponentManager::GetInstance().RegisterSyncDataRequest(networkId);
    EXPECT_EQ(ComponentManager::GetInstance().syncDeviceInfoMap_.empty(), false);
}

HWTEST_F(ComponentManagerTestNew, RegisterSyncDataRequest_003, TestSize.Level1)
{
    ComponentManager::GetInstance().syncDeviceInfoMap_.clear();
    std::string networkId = "networkId_test_12345678";
    ComponentManager::GetInstance().RegisterSyncDataRequest(networkId);
    ComponentManager::GetInstance().RegisterSyncDataRequest(networkId);
    EXPECT_EQ(ComponentManager::GetInstance().syncDeviceInfoMap_.size(), (size_t)1);
    ComponentManager::GetInstance().syncDeviceInfoMap_.clear();
}

HWTEST_F(ComponentManagerTestNew, StopPrivacy_001, TestSize.Level1)
{
    ComponentManager::GetInstance().audioCompPrivacy_ = std::make_shared<ComponentPrivacy>();
    ComponentManager::GetInstance().audioCompPrivacy_->SetPageFlagTrue();
    EXPECT_NO_FATAL_FAILURE(ComponentManager::GetInstance().StopPrivacy());
    ComponentManager::GetInstance().audioCompPrivacy_ = nullptr;
}

HWTEST_F(ComponentManagerTestNew, StopPrivacy_002, TestSize.Level1)
{
    ComponentManager::GetInstance().cameraCompPrivacy_ = std::make_shared<ComponentPrivacy>();
    ComponentManager::GetInstance().cameraCompPrivacy_->SetPageFlagTrue();
    ComponentManager::GetInstance().audioCompPrivacy_ = std::make_shared<ComponentPrivacy>();
    ComponentManager::GetInstance().audioCompPrivacy_->SetPageFlagTrue();
    EXPECT_NO_FATAL_FAILURE(ComponentManager::GetInstance().StopPrivacy());
    ComponentManager::GetInstance().cameraCompPrivacy_ = nullptr;
    ComponentManager::GetInstance().audioCompPrivacy_ = nullptr;
}

HWTEST_F(ComponentManagerTestNew, WaitForResult_002, TestSize.Level1)
{
    ActionResult actionsResult;
    std::promise<int32_t> p;
    std::future<int32_t> f = p.get_future();
    p.set_value(ERR_DH_FWK_COMPONENT_ENABLE_FAILED);
    actionsResult.emplace(DHType::CAMERA, f.share());
    auto ret = ComponentManager::GetInstance().WaitForResult(ComponentManager::Action::START_SINK, actionsResult);
    EXPECT_EQ(ret, false);
}

HWTEST_F(ComponentManagerTestNew, WaitForResult_003, TestSize.Level1)
{
    ActionResult actionsResult;
    std::promise<int32_t> p;
    std::future<int32_t> f = p.get_future();
    std::thread([p = std::move(p)] () mutable {
        std::this_thread::sleep_for(std::chrono::seconds(3));
        p.set_value(DH_FWK_SUCCESS);
    }).detach();
    actionsResult.emplace(DHType::CAMERA, f.share());
    ComponentManager::GetInstance().isUnInitTimeOut_.store(false);
    auto ret = ComponentManager::GetInstance().WaitForResult(ComponentManager::Action::STOP_SINK, actionsResult);
    EXPECT_EQ(ComponentManager::GetInstance().isUnInitTimeOut_.load(), true);
}

HWTEST_F(ComponentManagerTestNew, IsSourceEnabled_002, TestSize.Level1)
{
    ComponentManager::GetInstance().dhSourceStatus_.clear();
    ComponentManager::DHSourceStatus sourceStatus;
    sourceStatus.refLoad = 1;
    sourceStatus.listeners[{ .uid = 100, .pid = 200 }] =
        sptr<IHDSourceStatusListener>(nullptr);
    ComponentManager::GetInstance().dhSourceStatus_[DHType::CAMERA] = sourceStatus;
    auto ret = ComponentManager::GetInstance().IsSourceEnabled();
    EXPECT_EQ(ret, true);
    ComponentManager::GetInstance().dhSourceStatus_.clear();
}

HWTEST_F(ComponentManagerTestNew, IsSourceEnabled_003, TestSize.Level1)
{
    ComponentManager::GetInstance().dhSourceStatus_.clear();
    ComponentManager::DHSourceStatus sourceStatus;
    sourceStatus.refLoad = 1;
    sourceStatus.listeners.clear();
    ComponentManager::GetInstance().dhSourceStatus_[DHType::CAMERA] = sourceStatus;
    auto ret = ComponentManager::GetInstance().IsSourceEnabled();
    EXPECT_EQ(ret, false);
    ComponentManager::GetInstance().dhSourceStatus_.clear();
}

HWTEST_F(ComponentManagerTestNew, IsSourceEnabled_004, TestSize.Level1)
{
    ComponentManager::GetInstance().dhSourceStatus_.clear();
    ComponentManager::DHSourceStatus modemStatus;
    modemStatus.refLoad = 1;
    ComponentManager::GetInstance().dhSourceStatus_[DHType::MODEM] = modemStatus;
    auto ret = ComponentManager::GetInstance().IsSourceEnabled();
    EXPECT_EQ(ret, true);
    ComponentManager::GetInstance().dhSourceStatus_.clear();
}

HWTEST_F(ComponentManagerTestNew, IsSinkActiveEnabled_002, TestSize.Level1)
{
    ComponentManager::GetInstance().dhSinkStatus_.clear();
    ComponentManager::DHSinkStatus sinkStatus;
    sinkStatus.refLoad = 1;
    sinkStatus.listeners[{ .uid = 100, .pid = 200 }] =
        sptr<IHDSinkStatusListener>(nullptr);
    ComponentManager::GetInstance().dhSinkStatus_[DHType::CAMERA] = sinkStatus;
    auto ret = ComponentManager::GetInstance().IsSinkActiveEnabled();
    EXPECT_EQ(ret, true);
    ComponentManager::GetInstance().dhSinkStatus_.clear();
}

HWTEST_F(ComponentManagerTestNew, IsSinkActiveEnabled_003, TestSize.Level1)
{
    ComponentManager::GetInstance().dhSinkStatus_.clear();
    ComponentManager::DHSinkStatus sinkStatus;
    sinkStatus.refLoad = 1;
    sinkStatus.listeners.clear();
    ComponentManager::GetInstance().dhSinkStatus_[DHType::CAMERA] = sinkStatus;
    auto ret = ComponentManager::GetInstance().IsSinkActiveEnabled();
    EXPECT_EQ(ret, false);
    ComponentManager::GetInstance().dhSinkStatus_.clear();
}

HWTEST_F(ComponentManagerTestNew, RecoverActiveEnableSink_001, TestSize.Level1)
{
    ComponentManager::GetInstance().dhSinkStatus_.clear();
    EXPECT_NO_FATAL_FAILURE(ComponentManager::GetInstance().RecoverActiveEnableSink(DHType::CAMERA));
}

HWTEST_F(ComponentManagerTestNew, RecoverActiveEnableSink_002, TestSize.Level1)
{
    ComponentManager::GetInstance().dhSinkStatus_.clear();
    ComponentManager::DHSinkStatus sinkStatus;
    ComponentManager::DHStatusCtrlKey ctrlKey { .uid = CAMERA_UID, .pid = CAMERA_PID };
    ComponentManager::DHStatusEnableInfo enableInfo;
    enableInfo.dhStatusCtrl[ctrlKey].enableState = ComponentManager::EnableState::ENABLED;
    sinkStatus.enableInfos[CAMERA_DESCRIPTOR.id] = enableInfo;
    ComponentManager::GetInstance().dhSinkStatus_[DHType::CAMERA] = sinkStatus;
    EXPECT_NO_FATAL_FAILURE(ComponentManager::GetInstance().RecoverActiveEnableSink(DHType::CAMERA));
    ComponentManager::GetInstance().dhSinkStatus_.clear();
}

HWTEST_F(ComponentManagerTestNew, RecoverActiveEnableSource_001, TestSize.Level1)
{
    ComponentManager::GetInstance().dhSourceStatus_.clear();
    EXPECT_NO_FATAL_FAILURE(ComponentManager::GetInstance().RecoverActiveEnableSource(DHType::CAMERA));
}

HWTEST_F(ComponentManagerTestNew, RecoverActiveEnableSource_002, TestSize.Level1)
{
    ComponentManager::GetInstance().dhSourceStatus_.clear();
    ComponentManager::DHSourceStatus sourceStatus;
    ComponentManager::DHStatusCtrlKey ctrlKey { .uid = CAMERA_UID, .pid = CAMERA_PID };
    ComponentManager::DHStatusSourceEnableInfoKey enableInfoKey {
        .networkId = VALUABLE_DEVICE_INFO.networkId,
        .dhId = CAMERA_DESCRIPTOR.id
    };
    ComponentManager::DHStatusEnableInfo enableInfo;
    enableInfo.dhStatusCtrl[ctrlKey].enableState = ComponentManager::EnableState::ENABLED;
    sourceStatus.enableInfos[enableInfoKey] = enableInfo;
    ComponentManager::GetInstance().dhSourceStatus_[DHType::CAMERA] = sourceStatus;
    EXPECT_NO_FATAL_FAILURE(ComponentManager::GetInstance().RecoverActiveEnableSource(DHType::CAMERA));
    ComponentManager::GetInstance().dhSourceStatus_.clear();
}

HWTEST_F(ComponentManagerTestNew, SaveNeedRefreshTask_001, TestSize.Level1)
{
    TaskParam taskParam = {
        .networkId = "networkId_test",
        .uuid = "uuid_test",
        .udid = "udid_test",
        .dhId = "dhId_test",
        .dhType = DHType::CAMERA,
    };
    ComponentManager::GetInstance().needRefreshTaskParams_.clear();
    ComponentManager::GetInstance().SaveNeedRefreshTask(taskParam);
    EXPECT_EQ(ComponentManager::GetInstance().needRefreshTaskParams_.size(), (size_t)1);
    ComponentManager::GetInstance().needRefreshTaskParams_.clear();
}

HWTEST_F(ComponentManagerTestNew, FetchNeedRefreshTask_001, TestSize.Level1)
{
    std::pair<std::string, std::string> taskKey = {"networkId_test", "dhId_test"};
    TaskParam taskParam;
    ComponentManager::GetInstance().needRefreshTaskParams_.clear();
    auto ret = ComponentManager::GetInstance().FetchNeedRefreshTask(taskKey, taskParam);
    EXPECT_EQ(ret, false);
}

HWTEST_F(ComponentManagerTestNew, FetchNeedRefreshTask_002, TestSize.Level1)
{
    TaskParam savedParam = {
        .networkId = "networkId_test",
        .uuid = "uuid_test",
        .udid = "udid_test",
        .dhId = "dhId_test",
        .dhType = DHType::CAMERA,
    };
    ComponentManager::GetInstance().needRefreshTaskParams_.clear();
    ComponentManager::GetInstance().SaveNeedRefreshTask(savedParam);
    std::pair<std::string, std::string> taskKey = {"networkId_test", "dhId_test"};
    TaskParam fetchedParam;
    auto ret = ComponentManager::GetInstance().FetchNeedRefreshTask(taskKey, fetchedParam);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(fetchedParam.networkId, savedParam.networkId);
    EXPECT_EQ(fetchedParam.dhId, savedParam.dhId);
    EXPECT_EQ(ComponentManager::GetInstance().needRefreshTaskParams_.size(), (size_t)0);
}

HWTEST_F(ComponentManagerTestNew, CheckSinkConfigStart_002, TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    CompVersion localVersion = {
        .sourceVersion = "1.0",
        .sinkVersion = "1.0",
        .haveFeature = false
    };
    DHVersion dhVersion = {
        .uuid = "uuid-1",
        .dhVersion = "1.0",
        .compVersions = {{ DHType::CAMERA, localVersion }}
    };
    EXPECT_CALL(*componentLoader_, GetLocalDHVersion(_))
        .WillOnce(DoAll(SetArgReferee<0>(dhVersion), Return(DH_FWK_SUCCESS)));
    bool enableSink = false;
    auto ret = ComponentManager::GetInstance().CheckSinkConfigStart(DHType::CAMERA, enableSink);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
    EXPECT_EQ(enableSink, true);
}

HWTEST_F(ComponentManagerTestNew, CheckSinkConfigStart_003, TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    CompVersion localVersion = {
        .sourceVersion = "1.0",
        .sinkVersion = "1.0",
        .haveFeature = true,
        .sinkSupportedFeatures = {}
    };
    DHVersion dhVersion = {
        .uuid = "uuid-1",
        .dhVersion = "1.0",
        .compVersions = {{ DHType::CAMERA, localVersion }}
    };
    EXPECT_CALL(*componentLoader_, GetLocalDHVersion(_))
        .WillOnce(DoAll(SetArgReferee<0>(dhVersion), Return(DH_FWK_SUCCESS)));
    bool enableSink = false;
    auto ret = ComponentManager::GetInstance().CheckSinkConfigStart(DHType::CAMERA, enableSink);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
    EXPECT_EQ(enableSink, false);
}

HWTEST_F(ComponentManagerTestNew, CheckSinkConfigStart_004, TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    CompVersion localVersion = {
        .sourceVersion = "1.0",
        .sinkVersion = "1.0",
        .haveFeature = true,
        .sinkSupportedFeatures = { "feature1" }
    };
    DHVersion dhVersion = {
        .uuid = "uuid-1",
        .dhVersion = "1.0",
        .compVersions = {{ DHType::CAMERA, localVersion }}
    };
    EXPECT_CALL(*componentLoader_, GetLocalDHVersion(_))
        .WillOnce(DoAll(SetArgReferee<0>(dhVersion), Return(DH_FWK_SUCCESS)));
    bool enableSink = false;
    auto ret = ComponentManager::GetInstance().CheckSinkConfigStart(DHType::CAMERA, enableSink);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
    EXPECT_EQ(enableSink, true);
}

HWTEST_F(ComponentManagerTestNew, CheckSinkConfigStart_005, TestSize.Level2)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    EXPECT_CALL(*componentLoader_, GetLocalDHVersion(_)).WillOnce(Return(ERR_DH_FWK_LOADER_HANDLER_IS_NULL));
    bool enableSink = false;
    auto ret = ComponentManager::GetInstance().CheckSinkConfigStart(DHType::CAMERA, enableSink);
    EXPECT_EQ(ret, ERR_DH_FWK_LOADER_HANDLER_IS_NULL);
}

HWTEST_F(ComponentManagerTestNew, CheckSinkConfigStart_006, TestSize.Level2)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    DHVersion dhVersion = {
        .uuid = "uuid-1",
        .dhVersion = "1.0",
        .compVersions = {}
    };
    EXPECT_CALL(*componentLoader_, GetLocalDHVersion(_))
        .WillOnce(DoAll(SetArgReferee<0>(dhVersion), Return(DH_FWK_SUCCESS)));
    bool enableSink = false;
    auto ret = ComponentManager::GetInstance().CheckSinkConfigStart(DHType::CAMERA, enableSink);
    EXPECT_EQ(ret, ERR_DH_FWK_TYPE_NOT_EXIST);
}

HWTEST_F(ComponentManagerTestNew, EnableMetaSource_002, TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    EXPECT_CALL(*componentLoader_, IsDHTypeSupport(_)).WillRepeatedly(Return(true));
    ComponentManager::DHStatusSourceEnableInfoKey enableInfoKey {
        .networkId = VALUABLE_DEVICE_INFO.networkId,
        .dhId = CAMERA_DESCRIPTOR.id
    };
    ComponentManager::DHStatusCtrlKey ctrlKey { .uid = 0, .pid = 0 };
    auto &status = ComponentManager::GetInstance().dhSourceStatus_[CAMERA_DESCRIPTOR.dhType];
    auto &enableInfo = status.enableInfos[enableInfoKey];
    auto &statusCtrl = enableInfo.dhStatusCtrl[ctrlKey];
    statusCtrl.enableState = ComponentManager::EnableState::ENABLED;
    auto dhModemExt = std::make_shared<MockDHModemExt>();
    IDistributedHardwareSource *sourcePtr = nullptr;
    auto ret = ComponentManager::GetInstance().EnableMetaSource(
        VALUABLE_DEVICE_INFO.networkId, CAMERA_DESCRIPTOR, dhModemExt, sourcePtr);
    EXPECT_EQ(ret, ERR_DH_FWK_COMPONENT_REPEAT_CALL);
    ComponentManager::GetInstance().dhSourceStatus_.clear();
}

HWTEST_F(ComponentManagerTestNew, EnableMetaSource_003, TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    EXPECT_CALL(*componentLoader_, IsDHTypeSupport(_)).WillRepeatedly(Return(true));
    ComponentManager::DHStatusSourceEnableInfoKey enableInfoKey {
        .networkId = VALUABLE_DEVICE_INFO.networkId,
        .dhId = CAMERA_DESCRIPTOR.id
    };
    ComponentManager::DHStatusCtrlKey ctrlKey { .uid = 0, .pid = 0 };
    auto &status = ComponentManager::GetInstance().dhSourceStatus_[CAMERA_DESCRIPTOR.dhType];
    auto &enableInfo = status.enableInfos[enableInfoKey];
    auto &statusCtrl = enableInfo.dhStatusCtrl[ctrlKey];
    statusCtrl.enableState = ComponentManager::EnableState::DISABLED;
    enableInfo.refEnable = 1;
    status.refLoad = 1;
    auto dhModemExt = std::make_shared<MockDHModemExt>();
    IDistributedHardwareSource *sourcePtr = nullptr;
    auto ret = ComponentManager::GetInstance().EnableMetaSource(
        VALUABLE_DEVICE_INFO.networkId, CAMERA_DESCRIPTOR, dhModemExt, sourcePtr);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
    ComponentManager::GetInstance().dhSourceStatus_.clear();
}

HWTEST_F(ComponentManagerTestNew, EnableMetaSource_004, TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    EXPECT_CALL(*componentLoader_, IsDHTypeSupport(_)).WillRepeatedly(Return(true));
    ComponentManager::DHStatusSourceEnableInfoKey enableInfoKey {
        .networkId = VALUABLE_DEVICE_INFO.networkId,
        .dhId = CAMERA_DESCRIPTOR.id
    };
    ComponentManager::DHStatusCtrlKey ctrlKey { .uid = 0, .pid = 0 };
    auto &status = ComponentManager::GetInstance().dhSourceStatus_[CAMERA_DESCRIPTOR.dhType];
    auto &enableInfo = status.enableInfos[enableInfoKey];
    auto &statusCtrl = enableInfo.dhStatusCtrl[ctrlKey];
    statusCtrl.enableState = ComponentManager::EnableState::DISABLED;
    enableInfo.refEnable = 0;
    status.refLoad = 1;
    auto dhModemExt = std::make_shared<MockDHModemExt>();
    IDistributedHardwareSource *sourcePtr = nullptr;
    EXPECT_CALL(*dhModemExt, Enable(_, _)).WillOnce(Return(ERR_DH_FWK_PARA_INVALID));
    auto ret = ComponentManager::GetInstance().EnableMetaSource(
        VALUABLE_DEVICE_INFO.networkId, CAMERA_DESCRIPTOR, dhModemExt, sourcePtr);
    EXPECT_EQ(ret, ERR_DH_FWK_PARA_INVALID);
    ComponentManager::GetInstance().dhSourceStatus_.clear();
}

HWTEST_F(ComponentManagerTestNew, EnableMetaSource_005, TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    EXPECT_CALL(*componentLoader_, IsDHTypeSupport(_)).WillRepeatedly(Return(true));
    ComponentManager::DHStatusSourceEnableInfoKey enableInfoKey {
        .networkId = VALUABLE_DEVICE_INFO.networkId,
        .dhId = CAMERA_DESCRIPTOR.id
    };
    ComponentManager::DHStatusCtrlKey ctrlKey { .uid = 0, .pid = 0 };
    auto &status = ComponentManager::GetInstance().dhSourceStatus_[CAMERA_DESCRIPTOR.dhType];
    auto &enableInfo = status.enableInfos[enableInfoKey];
    auto &statusCtrl = enableInfo.dhStatusCtrl[ctrlKey];
    statusCtrl.enableState = ComponentManager::EnableState::DISABLED;
    enableInfo.refEnable = 0;
    status.refLoad = 1;
    auto dhModemExt = std::make_shared<MockDHModemExt>();
    IDistributedHardwareSource *sourcePtr = nullptr;
    EXPECT_CALL(*dhModemExt, Enable(_, _)).WillOnce(Return(DH_FWK_SUCCESS));
    auto ret = ComponentManager::GetInstance().EnableMetaSource(
        VALUABLE_DEVICE_INFO.networkId, CAMERA_DESCRIPTOR, dhModemExt, sourcePtr);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
    ComponentManager::GetInstance().dhSourceStatus_.clear();
}

HWTEST_F(ComponentManagerTestNew, DisableMetaSource_001, TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    ComponentManager::DHStatusSourceEnableInfoKey enableInfoKey {
        .networkId = VALUABLE_DEVICE_INFO.networkId,
        .dhId = CAMERA_DESCRIPTOR.id
    };
    ComponentManager::DHStatusCtrlKey ctrlKey { .uid = 0, .pid = 0 };
    auto &status = ComponentManager::GetInstance().dhSourceStatus_[CAMERA_DESCRIPTOR.dhType];
    auto &enableInfo = status.enableInfos[enableInfoKey];
    auto &statusCtrl = enableInfo.dhStatusCtrl[ctrlKey];
    statusCtrl.enableState = ComponentManager::EnableState::DISABLED;
    auto dhModemExt = std::make_shared<MockDHModemExt>();
    IDistributedHardwareSource *sourcePtr = nullptr;
    auto ret = ComponentManager::GetInstance().DisableMetaSource(
        VALUABLE_DEVICE_INFO.networkId, CAMERA_DESCRIPTOR, dhModemExt, sourcePtr);
    EXPECT_EQ(ret, ERR_DH_FWK_COMPONENT_REPEAT_CALL);
    ComponentManager::GetInstance().dhSourceStatus_.clear();
}

HWTEST_F(ComponentManagerTestNew, DisableMetaSource_002, TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    ComponentManager::DHStatusSourceEnableInfoKey enableInfoKey {
        .networkId = VALUABLE_DEVICE_INFO.networkId,
        .dhId = CAMERA_DESCRIPTOR.id
    };
    ComponentManager::DHStatusCtrlKey ctrlKey { .uid = 0, .pid = 0 };
    auto &status = ComponentManager::GetInstance().dhSourceStatus_[CAMERA_DESCRIPTOR.dhType];
    auto &enableInfo = status.enableInfos[enableInfoKey];
    auto &statusCtrl = enableInfo.dhStatusCtrl[ctrlKey];
    statusCtrl.enableState = ComponentManager::EnableState::ENABLED;
    enableInfo.refEnable = 2;
    status.refLoad = 2;
    auto dhModemExt = std::make_shared<MockDHModemExt>();
    IDistributedHardwareSource *sourcePtr = nullptr;
    auto ret = ComponentManager::GetInstance().DisableMetaSource(
        VALUABLE_DEVICE_INFO.networkId, CAMERA_DESCRIPTOR, dhModemExt, sourcePtr);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
    ComponentManager::GetInstance().dhSourceStatus_.clear();
}

HWTEST_F(ComponentManagerTestNew, DisableMetaSource_003, TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    ComponentManager::DHStatusSourceEnableInfoKey enableInfoKey {
        .networkId = VALUABLE_DEVICE_INFO.networkId,
        .dhId = CAMERA_DESCRIPTOR.id
    };
    ComponentManager::DHStatusCtrlKey ctrlKey { .uid = 0, .pid = 0 };
    auto &status = ComponentManager::GetInstance().dhSourceStatus_[CAMERA_DESCRIPTOR.dhType];
    auto &enableInfo = status.enableInfos[enableInfoKey];
    auto &statusCtrl = enableInfo.dhStatusCtrl[ctrlKey];
    statusCtrl.enableState = ComponentManager::EnableState::ENABLED;
    enableInfo.refEnable = 1;
    status.refLoad = 2;
    auto dhModemExt = std::make_shared<MockDHModemExt>();
    IDistributedHardwareSource *sourcePtr = nullptr;
    EXPECT_CALL(*dhModemExt, Disable(_, _)).WillOnce(Return(DH_FWK_SUCCESS));
    auto ret = ComponentManager::GetInstance().DisableMetaSource(
        VALUABLE_DEVICE_INFO.networkId, CAMERA_DESCRIPTOR, dhModemExt, sourcePtr);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
    ComponentManager::GetInstance().dhSourceStatus_.clear();
}


HWTEST_F(ComponentManagerTestNew, RecoverAutoEnableSource_001, TestSize.Level0)
{
    ASSERT_TRUE(metaInfoManager_ != nullptr);
    ASSERT_TRUE(dhContext_ != nullptr);
    DHType dhType = DHType::CAMERA;
    CompVersion compVersion{ .sinkVersion = "1.0" };
    auto metaCapInfo = std::make_shared<MetaCapabilityInfo>(
        "dhId_1", "deviceId-1", "devName_test", 14, dhType, "attrs_test", "subtype",
        "udidHash-1", compVersion);
    MetaCapInfoMap infoMap = {{ "udidHash-1", metaCapInfo }};
    EXPECT_CALL(*metaInfoManager_, GetMetaDataByDHType(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(infoMap), Return(DH_FWK_SUCCESS)));
    EXPECT_CALL(*dhContext_, GetUUIDByDeviceId(_)).WillRepeatedly(Return(""));
    EXPECT_NO_FATAL_FAILURE(ComponentManager::GetInstance().RecoverAutoEnableSource(dhType));
}

HWTEST_F(ComponentManagerTestNew, RecoverAutoEnableSource_002, TestSize.Level0)
{
    ASSERT_TRUE(metaInfoManager_ != nullptr);
    ASSERT_TRUE(dhContext_ != nullptr);
    DHType dhType = DHType::CAMERA;
    CompVersion compVersion{ .sinkVersion = "1.0" };
    auto metaCapInfo = std::make_shared<MetaCapabilityInfo>(
        "dhId_1", "deviceId-1", "devName_test", 14, dhType, "attrs_test", "subtype",
        "udidHash-1", compVersion);
    MetaCapInfoMap infoMap = {{ "udidHash-1", metaCapInfo }};
    EXPECT_CALL(*metaInfoManager_, GetMetaDataByDHType(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(infoMap), Return(DH_FWK_SUCCESS)));
    EXPECT_CALL(*dhContext_, GetUUIDByDeviceId(_)).WillRepeatedly(Return(VALUABLE_DEVICE_INFO.uuid));
    EXPECT_NO_FATAL_FAILURE(ComponentManager::GetInstance().RecoverAutoEnableSource(dhType));
}

HWTEST_F(ComponentManagerTestNew, GetRemoteVerInfo_001, TestSize.Level1)
{
    ASSERT_TRUE(metaInfoManager_ != nullptr);
    ASSERT_TRUE(dhContext_ != nullptr);
    MetaCapInfoMap emptyInfo;
    EXPECT_CALL(*metaInfoManager_, GetMetaDataByDHType(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(emptyInfo), Return(DH_FWK_SUCCESS)));
    CompVersion compVersion;
    auto ret = ComponentManager::GetInstance().GetRemoteVerInfo(
        compVersion, "udid-1", VALUABLE_DEVICE_INFO.uuid, DHType::CAMERA);
    EXPECT_EQ(ret, ERR_DH_FWK_COMPONENT_COMPVERSION_NOT_FOUND);
}

HWTEST_F(ComponentManagerTestNew, GetRemoteVerInfo_002, TestSize.Level1)
{
    ASSERT_TRUE(metaInfoManager_ != nullptr);
    ASSERT_TRUE(dhContext_ != nullptr);
    CompVersion compVersion{ .sinkVersion = "1.0", .sourceVersion = "1.0" };
    auto metaCapInfo = std::make_shared<MetaCapabilityInfo>();
    metaCapInfo->SetCompVersion(compVersion);
    metaCapInfo->SetDeviceId("deviceId-1");
    metaCapInfo->SetUdidHash("udidHash-1");
    MetaCapInfoMap infoMap = {{ "udidHash-1", metaCapInfo }};
    EXPECT_CALL(*metaInfoManager_, GetMetaDataByDHType(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(infoMap), Return(DH_FWK_SUCCESS)));
    EXPECT_CALL(*dhContext_, GetUUIDByDeviceId(_)).WillRepeatedly(Return(VALUABLE_DEVICE_INFO.uuid));
    CompVersion resultVersion;
    auto ret = ComponentManager::GetInstance().GetRemoteVerInfo(
        resultVersion, "udid-1", VALUABLE_DEVICE_INFO.uuid, DHType::CAMERA);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
}

HWTEST_F(ComponentManagerTestNew, AddAccessListener_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    sptr<IAuthorizationResultCallback> callback = nullptr;
    int32_t timeOut = 0;
    auto ret = ComponentManager::GetInstance().AddAccessListener(DHType::CAMERA, timeOut, "", callback);
    EXPECT_EQ(ret, ERR_DH_FWK_PARA_INVALID);
}

HWTEST_F(ComponentManagerTestNew, AddAccessListener_002, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    sptr<MockAuthorizationResultCallbackStub> callback = sptr<MockAuthorizationResultCallbackStub>(
        new (std::nothrow) MockAuthorizationResultCallbackStub());
    int32_t timeOut = 0;
    auto ret = ComponentManager::GetInstance().AddAccessListener(DHType::CAMERA, timeOut, "", callback);
    EXPECT_EQ(ret, ERR_DH_FWK_PARA_INVALID);
}

HWTEST_F(ComponentManagerTestNew, AddAccessListener_003, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    ComponentManager::GetInstance().compSink_.clear();
    sptr<MockAuthorizationResultCallbackStub> callback = sptr<MockAuthorizationResultCallbackStub>(
        new (std::nothrow) MockAuthorizationResultCallbackStub());
    int32_t timeOut = 0;
    const std::string TEST_PKG_NAME = "com.ohos.test";
    auto ret = ComponentManager::GetInstance().AddAccessListener(DHType::CAMERA, timeOut, TEST_PKG_NAME, callback);
    EXPECT_EQ(ret, ERR_DH_FWK_POINTER_IS_NULL);
}

HWTEST_F(ComponentManagerTestNew, AddAccessListener_004, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    IDistributedHardwareSink *nullSinkPtr = nullptr;
    ComponentManager::GetInstance().compSink_[DHType::CAMERA] = nullSinkPtr;
    sptr<MockAuthorizationResultCallbackStub> callback = sptr<MockAuthorizationResultCallbackStub>(
        new (std::nothrow) MockAuthorizationResultCallbackStub());
    int32_t timeOut = 0;
    const std::string TEST_PKG_NAME = "com.ohos.test";
    auto ret = ComponentManager::GetInstance().AddAccessListener(DHType::CAMERA, timeOut, TEST_PKG_NAME, callback);
    EXPECT_EQ(ret, ERR_DH_FWK_PARA_INVALID);
    ComponentManager::GetInstance().compSink_.clear();
}

HWTEST_F(ComponentManagerTestNew, AddAccessListener_005, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    auto sinkPtr = CreateDHSinkPtrWithSetExpectation();
    ComponentManager::GetInstance().compSink_[DHType::CAMERA] = sinkPtr.get();
    sptr<MockAuthorizationResultCallbackStub> callback = sptr<MockAuthorizationResultCallbackStub>(
        new (std::nothrow) MockAuthorizationResultCallbackStub());
    int32_t timeOut = 0;
    const std::string TEST_PKG_NAME = "com.ohos.test";
    auto ret = ComponentManager::GetInstance().AddAccessListener(DHType::CAMERA, timeOut, TEST_PKG_NAME, callback);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
    ComponentManager::GetInstance().compSink_.clear();
    ComponentManager::GetInstance().accessListenerMap_.clear();
}

HWTEST_F(ComponentManagerTestNew, RemoveAccessListener_001, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    auto ret = ComponentManager::GetInstance().RemoveAccessListener(DHType::CAMERA, "");
    EXPECT_EQ(ret, ERR_DH_FWK_PARA_INVALID);
}

HWTEST_F(ComponentManagerTestNew, RemoveAccessListener_002, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    ComponentManager::GetInstance().compSink_.clear();
    const std::string TEST_PKG_NAME = "com.ohos.test";
    auto ret = ComponentManager::GetInstance().RemoveAccessListener(DHType::CAMERA, TEST_PKG_NAME);
    EXPECT_EQ(ret, ERR_DH_FWK_POINTER_IS_NULL);
}

HWTEST_F(ComponentManagerTestNew, RemoveAccessListener_003, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    auto sinkPtr = CreateDHSinkPtrWithSetExpectation();
    ComponentManager::GetInstance().compSink_[DHType::CAMERA] = sinkPtr.get();
    ComponentManager::GetInstance().accessListenerMap_.clear();
    const std::string TEST_PKG_NAME = "com.ohos.test";
    auto ret = ComponentManager::GetInstance().RemoveAccessListener(DHType::CAMERA, TEST_PKG_NAME);
    EXPECT_EQ(ret, ERR_DH_FWK_PARA_INVALID);
    ComponentManager::GetInstance().compSink_.clear();
}

HWTEST_F(ComponentManagerTestNew, RemoveAccessListener_004, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    auto sinkPtr = CreateDHSinkPtrWithSetExpectation();
    ComponentManager::GetInstance().compSink_[DHType::CAMERA] = sinkPtr.get();
    sptr<MockAuthorizationResultCallbackStub> callback = sptr<MockAuthorizationResultCallbackStub>(
        new (std::nothrow) MockAuthorizationResultCallbackStub());
    int32_t timeOut = 0;
    const std::string TEST_PKG_NAME = "com.ohos.test";
    ComponentManager::GetInstance().AddAccessListener(DHType::CAMERA, timeOut, TEST_PKG_NAME, callback);
    auto ret = ComponentManager::GetInstance().RemoveAccessListener(DHType::CAMERA, TEST_PKG_NAME);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
    EXPECT_EQ(ComponentManager::GetInstance().accessListenerMap_.size(), (size_t)0);
    ComponentManager::GetInstance().compSink_.clear();
}

HWTEST_F(ComponentManagerTestNew, GetAccessListener_001, testing::ext::TestSize.Level1)
{
    auto ret = ComponentManager::GetInstance().GetAccessListener(DHType::CAMERA, "");
    EXPECT_EQ(ret, nullptr);
}

HWTEST_F(ComponentManagerTestNew, GetAccessListener_002, testing::ext::TestSize.Level1)
{
    ComponentManager::GetInstance().accessListenerMap_.clear();
    const std::string TEST_PKG_NAME = "com.ohos.test";
    auto ret = ComponentManager::GetInstance().GetAccessListener(DHType::CAMERA, TEST_PKG_NAME);
    EXPECT_EQ(ret, nullptr);
}

HWTEST_F(ComponentManagerTestNew, GetAccessListener_003, testing::ext::TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    auto sinkPtr = CreateDHSinkPtrWithSetExpectation();
    ComponentManager::GetInstance().compSink_[DHType::CAMERA] = sinkPtr.get();
    sptr<MockAuthorizationResultCallbackStub> callback = sptr<MockAuthorizationResultCallbackStub>(
        new (std::nothrow) MockAuthorizationResultCallbackStub());
    int32_t timeOut = 0;
    const std::string TEST_PKG_NAME = "com.ohos.test";
    ComponentManager::GetInstance().AddAccessListener(DHType::CAMERA, timeOut, TEST_PKG_NAME, callback);
    auto ret = ComponentManager::GetInstance().GetAccessListener(DHType::CAMERA, TEST_PKG_NAME);
    EXPECT_NE(ret, nullptr);
    ComponentManager::GetInstance().compSink_.clear();
    ComponentManager::GetInstance().accessListenerMap_.clear();
}

HWTEST_F(ComponentManagerTestNew, ForceDisableSinkInternal_001, TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    EXPECT_CALL(*componentLoader_, IsDHTypeSupport(_)).WillRepeatedly(Return(false));
    std::vector<sptr<IHDSinkStatusListener>> listeners;
    auto ret = ComponentManager::GetInstance().ForceDisableSinkInternal(CAMERA_DESCRIPTOR, listeners);
    EXPECT_EQ(ret, ERR_DH_FWK_TYPE_NOT_EXIST);
}

HWTEST_F(ComponentManagerTestNew, ForceDisableSinkInternal_002, TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    EXPECT_CALL(*componentLoader_, IsDHTypeSupport(_)).WillRepeatedly(Return(true));
    ComponentManager::GetInstance().dhSinkStatus_[CAMERA_DESCRIPTOR.dhType].enableInfos.clear();
    std::vector<sptr<IHDSinkStatusListener>> listeners;
    auto ret = ComponentManager::GetInstance().ForceDisableSinkInternal(CAMERA_DESCRIPTOR, listeners);
    EXPECT_EQ(ret, ERR_DH_FWK_COMPONENT_REPEAT_CALL);
    ComponentManager::GetInstance().dhSinkStatus_.clear();
}

HWTEST_F(ComponentManagerTestNew, ForceDisableSinkInternal_003, TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    EXPECT_CALL(*componentLoader_, IsDHTypeSupport(_)).WillRepeatedly(Return(true));
    auto sinkPtr = CreateDHSinkPtrWithSetExpectation();
    ComponentManager::GetInstance().compSink_[CAMERA_DESCRIPTOR.dhType] = sinkPtr.get();
    ComponentManager::DHSinkStatus &sinkStatus =
        ComponentManager::GetInstance().dhSinkStatus_[CAMERA_DESCRIPTOR.dhType];
    ComponentManager::DHStatusEnableInfo &enableInfo =
        sinkStatus.enableInfos[CAMERA_DESCRIPTOR.id];
    enableInfo.refEnable = 2;
    sinkStatus.refLoad = 3;
    sinkStatus.listeners[{ .uid = CAMERA_UID, .pid = CAMERA_PID }] =
        sptr<MockHDSinkStatusListenerStub>(new (std::nothrow) MockHDSinkStatusListenerStub());
    enableInfo.dhStatusCtrl[{ .uid = CAMERA_UID, .pid = CAMERA_PID }].enableState =
        ComponentManager::EnableState::ENABLED;
    std::vector<sptr<IHDSinkStatusListener>> listeners;
    auto ret = ComponentManager::GetInstance().ForceDisableSinkInternal(CAMERA_DESCRIPTOR, listeners);
    EXPECT_EQ(ret, DH_FWK_SUCCESS);
    EXPECT_EQ(listeners.size(), (size_t)1);
    ComponentManager::GetInstance().compSink_.clear();
    ComponentManager::GetInstance().dhSinkStatus_.clear();
}

HWTEST_F(ComponentManagerTestNew, ForceDisableSourceInternal_002, TestSize.Level1)
{
    ASSERT_TRUE(componentLoader_ != nullptr);
    ComponentManager::DHStatusSourceEnableInfoKey enableInfoKey {
        .networkId = VALUABLE_DEVICE_INFO.networkId,
        .dhId = CAMERA_DESCRIPTOR.id
    };
    ComponentManager::GetInstance().dhSourceStatus_[CAMERA_DESCRIPTOR.dhType].enableInfos.clear();
    std::vector<sptr<IHDSourceStatusListener>> listeners;
    auto ret = ComponentManager::GetInstance().ForceDisableSourceInternal(
        VALUABLE_DEVICE_INFO.networkId, CAMERA_DESCRIPTOR, listeners);
    EXPECT_EQ(ret, ERR_DH_FWK_COMPONENT_REPEAT_CALL);
    ComponentManager::GetInstance().dhSourceStatus_.clear();
}

HWTEST_F(ComponentManagerTestNew, SyncRemoteDeviceInfoBySoftbus_003, TestSize.Level1)
{
    std::string realNetworkId = "realNetworkId_test_12345";
    EnableStep enableStep = EnableStep::ENABLE_SOURCE;
    sptr<TestCallback> callback1 = sptr<TestCallback>(new (std::nothrow) TestCallback());
    sptr<TestCallback> callback2 = sptr<TestCallback>(new (std::nothrow) TestCallback());
    ComponentManager::GetInstance().syncDeviceInfoMap_.clear();
    ComponentManager::GetInstance().SyncRemoteDeviceInfoBySoftbus(realNetworkId, enableStep, callback1);
    size_t firstSize = ComponentManager::GetInstance().syncDeviceInfoMap_[realNetworkId].second.size();
    ComponentManager::GetInstance().SyncRemoteDeviceInfoBySoftbus(realNetworkId, enableStep, callback2);
    size_t secondSize = ComponentManager::GetInstance().syncDeviceInfoMap_[realNetworkId].second.size();
    EXPECT_EQ(secondSize, firstSize + 1);
    ComponentManager::GetInstance().syncDeviceInfoMap_.clear();
}

HWTEST_F(ComponentManagerTestNew, OnGetDescriptors_003, TestSize.Level1)
{
    std::string realNetworkId = "realNetworkId_test_12345";
    std::vector<DHDescriptor> descriptors;
    ComponentManager::GetInstance().syncDeviceInfoMap_.clear();
    ComponentManager::GetInstance().OnGetDescriptors(realNetworkId, descriptors);
}

HWTEST_F(ComponentManagerTestNew, OnGetDescriptors_004, TestSize.Level1)
{
    std::string realNetworkId = "realNetworkId_test_12345";
    EnableStep enableStep = EnableStep::ENABLE_SOURCE;
    std::vector<DHDescriptor> descriptors;
    DHDescriptor descriptor;
    descriptor.id = "camera_1";
    descriptor.dhType = DHType::CAMERA;
    descriptors.push_back(descriptor);
    sptr<TestCallback> callback = sptr<TestCallback>(new (std::nothrow) TestCallback());
    ComponentManager::GetInstance().syncDeviceInfoMap_[realNetworkId] = {enableStep, {callback}};
    ComponentManager::GetInstance().OnGetDescriptors(realNetworkId, descriptors);
    EXPECT_EQ(ComponentManager::GetInstance().syncDeviceInfoMap_.empty(), true);
}
} // namespace DistributedHardware
} // namespace OHOS
