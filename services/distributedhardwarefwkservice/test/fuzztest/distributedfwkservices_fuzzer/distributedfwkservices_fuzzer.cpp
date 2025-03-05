/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "distributedfwkservices_fuzzer.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <unistd.h>

#include "distributed_hardware_errno.h"
#include "distributed_hardware_service.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
    const int32_t SAID = 4801;
    const uint32_t QUERY_LOCAL_SYS_SIZE = 6;
    const QueryLocalSysSpecType SPEC_TYPE[QUERY_LOCAL_SYS_SIZE] = {
        QueryLocalSysSpecType::MIN, QueryLocalSysSpecType::HISTREAMER_AUDIO_ENCODER,
        QueryLocalSysSpecType::HISTREAMER_AUDIO_DECODER, QueryLocalSysSpecType::HISTREAMER_VIDEO_ENCODER,
        QueryLocalSysSpecType::HISTREAMER_VIDEO_DECODER, QueryLocalSysSpecType::MAX
    };
}

class MyFwkServicesFuzzTest : public IRemoteStub<IPublisherListener> {
public:
    virtual sptr<IRemoteObject> AsObject() override
    {
        return nullptr;
    }
    void OnMessage(const DHTopic topic, const std::string& message) override
    {
        return;
    }
};

void FwkServicesQueryLocalSysSpecFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint32_t))) {
        return;
    }
    DistributedHardwareService service(SAID, true);
    uint32_t sysSpec = *(reinterpret_cast<const uint32_t*>(data));
    QueryLocalSysSpecType spec = SPEC_TYPE[sysSpec % QUERY_LOCAL_SYS_SIZE];

    service.QueryLocalSysSpec(spec);
}

void FwkServicesQueryDhSysSpecFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    DistributedHardwareService service(SAID, true);
    std::string targetKey(reinterpret_cast<const char*>(data), size);
    std::string attrs(reinterpret_cast<const char*>(data), size);

    service.QueryDhSysSpec(targetKey, attrs);
}

void FwkServicesNotifySourceRemoteSinkStartedFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    DistributedHardwareService service(SAID, true);
    std::string deviceId(reinterpret_cast<const char*>(data), size);

    service.NotifySourceRemoteSinkStarted(deviceId);
}

void FwkServicesPauseDistributedHardwareFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    DistributedHardwareService service(SAID, true);
    DHType dhType = DHType::AUDIO;
    std::string networkId(reinterpret_cast<const char*>(data), size);

    service.PauseDistributedHardware(dhType, networkId);
}

void FwkServicesResumeDistributedHardwareFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    DistributedHardwareService service(SAID, true);
    DHType dhType = DHType::AUDIO;
    std::string networkId(reinterpret_cast<const char*>(data), size);

    service.ResumeDistributedHardware(dhType, networkId);
}

void FwkServicesStopDistributedHardwareFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    DistributedHardwareService service(SAID, true);
    DHType dhType = DHType::AUDIO;
    std::string networkId(reinterpret_cast<const char*>(data), size);
    
    service.StopDistributedHardware(dhType, networkId);
}

void FwkServicesGetDistributedHardwareFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    DistributedHardwareService service(SAID, true);
    std::string networkId(reinterpret_cast<const char*>(data), size);
    std::vector<DHDescriptor> descriptors;

    service.GetDistributedHardware(networkId, descriptors);
}

void FwkServicesRegisterDHStatusListenerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    DistributedHardwareService service(SAID, true);
    std::string networkId(reinterpret_cast<const char*>(data), size);
    sptr<IHDSourceStatusListener> listener = nullptr;

    service.RegisterDHStatusListener(networkId, listener);
}

void FwkServicesUnregisterDHStatusListenerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    DistributedHardwareService service(SAID, true);
    std::string networkId(reinterpret_cast<const char*>(data), size);
    sptr<IHDSourceStatusListener> listener = nullptr;

    service.UnregisterDHStatusListener(networkId, listener);
}

void FwkServicesEnableSinkFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    DistributedHardwareService service(SAID, true);
    std::vector<DHDescriptor> descriptors = {
        { std::string(reinterpret_cast<const char*>(data), size), DHType::AUDIO }
    };

    service.EnableSink(descriptors);
}

void FwkServicesDisableSinkFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    DistributedHardwareService service(SAID, true);
    std::vector<DHDescriptor> descriptors = {
        { std::string(reinterpret_cast<const char*>(data), size), DHType::AUDIO }
    };

    service.DisableSink(descriptors);
}

void FwkServicesEnableSourceFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    DistributedHardwareService service(SAID, true);
    std::string networkId(reinterpret_cast<const char*>(data), size);
    std::vector<DHDescriptor> descriptors = {
        { std::string(reinterpret_cast<const char*>(data), size), DHType::AUDIO }
    };

    service.EnableSource(networkId, descriptors);
}

void FwkServicesDisableSourceFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }
    DistributedHardwareService service(SAID, true);
    std::string networkId(reinterpret_cast<const char*>(data), size);
    std::vector<DHDescriptor> descriptors = {
        { std::string(reinterpret_cast<const char*>(data), size), DHType::AUDIO }
    };

    service.DisableSource(networkId, descriptors);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::FwkServicesQueryLocalSysSpecFuzzTest(data, size);
    OHOS::DistributedHardware::FwkServicesQueryDhSysSpecFuzzTest(data, size);
    OHOS::DistributedHardware::FwkServicesPauseDistributedHardwareFuzzTest(data, size);
    OHOS::DistributedHardware::FwkServicesResumeDistributedHardwareFuzzTest(data, size);
    OHOS::DistributedHardware::FwkServicesStopDistributedHardwareFuzzTest(data, size);
    return 0;
}
