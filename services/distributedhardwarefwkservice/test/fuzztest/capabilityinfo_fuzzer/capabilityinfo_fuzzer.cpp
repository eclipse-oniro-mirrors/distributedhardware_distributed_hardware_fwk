/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "capabilityinfo_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

#include <fuzzer/FuzzedDataProvider.h>

#include "cJSON.h"

#include "capability_info.h"
#include "capability_utils.h"
#include "constants.h"
#include "dh_utils_tool.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
    constexpr uint8_t JSON_CASE_COUNT = 5;
    constexpr uint8_t JSON_CASE_INVALID_DH_ID = 1;
    constexpr uint8_t JSON_CASE_INVALID_DEV_TYPE = 2;
    constexpr uint8_t JSON_CASE_INVALID_DH_TYPE = 3;
    constexpr uint8_t JSON_CASE_INVALID_DH_ATTRS = 4;
    const std::string VALID_DEVICE_ID = "validDeviceId_123";
    const std::string VALID_DH_ID = "validDhId_123456";
    const std::string OTHER_VALID_DEVICE_ID = "otherValidDevId_";
    const std::string MATCH_KEY = "validDeviceId_123###validDhId_123456";
}

void CapabilityInfoFromJsonStringFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint8_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    uint8_t jsonCase = fdp.ConsumeIntegral<uint8_t>() % JSON_CASE_COUNT;
    std::string jsonStr = fdp.ConsumeRandomLengthString();

    CapabilityInfo capInfo;
    // Cover the length invalid and json parse failed branches.
    capInfo.FromJsonString(jsonStr);

    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        return;
    }
    cJSON_AddStringToObject(root, DH_ID, VALID_DH_ID.c_str());
    cJSON_AddStringToObject(root, DEV_ID, VALID_DEVICE_ID.c_str());
    cJSON_AddStringToObject(root, DEV_NAME, "dev_name_test");
    cJSON_AddNumberToObject(root, DEV_TYPE, 1);
    cJSON_AddNumberToObject(root, DH_TYPE, 1);
    cJSON_AddStringToObject(root, DH_ATTRS, "attrs_test");
    cJSON_AddStringToObject(root, DH_SUBTYPE, "subtype_test");
    switch (jsonCase) {
        case JSON_CASE_INVALID_DH_ID:
            // DH_ID is not string, cover the DH_ID invalid branch.
            cJSON_DeleteItemFromObject(root, DH_ID);
            cJSON_AddNumberToObject(root, DH_ID, 0);
            break;
        case JSON_CASE_INVALID_DEV_TYPE:
            // DEV_TYPE is not number, cover the DEV_TYPE invalid branch.
            cJSON_DeleteItemFromObject(root, DEV_TYPE);
            cJSON_AddStringToObject(root, DEV_TYPE, "invalid");
            break;
        case JSON_CASE_INVALID_DH_TYPE:
            // DH_TYPE is not number, cover the DH_TYPE invalid branch.
            cJSON_DeleteItemFromObject(root, DH_TYPE);
            cJSON_AddStringToObject(root, DH_TYPE, "invalid");
            break;
        case JSON_CASE_INVALID_DH_ATTRS:
            // DH_ATTRS is not string, cover the DH_ATTRS invalid branch.
            cJSON_DeleteItemFromObject(root, DH_ATTRS);
            cJSON_AddNumberToObject(root, DH_ATTRS, 0);
            break;
        default:
            break;
    }
    char *cjson = cJSON_PrintUnformatted(root);
    if (cjson != nullptr) {
        std::string craftedJson(cjson);
        cJSON_free(cjson);
        // Cover all the field valid or invalid branches of FromJson.
        capInfo.FromJsonString(craftedJson);
    }
    cJSON_Delete(root);
}

void CapabilityInfoToJsonStringFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint16_t) + sizeof(uint32_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    uint16_t deviceType = fdp.ConsumeIntegral<uint16_t>();
    DHType dhType = static_cast<DHType>(fdp.ConsumeIntegral<uint32_t>());
    std::string dhId = fdp.ConsumeRandomLengthString();
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string deviceName = fdp.ConsumeRandomLengthString();
    std::string dhAttrs = fdp.ConsumeRandomLengthString();
    std::string dhSubtype = fdp.ConsumeRandomLengthString();

    std::shared_ptr<CapabilityInfo> capInfo = std::make_shared<CapabilityInfo>(dhId, deviceId, deviceName,
        deviceType, dhType, dhAttrs, dhSubtype);
    std::string jsonStr = capInfo->ToJsonString();

    CapabilityInfo parsedInfo;
    // Cover the FromJson success roundtrip branch.
    parsedInfo.FromJsonString(jsonStr);
}

void CapabilityInfoCompareFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint16_t) + sizeof(uint32_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    uint16_t deviceType = fdp.ConsumeIntegral<uint16_t>();
    DHType dhType = static_cast<DHType>(fdp.ConsumeIntegral<uint32_t>());
    std::string dhId = fdp.ConsumeRandomLengthString();
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string deviceName = fdp.ConsumeRandomLengthString();
    std::string dhAttrs = fdp.ConsumeRandomLengthString();
    std::string dhSubtype = fdp.ConsumeRandomLengthString();

    std::shared_ptr<CapabilityInfo> capInfo = std::make_shared<CapabilityInfo>(dhId, deviceId, deviceName,
        deviceType, dhType, dhAttrs, dhSubtype);
    std::shared_ptr<CapabilityInfo> otherInfo = std::make_shared<CapabilityInfo>(dhId, deviceId, deviceName,
        deviceType, dhType, dhAttrs, dhSubtype);
    // Cover the all fields equal branch.
    capInfo->Compare(*otherInfo);
    // Cover the fields not equal branches.
    std::shared_ptr<CapabilityInfo> diffInfo = std::make_shared<CapabilityInfo>("dhIdDiff", "devIdDiff",
        "devNameDiff", deviceType + 1, DHType::UNKNOWN, "attrsDiff", "subtypeDiff");
    capInfo->Compare(*diffInfo);
}

void CapabilityInfoKeyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string dhId = fdp.ConsumeRandomLengthString();
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string deviceName = fdp.ConsumeRandomLengthString();
    std::string dhAttrs = fdp.ConsumeRandomLengthString();
    std::string dhSubtype = fdp.ConsumeRandomLengthString();

    std::shared_ptr<CapabilityInfo> capInfo = std::make_shared<CapabilityInfo>(dhId, deviceId, deviceName,
        static_cast<uint16_t>(1), DHType::CAMERA, dhAttrs, dhSubtype);
    capInfo->GetKey();
    capInfo->GetAnonymousKey();

    // Cover GetCapabilityKey and IsCapKeyMatchDeviceId branches.
    std::string key = GetCapabilityKey(deviceId, dhId);
    IsCapKeyMatchDeviceId(key, deviceId);
    IsCapKeyMatchDeviceId(MATCH_KEY, VALID_DEVICE_ID);
    IsCapKeyMatchDeviceId(MATCH_KEY, OTHER_VALID_DEVICE_ID);
    IsCapKeyMatchDeviceId("noSeparatorKey", VALID_DEVICE_ID);
    IsCapKeyMatchDeviceId("", deviceId);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::CapabilityInfoFromJsonStringFuzzTest(data, size);
    OHOS::DistributedHardware::CapabilityInfoToJsonStringFuzzTest(data, size);
    OHOS::DistributedHardware::CapabilityInfoCompareFuzzTest(data, size);
    OHOS::DistributedHardware::CapabilityInfoKeyFuzzTest(data, size);
    return 0;
}
