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

#include "dhtransportobj_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include "cJSON.h"

#include "capability_info.h"
#include "constants.h"
#include "dh_transport_obj.h"
#include "dh_utils_tool.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"
#include "meta_capability_info.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
    const std::string VALID_NETWORK_ID = "validNetworkId123";
    constexpr uint8_t TWO = 2;
}

void CommMsgJsonFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t) + sizeof(uint64_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    CommMsg commMsg;
    commMsg.code = fdp.ConsumeIntegral<int32_t>();
    commMsg.userId = fdp.ConsumeIntegral<int32_t>();
    commMsg.tokenId = fdp.ConsumeIntegral<uint64_t>();
    commMsg.msg = fdp.ConsumeRandomLengthString();
    commMsg.accountId = fdp.ConsumeRandomLengthString();
    commMsg.isSyncMeta = fdp.ConsumeBool();

    // Cover the ToJson of CommMsg.
    std::string msgStr = GetCommMsgString(commMsg);

    // Cover the FromJson roundtrip branches of CommMsg.
    cJSON *root = cJSON_Parse(msgStr.c_str());
    if (root != nullptr) {
        CommMsg parsedMsg;
        FromJson(root, parsedMsg);
        cJSON_Delete(root);
    }

    // Cover the json pointer nullptr branches.
    ToJson(nullptr, commMsg);
    FromJson(nullptr, commMsg);

    // Cover the msg null print branch with an invalid json.
    cJSON *invalidRoot = cJSON_Parse(commMsg.msg.c_str());
    if (invalidRoot != nullptr) {
        CommMsg invalidMsg;
        FromJson(invalidRoot, invalidMsg);
        cJSON_Delete(invalidRoot);
    }
}

namespace {
void BuildFullCapsRspFromFdp(FuzzedDataProvider &fdp, FullCapsRsp &capsRsp, bool &isSyncMeta)
{
    uint16_t deviceType = fdp.ConsumeIntegral<uint16_t>();
    DHType dhType = static_cast<DHType>(fdp.ConsumeIntegral<uint32_t>());
    isSyncMeta = (fdp.ConsumeIntegral<uint8_t>() % TWO) == 0;
    std::string dhId = fdp.ConsumeRandomLengthString();
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string deviceName = fdp.ConsumeRandomLengthString();
    std::string dhAttrs = fdp.ConsumeRandomLengthString();
    std::string dhSubtype = fdp.ConsumeRandomLengthString();
    std::string udidHash = fdp.ConsumeRandomLengthString();

    capsRsp.networkId = fdp.ConsumeRandomLengthString();
    std::shared_ptr<CapabilityInfo> capInfo = std::make_shared<CapabilityInfo>(dhId, deviceId, deviceName,
        deviceType, dhType, dhAttrs, dhSubtype);
    capsRsp.caps.push_back(capInfo);
    std::shared_ptr<MetaCapabilityInfo> metaCapInfo = std::make_shared<MetaCapabilityInfo>(dhId, deviceId,
        deviceName, deviceType, dhType, dhAttrs, dhSubtype, udidHash, CompVersion { .sinkVersion = "1.0" });
    capsRsp.metaCaps.push_back(metaCapInfo);
}

void FuzzFullCapsRspJsonRoundtrip(const FullCapsRsp &capsRsp, bool isSyncMeta)
{
    // Cover the meta caps and common caps branches of ToJson.
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        return;
    }
    ToJson(root, capsRsp, isSyncMeta);
    char *cjson = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (cjson != nullptr) {
        std::string capsStr(cjson);
        cJSON_free(cjson);
        // Cover the FromJson branches of the parsed json.
        cJSON *parsedRoot = cJSON_Parse(capsStr.c_str());
        if (parsedRoot != nullptr) {
            FullCapsRsp parsedRsp;
            FromJson(parsedRoot, parsedRsp, isSyncMeta);
            FromJson(parsedRoot, parsedRsp, !isSyncMeta);
            cJSON_Delete(parsedRoot);
        }
    }

    // Cover the other isSyncMeta branch of ToJson.
    cJSON *otherRoot = cJSON_CreateObject();
    if (otherRoot == nullptr) {
        return;
    }
    ToJson(otherRoot, capsRsp, !isSyncMeta);
    cJSON_Delete(otherRoot);
}

void FuzzFullCapsRspFromConstructedJson(bool isSyncMeta)
{
    // Cover the networkId invalid and caps array missing branches.
    cJSON *root = cJSON_CreateObject();
    if (root == nullptr) {
        return;
    }
    cJSON *capsArray = cJSON_CreateArray();
    if (capsArray == nullptr) {
        cJSON_Delete(root);
        return;
    }
    cJSON_AddItemToObject(root, CAPS_RSP_NETWORKID_KEY, cJSON_CreateString(VALID_NETWORK_ID.c_str()));
    cJSON *capJson = cJSON_CreateObject();
    if (capJson == nullptr) {
        cJSON_Delete(capsArray);
        cJSON_Delete(root);
        return;
    }
    cJSON_AddStringToObject(capJson, DH_ID, "dhId_test_123");
    cJSON_AddStringToObject(capJson, DEV_ID, "devId_test_123");
    cJSON_AddStringToObject(capJson, DEV_NAME, "dev_name_test");
    cJSON_AddNumberToObject(capJson, DEV_TYPE, 1);
    cJSON_AddNumberToObject(capJson, DH_TYPE, 1);
    cJSON_AddStringToObject(capJson, DH_ATTRS, "attrs_test");
    cJSON_AddStringToObject(capJson, DH_SUBTYPE, "subtype_test");
    cJSON_AddItemToArray(capsArray, capJson);
    cJSON_AddItemToObject(root, CAPS_RSP_CAPS_KEY, capsArray);

    FullCapsRsp noNetworkIdRsp;
    FromJson(root, noNetworkIdRsp, isSyncMeta);

    FullCapsRsp validRsp;
    FromJson(root, validRsp, isSyncMeta);
    cJSON_Delete(root);
}
}

void FullCapsRspJsonFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint16_t) + sizeof(uint32_t) + sizeof(uint8_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    FullCapsRsp capsRsp;
    bool isSyncMeta = false;
    BuildFullCapsRspFromFdp(fdp, capsRsp, isSyncMeta);

    FuzzFullCapsRspJsonRoundtrip(capsRsp, isSyncMeta);
    FuzzFullCapsRspFromConstructedJson(isSyncMeta);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::CommMsgJsonFuzzTest(data, size);
    OHOS::DistributedHardware::FullCapsRspJsonFuzzTest(data, size);
    return 0;
}
