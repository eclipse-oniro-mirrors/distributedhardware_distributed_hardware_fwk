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

/*
 * lite variant of utils/src/dh_utils_tool.cpp. Deltas versus the standard
 * source:
 * 1. Sha256() is backed by the self-contained FIPS 180-4 implementation in
 *    utils/lite/sha256.cpp (no OpenSSL on lite). Value domain is identical
 *    to the standard system (64-char lowercase hex), so deviceId =
 *    Sha256(uuid) and udidHash = Sha256(udid) stay byte-comparable across
 *    L1/L2 (contracts C6).
 * 2. DeviceManager access is adapted to the current DM lite pure-C vtable
 *    SDK (DmDeviceManagerGetInstance); the DM-dependent id getters keep
 *    their frozen signatures from utils/include/dh_utils_tool.h.
 * 3. GetUUIDByDm/GetUDIDByDm are supplied by the softbus bus_center public
 *    API GetNodeKeyInfo via lite/node_key_provider (TASK-13, D-DM1 ruling 2).
 */

#include "dh_utils_tool.h"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <sys/time.h>
#include <vector>
#include <zlib.h>

#include "parameter.h"

#include "device_manager.h"
#include "dm_device_info.h"

#include "constants.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"
#include "node_key_provider.h"
#include "sha256.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
    constexpr uint32_t MAX_MESSAGE_LEN = 40 * 1024 * 1024;
    constexpr uint32_t MIN_MESSAGE_LEN = 0;
    constexpr uint32_t MAX_ID_LEN = 256;
    constexpr uint32_t MAX_ARR_SIZE = 10000;
    constexpr uint32_t MAX_JSON_SIZE = 40 * 1024 * 1024;
    constexpr uint32_t MAX_HASH_SIZE = 64;
    constexpr uint32_t MAX_KEY_SIZE = 256;
    constexpr int32_t MS_ONE_SECOND = 1000;
    constexpr int32_t WORD_WIDTH_8 = 8;
    constexpr int32_t WORD_WIDTH_4 = 4;
    constexpr int32_t COMPRESS_SLICE_SIZE = 1024;
    constexpr int32_t DM_LITE_UNAVAILABLE = -1;
    constexpr const char *PARAM_KEY_OS_TYPE = "OS_TYPE";
}

/*
 * NOTE (lite baseline drift @fae6ed46, resolved by TASK-13 / D-DM1 ruling 2):
 * the device_manager lite SDK is a pure C vtable API (DmDeviceManagerGetInstance
 * + DeviceManagerVtable) and exposes NO synchronous uuid/udid query. The
 * uuid/udid supply for GetUUIDByDm/GetUDIDByDm therefore comes from the softbus
 * bus_center public API GetNodeKeyInfo (NODE_KEY_UUID/NODE_KEY_UDID), wrapped by
 * node_key_provider.h. deviceId = Sha256(uuid) / udidHash = Sha256(udid)
 * (contracts C6) stay intact; failure paths keep the TASK-1 semantics:
 * return "" + DHLOGW, so the daemon online chain early-exits without crashing.
 */
namespace {
int32_t DmLiteGetLocalDeviceInfo(DmDeviceInfo &info)
{
    DeviceManager *dm = DmDeviceManagerGetInstance();
    if (dm == nullptr || dm->vtable == nullptr || dm->vtable->GetLocalDeviceInfo == nullptr) {
        DHLOGE("DM lite instance or GetLocalDeviceInfo is unavailable");
        return DM_LITE_UNAVAILABLE;
    }
    DmString pkgName = DmStringCreate(DH_FWK_PKG_NAME);
    int32_t ret = dm->vtable->GetLocalDeviceInfo(&pkgName, &info);
    DmStringDestroy(&pkgName);
    return ret;
}

/*
 * L1 DM lite cannot supply the local device identity: its GetLocalDeviceInfo
 * goes through the softbus client-plugin path, which is not built into the lite
 * rootfs (dlopen libdsoftbus_client_plugin.z.so fails, err 96929744). The
 * softbus bus_center API itself is available in-process (the audio lite sink
 * calls it successfully), so fall back to it. Without this the DH server
 * session name degrades to "ohos.dhardware.session_" (empty suffix) and the L2
 * peer cannot open the session (OpenSession -426115007 -> GET_DH -10811).
 */
bool GetLocalNodeInfoFromSoftbus(NodeBasicInfo &nodeInfo)
{
    nodeInfo = NodeBasicInfo {};
    int32_t ret = GetLocalNodeDeviceInfo(DH_FWK_PKG_NAME, &nodeInfo);
    if (ret != SOFTBUS_OK || nodeInfo.networkId[0] == '\0') {
        DHLOGE("softbus GetLocalNodeDeviceInfo fallback failed, ret = %{public}d", ret);
        return false;
    }
    return true;
}
} // namespace

int64_t GetCurrentTime()
{
    struct timeval tv {
        0
    };
    gettimeofday(&tv, nullptr);
    return tv.tv_sec * MS_ONE_SECOND + tv.tv_usec / MS_ONE_SECOND;
}

std::string GetRandomID()
{
    static std::random_device rd;
    static std::uniform_int_distribution<uint64_t> dist(0ULL, 0xFFFFFFFFFFFFFFFFULL);
    uint64_t ab = dist(rd);
    uint64_t cd = dist(rd);
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    std::stringstream ss;
    ab = (ab & 0xFFFFFFFFFFFF0FFFULL) | 0x0000000000004000ULL;
    cd = (cd & 0x3FFFFFFFFFFFFFFFULL) | 0x8000000000000000ULL;
    a = (ab >> 32U);
    b = (ab & 0xFFFFFFFFU);
    c = (cd >> 32U);
    d = (cd & 0xFFFFFFFFU);
    ss << std::hex << std::nouppercase << std::setfill('0');
    ss << std::setw(WORD_WIDTH_8) << (a);
    ss << std::setw(WORD_WIDTH_4) << (b >> 16U);
    ss << std::setw(WORD_WIDTH_4) << (b & 0xFFFFU);
    ss << std::setw(WORD_WIDTH_4) << (c >> 16U);
    ss << std::setw(WORD_WIDTH_4) << (c & 0xFFFFU);
    ss << std::setw(WORD_WIDTH_8) << d;

    return ss.str();
}

std::string GetUUIDByDm(const std::string &networkId)
{
    if (!IsIdLengthValid(networkId)) {
        return "";
    }
    // TASK-13 (D-DM1 ruling 2): softbus bus_center supplies uuid on lite.
    std::string uuid;
    int32_t ret = GetSoftbusNodeKey(networkId, SOFTBUS_NODE_KEY_UUID, uuid);
    if (ret != SOFTBUS_NODE_KEY_OK || uuid.empty()) {
        DHLOGW("GetUUIDByDm: softbus GetNodeKeyInfo(NODE_KEY_UUID) failed, ret = %{public}d", ret);
        return "";
    }
    return uuid;
}

std::string GetUDIDByDm(const std::string &networkId)
{
    if (!IsIdLengthValid(networkId)) {
        return "";
    }
    // TASK-13 (D-DM1 ruling 2): softbus bus_center supplies udid on lite.
    std::string udid;
    int32_t ret = GetSoftbusNodeKey(networkId, SOFTBUS_NODE_KEY_UDID, udid);
    if (ret != SOFTBUS_NODE_KEY_OK || udid.empty()) {
        DHLOGW("GetUDIDByDm: softbus GetNodeKeyInfo(NODE_KEY_UDID) failed, ret = %{public}d", ret);
        return "";
    }
    return udid;
}

std::string GetDeviceIdByUUID(const std::string &uuid)
{
    if (!IsIdLengthValid(uuid)) {
        DHLOGE("uuid is invalid!");
        return "";
    }
    return Sha256(uuid);
}

std::string Sha256(const std::string& in)
{
    return Sha256Hex(in);
}

DeviceInfo GetLocalDeviceInfo()
{
    DeviceInfo devInfo { "", "", "", "", "", "", 0 };
    auto fillFromSoftbus = [&devInfo](const NodeBasicInfo &nodeInfo) {
        devInfo.networkId = nodeInfo.networkId;
        devInfo.uuid = GetUUIDByDm(devInfo.networkId);
        devInfo.deviceId = GetDeviceIdByUUID(devInfo.uuid);
        devInfo.udid = GetUDIDByDm(devInfo.networkId);
        devInfo.udidHash = devInfo.udid.empty() ? "" : Sha256(devInfo.udid);
        devInfo.deviceName = nodeInfo.deviceName;
        devInfo.deviceType = nodeInfo.deviceTypeId;
    };
    DmDeviceInfo info;
    DmDeviceInfoInit(&info);
    auto ret = DmLiteGetLocalDeviceInfo(info);
    if (ret != DH_FWK_SUCCESS) {
        DHLOGE("GetLocalNodeDeviceInfo failed, errCode = %{public}d", ret);
        DmDeviceInfoDestroy(&info);
        NodeBasicInfo nodeInfo {};
        if (!GetLocalNodeInfoFromSoftbus(nodeInfo)) {
            return devInfo;
        }
        fillFromSoftbus(nodeInfo);
        DHLOGI("GetLocalDeviceInfo: softbus fallback hit, networkId_len=%{public}d",
            static_cast<int32_t>(devInfo.networkId.size()));
    } else {
        devInfo.networkId = info.networkId;
        devInfo.uuid = GetUUIDByDm(devInfo.networkId);
        devInfo.deviceId = GetDeviceIdByUUID(devInfo.uuid);
        devInfo.udid = GetUDIDByDm(devInfo.networkId);
        devInfo.udidHash = devInfo.udid.empty() ? "" : Sha256(devInfo.udid);
        devInfo.deviceName = info.deviceName;
        devInfo.deviceType = info.deviceTypeId;
        DmDeviceInfoDestroy(&info);
        if (devInfo.networkId.empty()) {
            NodeBasicInfo nodeInfo {};
            if (!GetLocalNodeInfoFromSoftbus(nodeInfo)) {
                return devInfo;
            }
            fillFromSoftbus(nodeInfo);
            DHLOGI("GetLocalDeviceInfo: softbus fallback hit (empty DM id), networkId_len=%{public}d",
                static_cast<int32_t>(devInfo.networkId.size()));
        }
    }
    if (devInfo.uuid.empty() || devInfo.udid.empty()) {
        DHLOGW("GetLocalDeviceInfo: partial identity, uuid_len=%{public}zu, udid_len=%{public}zu",
            devInfo.uuid.size(), devInfo.udid.size());
    }
    return devInfo;
}

std::string GetLocalNetworkId()
{
    DmDeviceInfo info;
    DmDeviceInfoInit(&info);
    auto ret = DmLiteGetLocalDeviceInfo(info);
    if (ret != DH_FWK_SUCCESS) {
        DHLOGE("GetLocalNodeDeviceInfo failed, errCode = %{public}d", ret);
        DmDeviceInfoDestroy(&info);
        NodeBasicInfo nodeInfo {};
        if (GetLocalNodeInfoFromSoftbus(nodeInfo)) {
            DHLOGI("GetLocalNetworkId: softbus fallback hit, networkId_len=%{public}d",
                static_cast<int32_t>(strlen(nodeInfo.networkId)));
            return nodeInfo.networkId;
        }
        return "";
    }
    std::string networkId = info.networkId;
    DmDeviceInfoDestroy(&info);
    if (networkId.empty()) {
        NodeBasicInfo nodeInfo {};
        if (GetLocalNodeInfoFromSoftbus(nodeInfo)) {
            DHLOGI("GetLocalNetworkId: softbus fallback hit (empty DM id), networkId_len=%{public}d",
                static_cast<int32_t>(strlen(nodeInfo.networkId)));
            return nodeInfo.networkId;
        }
    }
    return networkId;
}

std::string GetLocalUdid()
{
    DmDeviceInfo info;
    DmDeviceInfoInit(&info);
    auto ret = DmLiteGetLocalDeviceInfo(info);
    if (ret != DH_FWK_SUCCESS) {
        DHLOGE("GetLocalNodeDeviceInfo failed, errCode = %{public}d", ret);
        DmDeviceInfoDestroy(&info);
        NodeBasicInfo nodeInfo {};
        if (GetLocalNodeInfoFromSoftbus(nodeInfo)) {
            return GetUDIDByDm(nodeInfo.networkId);
        }
        return "";
    }
    std::string networkId = info.networkId;
    DmDeviceInfoDestroy(&info);
    if (networkId.empty()) {
        NodeBasicInfo nodeInfo {};
        if (GetLocalNodeInfoFromSoftbus(nodeInfo)) {
            return GetUDIDByDm(nodeInfo.networkId);
        }
    }
    return GetUDIDByDm(networkId);
}

bool IsUInt16(const cJSON* jsonObj)
{
    if (jsonObj == NULL || !cJSON_IsNumber(jsonObj)) {
        return false;
    }
    return (jsonObj->valueint >= 0 && jsonObj->valueint <= UINT16_MAX);
}

bool IsInt32(const cJSON* jsonObj)
{
    if (jsonObj == NULL || !cJSON_IsNumber(jsonObj)) {
        return false;
    }
    return (jsonObj->valueint >= INT32_MIN && jsonObj->valueint <= INT32_MAX);
}

bool IsUInt32(const cJSON* jsonObj)
{
    if (jsonObj == NULL || !cJSON_IsNumber(jsonObj)) {
        return false;
    }
    return (jsonObj->valueint >= 0 && jsonObj->valueint <= INT32_MAX);
}

bool IsBool(const cJSON* jsonObj)
{
    return (jsonObj != NULL && cJSON_IsBool(jsonObj));
}

bool IsString(const cJSON* jsonObj)
{
    if (jsonObj == NULL || !cJSON_IsString(jsonObj)) {
        return false;
    }
    return (strlen(jsonObj->valuestring) > MIN_MESSAGE_LEN && strlen(jsonObj->valuestring) <= MAX_MESSAGE_LEN);
}

bool IsArray(const cJSON* jsonObj)
{
    if (jsonObj == NULL || !cJSON_IsArray(jsonObj)) {
        return false;
    }
    return ((uint32_t)cJSON_GetArraySize(jsonObj) >= 0 && (uint32_t)cJSON_GetArraySize(jsonObj) <= MAX_ARR_SIZE);
}

std::string Compress(const std::string& data)
{
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    deflateInit(&strm, Z_DEFAULT_COMPRESSION);

    strm.next_in = reinterpret_cast<Bytef*>(const_cast<char *>(data.data()));
    strm.avail_in = data.size();
    std::string out;
    std::vector<Bytef> temp_out(COMPRESS_SLICE_SIZE, 0);

    do {
        strm.next_out = temp_out.data();
        strm.avail_out = COMPRESS_SLICE_SIZE;
        deflate(&strm, Z_FINISH);
        out.append(reinterpret_cast<char*>(temp_out.data()), COMPRESS_SLICE_SIZE - strm.avail_out);
    } while (strm.avail_out == 0);

    deflateEnd(&strm);
    return out;
}

std::string Decompress(const std::string& data)
{
    z_stream strm;
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;
    strm.avail_in = 0;
    strm.next_in = Z_NULL;
    inflateInit(&strm);

    strm.next_in = reinterpret_cast<Bytef*>(const_cast<char *>(data.data()));
    strm.avail_in = data.size();
    std::string out;
    std::vector<Bytef> temp_out(COMPRESS_SLICE_SIZE, 0);

    do {
        strm.next_out = temp_out.data();
        strm.avail_out = COMPRESS_SLICE_SIZE;
        inflate(&strm, Z_NO_FLUSH);
        out.append(reinterpret_cast<char*>(temp_out.data()), COMPRESS_SLICE_SIZE - strm.avail_out);
    } while (strm.avail_out == 0);

    inflateEnd(&strm);
    return out;
}

bool GetSysPara(const char *key, bool &value)
{
    if (key == nullptr) {
        DHLOGE("GetSysPara: key is nullptr");
        return false;
    }
    char paraValue[20] = {0}; // 20 for system parameter
    auto res = GetParameter(key, "false", paraValue, sizeof(paraValue));
    if (res <= 0) {
        DHLOGD("GetSysPara fail, key:%{public}s res:%{public}d", key, res);
        return false;
    }
    DHLOGI("GetSysPara: key:%{public}s value:%{public}s", key, paraValue);
    std::stringstream valueStr;
    valueStr << paraValue;
    valueStr >> std::boolalpha >> value;
    return true;
}

bool IsIdLengthValid(const std::string &inputID)
{
    if (inputID.empty() || inputID.length() > MAX_ID_LEN) {
        DHLOGE("On parameter length error, maybe empty or beyond MAX_ID_LEN!");
        return false;
    }
    return true;
}

bool IsMessageLengthValid(const std::string &inputMessage)
{
    if (inputMessage.empty() || inputMessage.length() > MAX_MESSAGE_LEN) {
        DHLOGE("On parameter error, maybe empty or beyond MAX_MESSAGE_LEN!");
        return false;
    }
    return true;
}

bool IsJsonLengthValid(const std::string &inputJsonStr)
{
    if (inputJsonStr.empty() || inputJsonStr.length() > MAX_JSON_SIZE) {
        DHLOGE("On parameter error, maybe empty or beyond MAX_JSON_SIZE");
        return false;
    }
    return true;
}

int32_t GetDeviceSystemType(const std::string &extraData)
{
    cJSON *jsonObj = cJSON_Parse(extraData.c_str());
    if (jsonObj == NULL) {
        DHLOGE("jsonStr parse failed");
        return ERR_DH_FWK_INVALID_OSTYPE;
    }
    cJSON *paramKey = cJSON_GetObjectItem(jsonObj, PARAM_KEY_OS_TYPE);
    if (paramKey == NULL || !cJSON_IsNumber(paramKey)) {
        DHLOGE("paramKey is null or paramKey is invalid type!");
        cJSON_Delete(jsonObj);
        return ERR_DH_FWK_INVALID_OSTYPE;
    }
    int32_t osType = paramKey->valueint;
    cJSON_Delete(jsonObj);
    return osType;
}
} // namespace DistributedHardware
} // namespace OHOS
