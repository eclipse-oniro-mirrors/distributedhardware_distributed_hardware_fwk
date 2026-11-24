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
 * Host-runnable unit test for the lite softbus node-key provider (TASK-13,
 * D-DM1 ruling 2: uuid/udid supply via softbus bus_center GetNodeKeyInfo).
 *
 * Injection model (link-time stub): node_key_provider.cpp calls the extern "C"
 * softbus symbol GetNodeKeyInfo(); this test provides a controllable stub
 * definition, so no softbus library is needed:
 *   g++ -std=c++17 -I utils/lite -I common/utils/include \
 *       -I <dsoftbus>/interfaces/kits/bus_center -I <dsoftbus>/interfaces/kits/common \
 *       utils/lite/node_key_provider.cpp utils/lite/test/node_key_provider_test.cpp \
 *       -o /tmp/task13_test
 *
 * Branches covered: GetNodeKeyInfo success / failure / success-but-empty /
 * invalid networkId guard / non-NUL-terminated buffer hardening, plus enum
 * mirror drift checks against the real softbus header.
 */

#include "../node_key_provider.h"

#include <cstring>
#include <string>

#include "constants.h"
#include "softbus_bus_center.h"
#include "softbus_error_code.h"

using OHOS::DistributedHardware::GetSoftbusNodeKey;
using OHOS::DistributedHardware::NODE_KEY_ERR_INVALID_PARAM;
using OHOS::DistributedHardware::SOFTBUS_NODE_KEY_OK;
using OHOS::DistributedHardware::SOFTBUS_NODE_KEY_UDID;
using OHOS::DistributedHardware::SOFTBUS_NODE_KEY_UUID;

namespace {
int g_total = 0;
int g_failed = 0;

void CheckBool(const std::string &name, bool ok)
{
    ++g_total;
    if (ok) {
        std::printf("[PASS] %s\n", name.c_str());
    } else {
        ++g_failed;
        std::printf("[FAIL] %s\n", name.c_str());
    }
}

void Check(const std::string &name, const std::string &actual, const std::string &expected)
{
    ++g_total;
    if (actual == expected) {
        std::printf("[PASS] %s\n", name.c_str());
    } else {
        ++g_failed;
        std::printf("[FAIL] %s\n  expected: %s\n  actual:   %s\n",
            name.c_str(), expected.c_str(), actual.c_str());
    }
}

/* --- link-time stub of the softbus bus_center API --- */
constexpr int32_t STUB_FAIL_RET = -6; /* arbitrary non-zero softbus-style error */
std::string g_stubValue;
int32_t g_stubRet = SOFTBUS_OK;
bool g_stubFillWithoutNul = false;
int g_callCount = 0;
std::string g_lastPkgName;
std::string g_lastNetworkId;
int32_t g_lastKey = -1;
int32_t g_lastInfoLen = -1;

void ResetStub()
{
    g_stubValue = "";
    g_stubRet = SOFTBUS_OK;
    g_stubFillWithoutNul = false;
    g_callCount = 0;
    g_lastPkgName = "";
    g_lastNetworkId = "";
    g_lastKey = -1;
    g_lastInfoLen = -1;
}
} // namespace

extern "C" int32_t GetNodeKeyInfo(const char *pkgName, const char *networkId,
    NodeDeviceInfoKey key, uint8_t *info, int32_t infoLen)
{
    ++g_callCount;
    g_lastPkgName = (pkgName != nullptr) ? pkgName : "";
    g_lastNetworkId = (networkId != nullptr) ? networkId : "";
    g_lastKey = static_cast<int32_t>(key);
    g_lastInfoLen = infoLen;
    if (info == nullptr || infoLen <= 0) {
        return STUB_FAIL_RET;
    }
    if (g_stubRet != SOFTBUS_OK) {
        return g_stubRet;
    }
    if (g_stubFillWithoutNul) {
        std::memset(info, 'A', static_cast<size_t>(infoLen));
        return SOFTBUS_OK;
    }
    if (static_cast<int32_t>(g_stubValue.size()) >= infoLen) {
        return STUB_FAIL_RET;
    }
    std::memcpy(info, g_stubValue.c_str(), g_stubValue.size() + 1);
    return SOFTBUS_OK;
}

int main()
{
    /* --- enum mirror must match the real softbus header (drift guard) --- */
    CheckBool("enum.node_key_udid_mirror", SOFTBUS_NODE_KEY_UDID == static_cast<int32_t>(NODE_KEY_UDID));
    CheckBool("enum.node_key_uuid_mirror", SOFTBUS_NODE_KEY_UUID == static_cast<int32_t>(NODE_KEY_UUID));

    /* --- success branch: uuid --- */
    ResetStub();
    g_stubValue = "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
    std::string value = "dirty";
    int32_t ret = GetSoftbusNodeKey("netId-001", SOFTBUS_NODE_KEY_UUID, value);
    CheckBool("uuid.success.ret_ok", ret == SOFTBUS_NODE_KEY_OK);
    Check("uuid.success.value", value, g_stubValue);
    CheckBool("uuid.success.called_once", g_callCount == 1);
    Check("uuid.success.pkg_name", g_lastPkgName, OHOS::DistributedHardware::DH_FWK_PKG_NAME);
    Check("uuid.success.network_id_passthrough", g_lastNetworkId, "netId-001");
    CheckBool("uuid.success.key_is_node_key_uuid", g_lastKey == static_cast<int32_t>(NODE_KEY_UUID));
    /* 64-char id + NUL must fit (DM dm_cert.h UDID_BUF_LEN = 65 convention) */
    CheckBool("uuid.success.buffer_len_fits_64_id", g_lastInfoLen >= 65);

    /* --- success branch: udid --- */
    ResetStub();
    g_stubValue = "udid-abcdef-0123456789";
    value = "dirty";
    ret = GetSoftbusNodeKey("netId-002", SOFTBUS_NODE_KEY_UDID, value);
    CheckBool("udid.success.ret_ok", ret == SOFTBUS_NODE_KEY_OK);
    Check("udid.success.value", value, g_stubValue);
    CheckBool("udid.success.key_is_node_key_udid", g_lastKey == static_cast<int32_t>(NODE_KEY_UDID));

    /* --- failure branch: softbus returns non-zero --- */
    ResetStub();
    g_stubRet = STUB_FAIL_RET;
    value = "dirty";
    ret = GetSoftbusNodeKey("netId-003", SOFTBUS_NODE_KEY_UUID, value);
    CheckBool("failure.ret_passthrough", ret == STUB_FAIL_RET);
    Check("failure.value_cleared", value, "");
    CheckBool("failure.called_once", g_callCount == 1);

    /* --- success but empty string: caller must treat as unusable --- */
    ResetStub();
    g_stubValue = "";
    value = "dirty";
    ret = GetSoftbusNodeKey("netId-004", SOFTBUS_NODE_KEY_UDID, value);
    CheckBool("empty.ret_ok_but_value_empty", ret == SOFTBUS_NODE_KEY_OK && value.empty());

    /* --- invalid networkId guard: no softbus call --- */
    ResetStub();
    value = "dirty";
    ret = GetSoftbusNodeKey("", SOFTBUS_NODE_KEY_UUID, value);
    CheckBool("guard.empty_network_id_ret", ret == NODE_KEY_ERR_INVALID_PARAM);
    Check("guard.empty_network_id_value_cleared", value, "");
    CheckBool("guard.empty_network_id_not_called", g_callCount == 0);

    /* --- hardening: softbus fills buffer without NUL terminator --- */
    ResetStub();
    g_stubFillWithoutNul = true;
    value = "dirty";
    ret = GetSoftbusNodeKey("netId-005", SOFTBUS_NODE_KEY_UUID, value);
    CheckBool("hardening.no_nul.ret_ok", ret == SOFTBUS_NODE_KEY_OK);
    CheckBool("hardening.no_nul.bounded_len", !value.empty() && value.size() <= 64);

    std::printf("\nnode_key_provider_test: total=%d failed=%d\n", g_total, g_failed);
    return g_failed == 0 ? 0 : 1;
}
