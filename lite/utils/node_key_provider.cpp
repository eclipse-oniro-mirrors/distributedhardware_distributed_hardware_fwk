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
 * Production implementation of the lite node-key provider (TASK-13).
 * Calls the softbus bus_center public API; the unit test substitutes this
 * symbol at link time with a controllable stub (no softbus lib needed).
 */

#include "node_key_provider.h"

#include <cstring>

#include "softbus_bus_center.h"
#include "softbus_error_code.h"

#include "constants.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
/* 64-char hex id + NUL, per DM convention (dm_cert.h UDID_BUF_LEN = 65);
 * softbus NODE_KEY_UDID/NODE_KEY_UUID are "in string format". */
constexpr int32_t NODE_KEY_BUF_LEN = 65;

/* Drift guards: local int32_t mirrors must equal the real softbus enum. */
static_assert(SOFTBUS_NODE_KEY_UDID == static_cast<int32_t>(NODE_KEY_UDID),
    "softbus NODE_KEY_UDID value drift, fix node_key_provider.h mirror");
static_assert(SOFTBUS_NODE_KEY_UUID == static_cast<int32_t>(NODE_KEY_UUID),
    "softbus NODE_KEY_UUID value drift, fix node_key_provider.h mirror");
} // namespace

int32_t GetSoftbusNodeKey(const std::string &networkId, int32_t key, std::string &value)
{
    value.clear();
    if (networkId.empty()) {
        return NODE_KEY_ERR_INVALID_PARAM;
    }
    uint8_t buf[NODE_KEY_BUF_LEN] = {0};
    int32_t ret = GetNodeKeyInfo(DH_FWK_PKG_NAME, networkId.c_str(),
        static_cast<NodeDeviceInfoKey>(key), buf, sizeof(buf));
    if (ret != SOFTBUS_OK) {
        value.clear();
        return ret;
    }
    /* Defensive: force NUL termination even if softbus filled the whole buffer. */
    buf[NODE_KEY_BUF_LEN - 1] = '\0';
    value.assign(reinterpret_cast<const char *>(buf));
    return SOFTBUS_NODE_KEY_OK;
}
} // namespace DistributedHardware
} // namespace OHOS
