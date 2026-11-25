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
 * Lite-only softbus bus_center node-key provider (TASK-13, D-DM1 ruling 2).
 *
 * The DM lite pure-C vtable SDK exposes no synchronous uuid/udid query, so
 * the uuid/udid supply for GetUUIDByDm/GetUDIDByDm comes from the softbus
 * bus_center public API GetNodeKeyInfo() (nm-verified export of
 * libsoftbus_client.so). This header is the injectable seam: it mirrors the
 * softbus NodeDeviceInfoKey values as plain int32_t constants (so consumers
 * need no softbus headers) and the production TU static_asserts the mirror
 * against the real enum. Deliberately logging-free and dependency-free so
 * the unit test can link a GetNodeKeyInfo stub on host.
 */

#ifndef OHOS_DHWFK_UTILS_LITE_NODE_KEY_PROVIDER_H
#define OHOS_DHWFK_UTILS_LITE_NODE_KEY_PROVIDER_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace DistributedHardware {
/* Mirrors of softbus NodeDeviceInfoKey (softbus_bus_center.h, NODE_KEY_UDID = 0,
 * NODE_KEY_UUID = 1); drift-checked by static_assert in node_key_provider.cpp. */
constexpr int32_t SOFTBUS_NODE_KEY_UDID = 0;
constexpr int32_t SOFTBUS_NODE_KEY_UUID = 1;

/* SOFTBUS_OK (softbus_error_code.h) — success return of GetNodeKeyInfo. */
constexpr int32_t SOFTBUS_NODE_KEY_OK = 0;
/* Local error: invalid parameter, softbus was not called. */
constexpr int32_t NODE_KEY_ERR_INVALID_PARAM = -1;

/*
 * Fetches one node key of the device identified by networkId via softbus
 * GetNodeKeyInfo(pkgName = DH_FWK_PKG_NAME, ...).
 *
 * Returns SOFTBUS_NODE_KEY_OK and fills value on success (value may still be
 * empty if softbus stored an empty string — callers must check), otherwise a
 * non-zero softbus return code (or NODE_KEY_ERR_INVALID_PARAM) with value
 * cleared. Never throws, never blocks beyond the softbus client call.
 */
int32_t GetSoftbusNodeKey(const std::string &networkId, int32_t key, std::string &value);
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_DHWFK_UTILS_LITE_NODE_KEY_PROVIDER_H
