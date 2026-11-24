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
 * lite-only FIPS 180-4 SHA-256 implementation (no OpenSSL dependency).
 * Replaces the OpenSSL based Sha256() of the standard system so that
 * deviceId = Sha256(uuid) / udidHash = Sha256(udid) stay byte-identical
 * across L1/L2 (contracts C6). Zero external deps: host-testable with g++.
 */

#ifndef OHOS_DISTRIBUTED_HARDWARE_UTILS_LITE_SHA256_H
#define OHOS_DISTRIBUTED_HARDWARE_UTILS_LITE_SHA256_H

#include <cstddef>
#include <cstdint>
#include <string>

namespace OHOS {
namespace DistributedHardware {
/* SHA-256 digest length in bytes (FIPS 180-4). */
constexpr uint32_t SHA256_DIGEST_LEN = 32;

/*
 * Compute the SHA-256 digest of len bytes at data.
 * digest must point to a buffer of at least SHA256_DIGEST_LEN bytes.
 */
void Sha256Digest(const uint8_t *data, size_t len, uint8_t *digest);

/*
 * Compute the SHA-256 of in and return it as a 64-character lowercase
 * hexadecimal string -- same value domain as the standard (OpenSSL)
 * Sha256() in utils/src/dh_utils_tool.cpp.
 */
std::string Sha256Hex(const std::string &in);
} // namespace DistributedHardware
} // namespace OHOS
#endif
