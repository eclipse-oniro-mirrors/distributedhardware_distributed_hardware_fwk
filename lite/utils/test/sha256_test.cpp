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
 * Host-runnable unit test for the lite FIPS 180-4 SHA-256 implementation.
 * Zero dependencies beyond sha256.cpp so it can be compiled directly:
 *   g++ -std=c++17 utils/lite/sha256.cpp utils/lite/test/sha256_test.cpp -o /tmp/t1_sha256_test
 * Vectors: FIPS 180-4 / NIST published digests + padding boundary lengths +
 * the deviceId = Sha256(uuid) scenario (contracts C6, 64-char lowercase hex).
 */

#include "../sha256.h"

#include <cstdio>
#include <string>

using OHOS::DistributedHardware::Sha256Digest;
using OHOS::DistributedHardware::Sha256Hex;
using OHOS::DistributedHardware::SHA256_DIGEST_LEN;

namespace {
constexpr uint32_t HEX_STR_LEN_PER_BYTE = 2;
constexpr size_t VECTOR_LEN_1M = 1000000;
constexpr size_t CN48_UTF8_BYTES = 144;
constexpr size_t BOUNDARY_LEN_55 = 55;
constexpr size_t BOUNDARY_LEN_56 = 56;
constexpr size_t BOUNDARY_LEN_57 = 57;
constexpr size_t BOUNDARY_LEN_63 = 63;
constexpr size_t BOUNDARY_LEN_64 = 64;
constexpr size_t BOUNDARY_LEN_65 = 65;
constexpr size_t BOUNDARY_LEN_119 = 119;
constexpr size_t BOUNDARY_LEN_120 = 120;
constexpr size_t BOUNDARY_LEN_121 = 121;
constexpr int32_t SNPRINTF_BUF_SIZE = 3;
int g_total = 0;
int g_failed = 0;

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

bool IsLowerHex64(const std::string &s)
{
    if (s.size() != SHA256_DIGEST_LEN * HEX_STR_LEN_PER_BYTE) {
        return false;
    }
    for (char c : s) {
        bool isHex = (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
        if (!isHex) {
            return false;
        }
    }
    return true;
}
} // namespace

void RunNistVectors()
{
    Check("vector.empty", Sha256Hex(""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    Check("vector.abc", Sha256Hex("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    Check("vector.448bit", Sha256Hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
    Check("vector.1M_a", Sha256Hex(std::string(VECTOR_LEN_1M, 'a')),
        "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
}

void RunCn48AndBoundaryVectors()
{
    const std::string cn48 = "分布式相机轻量级适配验证分布式相机轻量级适配验证"
        "分布式相机轻量级适配验证分布式相机轻量级适配验证";
    CheckBool("vector.cn48.length_is_144_utf8_bytes", cn48.size() == CN48_UTF8_BYTES);
    Check("vector.cn48", Sha256Hex(cn48),
        "fafabc06ebf12439362b9cc8a93ddf2efab2742041f455e015b5c8a7a854b383");

    Check("boundary.a55", Sha256Hex(std::string(BOUNDARY_LEN_55, 'a')),
        "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318");
    Check("boundary.a56", Sha256Hex(std::string(BOUNDARY_LEN_56, 'a')),
        "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a");
    Check("boundary.a57", Sha256Hex(std::string(BOUNDARY_LEN_57, 'a')),
        "f13b2d724659eb3bf47f2dd6af1accc87b81f09f59f2b75e5c0bed6589dfe8c6");
    Check("boundary.a63", Sha256Hex(std::string(BOUNDARY_LEN_63, 'a')),
        "7d3e74a05d7db15bce4ad9ec0658ea98e3f06eeecf16b4c6fff2da457ddc2f34");
    Check("boundary.a64", Sha256Hex(std::string(BOUNDARY_LEN_64, 'a')),
        "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb");
    Check("boundary.a65", Sha256Hex(std::string(BOUNDARY_LEN_65, 'a')),
        "635361c48bb9eab14198e76ea8ab7f1a41685d6ad62aa9146d301d4f17eb0ae0");
    Check("boundary.a119", Sha256Hex(std::string(BOUNDARY_LEN_119, 'a')),
        "31eba51c313a5c08226adf18d4a359cfdfd8d2e816b13f4af952f7ea6584dcfb");
    Check("boundary.a120", Sha256Hex(std::string(BOUNDARY_LEN_120, 'a')),
        "2f3d335432c70b580af0e8e1b3674a7c020d683aa5f73aaaedfdc55af904c21c");
    Check("boundary.a121", Sha256Hex(std::string(BOUNDARY_LEN_121, 'a')),
        "e9615320128cc7a3d6078e9af05603188e5ccbf0d07d8b735d3df5e8e0c1281f");
}

void RunFormatAndDigestChecks()
{
    const std::string uuidLike =
        "e4a1c8f02f9a4b7c9d3e5f6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708";
    Check("scenario.deviceId_sha256_uuid", Sha256Hex(uuidLike),
        "debdc0acc4f2289a59254b11144c725a30ffa2ad0ed2fa32aff4ec8f2ac1a346");

    CheckBool("format.lower_hex_64.empty", IsLowerHex64(Sha256Hex("")));
    CheckBool("format.lower_hex_64.abc", IsLowerHex64(Sha256Hex("abc")));
    const std::string cn48 = "分布式相机轻量级适配验证分布式相机轻量级适配验证"
        "分布式相机轻量级适配验证分布式相机轻量级适配验证";
    CheckBool("format.lower_hex_64.cn48", IsLowerHex64(Sha256Hex(cn48)));
    CheckBool("format.lower_hex_64.a1M", IsLowerHex64(Sha256Hex(std::string(VECTOR_LEN_1M, 'a'))));

    uint8_t digest[SHA256_DIGEST_LEN] = {0};
    const std::string abc = "abc";
    Sha256Digest(reinterpret_cast<const uint8_t *>(abc.data()), abc.size(), digest);
    std::string hexFromDigest;
    for (uint32_t i = 0; i < SHA256_DIGEST_LEN; ++i) {
        char buf[SNPRINTF_BUF_SIZE] = {0};
        int32_t snRet = std::snprintf(buf, sizeof(buf), "%02x", digest[i]);
        if (snRet < 0) {
            std::printf("[FAIL] snprintf returned %d at byte %u\n", snRet, i);
            ++g_failed;
            continue;
        }
        hexFromDigest += buf;
    }
    Check("api.digest_matches_hex", hexFromDigest, Sha256Hex(abc));
}

int main()
{
    RunNistVectors();
    RunCn48AndBoundaryVectors();
    RunFormatAndDigestChecks();

    std::printf("SHA256 TEST SUMMARY: %d/%d PASS, %d FAIL\n",
        g_total - g_failed, g_total, g_failed);
    return (g_failed == 0) ? 0 : 1;
}
