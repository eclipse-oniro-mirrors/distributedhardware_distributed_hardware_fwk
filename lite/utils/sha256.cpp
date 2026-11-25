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

#include "sha256.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
constexpr uint32_t SHA256_BLOCK_LEN = 64;
constexpr uint32_t SCHEDULE_LEN = 64;
constexpr uint32_t HEX_CHAR_LEN = 2;
constexpr uint32_t BITS_PER_BYTE = 8;
constexpr uint32_t BIG_ENDIAN_OFFSET = 24;
constexpr uint32_t STATE_WORDS = 8;
constexpr uint32_t BYTES_PER_WORD = 4;
constexpr uint32_t WORD_BIT_OFFSET_BYTE1 = 16;
constexpr uint32_t WORD_BIT_OFFSET_BYTE2 = 8;
constexpr uint32_t ROTR_BITS_2 = 2;
constexpr uint32_t ROTR_BITS_3 = 3;
constexpr uint32_t ROTR_BITS_6 = 6;
constexpr uint32_t ROTR_BITS_7 = 7;
constexpr uint32_t ROTR_BITS_10 = 10;
constexpr uint32_t ROTR_BITS_11 = 11;
constexpr uint32_t ROTR_BITS_13 = 13;
constexpr uint32_t ROTR_BITS_15 = 15;
constexpr uint32_t ROTR_BITS_16 = 16;
constexpr uint32_t ROTR_BITS_17 = 17;
constexpr uint32_t ROTR_BITS_18 = 18;
constexpr uint32_t ROTR_BITS_19 = 19;
constexpr uint32_t ROTR_BITS_22 = 22;
constexpr uint32_t ROTR_BITS_25 = 25;
constexpr uint32_t SCHED_IDX_2 = 2;
constexpr uint32_t SCHED_IDX_7 = 7;
constexpr uint32_t SCHED_IDX_15 = 15;
constexpr uint32_t SCHED_IDX_16 = 16;
constexpr uint32_t STATE_IDX_0 = 0;
constexpr uint32_t STATE_IDX_1 = 1;
constexpr uint32_t STATE_IDX_2 = 2;
constexpr uint32_t STATE_IDX_3 = 3;
constexpr uint32_t STATE_IDX_4 = 4;
constexpr uint32_t STATE_IDX_5 = 5;
constexpr uint32_t STATE_IDX_6 = 6;
constexpr uint32_t STATE_IDX_7 = 7;
constexpr uint32_t NIBBLE_HIGH_SHIFT = 4;
constexpr uint32_t NIBBLE_MASK = 0x0F;
constexpr uint32_t WORD_BITS = 32;
constexpr uint32_t BYTE_IDX_0 = 0;
constexpr uint32_t BYTE_IDX_1 = 1;
constexpr uint32_t BYTE_IDX_2 = 2;
constexpr uint32_t BYTE_IDX_3 = 3;

/* FIPS 180-4 section 4.2.2: first 32 bits of the fractional parts of the
 * cube roots of the first 64 primes. */
constexpr uint32_t K[SCHEDULE_LEN] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

/* FIPS 180-4 section 4.1.2 functions. */
inline uint32_t Rotr(uint32_t x, uint32_t n)
{
    return (x >> n) | (x << (WORD_BITS - n));
}

inline uint32_t Ch(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (~x & z);
}

inline uint32_t Maj(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & y) ^ (x & z) ^ (y & z);
}

inline uint32_t BigSigma0(uint32_t x)
{
    return Rotr(x, ROTR_BITS_2) ^ Rotr(x, ROTR_BITS_13) ^ Rotr(x, ROTR_BITS_22);
}

inline uint32_t BigSigma1(uint32_t x)
{
    return Rotr(x, ROTR_BITS_6) ^ Rotr(x, ROTR_BITS_11) ^ Rotr(x, ROTR_BITS_25);
}

inline uint32_t SmallSigma0(uint32_t x)
{
    return Rotr(x, ROTR_BITS_7) ^ Rotr(x, ROTR_BITS_18) ^ (x >> ROTR_BITS_3);
}

inline uint32_t SmallSigma1(uint32_t x)
{
    return Rotr(x, ROTR_BITS_17) ^ Rotr(x, ROTR_BITS_19) ^ (x >> ROTR_BITS_10);
}

/* Read a 32-bit big-endian word (FIPS 180-4 message schedule is big-endian). */
inline uint32_t LoadBE32(const uint8_t *p)
{
    return (static_cast<uint32_t>(p[BYTE_IDX_0]) << BIG_ENDIAN_OFFSET) |
           (static_cast<uint32_t>(p[BYTE_IDX_1]) << WORD_BIT_OFFSET_BYTE1) |
           (static_cast<uint32_t>(p[BYTE_IDX_2]) << BITS_PER_BYTE) |
           static_cast<uint32_t>(p[BYTE_IDX_3]);
}

inline void StoreBE32(uint8_t *p, uint32_t v)
{
    p[BYTE_IDX_0] = static_cast<uint8_t>(v >> BIG_ENDIAN_OFFSET);
    p[BYTE_IDX_1] = static_cast<uint8_t>(v >> WORD_BIT_OFFSET_BYTE1);
    p[BYTE_IDX_2] = static_cast<uint8_t>(v >> BITS_PER_BYTE);
    p[BYTE_IDX_3] = static_cast<uint8_t>(v);
}

/* FIPS 180-4 section 6.2.2: process one 512-bit block. */
void ProcessBlock(const uint8_t *block, uint32_t *state)
{
    uint32_t w[SCHEDULE_LEN] = {0};
    for (uint32_t i = 0; i < SHA256_BLOCK_LEN / BYTES_PER_WORD; ++i) {
        w[i] = LoadBE32(block + i * BYTES_PER_WORD);
    }
    for (uint32_t i = SHA256_BLOCK_LEN / BYTES_PER_WORD; i < SCHEDULE_LEN; ++i) {
        w[i] = SmallSigma1(w[i - SCHED_IDX_2]) + w[i - SCHED_IDX_7] +
               SmallSigma0(w[i - SCHED_IDX_15]) + w[i - SCHED_IDX_16];
    }

    uint32_t a = state[STATE_IDX_0];
    uint32_t b = state[STATE_IDX_1];
    uint32_t c = state[STATE_IDX_2];
    uint32_t d = state[STATE_IDX_3];
    uint32_t e = state[STATE_IDX_4];
    uint32_t f = state[STATE_IDX_5];
    uint32_t g = state[STATE_IDX_6];
    uint32_t h = state[STATE_IDX_7];

    for (uint32_t i = 0; i < SCHEDULE_LEN; ++i) {
        uint32_t t1 = h + BigSigma1(e) + Ch(e, f, g) + K[i] + w[i];
        uint32_t t2 = BigSigma0(a) + Maj(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    state[STATE_IDX_0] += a;
    state[STATE_IDX_1] += b;
    state[STATE_IDX_2] += c;
    state[STATE_IDX_3] += d;
    state[STATE_IDX_4] += e;
    state[STATE_IDX_5] += f;
    state[STATE_IDX_6] += g;
    state[STATE_IDX_7] += h;
}
} // namespace

void Sha256Digest(const uint8_t *data, size_t len, uint8_t *digest)
{
    if (digest == nullptr || (data == nullptr && len > 0)) {
        return;
    }
    /* FIPS 180-4 section 5.3.3: initial hash values. */
    uint32_t state[STATE_WORDS] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };

    size_t fullBlocks = len / SHA256_BLOCK_LEN;
    for (size_t i = 0; i < fullBlocks; ++i) {
        ProcessBlock(data + i * SHA256_BLOCK_LEN, state);
    }

    /* Padding (FIPS 180-4 section 5.1.1): remaining bytes + 0x80 + zeros +
     * 64-bit big-endian bit length. The tail always fits in one or two blocks. */
    uint8_t tail[SHA256_BLOCK_LEN * 2] = {0};
    size_t remain = len % SHA256_BLOCK_LEN;
    if (data != nullptr && remain > 0) {
        for (size_t i = 0; i < remain; ++i) {
            tail[i] = data[fullBlocks * SHA256_BLOCK_LEN + i];
        }
    }
    tail[remain] = 0x80U;
    uint64_t bitLen = static_cast<uint64_t>(len) * BITS_PER_BYTE;
    size_t lenOffset = (remain < SHA256_BLOCK_LEN - 8) ? SHA256_BLOCK_LEN - 8 : SHA256_BLOCK_LEN * 2 - 8;
    constexpr uint32_t U64_TOP_SHIFT = 56;
    for (uint32_t i = 0; i < sizeof(bitLen); ++i) {
        tail[lenOffset + i] = static_cast<uint8_t>(bitLen >> (U64_TOP_SHIFT - BITS_PER_BYTE * i));
    }
    size_t tailBlocks = (remain < SHA256_BLOCK_LEN - 8) ? 1 : 2;
    for (size_t i = 0; i < tailBlocks; ++i) {
        ProcessBlock(tail + i * SHA256_BLOCK_LEN, state);
    }

    for (uint32_t i = 0; i < STATE_WORDS; ++i) {
        StoreBE32(digest + i * BYTES_PER_WORD, state[i]);
    }
}

std::string Sha256Hex(const std::string &in)
{
    uint8_t digest[SHA256_DIGEST_LEN] = {0};
    Sha256Digest(reinterpret_cast<const uint8_t *>(in.data()), in.size(), digest);
    /* Same hex encoding as the standard implementation: each 8-bit byte
     * becomes two lowercase characters ([0-9a-f]). */
    const char *hexCode = "0123456789abcdef";
    std::string out(SHA256_DIGEST_LEN * HEX_CHAR_LEN, '0');
    for (uint32_t i = 0; i < SHA256_DIGEST_LEN; ++i) {
        out[i * HEX_CHAR_LEN] = hexCode[(digest[i] >> NIBBLE_HIGH_SHIFT) & NIBBLE_MASK];
        out[i * HEX_CHAR_LEN + 1] = hexCode[digest[i] & NIBBLE_MASK];
    }
    return out;
}
} // namespace DistributedHardware
} // namespace OHOS
