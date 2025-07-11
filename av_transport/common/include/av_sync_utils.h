/*
 * Copyright (C) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_AV_TRANSPORT_SHARED_MEMORY_H
#define OHOS_AV_TRANSPORT_SHARED_MEMORY_H

#include <memory>
#include <string>
#include "parcel.h"
#include "message_parcel.h"

namespace OHOS {
namespace DistributedHardware {
constexpr uint8_t INVALID_VALUE_FALG = 0;
constexpr uint32_t MAX_CLOCK_UNIT_COUNT = 50;
constexpr uint32_t DEFAULT_INVALID_FRAME_NUM = 0;
constexpr size_t NUM_ZERO = 0;
constexpr size_t NUM_FOUR = 4;
constexpr size_t NUM_EIGHT = 8;

struct AVTransSharedMemory {
    int32_t fd;
    int32_t size;
    std::string name;
    void* addr;
};

struct AVTransSharedMemoryExt : public AVTransSharedMemory, public Parcelable {
    using AVTransSharedMemory::AVTransSharedMemory;
    explicit AVTransSharedMemoryExt() {}
    virtual ~AVTransSharedMemoryExt() = default;
    explicit AVTransSharedMemoryExt(const AVTransSharedMemory& avTransSharedMemory)
    {
        fd = avTransSharedMemory.fd;
        size = avTransSharedMemory.size;
        name = avTransSharedMemory.name;
    }
    virtual bool Marshalling(Parcel &parcel) const override
    {
        MessageParcel &messageParcel = static_cast<MessageParcel&>(parcel);
        if (!messageParcel.WriteFileDescriptor(fd)) {
            return false;
        }
        if (!parcel.WriteInt32(size)) {
            return false;
        }
        if (!parcel.WriteString(name)) {
            return false;
        }
        return true;
    }

    static AVTransSharedMemoryExt *Unmarshalling(Parcel &parcel)
    {
        MessageParcel &messageParcel = static_cast<MessageParcel&>(parcel);
        AVTransSharedMemoryExt *avTransSharedMemory = new (std::nothrow) AVTransSharedMemoryExt();
        if (avTransSharedMemory == nullptr) {
            return nullptr;
        }
        avTransSharedMemory->fd = messageParcel.ReadFileDescriptor();
        avTransSharedMemory->size = parcel.ReadInt32();
        avTransSharedMemory->name = parcel.ReadString();
        return avTransSharedMemory;
    }
};

struct AVSyncClockUnit {
    uint32_t index;
    uint32_t frameNum;
    int64_t pts;
};

/**
 * @brief create shared memory space for av sync.
 * @param name    name for the shared memory.
 * @return shared memory struct, include fd, size and name.
 */
AVTransSharedMemory CreateAVTransSharedMemory(const std::string &name, size_t size);

/**
 * @brief close shared memory space.
 * @param memory    shared memory.
 */
void CloseAVTransSharedMemory(AVTransSharedMemory &memory) noexcept;

/**
 * @brief write the clock unit into the shared memory space.
 * @param memory       shared memory
 * @param clockUnit    the clock unit
 * @return Returns DH_AVT_SUCCESS(0) if successful, otherwise returns other error code.
 */
int32_t WriteClockUnitToMemory(const AVTransSharedMemory &memory, AVSyncClockUnit &clockUnit);

/**
 * @brief read clock unit from the shared memory space.
 * @param memory       shared memory
 * @param clockUnit    the clock unit
 * @return Returns DH_AVT_SUCCESS(0) if successful, otherwise returns other error code.
 */
int32_t ReadClockUnitFromMemory(const AVTransSharedMemory &memory, AVSyncClockUnit &clockUnit);

/**
 * @brief write frame number and pts into the shared memory space.
 * @param memory       shared memory
 * @param frameNum     the frame number
 * @param timestamp    the pts
 * @return Returns DH_AVT_SUCCESS(0) if successful, otherwise returns other error code.
 */
int32_t WriteFrameInfoToMemory(const AVTransSharedMemory &memory, uint32_t frameNum, int64_t timestamp);

/**
 * @brief read frame number and pts from the shared memory space.
 * @param memory       shared memory
 * @param frameNum     the frame number
 * @param timestamp    the pts
 * @return Returns DH_AVT_SUCCESS(0) if successful, otherwise returns other error code.
 */
int32_t ReadFrameInfoFromMemory(const AVTransSharedMemory &memory, uint32_t &frameNum, int64_t &timestamp);

/**
 * @brief reset the shared memory value to all zeros.
 * @param memory       shared memory
 * @return Returns DH_AVT_SUCCESS(0) if successful, otherwise returns other error code.
 */
int32_t ResetSharedMemory(const AVTransSharedMemory &memory);

bool IsInValidSharedMemory(const AVTransSharedMemory &memory);
bool IsInValidClockUnit(const AVSyncClockUnit &clockUnit);

std::string MarshalSharedMemory(const AVTransSharedMemory &memory);
AVTransSharedMemory UnmarshalSharedMemory(const std::string &jsonStr);

uint32_t U8ToU32(const uint8_t *arrayPtr, size_t arraySize);
uint64_t U8ToU64(const uint8_t *arrayPtr, size_t arraySize);
void U32ToU8(uint8_t *arrayPtr, uint32_t value, size_t arraySize);
void U64ToU8(uint8_t *arrayPtr, uint64_t value, size_t arraySize);
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_AV_TRANSPORT_SHARED_MEMORY_H