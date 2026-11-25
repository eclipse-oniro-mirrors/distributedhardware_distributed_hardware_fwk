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
 * lite empty implementation of the HiSysEvent utils.
 * HiSysEvent (hiviewdfx) is not available on lite; lite call sites are
 * compiled out. This file only provides ABI-compatible no-op symbols so
 * that the lite SO keeps a self-contained link closure (lesson T-C02:
 * never leave symbols to be resolved by another repository's SO).
 * The local EventType declaration mirrors OHOS::HiviewDFX::HiSysEvent
 * from hisysevent.h so the mangled signatures match the shared header
 * utils/include/dh_utils_hisysevent.h (which lite TUs must not include:
 * it pulls hisysevent.h).
 */

#include <cstdint>
#include <string>

#include "device_type.h"

namespace OHOS {
namespace HiviewDFX {
class HiSysEvent {
public:
    enum EventType : uint16_t { BEHAVIOR = 1, FAULT = 2, STATISTIC = 4, SECURITY = 8 };
};
} // namespace HiviewDFX
namespace DistributedHardware {
void HiSysEventWriteMsg(const std::string &status, const OHOS::HiviewDFX::HiSysEvent::EventType eventType,
    const std::string &msg)
{
    (void)status;
    (void)eventType;
    (void)msg;
}

void HiSysEventWriteReleaseMsg(const std::string &status, const OHOS::HiviewDFX::HiSysEvent::EventType eventType,
    const DHType dhType, int32_t errCode, const std::string &msg)
{
    (void)status;
    (void)eventType;
    (void)dhType;
    (void)errCode;
    (void)msg;
}

void HiSysEventWriteCompOfflineMsg(const std::string &status, const OHOS::HiviewDFX::HiSysEvent::EventType eventType,
    const std::string &anonyNetworkId, const std::string &msg)
{
    (void)status;
    (void)eventType;
    (void)anonyNetworkId;
    (void)msg;
}

void HiSysEventWriteCompMgrFailedMsg(const std::string &status, const OHOS::HiviewDFX::HiSysEvent::EventType eventType,
    const std::string &anonyDHId, int32_t errCode, const std::string &msg)
{
    (void)status;
    (void)eventType;
    (void)anonyDHId;
    (void)errCode;
    (void)msg;
}
} // namespace DistributedHardware
} // namespace OHOS
