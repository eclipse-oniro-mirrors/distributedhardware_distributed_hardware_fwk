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
 * lite empty implementation of the HiTrace utils.
 * hitrace_meter is not available on lite; lite call sites are compiled
 * out. This file only provides no-op symbols so the lite SO keeps a
 * self-contained link closure (lesson T-C02). Signatures mirror the
 * shared header utils/include/dh_utils_hitrace.h (which lite TUs must
 * not include: it pulls hitrace_meter.h).
 */

#include <string>

#include "device_type.h"

namespace OHOS {
namespace DistributedHardware {
void DHCompMgrTraceStart(const std::string &anonyNetworkId, const std::string &anonyDHId, const std::string &msg)
{
    (void)anonyNetworkId;
    (void)anonyDHId;
    (void)msg;
}

void DHQueryTraceStart(const DHType dhType)
{
    (void)dhType;
}

void DHTraceStart(const std::string &msg)
{
    (void)msg;
}

void DHTraceEnd()
{
}
} // namespace DistributedHardware
} // namespace OHOS
