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

#include "dh_timer.h"

#include <chrono>
#include <pthread.h>

#include "anonymous_string.h"
#include "constants.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
    constexpr const char *EVENT_RUN = "EventRun";
}

#undef DH_LOG_TAG
#define DH_LOG_TAG "DHTimer"

DHTimer::DHTimer(std::string timerId, int32_t delayTimeMs) : timerId_(timerId), delayTimeMs_(delayTimeMs)
{
    DHLOGI("DHTimer ctor!");
}

DHTimer::~DHTimer()
{
    DHLOGI("DHTimer dtor!");
    ReleaseTimer();
}

void DHTimer::InitTimer()
{
    DHLOGI("start");
    std::unique_lock<std::mutex> lock(timerMutex_);
    timerRunning_.store(true);
    DHLOGI("end");
}

void DHTimer::ReleaseTimer()
{
    DHLOGI("start");
    std::lock_guard<std::mutex> lock(timerMutex_);
    timerRunning_.store(false);
    timerCond_.notify_all();
    DHLOGI("end");
}


} // namespace DistributedHardware
} // namespace OHOS
