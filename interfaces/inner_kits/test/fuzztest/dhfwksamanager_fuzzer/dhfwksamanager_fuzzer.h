/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef TEST_DHFWK_SA_MANAGER_FUZZER_H
#define TEST_DHFWK_SA_MANAGER_FUZZER_H

#define FUZZ_PROJECT_NAME "dhfwksamanager_fuzzer.cpp"

#include <string>
#include "publisher_listener_stub.h"
#include "av_trans_control_center_callback_stub.h"
#include "dhfwk_sa_manager.h"

namespace OHOS {
namespace DistributedHardware {

class FuzzPublisherListenerStub final : public PublisherListenerStub {
public:
    void OnMessage(const DHTopic, const std::string &) override
    {
        return;
    }
};

class FuzzAVTransControlCenterCallback final : public AvTransControlCenterCallbackStub {
public:
    ErrCode SetParameter(uint32_t, const std::string &) override
    {
        return 0;
    }
    ErrCode Notify(const AVTransEventExt &) override
    {
        return 0;
    }
};
} // namespace DistributedHardware
} // namespace OHOS
#endif
