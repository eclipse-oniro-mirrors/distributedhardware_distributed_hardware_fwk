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

#ifndef OHOS_GET_DH_DESCRIPTORS_CALLBACK_STUB_H
#define OHOS_GET_DH_DESCRIPTORS_CALLBACK_STUB_H

#include "iget_dh_descriptors_callback.h"

#include "iremote_stub.h"

namespace OHOS {
namespace DistributedHardware {
class GetDhDescriptorsCallbackStub : public IRemoteStub<IGetDhDescriptorsCallback> {
public:
    GetDhDescriptorsCallbackStub();
    virtual ~GetDhDescriptorsCallbackStub() override;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
private:
    int32_t ReadDescriptors(MessageParcel &data, std::vector<DHDescriptor> &descriptors);
private:
    DISALLOW_COPY_AND_MOVE(GetDhDescriptorsCallbackStub);
};
} // namespace DistributedHardware
} // namespace OHOS
#endif // OHOS_GET_DH_DESCRIPTORS_CALLBACK_STUB_H