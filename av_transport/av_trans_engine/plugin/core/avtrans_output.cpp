/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "avtrans_output.h"

#include "avtrans_output_plugin.h"

namespace OHOS {
namespace DistributedHardware {

AvTransOutput::AvTransOutput(uint32_t pkgVer, uint32_t apiVer, std::shared_ptr<AvTransOutputPlugin> plugin)
    : Base(pkgVer, apiVer, plugin), AvTransOutputPlugin_(std::move(plugin)) {}

Status AvTransOutput::PushData(const std::string& inPort, std::shared_ptr<Plugin::Buffer> buffer, int32_t offset)
{
    if (AvTransOutputPlugin_ == nullptr) {
        return Status::ERROR_NOT_EXISTED;
    }
    return AvTransOutputPlugin_->PushData(inPort, buffer, offset);
}

Status AvTransOutput::SetDataCallback(std::function<void(std::shared_ptr<Plugin::Buffer>)> callback)
{
    if (AvTransOutputPlugin_ == nullptr) {
        return Status::ERROR_NOT_EXISTED;
    }
    return AvTransOutputPlugin_->SetDataCallback(callback);
}
}
}