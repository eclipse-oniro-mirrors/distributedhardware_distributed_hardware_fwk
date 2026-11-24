/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "dh_modem_context_ext.h"

#include <dlfcn.h>
#include <string>

#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"
namespace OHOS {
namespace DistributedHardware {
FWK_IMPLEMENT_SINGLE_INSTANCE(DHModemContextExt);

constexpr const char* LIB_DISTRIBUTEDMODEM_EXT_NAME = "libdistributedmodem_ext.z.so";

DHModemContextExt::DHModemContextExt()
{
    DHLOGI("Ctor DHModemContextExt");
}

DHModemContextExt::~DHModemContextExt()
{
    DHLOGI("Dtor DHModemContextExt");
}

int32_t DHModemContextExt::GetHandler()
{
    soHandle_ = dlopen(LIB_DISTRIBUTEDMODEM_EXT_NAME, RTLD_LAZY | RTLD_NODELETE);
    if (soHandle_ == nullptr) {
        DHLOGE("load so failed, failed reason: %{public}s", dlerror());
        return ERR_DH_FWK_POINTER_IS_NULL;
    }
    return DH_FWK_SUCCESS;
}

std::shared_ptr<IDistributedModemExt> DHModemContextExt::GetModemExtInstance()
{
    if (soHandle_ == nullptr && GetHandler() != DH_FWK_SUCCESS) {
        DHLOGE("load modem_ext so failed.");
        return nullptr;
    }
    auto func = (CreateDistributedModemExtImplFuncPtr)dlsym(soHandle_, "CreateDistributedModemExtImplObject");
    if (dlerror() != nullptr || func == nullptr) {
        dlclose(soHandle_);
        soHandle_ = nullptr;
        DHLOGE("Create object function is not exist.");
        return nullptr;
    }
    return std::shared_ptr<IDistributedModemExt>(func());
}

} // namespace DistributedHardware
} // namespace OHOS
