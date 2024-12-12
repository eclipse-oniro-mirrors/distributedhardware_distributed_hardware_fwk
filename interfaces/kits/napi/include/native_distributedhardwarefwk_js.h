/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_DH_NATIVE_DISTRIBUTED_HARDWARE_JS_H
#define OHOS_DH_NATIVE_DISTRIBUTED_HARDWARE_JS_H

#include <string>

#include "napi/native_api.h"
#include "napi/native_node_api.h"
#include "cJSON.h"

constexpr int32_t ALL = 0;
constexpr int32_t CAMERA = 1;
constexpr int32_t SCREEN = 8;
constexpr int32_t MODEM_MIC = 256;
constexpr int32_t MODEM_SPEAKER = 512;
constexpr int32_t MIC = 1024;
constexpr int32_t SPEAKER = 2048;

class DistributedHardwareManager {
public:
    explicit DistributedHardwareManager(napi_env env, napi_value thisVar);
    ~DistributedHardwareManager();
    static napi_value Init(napi_env env, napi_value exports);
    static void InitDistributedHardwareType(napi_env env, napi_value exports);
    static napi_value PauseDistributedHardware(napi_env env, napi_callback_info info);
    static napi_value ResumeDistributedHardware(napi_env env, napi_callback_info info);
    static napi_value StopDistributedHardware(napi_env env, napi_callback_info info);
    static void JsObjectToString(const napi_env &env, const napi_value &object, const std::string &fieldStr, char *dest,
                                 const int32_t destLen);
    static void JsObjectToInt(const napi_env &env, const napi_value &object, const std::string &fieldStr,
                              int32_t &fieldRef);
    static napi_value CreateBusinessErr(napi_env env, int32_t errCode);

private:
    static bool IsSystemApp();
};
#endif // OHOS_DH_NATIVE_DISTRIBUTED_HARDWARE_JS_H
