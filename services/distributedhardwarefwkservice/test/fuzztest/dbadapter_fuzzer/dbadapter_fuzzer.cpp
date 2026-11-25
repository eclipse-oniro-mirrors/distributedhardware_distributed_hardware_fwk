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

#include "dbadapter_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <fuzzer/FuzzedDataProvider.h>

#include "capability_info_manager.h"
#include "constants.h"
#include "db_adapter.h"
#include "dh_context.h"
#include "dh_utils_tool.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"
#include "meta_info_manager.h"
#include "version_info_manager.h"

namespace OHOS {
namespace DistributedHardware {
namespace {
    const std::string VALID_KEY = "1234567890";
    const std::string GLOBAL_CAPABILITY_STORE_ID = "global_capability_info";
    const std::string GLOBAL_VERSION_STORE_ID = "global_version_info";
    const std::string GLOBAL_META_STORE_ID = "global_meta_info";
    std::once_flag g_eventHandlerInitFlag;
}

void DBAdapterOperationFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint8_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    bool isAutoSync = fdp.ConsumeBool();
    std::string appId = fdp.ConsumeRandomLengthString();
    std::string storeId = fdp.ConsumeRandomLengthString();
    std::string key = fdp.ConsumeRandomLengthString();
    std::string value = fdp.ConsumeRandomLengthString();
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string networkId = fdp.ConsumeRandomLengthString();

    // kvStoragePtr_ is nullptr when db is not inited, cover the nullptr and param check branches.
    std::shared_ptr<DBAdapter> dbAdapter = std::make_shared<DBAdapter>(appId.c_str(), storeId.c_str(), nullptr);

    std::string outData;
    dbAdapter->GetDataByKey(key, outData);
    std::vector<std::string> values;
    dbAdapter->GetDataByKeyPrefix(key, values);
    dbAdapter->PutData(key, value);
    std::vector<std::string> keys;
    keys.push_back(key);
    std::vector<std::string> sameSizeValues;
    sameSizeValues.push_back(value);
    dbAdapter->PutDataBatch(keys, sameSizeValues);
    std::vector<std::string> diffSizeValues;
    diffSizeValues.push_back(value);
    diffSizeValues.push_back(value);
    dbAdapter->PutDataBatch(keys, diffSizeValues);
    dbAdapter->RemoveDeviceData(deviceId);
    dbAdapter->RemoveDataByKey(key);
    dbAdapter->GetEntriesByKeys(keys);
    dbAdapter->SyncDataByNetworkId(networkId);
    dbAdapter->ClearDataByPrefix(key);
    dbAdapter->DeleteKvStore();
    dbAdapter->ReInit(isAutoSync);
    dbAdapter->UnInit();

    // Cover the id-valid branches of GetNetworkIdByKey and SyncByNotFound.
    dbAdapter->GetNetworkIdByKey(VALID_KEY);
    dbAdapter->GetNetworkIdByKey(key);
    dbAdapter->SyncByNotFound(VALID_KEY);
    dbAdapter->SyncByNotFound(key);
}

void DBAdapterSyncDBForRecoverFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string storeId = fdp.ConsumeRandomLengthString();
    std::call_once(g_eventHandlerInitFlag, []() {
        // The recover event handlers of the three managers must be ready before recover sync.
        std::shared_ptr<AppExecFwk::EventRunner> runner = AppExecFwk::EventRunner::Create(true);
        auto capMgr = CapabilityInfoManager::GetInstance();
        capMgr->eventHandler_ = std::make_shared<CapabilityInfoManager::CapabilityInfoManagerEventHandler>(
            runner, capMgr);
        auto verMgr = VersionInfoManager::GetInstance();
        verMgr->eventHandler_ = std::make_shared<VersionInfoManager::VersionInfoManagerEventHandler>(
            runner, verMgr);
        auto metaMgr = MetaInfoManager::GetInstance();
        metaMgr->eventHandler_ = std::make_shared<MetaInfoManager::MetaInfoManagerEventHandler>(runner, metaMgr);
    });

    // No storeId matched branch.
    std::shared_ptr<DBAdapter> dbAdapter = std::make_shared<DBAdapter>("appTest", storeId.c_str(), nullptr);
    dbAdapter->SyncDBForRecover();

    // Capability store recover branch.
    dbAdapter = std::make_shared<DBAdapter>("appTest", GLOBAL_CAPABILITY_STORE_ID.c_str(), nullptr);
    dbAdapter->SyncDBForRecover();

    // Version store recover branch.
    dbAdapter = std::make_shared<DBAdapter>("appTest", GLOBAL_VERSION_STORE_ID.c_str(), nullptr);
    dbAdapter->SyncDBForRecover();

    // Meta store recover branch.
    dbAdapter = std::make_shared<DBAdapter>("appTest", GLOBAL_META_STORE_ID.c_str(), nullptr);
    dbAdapter->SyncDBForRecover();
}

void DBAdapterDBDiedOptFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size == 0)) {
        return;
    }

    // DBDiedOpt sleeps 100ms on the failed branch, run it only once to keep the fuzz effective.
    static std::once_flag diedOptFlag;
    std::call_once(diedOptFlag, []() {
        // kvStoragePtr_ is nullptr, ReInit failed and times increase.
        std::shared_ptr<DBAdapter> dbAdapter = std::make_shared<DBAdapter>("appTest", "storeTest", nullptr);
        int32_t times = 0;
        dbAdapter->DBDiedOpt(times);
    });
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::DistributedHardware::DBAdapterOperationFuzzTest(data, size);
    OHOS::DistributedHardware::DBAdapterSyncDBForRecoverFuzzTest(data, size);
    OHOS::DistributedHardware::DBAdapterDBDiedOptFuzzTest(data, size);
    return 0;
}
