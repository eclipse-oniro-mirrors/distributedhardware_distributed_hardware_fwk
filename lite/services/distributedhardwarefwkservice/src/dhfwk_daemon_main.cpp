/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
 * L1 dhfwk_daemon entry (l1-dcamera, DD-2/DD-3).
 * Deltas versus the old-fork daemon main:
 * 1. The InitSink direct-pull segment (StartCameraSinkInProcess) is replaced
 *    by RegisterStaticSink(DHType::CAMERA, <camera handler lite singleton>)
 *    per contracts C1 v1.1 -- the static sink registry is the only sink path
 *    (D3). The DHFWK_LITE_CAMERA_SINK_SDK gn switch is ENABLED in the lite
 *    daemon target (TASK-5 link closure): the camera lite deps supply the
 *    frozen extern "C" producers GetHardwareHandler() (registry wrapper
 *    input) and GetSinkHardwareHandler() (InitCompSink sink-instance
 *    producer). The weak reference stub branch below is retained only for
 *    hypothetical builds without the define (stub period, TASK-2).
 * 2. DeviceManager face: DM lite is a pure-C vtable SDK; DmDeviceInfo here is
 *    the C struct (lite DM headers), filled from softbus NodeBasicInfo.
 * 3. Boot log anchors follow the frozen six-step grep template; identifiers
 *    are anonymized (BR7 — no plaintext device identifiers in anchor logs).
 */

#include <csignal>
#include <cstring>
#include <dlfcn.h>
#include <memory>
#include <unistd.h>

#include <securec.h>

#include "access_manager.h"
#include "component_manager.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"
#include "distributed_hardware_manager.h"
#include "dm_device_info.h"
#include "idistributed_hardware_sink.h"
#include "ihardware_handler.h"
#include "softbus_bus_center.h"

namespace OHOS {
namespace DistributedHardware {
#if !defined(DHFWK_LITE_CAMERA_SINK_SDK)
// Weak stub DEFINITION of the frozen extern "C" sink-instance producer
// (idistributed_hardware_sink.h) consumed by ComponentManager::InitCompSink
// inside libdistributedhardwarefwksvr.so. The daemon links with
// --no-allow-shlib-undefined, so a weak declaration alone would not satisfy
// the SO reference — a weak definition returning nullptr does, and TASK-5's
// camera sink SDK strong definition overrides it at link time. The
// stub-period path is unreachable at runtime: InitCompSink short-circuits on
// the empty static registry before calling the producer.
extern "C" __attribute__((weak)) IDistributedHardwareSink *GetSinkHardwareHandler()
{
    return nullptr;
}
#endif
} // namespace DistributedHardware
} // namespace OHOS

using namespace OHOS::DistributedHardware;

#if defined(DHFWK_LITE_CAMERA_SINK_SDK)
// TASK-5 link closure (contracts C1 v1.1): no camera header include is
// needed here. Both frozen extern "C" producers are declared by fwk's own
// headers (already included above) and defined by the camera lite GN deps
// of this target (services BUILD.gn):
//   - GetSinkHardwareHandler() -> IDistributedHardwareSink*
//     (idistributed_hardware_sink.h:113; libdistributed_camera_sink_sdk.so;
//     consumed by ComponentManager::InitCompSink inside the fwksvr SO --
//     the executable link satisfies its undefined reference);
//   - GetHardwareHandler() -> IHardwareHandler*
//     (ihardware_handler.h:49; libdistributed_camera_handler.so; wrapped
//     below into the shared_ptr form RegisterStaticSink expects -- the
//     camera handler singleton is process-lifetime, so the wrapper uses a
//     no-op deleter, matching C1 "UnregisterStaticSink never destroys").
#else
/* Weak reference stub period (TASK-2): undefined weak reference at GLOBAL
 * scope, on purpose:
 * 1. Inside namespace OHOS::DistributedHardware it would collide with the
 *    frozen extern "C" IDistributedHardwareSink* GetSinkHardwareHandler()
 *    producer declared by idistributed_hardware_sink.h (same name/scope,
 *    differing only in return type - not overloadable).
 * 2. As a real declaration in the global scope it HIDES the namespace-scoped
 *    extern "C" name imported by the using-directive above at the unqualified
 *    call site ([namespace.udir]: real declarations hide directive imports).
 * The daemon checks the weak address before calling; this branch is compiled
 * out since TASK-5 (DHFWK_LITE_CAMERA_SINK_SDK enabled in the lite daemon
 * target) and kept only for stub-period rebuilds.
 * Coordination note RESOLVED (TASK-5, contracts C1 v1.1): the camera side
 * exports ONLY the fwk-frozen extern "C" symbols -- GetSinkHardwareHandler()
 * (sink SDK lite, idistributed_hardware_sink.h:113) and GetHardwareHandler()
 * (operator handler lite, ihardware_handler.h:49); no same-name C++ overload
 * exists. The enabled call site wraps GetHardwareHandler() for
 * RegisterStaticSink(DHType::CAMERA, handler) -- semantics and the frozen
 * anchor log unchanged.
 */
__attribute__((weak)) std::shared_ptr<OHOS::DistributedHardware::IHardwareHandler> GetSinkHardwareHandler();
#endif

namespace {
    constexpr int32_t SLEEP_INTERVAL_SECONDS = 10;
    constexpr const char *DHFWK_PKG_NAME = "distributed_hardware_fwk";
    constexpr int32_t INIT_MAX_RETRY = 15;
    constexpr uint32_t RETRY_INTERVAL_SEC = 2;
    volatile sig_atomic_t g_running = 1;

    void FillDmDeviceInfo(const NodeBasicInfo *info, DmDeviceInfo &devInfo)
    {
        DmDeviceInfoInit(&devInfo);
        (void)strncpy_s(devInfo.deviceName, sizeof(devInfo.deviceName), info->deviceName,
            sizeof(devInfo.deviceName) - 1);
        (void)strncpy_s(devInfo.networkId, sizeof(devInfo.networkId), info->networkId,
            sizeof(devInfo.networkId) - 1);
        devInfo.deviceTypeId = info->deviceTypeId;
    }

    void OnDhfwkDeviceOnline(NodeBasicInfo *info)
    {
        if (info == nullptr) {
            DHLOGE("OnDhfwkDeviceOnline: info is null");
            return;
        }
        DHLOGI("OnDhfwkDeviceOnline: node online event received");
        DmDeviceInfo devInfo {};
        FillDmDeviceInfo(info, devInfo);
        auto accessMgr = AccessManager::GetInstance();
        accessMgr->OnDeviceOnline(devInfo);
        DmDeviceInfoDestroy(&devInfo);
    }

    void OnDhfwkDeviceOffline(NodeBasicInfo *info)
    {
        if (info == nullptr) {
            DHLOGE("OnDhfwkDeviceOffline: info is null");
            return;
        }
        DHLOGI("OnDhfwkDeviceOffline: node offline event received");
        DmDeviceInfo devInfo {};
        FillDmDeviceInfo(info, devInfo);
        auto accessMgr = AccessManager::GetInstance();
        accessMgr->OnDeviceOffline(devInfo);
        DmDeviceInfoDestroy(&devInfo);
    }

    INodeStateCb g_dhfwkNodeStateCb = {
        .events = EVENT_NODE_STATE_ONLINE | EVENT_NODE_STATE_OFFLINE,
        .onNodeOnline = OnDhfwkDeviceOnline,
        .onNodeOffline = OnDhfwkDeviceOffline,
        .onNodeBasicInfoChanged = nullptr,
        .onLocalNetworkIdChanged = nullptr,
        .onNodeDeviceTrustedChange = nullptr,
        .onNodeStatusChanged = nullptr,
        .onHichainProofException = nullptr,
    };

    // DD-3 (contracts C1): static sink registration replaces the old-fork
    // InitSink direct-pull segment. RegisterStaticSink initializes the
    // handler and records it in staticSinkMap_; the ENABLE_SINK task chain
    // later reuses the registry via InitCompSink (no dlopen path).
    void RegisterCameraStaticSink()
    {
#if defined(DHFWK_LITE_CAMERA_SINK_SDK)
        // C1 v1.1: the camera operator handler lite defines the fwk-frozen
        // extern "C" IHardwareHandler* GetHardwareHandler(); wrap the
        // process-lifetime singleton (no-op deleter) for the registry.
        for (int32_t i = 0; i < INIT_MAX_RETRY; i++) {
            IHardwareHandler *rawHandler = GetHardwareHandler();
            if (rawHandler != nullptr) {
                std::shared_ptr<IHardwareHandler> handler(rawHandler, [](IHardwareHandler *) {});
                int32_t ret = ComponentManager::GetInstance().RegisterStaticSink(DHType::CAMERA, handler);
                if (ret == DH_FWK_SUCCESS) {
                    DHLOGI("RegisterStaticSink CAMERA ok");
                    return;
                }
                DHLOGE("dhfwk_daemon: RegisterStaticSink failed, ret=%{public}d, retry %{public}d/%{public}d",
                    ret, i + 1, INIT_MAX_RETRY);
            } else {
                DHLOGE("dhfwk_daemon: GetHardwareHandler returned null, retry %{public}d/%{public}d",
                    i + 1, INIT_MAX_RETRY);
            }
            sleep(RETRY_INTERVAL_SEC);
        }
        DHLOGE("dhfwk_daemon: RegisterStaticSink CAMERA failed after %{public}d retries", INIT_MAX_RETRY);
#else
        if (::GetSinkHardwareHandler == nullptr) {
            DHLOGW("dhfwk_daemon: camera sink SDK not linked (stub period), skip RegisterStaticSink");
            return;
        }
        for (int32_t i = 0; i < INIT_MAX_RETRY; i++) {
            auto handler = ::GetSinkHardwareHandler();
            if (handler != nullptr) {
                int32_t ret = ComponentManager::GetInstance().RegisterStaticSink(DHType::CAMERA, handler);
                if (ret == DH_FWK_SUCCESS) {
                    DHLOGI("RegisterStaticSink CAMERA ok");
                    return;
                }
                DHLOGE("dhfwk_daemon: RegisterStaticSink failed, ret=%{public}d, retry %{public}d/%{public}d",
                    ret, i + 1, INIT_MAX_RETRY);
            } else {
                DHLOGE("dhfwk_daemon: GetSinkHardwareHandler returned null, retry %{public}d/%{public}d",
                    i + 1, INIT_MAX_RETRY);
            }
            sleep(RETRY_INTERVAL_SEC);
        }
        DHLOGE("dhfwk_daemon: RegisterStaticSink CAMERA failed after %{public}d retries", INIT_MAX_RETRY);
#endif
    }

    // SR-5 TASK-3b: AUDIO lite handler/sink factories are loaded at runtime with
    // dlopen+dlsym. Weak symbols cannot bind on L1 because the audio SOs are not
    // link-time deps of this executable; runtime dynload keeps CAMERA untouched
    // and makes AUDIO registration independent of the fwk link closure.
    constexpr const char *AUDIO_HANDLER_LIB = "libdistributed_audio_handler.so";
    constexpr const char *AUDIO_SINK_LIB = "libdistributed_audio_sink_sdk.so";
    constexpr const char *AUDIO_HANDLER_SYMBOL = "GetAudioHardwareHandler";
    constexpr const char *AUDIO_SINK_SYMBOL = "GetAudioSinkHardwareHandler";

    using GetAudioHardwareHandlerFn = IHardwareHandler *(*)();
    using GetAudioSinkHardwareHandlerFn = IDistributedHardwareSink *(*)();

    void RegisterAudioStaticSink()
    {
        // Idempotent: after a successful registration later calls are no-ops.
        static bool audioRegistered = false;
        // Keep the dlopen handles process-lifetime (the factory returns a
        // process-unique singleton whose code lives in these SOs).
        static void *handlerHandle = nullptr;
        static void *sinkHandle = nullptr;
        if (audioRegistered) {
            DHLOGI("dhfwk_daemon: AUDIO static sink already registered, skip.");
            return;
        }
        if (handlerHandle == nullptr) {
            handlerHandle = dlopen(AUDIO_HANDLER_LIB, RTLD_NOW | RTLD_NODELETE);
            if (handlerHandle == nullptr) {
                DHLOGE("dlopen audio handler failed: %{public}s", dlerror());
                return;
            }
        }
        if (sinkHandle == nullptr) {
            sinkHandle = dlopen(AUDIO_SINK_LIB, RTLD_NOW | RTLD_NODELETE);
            if (sinkHandle == nullptr) {
                DHLOGE("dlopen audio sink failed: %{public}s", dlerror());
                return;
            }
        }
        auto getHandler = reinterpret_cast<GetAudioHardwareHandlerFn>(
            dlsym(handlerHandle, AUDIO_HANDLER_SYMBOL));
        if (getHandler == nullptr) {
            DHLOGE("dlsym audio handler symbol failed: %{public}s", dlerror());
            return;
        }
        auto getSink = reinterpret_cast<GetAudioSinkHardwareHandlerFn>(
            dlsym(sinkHandle, AUDIO_SINK_SYMBOL));
        if (getSink == nullptr) {
            DHLOGE("dlsym audio sink symbol failed: %{public}s", dlerror());
            return;
        }
        IHardwareHandler *rawHandler = getHandler();
        IDistributedHardwareSink *rawSink = getSink();
        if (rawHandler == nullptr || rawSink == nullptr) {
            DHLOGE("dhfwk_daemon: audio handler/sink factory returned null, skip RegisterStaticSink AUDIO");
            return;
        }
        // The audio handler/sink singletons are process lifetime; no-op deleters
        // match the registry contract (UnregisterStaticSink never destroys).
        std::shared_ptr<IHardwareHandler> handler(rawHandler, [](IHardwareHandler *) {});
        std::shared_ptr<IDistributedHardwareSink> sink(rawSink, [](IDistributedHardwareSink *) {});
        int32_t ret = ComponentManager::GetInstance().RegisterStaticSink(DHType::AUDIO, handler, sink);
        if (ret == DH_FWK_SUCCESS) {
            audioRegistered = true;
            DHLOGI("RegisterStaticSink AUDIO ok");
        } else {
            DHLOGE("dhfwk_daemon: RegisterStaticSink AUDIO failed, ret=%{public}d", ret);
        }
    }
}

static void SignalHandler(int sig)
{
    (void)sig;
    g_running = 0;
}

using namespace OHOS::DistributedHardware;

int main()
{
    void (*prevSigTerm)(int) = signal(SIGTERM, SignalHandler);
    if (prevSigTerm == SIG_ERR) {
        DHLOGE("dhfwk_daemon: signal(SIGTERM) failed");
    }
    void (*prevSigInt)(int) = signal(SIGINT, SignalHandler);
    if (prevSigInt == SIG_ERR) {
        DHLOGE("dhfwk_daemon: signal(SIGINT) failed");
    }

    DHLOGI("dhfwk_daemon: starting");

    /* T-SR5-182 reorder fix: register static sinks BEFORE Initialize().
     * LocalInit()->CheckSinkConfigStart triggers auto-EnableSink for components
     * whose cfg lacks feature keys ("old configuration"); without pre-registered
     * sinks InitCompSink fails (-10600) and main thread blocks in synchronous
     * binder IPC. RegisterStaticSink is pure in-memory (staticSinkMap_ + dlopen),
     * verified zero Initialize dependency (component_manager.cpp:183/:214). */
    RegisterCameraStaticSink();
    RegisterAudioStaticSink();

    auto accessManager = AccessManager::GetInstance();
    while (accessManager->Init() != DH_FWK_SUCCESS) {
        DHLOGE("dhfwk_daemon: AccessManager::Init failed, retry after %{public}u sec", RETRY_INTERVAL_SEC);
        sleep(RETRY_INTERVAL_SEC);
    }
    DHLOGI("dhfwk_daemon: AccessManager init success");

    auto ret = DistributedHardwareManager::GetInstance().Initialize();
    if (ret != DH_FWK_SUCCESS) {
        DHLOGE("dhfwk_daemon: DistributedHardwareManager::Initialize failed, ret = %{public}d", ret);
        return 1;
    }
    DHLOGI("dhfwk_daemon: Initialize done");

    // lite: the DM softbus listener does not register the node-state callback,
    // so the daemon self-registers (softbus -> OnDeviceOnline bridge).
    int32_t regRet = RegNodeDeviceStateCb(DHFWK_PKG_NAME, &g_dhfwkNodeStateCb);
    if (regRet != 0) {
        DHLOGE("dhfwk_daemon: RegNodeDeviceStateCb failed, ret = %{public}d", regRet);
    } else {
        DHLOGI("dhfwk_daemon: RegNodeDeviceStateCb ok");
    }

    DHLOGI("dhfwk_daemon: trusted-device replay begin");
    accessManager->CheckTrustedDeviceOnline();
    DHLOGI("dhfwk_daemon: trusted-device replay done");

    DHLOGI("dhfwk_daemon: softbus listening (node-state callback registered)");
    DHLOGI("dhfwk_daemon: main loop enter");
    while (g_running) {
        sleep(SLEEP_INTERVAL_SECONDS);
    }

    DHLOGI("dhfwk_daemon: exiting");
    return 0;
}
