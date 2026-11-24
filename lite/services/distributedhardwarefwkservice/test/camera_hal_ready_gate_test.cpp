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

// TASK-22 host unit test: camera HAL ready gate (DEF-20bB-1, route A-adjusted).
//
// Boot-window race (20bB board-proven, function-level): the daemon's
// LocalHardwareManager::Init constructs the camera_lite CameraManager
// singleton (via DCameraHandler::Initialize -> CameraManager::GetInstance)
// while the media_server HAL init window (~3s+) is still open. The singleton
// freezes its first enumeration result for the whole process lifetime
// (cameraMapCache_ is filled only at construction; GetCameraIds() never
// re-queries), so the EX2 3x1s query retry cannot pierce it -> boot instance
// reports 0 cameras until the process is restarted.
//
// The gate (camera_hal_ready_gate.*) defers the first client construction
// until the HAL-owner readiness flag /dev/.camera_hal_inited appears
// (written by camera_lite services/impl/src/camera_service.cpp
// MarkCameraHalInited after HalCameraInit success; /dev is tmpfs -> per-boot,
// no stale-flag risk). Fail-open: on timeout the caller proceeds and the
// legacy EX2 degradation applies unchanged.
//
// These tests exercise the pure wait-loop core with stub-injected readiness
// timing (immediate / ready-after-3s / timeout -- the three TASK-22 branches)
// plus the production wrapper against tmp flag files (no board, no /dev
// pollution).
//
// Build & run (from the fwk repo root on the Linux build host; single line):
//   g++ -std=c++17 -Wall
//       -I services/distributedhardwarefwkservice/lite/include/localhardwaremanager
//       services/distributedhardwarefwkservice/lite/src/camera_hal_ready_gate.cpp
//       services/distributedhardwarefwkservice/lite/test/camera_hal_ready_gate_test.cpp
//       -o /tmp/task22_test && /tmp/task22_test

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <functional>
#include <string>

#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>

#include "camera_hal_ready_gate.h"

using namespace OHOS::DistributedHardware;

static int g_failures = 0;
static int g_checks = 0;

#define T22_CHECK(cond, msg)                                                 \
    do {                                                                     \
        g_checks++;                                                          \
        if (!(cond)) {                                                       \
            g_failures++;                                                    \
            fprintf(stderr, "FAIL [%s:%d] %s\n", __FILE__, __LINE__, (msg)); \
        } else {                                                             \
            fprintf(stderr, "ok   %s\n", (msg));                             \
        }                                                                    \
    } while (0)

namespace {
// Stub probe: returns false for the first `falseTimes` calls, then true.
struct TimedProbe {
    uint32_t falseTimes;
    uint32_t calls = 0;
    bool operator()()
    {
        calls++;
        return calls > falseTimes;
    }
};

struct StepCounter {
    uint32_t calls = 0;
    void operator()()
    {
        calls++;
    }
};

std::string TmpFlagPath(const char *tag)
{
    return std::string("/tmp/task22_gate_flag_") + tag + "_" + std::to_string(static_cast<long>(getpid()));
}

void TouchFile(const std::string &path)
{
    int fd = open(path.c_str(), O_CREAT | O_WRONLY, 0644);
    if (fd >= 0) {
        close(fd);
    }
}

void TestCoreImmediateReady()
{
    fprintf(stderr, "-- branch 1: immediate ready (HAL flag already present, e.g. kill-relaunch)\n");
    TimedProbe probe {0};
    StepCounter step;
    ReadyGateResult r = WaitForReadyGate(std::ref(probe), std::ref(step), 15);
    T22_CHECK(r.ready, "core: immediate ready -> ready=true");
    T22_CHECK(r.probes == 1, "core: immediate ready consumes exactly 1 probe");
    T22_CHECK(step.calls == 0, "core: immediate ready performs no wait step");
    T22_CHECK(probe.calls == 1, "core: stub probe called exactly once");
}

void TestCoreReadyAfter3s()
{
    fprintf(stderr, "-- branch 2: ready after 3s (20bB boot timeline: HAL window overlaps query window)\n");
    TimedProbe probe {3};
    StepCounter step;
    ReadyGateResult r = WaitForReadyGate(std::ref(probe), std::ref(step), 15);
    T22_CHECK(r.ready, "core: ready after 3 failed probes -> ready=true");
    T22_CHECK(r.probes == 4, "core: ready after 3s consumes 4 probes (t=0..3s)");
    T22_CHECK(step.calls == 3, "core: ready after 3s performs 3 wait steps");
}

void TestCoreTimeout()
{
    fprintf(stderr, "-- branch 3: timeout (flag never appears -> fail-open, EX2 degradation retained)\n");
    TimedProbe probe {UINT32_MAX};
    StepCounter step;
    ReadyGateResult r = WaitForReadyGate(std::ref(probe), std::ref(step), 15);
    T22_CHECK(!r.ready, "core: never ready -> ready=false (fail-open signal)");
    T22_CHECK(r.probes == 15, "core: timeout exhausts all 15 probes");
    T22_CHECK(step.calls == 15, "core: timeout performs 15 wait steps (cap ~15s)");
}

void TestCoreDegenerateArgs()
{
    fprintf(stderr, "-- core degenerate args: null probe / maxProbes=0 must not crash or hang\n");
    StepCounter step;
    ReadyGateResult r1 = WaitForReadyGate(nullptr, std::ref(step), 15);
    T22_CHECK(!r1.ready && r1.probes == 0, "core: null probe -> not ready, 0 probes");
    TimedProbe probe {0};
    ReadyGateResult r2 = WaitForReadyGate(std::ref(probe), nullptr, 15);
    T22_CHECK(!r2.ready && r2.probes == 0, "core: null waitStep -> not ready, 0 probes (no UB)");
    ReadyGateResult r3 = WaitForReadyGate(std::ref(probe), std::ref(step), 0);
    T22_CHECK(!r3.ready && r3.probes == 0, "core: maxProbes=0 -> not ready, 0 probes");
}

void TestWrapperFlagPresent()
{
    fprintf(stderr, "-- wrapper: flag present -> immediate pass (relaunch path keeps 153ms recovery)\n");
    std::string path = TmpFlagPath("present");
    TouchFile(path);
    time_t t0 = time(nullptr);
    ReadyGateResult r = WaitCameraHalReady(3, 1, path.c_str());
    time_t elapsed = time(nullptr) - t0;
    T22_CHECK(r.ready && r.probes == 1, "wrapper: existing flag -> ready on first probe");
    T22_CHECK(elapsed <= 1, "wrapper: no sleep when flag present");
    unlink(path.c_str());
}

void TestWrapperFlagLate()
{
    fprintf(stderr, "-- wrapper: flag appears mid-wait (child touches it after ~2s)\n");
    std::string path = TmpFlagPath("late");
    unlink(path.c_str());
    pid_t pid = fork();
    if (pid == 0) {
        sleep(2);
        TouchFile(path);
        _exit(0);
    }
    T22_CHECK(pid > 0, "wrapper: fork child for late-flag timing");
    ReadyGateResult r = WaitCameraHalReady(10, 1, path.c_str());
    T22_CHECK(r.ready, "wrapper: late-appearing flag -> ready=true");
    T22_CHECK(r.probes >= 2 && r.probes <= 4, "wrapper: detected within probes 2..4 (~2s)");
    int status = 0;
    if (pid > 0) {
        waitpid(pid, &status, 0);
    }
    unlink(path.c_str());
}

void TestWrapperTimeout()
{
    fprintf(stderr, "-- wrapper: flag absent -> fail-open timeout with real ~1s cadence\n");
    std::string path = TmpFlagPath("absent");
    unlink(path.c_str());
    time_t t0 = time(nullptr);
    ReadyGateResult r = WaitCameraHalReady(2, 1, path.c_str());
    time_t elapsed = time(nullptr) - t0;
    T22_CHECK(!r.ready, "wrapper: absent flag -> not ready (fail-open)");
    T22_CHECK(r.probes == 2, "wrapper: timeout=2/interval=1 -> 2 probes");
    T22_CHECK(elapsed >= 1 && elapsed <= 4, "wrapper: wall time honors interval (~2s)");
    ReadyGateResult rn = WaitCameraHalReady(2, 1, nullptr);
    T22_CHECK(!rn.ready && rn.probes == 0, "wrapper: null flagPath -> safe, 0 probes");
}

void TestProductionConstants()
{
    fprintf(stderr, "-- production constants: cross-repo readiness contract pinning\n");
    T22_CHECK(strcmp(CAMERA_HAL_READY_FLAG, "/dev/.camera_hal_inited") == 0,
        "flag path verbatim == camera_lite CAMERA_HAL_INIT_FLAG (camera_service.cpp:28 @af78fdc)");
    T22_CHECK(CAMERA_HAL_READY_TIMEOUT_SEC == 15, "timeout cap = 15s (TASK-22 target)");
    T22_CHECK(CAMERA_HAL_READY_INTERVAL_SEC == 1, "interval = 1s (EX2 cadence)");
    ReadyGateResult r = WaitCameraHalReady(0, 0, "/tmp/task22_nonexistent_flag_xyz");
    T22_CHECK(!r.ready && r.probes >= 1, "wrapper: degenerate 0/0 args -> >=1 probe, no hang");
}
} // namespace

int main()
{
    fprintf(stderr, "==== camera_hal_ready_gate_test (TASK-22: DEF-20bB-1 route A-adjusted) ====\n");
    TestCoreImmediateReady();
    TestCoreReadyAfter3s();
    TestCoreTimeout();
    TestCoreDegenerateArgs();
    TestWrapperFlagPresent();
    TestWrapperFlagLate();
    TestWrapperTimeout();
    TestProductionConstants();
    fprintf(stderr, "==== camera_hal_ready_gate_test %s (checks=%d failures=%d) ====\n",
        g_failures == 0 ? "PASS" : "FAIL", g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
