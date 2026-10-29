/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <string>
#include <dlfcn.h>

#include "anonymous_string.h"
#include "dh_utils_hisysevent.h"
#include "dh_utils_hitrace.h"
#include "dh_utils_tool.h"
#include "histreamer_query_tool.h"
#include "distributed_hardware_errno.h"
#include "distributed_hardware_log.h"
#include "device_type.h"

using namespace testing::ext;
using namespace OHOS;
using namespace OHOS::DistributedHardware;

class DhUtilsCoverageTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DhUtilsCoverageTest::SetUpTestCase(void) {}
void DhUtilsCoverageTest::TearDownTestCase(void) {}
void DhUtilsCoverageTest::SetUp(void) {}
void DhUtilsCoverageTest::TearDown(void) {}

/* ==================== GetAnonyString ==================== */

HWTEST_F(DhUtilsCoverageTest, GetAnonyString_001, TestSize.Level1)
{
    std::string result = GetAnonyString("");
    EXPECT_EQ(result, "");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyString_002, TestSize.Level1)
{
    std::string result = GetAnonyString("ab");
    EXPECT_EQ(result, "******");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyString_003, TestSize.Level1)
{
    std::string result = GetAnonyString("abc");
    EXPECT_EQ(result.length(), 8u);
    EXPECT_EQ(result.substr(0, 1), "a");
    EXPECT_EQ(result.substr(7, 1), "c");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyString_004, TestSize.Level1)
{
    std::string input(20, 'x');
    std::string result = GetAnonyString(input);
    EXPECT_EQ(result.length(), 8u);
    EXPECT_EQ(result.substr(0, 1), "x");
    EXPECT_EQ(result.substr(7, 1), "x");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyString_005, TestSize.Level1)
{
    std::string input = "abcdefghijklmnopqrstuvwxyz1234567890";
    std::string result = GetAnonyString(input);
    EXPECT_EQ(result.length(), 14u);
    EXPECT_EQ(result.substr(0, 4), "abcd");
    EXPECT_EQ(result.substr(10, 4), "7890");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyString_006, TestSize.Level1)
{
    std::string input(21, 'y');
    std::string result = GetAnonyString(input);
    EXPECT_EQ(result.length(), 14u);
    EXPECT_EQ(result.substr(0, 4), "yyyy");
    EXPECT_EQ(result.substr(10, 4), "yyyy");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyString_007, TestSize.Level1)
{
    std::string result = GetAnonyString("HelloWorld123");
    EXPECT_EQ(result.length(), 8u);
    EXPECT_EQ(result.substr(0, 1), "H");
    EXPECT_EQ(result.substr(7, 1), "3");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyString_008, TestSize.Level1)
{
    std::string hugeStr(41 * 1024 * 1024, 'z');
    std::string result = GetAnonyString(hugeStr);
    EXPECT_EQ(result, "");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyString_009, TestSize.Level1)
{
    std::string result = GetAnonyString("a");
    EXPECT_EQ(result, "******");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyString_010, TestSize.Level1)
{
    std::string result = GetAnonyString("xy");
    EXPECT_EQ(result, "******");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyString_011, TestSize.Level1)
{
    std::string input(19, 'a');
    std::string result = GetAnonyString(input);
    EXPECT_EQ(result.length(), 8u);
    EXPECT_EQ(result.substr(0, 1), "a");
    EXPECT_EQ(result.substr(7, 1), "a");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyString_012, TestSize.Level1)
{
    std::string input = "01234567890123456789";
    std::string result = GetAnonyString(input);
    EXPECT_EQ(result.length(), 8u);
    EXPECT_EQ(result.substr(0, 1), "0");
    EXPECT_EQ(result.substr(7, 1), "9");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyString_013, TestSize.Level1)
{
    std::string input = "012345678901234567890";
    std::string result = GetAnonyString(input);
    EXPECT_EQ(result.length(), 14u);
    EXPECT_EQ(result.substr(0, 4), "0123");
    EXPECT_EQ(result.substr(10, 4), "7890");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyString_014, TestSize.Level1)
{
    std::string result = GetAnonyString("AB");
    EXPECT_EQ(result, "******");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyString_015, TestSize.Level1)
{
    std::string input(100, 'z');
    std::string result = GetAnonyString(input);
    EXPECT_EQ(result.length(), 14u);
    EXPECT_EQ(result.substr(0, 4), "zzzz");
    EXPECT_EQ(result.substr(10, 4), "zzzz");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyString_016, TestSize.Level1)
{
    std::string result = GetAnonyString("!@#$%^&*()");
    EXPECT_EQ(result.length(), 8u);
    EXPECT_EQ(result.substr(0, 1), "!");
    EXPECT_EQ(result.substr(7, 1), ")");
}

/* ==================== GetAnonyInt32 ==================== */

HWTEST_F(DhUtilsCoverageTest, GetAnonyInt32_001, TestSize.Level1)
{
    EXPECT_EQ(GetAnonyInt32(0), "*");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyInt32_002, TestSize.Level1)
{
    EXPECT_EQ(GetAnonyInt32(5), "*");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyInt32_003, TestSize.Level1)
{
    std::string result = GetAnonyInt32(-7);
    EXPECT_EQ(result.length(), 2u);
    EXPECT_EQ(result.substr(0, 1), "-");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyInt32_004, TestSize.Level1)
{
    std::string result = GetAnonyInt32(123456);
    EXPECT_EQ(result.length(), 6u);
    EXPECT_EQ(result.substr(0, 1), "1");
    for (size_t i = 1; i < 6; i++) {
        EXPECT_EQ(result.substr(i, 1), "*");
    }
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyInt32_005, TestSize.Level1)
{
    std::string result = GetAnonyInt32(-987654);
    EXPECT_EQ(result.length(), 7u);
    EXPECT_EQ(result.substr(0, 1), "-");
    for (size_t i = 1; i < 7; i++) {
        EXPECT_EQ(result.substr(i, 1), "*");
    }
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyInt32_006, TestSize.Level1)
{
    std::string result = GetAnonyInt32(2147483647);
    EXPECT_EQ(result.length(), 10u);
    EXPECT_EQ(result.substr(0, 1), "2");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyInt32_007, TestSize.Level1)
{
    std::string result = GetAnonyInt32(-2147483648);
    EXPECT_FALSE(result.empty());
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyInt32_008, TestSize.Level1)
{
    EXPECT_EQ(GetAnonyInt32(1), "*");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyInt32_009, TestSize.Level1)
{
    std::string result = GetAnonyInt32(-1);
    EXPECT_EQ(result.length(), 2u);
    EXPECT_EQ(result.substr(0, 1), "-");
    EXPECT_EQ(result.substr(1, 1), "*");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyInt32_010, TestSize.Level1)
{
    std::string result = GetAnonyInt32(10);
    EXPECT_EQ(result.length(), 2u);
    EXPECT_EQ(result.substr(0, 1), "1");
    EXPECT_EQ(result.substr(1, 1), "*");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyInt32_011, TestSize.Level1)
{
    std::string result = GetAnonyInt32(99);
    EXPECT_EQ(result.length(), 2u);
    EXPECT_EQ(result.substr(0, 1), "9");
    EXPECT_EQ(result.substr(1, 1), "*");
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyInt32_012, TestSize.Level1)
{
    std::string result = GetAnonyInt32(100);
    EXPECT_EQ(result.length(), 3u);
    EXPECT_EQ(result.substr(0, 1), "1");
    for (size_t i = 1; i < 3; i++) {
        EXPECT_EQ(result.substr(i, 1), "*");
    }
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyInt32_013, TestSize.Level1)
{
    std::string result = GetAnonyInt32(-100);
    EXPECT_EQ(result.length(), 4u);
    EXPECT_EQ(result.substr(0, 1), "-");
    for (size_t i = 1; i < 4; i++) {
        EXPECT_EQ(result.substr(i, 1), "*");
    }
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyInt32_014, TestSize.Level1)
{
    std::string result = GetAnonyInt32(1000000);
    EXPECT_EQ(result.length(), 7u);
    EXPECT_EQ(result.substr(0, 1), "1");
    for (size_t i = 1; i < 7; i++) {
        EXPECT_EQ(result.substr(i, 1), "*");
    }
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyInt32_015, TestSize.Level1)
{
    std::string result = GetAnonyInt32(-1000000);
    EXPECT_EQ(result.length(), 8u);
    EXPECT_EQ(result.substr(0, 1), "-");
    for (size_t i = 1; i < 8; i++) {
        EXPECT_EQ(result.substr(i, 1), "*");
    }
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyInt32_016, TestSize.Level1)
{
    std::string result = GetAnonyInt32(999999);
    EXPECT_EQ(result.length(), 6u);
    EXPECT_EQ(result.substr(0, 1), "9");
    for (size_t i = 1; i < 6; i++) {
        EXPECT_EQ(result.substr(i, 1), "*");
    }
}

HWTEST_F(DhUtilsCoverageTest, GetAnonyInt32_017, TestSize.Level1)
{
    std::string result = GetAnonyInt32(-999999);
    EXPECT_EQ(result.length(), 7u);
    EXPECT_EQ(result.substr(0, 1), "-");
    for (size_t i = 1; i < 7; i++) {
        EXPECT_EQ(result.substr(i, 1), "*");
    }
}

/* ==================== HiSysEventWriteMsg ==================== */

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteMsg_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteMsg(DHFWK_INIT_FAIL, HiviewDFX::HiSysEvent::EventType::FAULT, "test fault msg"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteMsg_002, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteMsg(DHFWK_INIT_BEGIN, HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "test behavior msg"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteMsg_003, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteMsg(DHFWK_INIT_END, HiviewDFX::HiSysEvent::EventType::BEHAVIOR, ""));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteMsg_004, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteMsg(DHFWK_EXIT_BEGIN, HiviewDFX::HiSysEvent::EventType::STATISTIC, "stat msg"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteMsg_005, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteMsg(DHFWK_EXIT_END, HiviewDFX::HiSysEvent::EventType::SECURITY, "security msg"));
}

/* ==================== HiSysEventWriteErrCodeMsg ==================== */

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteErrCodeMsg_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteErrCodeMsg(DHFWK_DH_REGISTER_FAIL,
            HiviewDFX::HiSysEvent::EventType::FAULT, ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, "register failed"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteErrCodeMsg_002, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteErrCodeMsg(DHFWK_DH_UNREGISTER_FAIL,
            HiviewDFX::HiSysEvent::EventType::FAULT, 0, "unregister success code"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteErrCodeMsg_003, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteErrCodeMsg(DHFWK_INIT_FAIL,
            HiviewDFX::HiSysEvent::EventType::FAULT, ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, ""));
}

/* ==================== HiSysEventWriteReleaseMsg ==================== */

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteReleaseMsg_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteReleaseMsg(DHFWK_RELEASE_FAIL,
            HiviewDFX::HiSysEvent::EventType::FAULT, DHType::CAMERA,
            ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, "camera release fail"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteReleaseMsg_002, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteReleaseMsg(DHFWK_RELEASE_FAIL,
            HiviewDFX::HiSysEvent::EventType::FAULT, DHType::AUDIO,
            ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, "audio release fail"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteReleaseMsg_003, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteReleaseMsg(DHFWK_RELEASE_FAIL,
            HiviewDFX::HiSysEvent::EventType::FAULT, DHType::SCREEN,
            ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, "screen release fail"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteReleaseMsg_004, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteReleaseMsg(DHFWK_RELEASE_FAIL,
            HiviewDFX::HiSysEvent::EventType::FAULT, DHType::MODEM,
            ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, "modem release fail"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteReleaseMsg_005, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteReleaseMsg(DHFWK_RELEASE_FAIL,
            HiviewDFX::HiSysEvent::EventType::FAULT, DHType::UNKNOWN,
            ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, "unknown dh type release fail"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteReleaseMsg_006, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteReleaseMsg(DHFWK_RELEASE_FAIL,
            HiviewDFX::HiSysEvent::EventType::FAULT, DHType::MAX_DH,
            ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, "max dh type release fail"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteReleaseMsg_007, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteReleaseMsg(DHFWK_RELEASE_FAIL,
            HiviewDFX::HiSysEvent::EventType::FAULT, DHType::GPS,
            ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, "gps release fail"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteReleaseMsg_008, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteReleaseMsg(DHFWK_RELEASE_FAIL,
            HiviewDFX::HiSysEvent::EventType::FAULT, DHType::INPUT,
            ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, "input release fail"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteReleaseMsg_009, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteReleaseMsg(DHFWK_RELEASE_FAIL,
            HiviewDFX::HiSysEvent::EventType::FAULT, DHType::HFP,
            ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, "hfp release fail"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteReleaseMsg_010, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteReleaseMsg(DHFWK_RELEASE_FAIL,
            HiviewDFX::HiSysEvent::EventType::FAULT, DHType::A2D,
            ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, "a2d release fail"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteReleaseMsg_011, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteReleaseMsg(DHFWK_RELEASE_FAIL,
            HiviewDFX::HiSysEvent::EventType::FAULT, DHType::VIRMODEM_AUDIO,
            ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, "virmodem release fail"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteReleaseMsg_012, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteReleaseMsg(DHFWK_RELEASE_FAIL,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR, DHType::CAMERA,
            DH_FWK_SUCCESS, "camera release success"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteReleaseMsg_013, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteReleaseMsg(DHFWK_RELEASE_FAIL,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR, DHType::AUDIO,
            DH_FWK_SUCCESS, "audio release success"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteReleaseMsg_014, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteReleaseMsg(DHFWK_RELEASE_FAIL,
            HiviewDFX::HiSysEvent::EventType::STATISTIC, DHType::CAMERA,
            ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, "camera stat"));
}

/* ==================== HiSysEventWriteCompOfflineMsg ==================== */

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteCompOfflineMsg_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteCompOfflineMsg(DHFWK_DEV_OFFLINE,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "anony_network_id_12345", "device offline"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteCompOfflineMsg_002, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteCompOfflineMsg(DHFWK_DEV_OFFLINE,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "", "empty networkId offline"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteCompOfflineMsg_003, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteCompOfflineMsg(DHFWK_DEV_OFFLINE,
            HiviewDFX::HiSysEvent::EventType::FAULT, "anony_net_456", "offline fault"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteCompOfflineMsg_004, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteCompOfflineMsg(DHFWK_DEV_OFFLINE,
            HiviewDFX::HiSysEvent::EventType::STATISTIC, "net_stat_001", "statistic offline"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteCompOfflineMsg_005, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteCompOfflineMsg(DHFWK_DEV_OFFLINE,
            HiviewDFX::HiSysEvent::EventType::SECURITY, "net_sec_001", "security offline"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteCompOfflineMsg_006, TestSize.Level1)
{
    std::string longNetId(256, 'n');
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteCompOfflineMsg(DHFWK_DEV_OFFLINE,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR, longNetId, "long networkId offline"));
}

/* ==================== HiSysEventWriteCompMgrFailedMsg ==================== */

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteCompMgrFailedMsg_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteCompMgrFailedMsg(DHFWK_DH_REGISTER_FAIL,
            HiviewDFX::HiSysEvent::EventType::FAULT, "anony_dh_id_001",
            ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, "comp mgr register failed"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteCompMgrFailedMsg_002, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteCompMgrFailedMsg(DHFWK_DH_UNREGISTER_FAIL,
            HiviewDFX::HiSysEvent::EventType::FAULT, "anony_dh_id_002",
            0, "comp mgr unregister zero code"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteCompMgrFailedMsg_003, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteCompMgrFailedMsg(DHFWK_DH_REGISTER_FAIL,
            HiviewDFX::HiSysEvent::EventType::FAULT, "",
            ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, ""));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteCompMgrFailedMsg_004, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteCompMgrFailedMsg(DHFWK_DH_REGISTER_FAIL,
            HiviewDFX::HiSysEvent::EventType::FAULT, "anony_dh_id_003",
            ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, "register fail with long msg"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteCompMgrFailedMsg_005, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteCompMgrFailedMsg(DHFWK_DH_UNREGISTER_FAIL,
            HiviewDFX::HiSysEvent::EventType::BEHAVIOR, "anony_dh_id_004",
            DH_FWK_SUCCESS, "unregister success info"));
}

HWTEST_F(DhUtilsCoverageTest, HiSysEventWriteCompMgrFailedMsg_006, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        HiSysEventWriteCompMgrFailedMsg(DHFWK_DH_REGISTER_FAIL,
            HiviewDFX::HiSysEvent::EventType::STATISTIC, "anony_dh_id_005",
            ERR_DH_FWK_ACCESS_PERMISSION_CHECK_FAIL, "register stat"));
}

/* ==================== DHCompMgrTraceStart ==================== */

HWTEST_F(DhUtilsCoverageTest, DHCompMgrTraceStart_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        DHCompMgrTraceStart("anony_network_id", "anony_dh_id", "ENABLE_START"));
}

HWTEST_F(DhUtilsCoverageTest, DHCompMgrTraceStart_002, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DHCompMgrTraceStart("", "", ""));
}

HWTEST_F(DhUtilsCoverageTest, DHCompMgrTraceStart_003, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        DHCompMgrTraceStart("net123", "dhId456", COMPONENT_LOAD_START));
}

HWTEST_F(DhUtilsCoverageTest, DHCompMgrTraceStart_004, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(
        DHCompMgrTraceStart("net789", "dhId012", COMPONENT_UNLOAD_START));
}

/* ==================== DHQueryTraceStart ==================== */

HWTEST_F(DhUtilsCoverageTest, DHQueryTraceStart_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DHQueryTraceStart(DHType::CAMERA));
}

HWTEST_F(DhUtilsCoverageTest, DHQueryTraceStart_002, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DHQueryTraceStart(DHType::AUDIO));
}

HWTEST_F(DhUtilsCoverageTest, DHQueryTraceStart_003, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DHQueryTraceStart(DHType::SCREEN));
}

HWTEST_F(DhUtilsCoverageTest, DHQueryTraceStart_004, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DHQueryTraceStart(DHType::GPS));
}

HWTEST_F(DhUtilsCoverageTest, DHQueryTraceStart_005, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DHQueryTraceStart(DHType::INPUT));
}

HWTEST_F(DhUtilsCoverageTest, DHQueryTraceStart_006, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DHQueryTraceStart(DHType::HFP));
}

HWTEST_F(DhUtilsCoverageTest, DHQueryTraceStart_007, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DHQueryTraceStart(DHType::A2D));
}

HWTEST_F(DhUtilsCoverageTest, DHQueryTraceStart_008, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DHQueryTraceStart(DHType::VIRMODEM_AUDIO));
}

HWTEST_F(DhUtilsCoverageTest, DHQueryTraceStart_009, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DHQueryTraceStart(DHType::MODEM));
}

HWTEST_F(DhUtilsCoverageTest, DHQueryTraceStart_010, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DHQueryTraceStart(DHType::UNKNOWN));
}

HWTEST_F(DhUtilsCoverageTest, DHQueryTraceStart_011, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DHQueryTraceStart(DHType::MAX_DH));
}

/* ==================== DHTraceStart ==================== */

HWTEST_F(DhUtilsCoverageTest, DHTraceStart_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DHTraceStart(DH_ENABLE_START));
}

HWTEST_F(DhUtilsCoverageTest, DHTraceStart_002, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DHTraceStart(DH_DISABLE_START));
}

HWTEST_F(DhUtilsCoverageTest, DHTraceStart_003, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DHTraceStart(COMPONENT_INIT_START));
}

HWTEST_F(DhUtilsCoverageTest, DHTraceStart_004, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DHTraceStart(COMPONENT_RELEASE_START));
}

HWTEST_F(DhUtilsCoverageTest, DHTraceStart_005, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DHTraceStart(""));
}

/* ==================== DHTraceEnd ==================== */

HWTEST_F(DhUtilsCoverageTest, DHTraceEnd_001, TestSize.Level1)
{
    EXPECT_NO_FATAL_FAILURE(DHTraceEnd());
}

HWTEST_F(DhUtilsCoverageTest, DHTraceEnd_002, TestSize.Level1)
{
    DHTraceStart("PAIRED_TRACE_TEST");
    EXPECT_NO_FATAL_FAILURE(DHTraceEnd());
}

HWTEST_F(DhUtilsCoverageTest, DHTraceEnd_003, TestSize.Level1)
{
    DHCompMgrTraceStart("net_test", "dhId_test", "PAIRED_COMP_MGR");
    EXPECT_NO_FATAL_FAILURE(DHTraceEnd());
}

/* ==================== DHTraceStart/DHTraceEnd 配对组合 ==================== */

HWTEST_F(DhUtilsCoverageTest, DHTraceStart_DHTraceEnd_Pair_001, TestSize.Level1)
{
    DHTraceStart(DH_ENABLE_START);
    EXPECT_NO_FATAL_FAILURE(DHTraceEnd());
}

HWTEST_F(DhUtilsCoverageTest, DHTraceStart_DHTraceEnd_Pair_002, TestSize.Level1)
{
    DHTraceStart(DH_DISABLE_START);
    EXPECT_NO_FATAL_FAILURE(DHTraceEnd());
}

HWTEST_F(DhUtilsCoverageTest, DHTraceStart_DHTraceEnd_Pair_003, TestSize.Level1)
{
    DHTraceStart(COMPONENT_INIT_START);
    EXPECT_NO_FATAL_FAILURE(DHTraceEnd());
}

HWTEST_F(DhUtilsCoverageTest, DHTraceStart_DHTraceEnd_Pair_004, TestSize.Level1)
{
    DHTraceStart(COMPONENT_RELEASE_START);
    EXPECT_NO_FATAL_FAILURE(DHTraceEnd());
}

HWTEST_F(DhUtilsCoverageTest, DHQueryTraceStart_DHTraceEnd_Pair_001, TestSize.Level1)
{
    DHQueryTraceStart(DHType::CAMERA);
    EXPECT_NO_FATAL_FAILURE(DHTraceEnd());
}

HWTEST_F(DhUtilsCoverageTest, DHQueryTraceStart_DHTraceEnd_Pair_002, TestSize.Level1)
{
    DHQueryTraceStart(DHType::AUDIO);
    EXPECT_NO_FATAL_FAILURE(DHTraceEnd());
}

HWTEST_F(DhUtilsCoverageTest, DHQueryTraceStart_DHTraceEnd_Pair_003, TestSize.Level1)
{
    DHQueryTraceStart(DHType::UNKNOWN);
    EXPECT_NO_FATAL_FAILURE(DHTraceEnd());
}

HWTEST_F(DhUtilsCoverageTest, DHCompMgrTrace_DHTraceEnd_Pair_001, TestSize.Level1)
{
    DHCompMgrTraceStart("net_pair", "dhId_pair", COMPONENT_LOAD_START);
    EXPECT_NO_FATAL_FAILURE(DHTraceEnd());
}

HWTEST_F(DhUtilsCoverageTest, DHCompMgrTrace_DHTraceEnd_Pair_002, TestSize.Level1)
{
    DHCompMgrTraceStart("net_pair2", "dhId_pair2", COMPONENT_UNLOAD_START);
    EXPECT_NO_FATAL_FAILURE(DHTraceEnd());
}

HWTEST_F(DhUtilsCoverageTest, DHCompMgrTrace_DHTraceEnd_Pair_003, TestSize.Level1)
{
    DHCompMgrTraceStart("net_pair3", "dhId_pair3", COMPONENT_INIT_START);
    EXPECT_NO_FATAL_FAILURE(DHTraceEnd());
}

HWTEST_F(DhUtilsCoverageTest, DHCompMgrTrace_DHTraceEnd_Pair_004, TestSize.Level1)
{
    DHCompMgrTraceStart("net_pair4", "dhId_pair4", COMPONENT_RELEASE_START);
    EXPECT_NO_FATAL_FAILURE(DHTraceEnd());
}

/* ==================== HiStreamerQueryTool ==================== */

HWTEST_F(DhUtilsCoverageTest, HiStreamerQueryTool_Init_001, TestSize.Level1)
{
    auto &tool = HiStreamerQueryTool::GetInstance();
    EXPECT_NO_FATAL_FAILURE(tool.Init());
}

HWTEST_F(DhUtilsCoverageTest, HiStreamerQueryTool_Query_001, TestSize.Level1)
{
    auto &tool = HiStreamerQueryTool::GetInstance();
    std::string result = tool.QueryHiStreamerPluginInfo(HISTREAM_PLUGIN_TYPE::AUDIO_ENCODER);
    EXPECT_NO_FATAL_FAILURE(result.c_str());
}

HWTEST_F(DhUtilsCoverageTest, HiStreamerQueryTool_Query_002, TestSize.Level1)
{
    auto &tool = HiStreamerQueryTool::GetInstance();
    std::string result = tool.QueryHiStreamerPluginInfo(HISTREAM_PLUGIN_TYPE::AUDIO_DECODER);
    EXPECT_NO_FATAL_FAILURE(result.c_str());
}

HWTEST_F(DhUtilsCoverageTest, HiStreamerQueryTool_Query_003, TestSize.Level1)
{
    auto &tool = HiStreamerQueryTool::GetInstance();
    std::string result = tool.QueryHiStreamerPluginInfo(HISTREAM_PLUGIN_TYPE::VIDEO_ENCODER);
    EXPECT_NO_FATAL_FAILURE(result.c_str());
}

HWTEST_F(DhUtilsCoverageTest, HiStreamerQueryTool_Query_004, TestSize.Level1)
{
    auto &tool = HiStreamerQueryTool::GetInstance();
    std::string result = tool.QueryHiStreamerPluginInfo(HISTREAM_PLUGIN_TYPE::VIDEO_DECODER);
    EXPECT_NO_FATAL_FAILURE(result.c_str());
}

/* ==================== IsMessageLengthValid ==================== */

HWTEST_F(DhUtilsCoverageTest, IsMessageLengthValid_001, TestSize.Level1)
{
    EXPECT_FALSE(IsMessageLengthValid(""));
}

HWTEST_F(DhUtilsCoverageTest, IsMessageLengthValid_002, TestSize.Level1)
{
    EXPECT_TRUE(IsMessageLengthValid("valid_message"));
}

HWTEST_F(DhUtilsCoverageTest, IsMessageLengthValid_003, TestSize.Level1)
{
    std::string hugeStr(41 * 1024 * 1024, 'x');
    EXPECT_FALSE(IsMessageLengthValid(hugeStr));
}

HWTEST_F(DhUtilsCoverageTest, IsMessageLengthValid_004, TestSize.Level1)
{
    EXPECT_TRUE(IsMessageLengthValid("a"));
}

/* ==================== IsJsonLengthValid ==================== */

HWTEST_F(DhUtilsCoverageTest, IsJsonLengthValid_001, TestSize.Level1)
{
    EXPECT_FALSE(IsJsonLengthValid(""));
}

HWTEST_F(DhUtilsCoverageTest, IsJsonLengthValid_002, TestSize.Level1)
{
    EXPECT_TRUE(IsJsonLengthValid("{\"key\":\"value\"}"));
}

HWTEST_F(DhUtilsCoverageTest, IsJsonLengthValid_003, TestSize.Level1)
{
    EXPECT_TRUE(IsJsonLengthValid("{}"));
}

HWTEST_F(DhUtilsCoverageTest, IsJsonLengthValid_004, TestSize.Level1)
{
    EXPECT_TRUE(IsJsonLengthValid("[1,2,3]"));
}

HWTEST_F(DhUtilsCoverageTest, IsJsonLengthValid_005, TestSize.Level1)
{
    std::string hugeJson(41 * 1024 * 1024, 'x');
    EXPECT_FALSE(IsJsonLengthValid(hugeJson));
}
