/******************************************************************************
 *  * Copyright (c) Open Connectivity Foundation (OCF) and AllJoyn Open
 *    Source Project (AJOSP) Contributors and others.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Copyright (c) Open Connectivity Foundation and Contributors to AllSeen
 *    Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for
 *    any purpose with or without fee is hereby granted, provided that the
 *    above copyright notice and this permission notice appear in all
 *    copies.
 *
 *     THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 *     WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 *     WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 *     AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 *     DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 *     PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 *     TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *     PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/
#include <qcc/platform.h>

#include <signal.h>
#include <stdio.h>
#include <vector>

#include <qcc/String.h>
#include <qcc/Util.h>

#include <alljoyn/BusAttachment.h>
#include <alljoyn/DBusStd.h>
#include <alljoyn/AllJoynStd.h>
#include <alljoyn/BusObject.h>
#include <alljoyn/MsgArg.h>
#include <alljoyn/version.h>

#include <alljoyn/Status.h>

/* Header files included for Google Test Framework */
#include <gtest/gtest.h>
#include "ajTestCommon.h"
//#include <qcc/time.h>

using namespace std;
using namespace qcc;
using namespace ajn;
class AlljoynObjTest : public testing::Test {
  public:
    BusAttachment gbus;

    AlljoynObjTest() : gbus("testAlljoynObj", false) { };

    virtual void SetUp() {
        QStatus status = ER_OK;
        status = gbus.Start();
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
        status = gbus.Connect(getConnectArg().c_str());
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
    }

    virtual void TearDown() {
        gbus.Stop();
        gbus.Join();
    }

};

TEST_F(AlljoynObjTest, ReloadConfig) {
    QStatus status = ER_OK;
    bool reloaded = false;

    const ProxyBusObject& alljoynObj = gbus.GetAllJoynProxyObj();

    Message reply(gbus);

    status = alljoynObj.MethodCall(org::alljoyn::Bus::InterfaceName,
                                   "ReloadConfig",
                                   NULL,
                                   0,
                                   reply);

    ASSERT_EQ(ER_OK, status) << "  AlljoynObj::ReloadConfig: " << QCC_StatusText(status);



    status = reply->GetArgs("b", &reloaded);

    ASSERT_EQ(ER_OK, status) << "  AlljoynObj::GetReturn: " << QCC_StatusText(status);

    ASSERT_EQ(true, reloaded) << "  Reload fail! ";

}

TEST_F(AlljoynObjTest, DenyOwnName) {
    QStatus status = ER_OK;
    /* Preload deny own gov.a rule  */

    status = gbus.RequestName("gov.a", DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE);
    cout << "RequestName gov.a should fail " << endl;
    ASSERT_NE(ER_OK, status) << " Unexpected ok to request gov.a as expected " << QCC_StatusText(status);

    status = gbus.RequestName("gov.b", DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE);
    cout << "RequestName gov.b should succeed " << endl;
    ASSERT_EQ(ER_OK, status) << " Unexpected fail to request gov.b " << QCC_StatusText(status);


}