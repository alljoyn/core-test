/******************************************************************************
 *    Copyright (c) Open Connectivity Foundation (OCF) and AllJoyn Open
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
#include <gtest/gtest.h>

extern "C" {
#include "aj_debug.h"
#include "alljoyn.h"
}
#define CONNECT_TIMEOUT    (1000ul * 200)
#define UNMARSHAL_TIMEOUT  (100)

static const char PWD[] = "ABCDEFGH";

static AJ_BusAttachment testBus;
static const char ServiceName[] = "object.security.test";


class ObjSecurityTest : public testing::Test {
  public:

    ObjSecurityTest() { authStatus = AJ_ERR_NULL; }

    static uint32_t PasswordCallback(uint8_t* buffer, uint32_t bufLen)
    {
        memcpy(buffer, PWD, sizeof(PWD));
        return sizeof(PWD) - 1;
    }

    static void AuthCallback(const void* context, AJ_Status status)
    {
        *((AJ_Status*)context) = status;
        ASSERT_EQ(AJ_OK, status) << "Auth callback returns fail" << AJ_StatusText(status);
    }

    virtual void SetUp() {
        AJ_Status status = AJ_OK;
        AJ_Initialize();
        status = AJ_Connect(&testBus, NULL, CONNECT_TIMEOUT);
        ASSERT_EQ(AJ_OK, status) << "Unable to connect to the daemon. " << "The status returned is " << AJ_StatusText(status);
        if (AJ_OK == status) {
            AJ_Printf("Connected to the bus. The unique name is %s\n", AJ_GetUniqueName(&testBus));
        }


        //enable security by defalut
        //AJ_Status authStatus = AJ_ERR_NULL;
        AJ_BusSetPasswordCallback(&testBus, PasswordCallback);
        status = AJ_BusAuthenticatePeer(&testBus, ServiceName, AuthCallback, &(this->authStatus));
        ASSERT_EQ(AJ_OK, status) << "AJ_BusAuthenticatePeer failed: " << AJ_StatusText(status);
        //ASSERT_EQ(AJ_OK, authStatus) << "auth Status is bad " << AJ_StatusText(authStatus);
    }
    virtual void TearDown() {
        AJ_Disconnect(&testBus);
    }

    AJ_Status authStatus;

};

void MakeMethodCall(int*count, uint32_t ID, bool*sec_enforced) {

    AJ_Message msg;
    AJ_Status status = AJ_OK;
    if (*count == 0) {
        *count = 1;
        status = AJ_MarshalMethodCall(&testBus, &msg, ID, ServiceName, 0, 0, 5000);
        ASSERT_EQ(AJ_OK, status) << "Cannot marshal method calls parameters" << AJ_StatusText(status);
        *sec_enforced = (msg.hdr->flags & AJ_FLAG_ENCRYPTED) ? true : false;
        status = AJ_MarshalArgs(&msg, "s", "Hello World");
        ASSERT_EQ(AJ_OK, status) << "Cannot marshal method calls arguments" << AJ_StatusText(status);
        status = AJ_DeliverMsg(&msg);
        ASSERT_EQ(AJ_OK, status) << "Cannot deliver msg" << AJ_StatusText(status);
    }

}

void SendSignal(int*count, uint32_t ID, bool*sec_enforced) {

    AJ_Message msg;
    AJ_Status status = AJ_OK;
    if (*count == 0) {
        *count = 1;
        status = AJ_MarshalSignal(&testBus, &msg, ID, ServiceName, 0, 0, 5000);
        ASSERT_EQ(AJ_OK, status) << "Cannot marshal signal parameters" << AJ_StatusText(status);
        *sec_enforced = (msg.hdr->flags & AJ_FLAG_ENCRYPTED) ? true : false;
        status = AJ_MarshalArgs(&msg, "s", "Hello World");
        ASSERT_EQ(AJ_OK, status) << "Cannot marshal signal arguments" << AJ_StatusText(status);
        status = AJ_DeliverMsg(&msg);
        ASSERT_EQ(AJ_OK, status) << "Cannot deliver msg" << AJ_StatusText(status);
    }
}

void SetProperty(uint32_t ID, uint32_t PROPID, bool*sec_enforced)
{
    AJ_Status status = AJ_OK;
    AJ_Message msg;
    int val = 520;

    status = AJ_MarshalMethodCall(&testBus, &msg, ID, ServiceName, 0, 0, 5000);
    ASSERT_EQ(AJ_OK, status) << "Cannot marshal method calls parameters" << AJ_StatusText(status);

    status = AJ_MarshalPropertyArgs(&msg, PROPID);
    ASSERT_EQ(AJ_OK, status) << "Cannot marshal property arguments" << AJ_StatusText(status);

    *sec_enforced = (msg.hdr->flags & AJ_FLAG_ENCRYPTED) ? true : false;
    status = AJ_MarshalArgs(&msg, "i", val);
    ASSERT_EQ(AJ_OK, status) << "Cannot marshal arguments" << AJ_StatusText(status);

    status = AJ_DeliverMsg(&msg);
    ASSERT_EQ(AJ_OK, status) << "Cannot deliver msg" << AJ_StatusText(status);
}

void GetProperty(uint32_t ID, uint32_t PROPID, bool*sec_enforced)
{
    AJ_Status status = AJ_OK;
    AJ_Message msg;
    status = AJ_MarshalMethodCall(&testBus, &msg, ID, ServiceName, 0, 0, 5000);

    ASSERT_EQ(AJ_OK, status) << "Cannot marshal method calls parameters" << AJ_StatusText(status);
    status = AJ_MarshalPropertyArgs(&msg, PROPID);

    ASSERT_EQ(AJ_OK, status) << "Cannot marshal property arguments" << AJ_StatusText(status);
    *sec_enforced = (msg.hdr->flags & AJ_FLAG_ENCRYPTED) ? true : false;
    status = AJ_DeliverMsg(&msg);
    ASSERT_EQ(AJ_OK, status) << "Cannot deliver msg" << AJ_StatusText(status);
}


TEST_F(ObjSecurityTest, Test1)
{
    /* Test1 - Interfaces. */
    static const char* const Test1_Interface1[] = { "org.alljoyn.test1", "?my_ping inStr<s outStr>s", NULL };
    static const char* const Test1_Interface2[] = { "org.alljoyn.test2", "@prop_int_val=i", NULL };

    static const AJ_InterfaceDescription Test1_Interfaces[] = { AJ_PropertiesIface, Test1_Interface1, Test1_Interface2, NULL };

    static const AJ_Object AppObjects[] = {
        { "/test1", Test1_Interfaces },
        { NULL }
    };

    uint32_t TEST1_APP_MY_PING    = AJ_PRX_MESSAGE_ID(0, 1, 0);
    uint32_t TEST1_APP_GET_PROP  = AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_GET);
    uint32_t TEST1_APP_SET_PROP  = AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_SET);
    uint32_t TEST1_PROP_INT      = AJ_PRX_PROPERTY_ID(0, 2, 0);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(NULL, AppObjects);

    //TODO remove this
    AJ_PrintXML(AppObjects);

    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;
    char*value;
    int get_prop = 0;
    bool sec_enforced = false;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                MakeMethodCall(&count, TEST1_APP_MY_PING, &sec_enforced);
            }
            if (count == 1) {
                EXPECT_FALSE(sec_enforced);
            }
        } else if (msg.msgId == AJ_REPLY_ID(TEST1_APP_MY_PING)) {
            EXPECT_EQ(0, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            AJ_UnmarshalArgs(&msg, "s", &value);
            ASSERT_STREQ("Hello World", value);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            SetProperty(TEST1_APP_SET_PROP, TEST1_PROP_INT, &sec_enforced);
            EXPECT_FALSE(sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST1_APP_SET_PROP)) {
            EXPECT_EQ(0, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            GetProperty(TEST1_APP_GET_PROP, TEST1_PROP_INT, &sec_enforced);
            EXPECT_FALSE(sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST1_APP_GET_PROP)) {
            const char* sig;
            EXPECT_EQ(0, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            status = AJ_UnmarshalVariant(&msg, &sig);
            ASSERT_EQ(AJ_OK, status) << "Cannot unmarshal variant" << AJ_StatusText(status);
            status = AJ_UnmarshalArgs(&msg, sig, &get_prop);
            ASSERT_EQ(AJ_OK, status) << "Cannot unmarshal args" << AJ_StatusText(status);
            ASSERT_EQ(get_prop, 520) << "Get property error." << AJ_StatusText(status);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}


TEST_F(ObjSecurityTest, Test2)
{
    /* Test2 - Interfaces. */
    static const char* const Test2_Interface1[] = { "#org.alljoyn.test1", "?my_ping inStr<s outStr>s", NULL };
    static const char* const Test2_Interface2[] = { "#org.alljoyn.test2", "@prop_int_val=i", NULL };

    static const AJ_InterfaceDescription Test2_Interfaces[] = { AJ_PropertiesIface, Test2_Interface1, Test2_Interface2, NULL };

    static const AJ_Object AppObjects[] = {
        { "/test2", Test2_Interfaces },
        { NULL }
    };

    uint32_t TEST2_APP_MY_PING    = AJ_PRX_MESSAGE_ID(0, 1, 0);
    uint32_t TEST2_APP_GET_PROP  = AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_GET);
    uint32_t TEST2_APP_SET_PROP  = AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_SET);
    uint32_t TEST2_PROP_INT      = AJ_PRX_PROPERTY_ID(0, 2, 0);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(NULL, AppObjects);

    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;
    int get_prop = 0;
    bool sec_enforced = false;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                MakeMethodCall(&count, TEST2_APP_MY_PING, &sec_enforced);
            }
            if (count == 1) {
                EXPECT_FALSE(sec_enforced);
            }
        }  else if (msg.msgId == AJ_REPLY_ID(TEST2_APP_MY_PING)) {
            EXPECT_EQ(0, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            char*value;
            AJ_UnmarshalArgs(&msg, "s", &value);
            ASSERT_STREQ("Hello World", value);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            SetProperty(TEST2_APP_SET_PROP, TEST2_PROP_INT, &sec_enforced);
            EXPECT_FALSE(sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST2_APP_SET_PROP)) {
            EXPECT_EQ(0, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            GetProperty(TEST2_APP_GET_PROP, TEST2_PROP_INT, &sec_enforced);
            EXPECT_FALSE(sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST2_APP_GET_PROP)) {
            const char* sig;
            EXPECT_EQ(0, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            status = AJ_UnmarshalVariant(&msg, &sig);
            ASSERT_EQ(AJ_OK, status) << "Cannot unmarshal variant" << AJ_StatusText(status);
            status = AJ_UnmarshalArgs(&msg, sig, &get_prop);
            ASSERT_EQ(get_prop, 520) << "Get property error." << AJ_StatusText(status);
            ASSERT_EQ(AJ_OK, status) << "Cannot unmarshal args" << AJ_StatusText(status);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}


TEST_F(ObjSecurityTest, Test3)
{
    /* Test3 - Interfaces. */
    static const char* const Test3_Interface1[] = { "$org.alljoyn.test1", "?my_ping inStr<s outStr>s", NULL };
    static const char* const Test3_Interface2[] = { "$org.alljoyn.test2", "@prop_int_val=i", NULL };

    static const AJ_InterfaceDescription Test3_Interfaces[] = { AJ_PropertiesIface, Test3_Interface1, Test3_Interface2, NULL };

    static const AJ_Object AppObjects[] = {
        { "/test3", Test3_Interfaces },
        { NULL }
    };

    uint32_t TEST3_APP_MY_PING   =  AJ_PRX_MESSAGE_ID(0, 1, 0);
    uint32_t TEST3_APP_GET_PROP  = AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_GET);
    uint32_t TEST3_APP_SET_PROP  = AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_SET);
    uint32_t TEST3_PROP_INT     = AJ_PRX_PROPERTY_ID(0, 2, 0);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(NULL, AppObjects);

    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;
    int get_prop = 0;
    bool sec_enforced = false;


    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                MakeMethodCall(&count, TEST3_APP_MY_PING, &sec_enforced);
            }
            if (count == 1) {
                EXPECT_TRUE(sec_enforced);
            }
        }  else if (msg.msgId == AJ_REPLY_ID(TEST3_APP_MY_PING)) {
            EXPECT_EQ(128, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            char*value;
            AJ_UnmarshalArgs(&msg, "s", &value);
            ASSERT_STREQ("Hello World", value);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            SetProperty(TEST3_APP_SET_PROP, TEST3_PROP_INT, &sec_enforced);
            EXPECT_TRUE(sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST3_APP_SET_PROP)) {
            EXPECT_EQ(128, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            GetProperty(TEST3_APP_GET_PROP, TEST3_PROP_INT, &sec_enforced);
            EXPECT_TRUE(sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST3_APP_GET_PROP)) {
            const char* sig;
            EXPECT_EQ(128, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            status = AJ_UnmarshalVariant(&msg, &sig);
            ASSERT_EQ(AJ_OK, status) << "Cannot unmarshal variant" << AJ_StatusText(status);
            status = AJ_UnmarshalArgs(&msg, sig, &get_prop);
            ASSERT_EQ(get_prop, 520) << "Get property error." << AJ_StatusText(status);
            ASSERT_EQ(AJ_OK, status) << "Cannot unmarshal args" << AJ_StatusText(status);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}


TEST_F(ObjSecurityTest, Test4)
{
    /* Test4 - Interfaces. */
    static const char* const Test4_Interface1[] = { "org.alljoyn.test1", "?my_ping inStr<s outStr>s", NULL };
    static const char* const Test4_Interface2[] = { "org.alljoyn.test2", "@prop_int_val=i", NULL };

    static const AJ_InterfaceDescription Test4_Interfaces[] = { AJ_PropertiesIface, Test4_Interface1, Test4_Interface2, NULL };

    static const AJ_Object AppObjects[] = {
        { "/test4", Test4_Interfaces, AJ_OBJ_FLAG_SECURE },
        { NULL }
    };

    uint32_t TEST4_APP_MY_PING   = AJ_PRX_MESSAGE_ID(0, 1, 0);
    uint32_t TEST4_APP_GET_PROP  = AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_GET);
    uint32_t TEST4_APP_SET_PROP  = AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_SET);
    uint32_t TEST4_PROP_INT      = AJ_PRX_PROPERTY_ID(0, 2, 0);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(NULL, AppObjects);

    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;
    int get_prop = 0;
    bool sec_enforced = false;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                MakeMethodCall(&count, TEST4_APP_MY_PING, &sec_enforced);
            }
            if (count == 1) {
                EXPECT_TRUE(sec_enforced);
            }
        }  else if (msg.msgId == AJ_REPLY_ID(TEST4_APP_MY_PING)) {
            EXPECT_EQ(128, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            char*value;
            AJ_UnmarshalArgs(&msg, "s", &value);
            ASSERT_STREQ("Hello World", value);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            SetProperty(TEST4_APP_SET_PROP, TEST4_PROP_INT, &sec_enforced);
            EXPECT_TRUE(sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST4_APP_SET_PROP)) {
            EXPECT_EQ(128, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            GetProperty(TEST4_APP_GET_PROP, TEST4_PROP_INT, &sec_enforced);
            EXPECT_TRUE(sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST4_APP_GET_PROP)) {
            const char* sig;
            EXPECT_EQ(128, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            status = AJ_UnmarshalVariant(&msg, &sig);
            ASSERT_EQ(AJ_OK, status) << "Cannot unmarshal variant" << AJ_StatusText(status);
            status = AJ_UnmarshalArgs(&msg, sig, &get_prop);
            ASSERT_EQ(get_prop, 520) << "Get property error." << AJ_StatusText(status);
            ASSERT_EQ(AJ_OK, status) << "Cannot unmarshal args" << AJ_StatusText(status);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}


TEST_F(ObjSecurityTest, Test5)
{
    /* Test5 - Interfaces. */
    static const char* const Test5_Interface1[] = { "#org.alljoyn.test1", "?my_ping inStr<s outStr>s", NULL };
    static const char* const Test5_Interface2[] = { "#org.alljoyn.test2", "@prop_int_val=i", NULL };

    static const AJ_InterfaceDescription Test5_Interfaces[] = { AJ_PropertiesIface, Test5_Interface1, Test5_Interface2, NULL };

    static const AJ_Object AppObjects[] = {
        { "/test5", Test5_Interfaces, AJ_OBJ_FLAG_SECURE },
        { NULL }
    };

    uint32_t TEST5_APP_MY_PING   = AJ_PRX_MESSAGE_ID(0, 1, 0);
    uint32_t TEST5_APP_GET_PROP  = AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_GET);
    uint32_t TEST5_APP_SET_PROP  = AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_SET);
    uint32_t TEST5_PROP_INT      = AJ_PRX_PROPERTY_ID(0, 2, 0);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(NULL, AppObjects);

    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;
    int get_prop = 0;
    bool sec_enforced = false;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                MakeMethodCall(&count, TEST5_APP_MY_PING, &sec_enforced);
            }
            if (count == 1) {
                EXPECT_FALSE(sec_enforced);
            }
        }  else if (msg.msgId == AJ_REPLY_ID(TEST5_APP_MY_PING)) {
            EXPECT_EQ(0, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            char*value;
            AJ_UnmarshalArgs(&msg, "s", &value);
            ASSERT_STREQ("Hello World", value);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            SetProperty(TEST5_APP_SET_PROP, TEST5_PROP_INT, &sec_enforced);
            EXPECT_FALSE(sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST5_APP_SET_PROP)) {
            EXPECT_EQ(0, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            GetProperty(TEST5_APP_GET_PROP, TEST5_PROP_INT, &sec_enforced);
            EXPECT_FALSE(sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST5_APP_GET_PROP)) {
            const char* sig;
            EXPECT_EQ(0, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            status = AJ_UnmarshalVariant(&msg, &sig);
            ASSERT_EQ(AJ_OK, status) << "Cannot unmarshal variant" << AJ_StatusText(status);
            status = AJ_UnmarshalArgs(&msg, sig, &get_prop);
            ASSERT_EQ(get_prop, 520) << "Get property error." << AJ_StatusText(status);
            ASSERT_EQ(AJ_OK, status) << "Cannot unmarshal args" << AJ_StatusText(status);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}


TEST_F(ObjSecurityTest, Test6)
{
    /* Test5 - Interfaces. */
    static const char* const Test6_Interface1[] = { "$org.alljoyn.test1", "?my_ping inStr<s outStr>s", NULL };
    static const char* const Test6_Interface2[] = { "$org.alljoyn.test2", "@prop_int_val=i", NULL };

    static const AJ_InterfaceDescription Test6_Interfaces[] = { AJ_PropertiesIface, Test6_Interface1, Test6_Interface2, NULL };

    static const AJ_Object AppObjects[] = {
        { "/test6", Test6_Interfaces, AJ_OBJ_FLAG_SECURE },
        { NULL }
    };

    uint32_t TEST6_APP_MY_PING   =  AJ_PRX_MESSAGE_ID(0, 1, 0);
    uint32_t TEST6_APP_GET_PROP  = AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_GET);
    uint32_t TEST6_APP_SET_PROP  = AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_SET);
    uint32_t TEST6_PROP_INT      = AJ_PRX_PROPERTY_ID(0, 2, 0);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(NULL, AppObjects);

    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;
    int get_prop = 0;
    bool sec_enforced = false;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                MakeMethodCall(&count, TEST6_APP_MY_PING, &sec_enforced);
            }
            if (count == 1) {
                EXPECT_TRUE(sec_enforced);
            }
        }  else if (msg.msgId == AJ_REPLY_ID(TEST6_APP_MY_PING)) {
            EXPECT_EQ(128, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            char*value;
            AJ_UnmarshalArgs(&msg, "s", &value);
            ASSERT_STREQ("Hello World", value);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            SetProperty(TEST6_APP_SET_PROP, TEST6_PROP_INT, &sec_enforced);
            EXPECT_TRUE(sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST6_APP_SET_PROP)) {
            EXPECT_EQ(128, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            GetProperty(TEST6_APP_GET_PROP, TEST6_PROP_INT, &sec_enforced);
            EXPECT_TRUE(sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST6_APP_GET_PROP)) {
            const char* sig;
            EXPECT_EQ(128, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            status = AJ_UnmarshalVariant(&msg, &sig);
            ASSERT_EQ(AJ_OK, status) << "Cannot unmarshal variant" << AJ_StatusText(status);
            status = AJ_UnmarshalArgs(&msg, sig, &get_prop);
            ASSERT_EQ(get_prop, 520) << "Get property error." << AJ_StatusText(status);
            ASSERT_EQ(AJ_OK, status) << "Cannot unmarshal args" << AJ_StatusText(status);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}



/* Object sec= false
 * Interface = inherit
 */

TEST_F(ObjSecurityTest, Test7)
{
    /* Test5 - Interfaces. */
    static const char* const Test7_Interface1[] = { "org.alljoyn.test1", "!my_signal >s", "!my_return_signal >u", NULL };

    static const AJ_InterfaceDescription Test7_Interfaces[] = { Test7_Interface1,  NULL };

    static const AJ_Object AppObjects[] = {
        { "/test7", Test7_Interfaces },
        { NULL }
    };

    uint32_t TEST7_APP_MY_SIGNAL    = AJ_APP_MESSAGE_ID(0, 0, 0);
    uint32_t TEST7_APP_RETURN_MY_SIGNAL  = AJ_APP_MESSAGE_ID(0, 0, 1);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(AppObjects, NULL);

    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;
    bool sec_enforced = false;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                SendSignal(&count, TEST7_APP_MY_SIGNAL, &sec_enforced);
            }
            if (count == 1) {
                EXPECT_FALSE(sec_enforced);
            }
        } else if (msg.msgId == TEST7_APP_RETURN_MY_SIGNAL) {
            int value = 9;
            AJ_UnmarshalArgs(&msg, "u", &value);
            ASSERT_EQ(0, value);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}

/* Object sec= false
 * Interface = required
 */

TEST_F(ObjSecurityTest, Test8)
{
    /* Test5 - Interfaces. */
    static const char* const Test8_Interface1[] = { "$org.alljoyn.test1", "!my_signal >s", "!my_return_signal >u", NULL };

    static const AJ_InterfaceDescription Test8_Interfaces[] = { Test8_Interface1,  NULL };

    static const AJ_Object AppObjects[] = {
        { "/test8", Test8_Interfaces },
        { NULL }
    };

    uint32_t TEST8_APP_MY_SIGNAL   =  AJ_APP_MESSAGE_ID(0, 0, 0);
    uint32_t TEST8_APP_RETURN_MY_SIGNAL  = AJ_APP_MESSAGE_ID(0, 0, 1);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(AppObjects, NULL);

    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;
    bool sec_enforced = false;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                SendSignal(&count, TEST8_APP_MY_SIGNAL, &sec_enforced);
            }
            if (count == 1) {
                EXPECT_TRUE(sec_enforced);
            }
        } else if (msg.msgId == TEST8_APP_RETURN_MY_SIGNAL) {
            uint32_t value = 9;
            AJ_UnmarshalArgs(&msg, "u", &value);
            ASSERT_EQ(1, value);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}


/* Object sec= false
 * Interface = off
 */

TEST_F(ObjSecurityTest, Test9)
{
    /* Test5 - Interfaces. */
    static const char* const Test9_Interface1[] = { "#org.alljoyn.test1", "!my_signal >s", "!my_return_signal >u", NULL };

    static const AJ_InterfaceDescription Test9_Interfaces[] = { Test9_Interface1,  NULL };

    static const AJ_Object AppObjects[] = {
        { "/test9", Test9_Interfaces },
        { NULL }
    };

    uint32_t TEST9_APP_MY_SIGNAL   = AJ_APP_MESSAGE_ID(0, 0, 0);
    uint32_t TEST9_APP_RETURN_MY_SIGNAL  = AJ_APP_MESSAGE_ID(0, 0, 1);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(AppObjects, NULL);

    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;
    bool sec_enforced = false;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                SendSignal(&count, TEST9_APP_MY_SIGNAL, &sec_enforced);
            }
            if (count == 1) {
                EXPECT_FALSE(sec_enforced);
            }
        } else if (msg.msgId == TEST9_APP_RETURN_MY_SIGNAL) {
            uint32_t value = 9;
            AJ_UnmarshalArgs(&msg, "u", &value);
            ASSERT_EQ(0, value);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}


/* Object sec= true
 * Interface = inherit
 */

TEST_F(ObjSecurityTest, Test10)
{
    /* Test10 - Interfaces. */
    static const char* const Test10_Interface1[] = { "org.alljoyn.test1", "!my_signal >s", "!my_return_signal >u", NULL };

    static const AJ_InterfaceDescription Test10_Interfaces[] = { Test10_Interface1,  NULL };

    static const AJ_Object AppObjects[] = {
        { "/test10", Test10_Interfaces, AJ_OBJ_FLAG_SECURE },
        { NULL }
    };

    uint32_t TEST10_APP_MY_SIGNAL  =  AJ_APP_MESSAGE_ID(0, 0, 0);
    uint32_t TEST10_APP_RETURN_MY_SIGNAL  = AJ_APP_MESSAGE_ID(0, 0, 1);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(AppObjects, NULL);

    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;
    bool sec_enforced = false;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                SendSignal(&count, TEST10_APP_MY_SIGNAL, &sec_enforced);
            }
            if (count == 1) {
                EXPECT_TRUE(sec_enforced);
            }
        } else if (msg.msgId == TEST10_APP_RETURN_MY_SIGNAL) {
            uint32_t value = 9;
            AJ_UnmarshalArgs(&msg, "u", &value);
            ASSERT_EQ(1, value);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}


/* Object sec= true
 * Interface = required
 */

TEST_F(ObjSecurityTest, Test11)
{
    /* Test11 - Interfaces. */
    static const char* const Test11_Interface1[] = { "$org.alljoyn.test1", "!my_signal >s", "!my_return_signal >u", NULL };

    static const AJ_InterfaceDescription Test11_Interfaces[] = { Test11_Interface1,  NULL };

    static const AJ_Object AppObjects[] = {
        { "/test11", Test11_Interfaces, AJ_OBJ_FLAG_SECURE },
        { NULL }
    };

    uint32_t TEST11_APP_MY_SIGNAL    = AJ_APP_MESSAGE_ID(0, 0, 0);
    uint32_t TEST11_APP_RETURN_MY_SIGNAL  = AJ_APP_MESSAGE_ID(0, 0, 1);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(AppObjects, NULL);

    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;
    int get_prop = 0;
    bool sec_enforced = false;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                SendSignal(&count, TEST11_APP_MY_SIGNAL, &sec_enforced);
            }
            if (count == 1) {
                EXPECT_TRUE(sec_enforced);
            }
        } else if (msg.msgId == TEST11_APP_RETURN_MY_SIGNAL) {
            uint32_t value = 9;
            AJ_UnmarshalArgs(&msg, "u", &value);
            ASSERT_EQ(1, value);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}

/* Object sec= true
 * Interface = off
 */

TEST_F(ObjSecurityTest, Test12)
{
    /* Test12 - Interfaces. */
    static const char* const Test12_Interface1[] = { "#org.alljoyn.test1", "!my_signal >s", "!my_return_signal >u", NULL };

    static const AJ_InterfaceDescription Test12_Interfaces[] = { Test12_Interface1,  NULL };

    static const AJ_Object AppObjects[] = {
        { "/test12", Test12_Interfaces, AJ_OBJ_FLAG_SECURE },
        { NULL }
    };

    uint32_t TEST12_APP_MY_SIGNAL   =  AJ_APP_MESSAGE_ID(0, 0, 0);
    uint32_t TEST12_APP_RETURN_MY_SIGNAL  =  AJ_APP_MESSAGE_ID(0, 0, 1);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(AppObjects, NULL);

    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;
    int get_prop = 0;
    bool sec_enforced = false;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                SendSignal(&count, TEST12_APP_MY_SIGNAL, &sec_enforced);
            }
            if (count == 1) {
                EXPECT_FALSE(sec_enforced);
            }
        } else if (msg.msgId == TEST12_APP_RETURN_MY_SIGNAL) {
            uint32_t value = 9;
            AJ_UnmarshalArgs(&msg, "u", &value);
            ASSERT_EQ(0, value);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}


//Add one for object hierarchy

TEST_F(ObjSecurityTest, Test13)
{
    //Test13 - Interfaces.
    static const char* const Test13_grand_parent_Interface1[] = { "org.alljoyn.alljoyn_test.grand_parent.interface1", "?my_grand_parent_ping inStr<s outStr>s", NULL };
    static const char* const Test13_parent_Interface1[] = { "#org.alljoyn.alljoyn_test.parent.interface1", "?my_parent_ping inStr<s outStr>s", NULL };
    static const char* const Test13_child_Interface1[] = { "org.alljoyn.alljoyn_test.child.interface1", "?my_child_ping inStr<s outStr>s", NULL };

    static const AJ_InterfaceDescription Test13_Interfaces_GrandParent[] = { Test13_grand_parent_Interface1, NULL };
    static const AJ_InterfaceDescription Test13_Interfaces_Parent[] = { Test13_parent_Interface1, NULL };
    static const AJ_InterfaceDescription Test13_Interfaces_Child[] = { Test13_child_Interface1, NULL };


    static const AJ_Object AppObjects[] = {
        { "/test13/grandparent", Test13_Interfaces_GrandParent, AJ_OBJ_FLAG_SECURE },
        { "/test13/grandparent/parent", Test13_Interfaces_Parent },
        { "/test13/grandparent/parent/child", Test13_Interfaces_Child },
        { NULL }
    };

    uint32_t TEST13_APP_MY_GRAND_PARENT_PING = AJ_PRX_MESSAGE_ID(0, 0, 0);
    uint32_t TEST13_APP_MY_PARENT_PING  = AJ_PRX_MESSAGE_ID(1, 0, 0);
    uint32_t TEST13_APP_MY_CHILD_PING = AJ_PRX_MESSAGE_ID(2, 0, 0);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(NULL, AppObjects);

    //TODO - Remove this
    AJ_PrintXML(AppObjects);

    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;
    bool sec_enforced = false;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                MakeMethodCall(&count, TEST13_APP_MY_GRAND_PARENT_PING, &sec_enforced);
            }
            if (count == 1) {
                EXPECT_TRUE(sec_enforced);
            }
        }  else if (msg.msgId == AJ_REPLY_ID(TEST13_APP_MY_GRAND_PARENT_PING)) {
            EXPECT_EQ(128, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            char*value;
            AJ_UnmarshalArgs(&msg, "s", &value);
            ASSERT_STREQ("Hello World", value);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            count = 0;
            MakeMethodCall(&count, TEST13_APP_MY_PARENT_PING, &sec_enforced);
            //No security expected as parent object  has OFF interface
            EXPECT_FALSE(sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST13_APP_MY_PARENT_PING)) {
            EXPECT_EQ(0, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            char*value;
            AJ_UnmarshalArgs(&msg, "s", &value);
            ASSERT_STREQ("Hello World", value);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            count = 0;
            MakeMethodCall(&count, TEST13_APP_MY_CHILD_PING, &sec_enforced);
            //security is expected as child object inherits security from grandparent object and interface inherits from object
            EXPECT_TRUE(sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST13_APP_MY_CHILD_PING)) {
            EXPECT_EQ(128, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            char*value;
            AJ_UnmarshalArgs(&msg, "s", &value);
            ASSERT_STREQ("Hello World", value);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}


void MakeIntrospect(int*count, uint32_t ID) {

    AJ_Message msg;
    AJ_Status status = AJ_OK;
    if (*count == 0) {
        *count = 1;
        status = AJ_MarshalMethodCall(&testBus, &msg, ID, ServiceName, 0, 0, 5000);
        ASSERT_EQ(AJ_OK, status) << "Cannot marshal method calls parameters" << AJ_StatusText(status);
        //status = AJ_MarshalArgs(&msg, "s", "Hello World");
        //ASSERT_EQ(AJ_OK, status) << "Cannot marshal method calls arguments" << AJ_StatusText(status);
        status = AJ_DeliverMsg(&msg);
        ASSERT_EQ(AJ_OK, status) << "Cannot deliver msg" << AJ_StatusText(status);
    }
}

//Do D-Bus introspection on an object which is disabled
TEST_F(ObjSecurityTest, Test14)
{
    //Test14 - Interfaces.
    static const AJ_InterfaceDescription Test14_Interfaces[] = { AJ_IntrospectionIface, NULL };

    static const AJ_Object AppObjects[] = {
        { "/test14", Test14_Interfaces },
        { NULL }
    };

    uint32_t TEST14_INTROSPECT_ID = AJ_PRX_MESSAGE_ID(0, 0, 0);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(NULL, AppObjects);


    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                MakeIntrospect(&count, TEST14_INTROSPECT_ID);
            }
        }  else if (msg.msgId == AJ_REPLY_ID(TEST14_INTROSPECT_ID)) {
            char*value;
            EXPECT_EQ(AJ_MSG_ERROR, msg.hdr->msgType);
            EXPECT_STREQ("org.freedesktop.DBus.Error.ServiceUnknown", msg.error);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }


}

/* Make method calls and properties on Object which is disabled. They should fail. */
TEST_F(ObjSecurityTest, Test15)
{
    /* Test15 - Interfaces. */
    static const char* const Test15_Interface1[] = { "org.alljoyn.test1", "?my_ping inStr<s outStr>s", NULL };
    static const char* const Test15_Interface2[] = { "org.alljoyn.test2", "@prop_int_val=i", NULL };

    static const AJ_InterfaceDescription Test15_Interfaces[] = { AJ_PropertiesIface, Test15_Interface1, Test15_Interface2, NULL };

    static const AJ_Object AppObjects[] = {
        { "/test15", Test15_Interfaces },
        { NULL }
    };

    uint32_t TEST15_APP_MY_PING   = AJ_PRX_MESSAGE_ID(0, 1, 0);
    uint32_t TEST15_APP_GET_PROP  = AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_GET);
    uint32_t TEST15_APP_SET_PROP  = AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_SET);
    uint32_t TEST15_PROP_INT      = AJ_PRX_PROPERTY_ID(0, 2, 0);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(NULL, AppObjects);

    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;
    int get_prop = 0;
    bool sec_enforced = false;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                MakeMethodCall(&count, TEST15_APP_MY_PING, &sec_enforced);
            }
        }  else if (msg.msgId == AJ_REPLY_ID(TEST15_APP_MY_PING)) {
            EXPECT_EQ(AJ_MSG_ERROR, msg.hdr->msgType);
            EXPECT_STREQ("org.freedesktop.DBus.Error.ServiceUnknown", msg.error);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            SetProperty(TEST15_APP_SET_PROP, TEST15_PROP_INT, &sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST15_APP_SET_PROP)) {
            EXPECT_EQ(AJ_MSG_ERROR, msg.hdr->msgType);
            EXPECT_STREQ("org.freedesktop.DBus.Error.ServiceUnknown", msg.error);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            GetProperty(TEST15_APP_GET_PROP, TEST15_PROP_INT, &sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST15_APP_GET_PROP)) {
            EXPECT_EQ(AJ_MSG_ERROR, msg.hdr->msgType);
            EXPECT_STREQ("org.freedesktop.DBus.Error.ServiceUnknown", msg.error);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}


/* Object sec= DISABLED
 * Sending a signal will fail
 */

TEST_F(ObjSecurityTest, Test16a)
{
    /* Test16a - Interfaces. */
    static const char* const Test16a_Interface1[] = { "$org.alljoyn.test1", "!my_signal >s", "!my_return_signal >u", NULL };

    static const AJ_InterfaceDescription Test16a_Interfaces[] = { Test16a_Interface1,  NULL };

    static const AJ_Object AppObjects[] = {
        { "/test16a", Test16a_Interfaces, AJ_OBJ_FLAG_DISABLED },
        { NULL }
    };

    uint32_t TEST16a_APP_MY_SIGNAL   =  AJ_APP_MESSAGE_ID(0, 0, 0);
    uint32_t TEST16a_APP_RETURN_MY_SIGNAL  =  AJ_APP_MESSAGE_ID(0, 0, 1);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(AppObjects, NULL);

    AJ_Status status = AJ_OK;
    AJ_Message msg;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                status = AJ_MarshalSignal(&testBus, &msg, TEST16a_APP_MY_SIGNAL, ServiceName, 0, 0, 5000);
                EXPECT_EQ(AJ_ERR_INVALID, status);
                break;
            }
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}


//Object hierarchy, parent object is disabled.

TEST_F(ObjSecurityTest, Test17)
{
    //Test17 - Interfaces.
    static const char* const Test17_grand_parent_Interface1[] = { "org.alljoyn.alljoyn_test.grand_parent.interface1", "?my_grand_parent_ping inStr<s outStr>s", NULL };
    static const char* const Test17_parent_Interface1[] = { "#org.alljoyn.alljoyn_test.parent.interface1", "?my_parent_ping inStr<s outStr>s", NULL };

    static const AJ_InterfaceDescription Test17_Interfaces_GrandParent[] = { Test17_grand_parent_Interface1, NULL };
    static const AJ_InterfaceDescription Test17_Interfaces_Parent[] = { Test17_parent_Interface1, NULL };

    static const AJ_Object AppObjects[] = {
        { "/test17/grandparent", Test17_Interfaces_GrandParent },
        { "/test17/grandparent/parent", Test17_Interfaces_Parent },
        { NULL }
    };

    uint32_t TEST17_APP_MY_GRAND_PARENT_PING = AJ_PRX_MESSAGE_ID(0, 0, 0);
    uint32_t TEST17_APP_MY_PARENT_PING  = AJ_PRX_MESSAGE_ID(1, 0, 0);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(NULL, AppObjects);


    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;
    bool sec_enforced = false;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                MakeMethodCall(&count, TEST17_APP_MY_GRAND_PARENT_PING, &sec_enforced);
            }
        }  else if (msg.msgId == AJ_REPLY_ID(TEST17_APP_MY_GRAND_PARENT_PING)) {
            EXPECT_EQ(AJ_MSG_ERROR, msg.hdr->msgType);
            EXPECT_STREQ("org.freedesktop.DBus.Error.ServiceUnknown", msg.error);
            AJ_CloseMsg(&msg);
            count = 0;
            MakeMethodCall(&count, TEST17_APP_MY_PARENT_PING, &sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST17_APP_MY_PARENT_PING)) {
            EXPECT_EQ(AJ_MSG_ERROR, msg.hdr->msgType);
            EXPECT_STREQ("org.freedesktop.DBus.Error.ServiceUnknown", msg.error);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}

//Do D-Bus introspection on an object which is hidden
TEST_F(ObjSecurityTest, Test18)
{
    //Test18 - Interfaces.
    static const AJ_InterfaceDescription Test18_Interfaces[] = { AJ_IntrospectionIface, NULL };

    static const AJ_Object AppObjects[] = {
        { "/test18", Test18_Interfaces },
        { NULL }
    };

    uint32_t TEST18_INTROSPECT_ID = AJ_PRX_MESSAGE_ID(0, 0, 0);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(NULL, AppObjects);


    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                MakeIntrospect(&count, TEST18_INTROSPECT_ID);
            }
        }  else if (msg.msgId == AJ_REPLY_ID(TEST18_INTROSPECT_ID)) {
            char*value;
            EXPECT_EQ(AJ_MSG_ERROR, msg.hdr->msgType);
            EXPECT_STREQ("org.freedesktop.DBus.Error.ServiceUnknown", msg.error);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}

//Consume hidden objects on service side.
TEST_F(ObjSecurityTest, Test19)
{
    /* Test1 - Interfaces. */
    static const char* const Test19_Interface1[] = { "org.alljoyn.test1", "?my_ping inStr<s outStr>s", NULL };
    static const char* const Test19_Interface2[] = { "org.alljoyn.test2", "@prop_int_val=i", NULL };

    static const AJ_InterfaceDescription Test19_Interfaces[] = { AJ_PropertiesIface, Test19_Interface1, Test19_Interface2, NULL };

    static const AJ_Object AppObjects[] = {
        { "/test19", Test19_Interfaces },
        { NULL }
    };

    uint32_t TEST19_APP_MY_PING    = AJ_PRX_MESSAGE_ID(0, 1, 0);
    uint32_t TEST19_APP_GET_PROP  = AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_GET);
    uint32_t TEST19_APP_SET_PROP  = AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_SET);
    uint32_t TEST19_PROP_INT      = AJ_PRX_PROPERTY_ID(0, 2, 0);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(NULL, AppObjects);


    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;
    char*value;
    int get_prop = 0;
    bool sec_enforced = false;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                MakeMethodCall(&count, TEST19_APP_MY_PING, &sec_enforced);
            }
            if (count == 1) {
                EXPECT_FALSE(sec_enforced);
            }
        } else if (msg.msgId == AJ_REPLY_ID(TEST19_APP_MY_PING)) {
            EXPECT_EQ(0, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            AJ_UnmarshalArgs(&msg, "s", &value);
            ASSERT_STREQ("Hello World", value);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            SetProperty(TEST19_APP_SET_PROP, TEST19_PROP_INT, &sec_enforced);
            EXPECT_FALSE(sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST19_APP_SET_PROP)) {
            EXPECT_EQ(0, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            GetProperty(TEST19_APP_GET_PROP, TEST19_PROP_INT, &sec_enforced);
            EXPECT_FALSE(sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST19_APP_GET_PROP)) {
            const char* sig;
            EXPECT_EQ(0, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            status = AJ_UnmarshalVariant(&msg, &sig);
            ASSERT_EQ(AJ_OK, status) << "Cannot unmarshal variant" << AJ_StatusText(status);
            status = AJ_UnmarshalArgs(&msg, sig, &get_prop);
            ASSERT_EQ(AJ_OK, status) << "Cannot unmarshal args" << AJ_StatusText(status);
            ASSERT_EQ(get_prop, 520) << "Get property error." << AJ_StatusText(status);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}


/* Send signal to hidden object and receive signals from hidden object.*/

TEST_F(ObjSecurityTest, Test20)
{
    /* Test20 - Interfaces. */
    static const char* const Test20_Interface1[] = { "org.alljoyn.test1", "!my_signal >s", "!my_return_signal >u", NULL };

    static const AJ_InterfaceDescription Test20_Interfaces[] = { Test20_Interface1,  NULL };

    static const AJ_Object AppObjects[] = {
        { "/test20", Test20_Interfaces },
        { NULL }
    };

    uint32_t TEST20_APP_MY_SIGNAL   =  AJ_APP_MESSAGE_ID(0, 0, 0);
    uint32_t TEST20_APP_RETURN_MY_SIGNAL  =  AJ_APP_MESSAGE_ID(0, 0, 1);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(AppObjects, NULL);

    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;
    int get_prop = 0;
    bool sec_enforced = false;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                SendSignal(&count, TEST20_APP_MY_SIGNAL, &sec_enforced);
            }
            if (count == 1) {
                EXPECT_FALSE(sec_enforced);
            }
        } else if (msg.msgId == TEST20_APP_RETURN_MY_SIGNAL) {
            uint32_t value = 9;
            AJ_UnmarshalArgs(&msg, "u", &value);
            ASSERT_EQ(0, value);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}


//Object hierarchy, parent object is hidden.
TEST_F(ObjSecurityTest, Test21)
{
    //Test21- Interfaces.
    static const char* const Test21_grand_parent_Interface1[] = { "org.alljoyn.alljoyn_test.grand_parent.interface1", "?my_grand_parent_ping inStr<s outStr>s", NULL };
    static const char* const Test21_parent_Interface1[] = { "#org.alljoyn.alljoyn_test.parent.interface1", "?my_parent_ping inStr<s outStr>s", NULL };

    static const AJ_InterfaceDescription Test21_Interfaces_GrandParent[] = { Test21_grand_parent_Interface1, NULL };
    static const AJ_InterfaceDescription Test21_Interfaces_Parent[] = { Test21_parent_Interface1, NULL };

    static const AJ_Object AppObjects[] = {
        { "/test21/grandparent", Test21_Interfaces_GrandParent },
        { "/test21/grandparent/parent", Test21_Interfaces_Parent },
        { NULL }
    };

    uint32_t TEST21_APP_MY_GRAND_PARENT_PING = AJ_PRX_MESSAGE_ID(0, 0, 0);
    uint32_t TEST21_APP_MY_PARENT_PING  = AJ_PRX_MESSAGE_ID(1, 0, 0);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(NULL, AppObjects);


    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;
    bool sec_enforced = false;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                MakeMethodCall(&count, TEST21_APP_MY_GRAND_PARENT_PING, &sec_enforced);
            }
            if (count == 1) {
                EXPECT_FALSE(sec_enforced);
            }
        }  else if (msg.msgId == AJ_REPLY_ID(TEST21_APP_MY_GRAND_PARENT_PING)) {
            EXPECT_EQ(0, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            char*value;
            AJ_UnmarshalArgs(&msg, "s", &value);
            ASSERT_STREQ("Hello World", value);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            count = 0;
            MakeMethodCall(&count, TEST21_APP_MY_PARENT_PING, &sec_enforced);
            //No security expected as parent object  has OFF interface
            EXPECT_FALSE(sec_enforced);
        }  else if (msg.msgId == AJ_REPLY_ID(TEST21_APP_MY_GRAND_PARENT_PING)) {
            EXPECT_EQ(0, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            char*value;
            AJ_UnmarshalArgs(&msg, "s", &value);
            ASSERT_STREQ("Hello World", value);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            count = 0;
            MakeMethodCall(&count, TEST21_APP_MY_PARENT_PING, &sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST21_APP_MY_PARENT_PING)) {
            EXPECT_EQ(0, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            char*value;
            AJ_UnmarshalArgs(&msg, "s", &value);
            ASSERT_STREQ("Hello World", value);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}



//Do D-Bus introspection on an object which is hidden | secure. Introspect should fail
TEST_F(ObjSecurityTest, Test22)
{
    //Test22- Interfaces.
    static const AJ_InterfaceDescription Test22_Interfaces[] = { AJ_IntrospectionIface, NULL };

    static const AJ_Object AppObjects[] = {
        { "/test22", Test22_Interfaces },
        { NULL }
    };

    uint32_t TEST22_INTROSPECT_ID = AJ_PRX_MESSAGE_ID(0, 0, 0);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(NULL, AppObjects);


    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                MakeIntrospect(&count, TEST22_INTROSPECT_ID);
            }
        }  else if (msg.msgId == AJ_REPLY_ID(TEST22_INTROSPECT_ID)) {
            char*value;
            EXPECT_EQ(AJ_MSG_ERROR, msg.hdr->msgType);
            EXPECT_STREQ("org.freedesktop.DBus.Error.ServiceUnknown", msg.error);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}


//Object security is HIDDEN | SECURE. Clients should be able make method calls securely.
TEST_F(ObjSecurityTest, Test23)
{
    /* Test1 - Interfaces. */
    static const char* const Test23_Interface1[] = { "org.alljoyn.test1", "?my_ping inStr<s outStr>s", NULL };
    static const char* const Test23_Interface2[] = { "org.alljoyn.test2", "@prop_int_val=i", NULL };

    static const AJ_InterfaceDescription Test23_Interfaces[] = { AJ_PropertiesIface, Test23_Interface1, Test23_Interface2, NULL };

    static const AJ_Object AppObjects[] = {
        { "/test23", Test23_Interfaces, AJ_OBJ_FLAG_SECURE },
        { NULL }
    };

    uint32_t TEST23_APP_MY_PING    = AJ_PRX_MESSAGE_ID(0, 1, 0);
    uint32_t TEST23_APP_GET_PROP  = AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_GET);
    uint32_t TEST23_APP_SET_PROP  = AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_SET);
    uint32_t TEST23_PROP_INT      = AJ_PRX_PROPERTY_ID(0, 2, 0);

    // Register bus objects and proxy bus objects
    AJ_RegisterObjects(NULL, AppObjects);


    AJ_Status status = AJ_OK;
    int count = 0;
    AJ_Message msg;
    char*value;
    int get_prop = 0;
    bool sec_enforced = false;

    while (TRUE) {

        status = AJ_UnmarshalMsg(&testBus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            if (this->authStatus == AJ_OK) {
                MakeMethodCall(&count, TEST23_APP_MY_PING, &sec_enforced);
            }
            if (count == 1) {
                EXPECT_TRUE(sec_enforced);
            }
        } else if (msg.msgId == AJ_REPLY_ID(TEST23_APP_MY_PING)) {
            EXPECT_EQ(128, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            AJ_UnmarshalArgs(&msg, "s", &value);
            ASSERT_STREQ("Hello World", value);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            SetProperty(TEST23_APP_SET_PROP, TEST23_PROP_INT, &sec_enforced);
            EXPECT_TRUE(sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST23_APP_SET_PROP)) {
            EXPECT_EQ(128, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            AJ_CloseMsg(&msg);
            sec_enforced = false;
            GetProperty(TEST23_APP_GET_PROP, TEST23_PROP_INT, &sec_enforced);
            EXPECT_TRUE(sec_enforced);
        } else if (msg.msgId == AJ_REPLY_ID(TEST23_APP_GET_PROP)) {
            const char* sig;
            EXPECT_EQ(128, msg.hdr->flags & AJ_FLAG_ENCRYPTED);
            status = AJ_UnmarshalVariant(&msg, &sig);
            ASSERT_EQ(AJ_OK, status) << "Cannot unmarshal variant" << AJ_StatusText(status);
            status = AJ_UnmarshalArgs(&msg, sig, &get_prop);
            ASSERT_EQ(AJ_OK, status) << "Cannot unmarshal args" << AJ_StatusText(status);
            ASSERT_EQ(get_prop, 520) << "Get property error." << AJ_StatusText(status);
            AJ_CloseMsg(&msg);
            break;
        } else {
            status = AJ_BusHandleBusMessage(&msg);
        }


        AJ_CloseMsg(&msg);
    }

}



