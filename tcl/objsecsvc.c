/**
 * @file
 */
/******************************************************************************
 * Copyright (c) 2016 Open Connectivity Foundation (OCF) and AllJoyn Open
 *    Source Project (AJOSP) Contributors and others.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Copyright 2016 Open Connectivity Foundation and Contributors to
 *    AllSeen Alliance. All rights reserved.
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

#include <alljoyn.h>

#define CONNECT_TIMEOUT    (1000 * 200)
#define UNMARSHAL_TIMEOUT  (1000 * 1)

AJ_BusAttachment bus;
static const char ServiceName[] = "object.security.test";

/* Test1-  Interface defined with NONE security. */
static const char* const Test1_Interface1[] = { "org.alljoyn.test1", "?my_ping inStr<s outStr>s", NULL };
static const char* const Test1_Interface2[] = { "org.alljoyn.test2", "@prop_int_val=i", NULL };

/* Test2- Interface defined with OFF security. */
static const char* const Test2_Interface1[] = { "#org.alljoyn.test1", "?my_ping inStr<s outStr>s", NULL };
static const char* const Test2_Interface2[] = { "#org.alljoyn.test2", "@prop_int_val=i", NULL };

/* Test3- Interface defined with REQUIRED security. */
static const char* const Test3_Interface1[] = { "$org.alljoyn.test1", "?my_ping inStr<s outStr>s", NULL };
static const char* const Test3_Interface2[] = { "$org.alljoyn.test2", "@prop_int_val=i", NULL };

/* Test4- Interface defined with REQUIRED security. */
static const char* const Test4_Interface1[] = { "org.alljoyn.test1", "?my_ping inStr<s outStr>s", NULL };
static const char* const Test4_Interface2[] = { "org.alljoyn.test2", "@prop_int_val=i", NULL };

/* Test5- Interface defined with REQUIRED security. */
static const char* const Test5_Interface1[] = { "#org.alljoyn.test1", "?my_ping inStr<s outStr>s", NULL };
static const char* const Test5_Interface2[] = { "#org.alljoyn.test2", "@prop_int_val=i", NULL };

/* Test6- Interface defined with REQUIRED security. */
static const char* const Test6_Interface1[] = { "$org.alljoyn.test1", "?my_ping inStr<s outStr>s", NULL };
static const char* const Test6_Interface2[] = { "$org.alljoyn.test2", "@prop_int_val=i", NULL };

/* Test7- Interface defined with INHERIT (default) security. */
static const char* const Test7_Interface1[] = { "org.alljoyn.test1", "!my_signal >s", "!my_return_signal >u", NULL };

/* Test8- Interface defined with REQUIRED security. */
static const char* const Test8_Interface1[] = { "$org.alljoyn.test1", "!my_signal >s", "!my_return_signal >u", NULL };

/* Test9- Interface defined with OFF security. */
static const char* const Test9_Interface1[] = { "#org.alljoyn.test1", "!my_signal >s", "!my_return_signal >u", NULL };

/* Test10- Interface defined with INHERIT (default) security. */
static const char* const Test10_Interface1[] = { "org.alljoyn.test1", "!my_signal >s", "!my_return_signal >u", NULL };

/* Test11- Interface defined with REQUIRED security. */
static const char* const Test11_Interface1[] = { "$org.alljoyn.test1", "!my_signal >s", "!my_return_signal >u", NULL };

/* Test12- Interface defined with OFF security. */
static const char* const Test12_Interface1[] = { "#org.alljoyn.test1", "!my_signal >s", "!my_return_signal >u", NULL };

/* Test13- Object hierarchy. */
static const char* const Test13_grand_parent_Interface1[] = { "org.alljoyn.alljoyn_test.grand_parent.interface1", "?my_grand_parent_ping inStr<s outStr>s", NULL };
static const char* const Test13_parent_Interface1[] = { "#org.alljoyn.alljoyn_test.parent.interface1", "?my_parent_ping inStr<s outStr>s", NULL };
static const char* const Test13_child_Interface1[] = { "org.alljoyn.alljoyn_test.child.interface1", "?my_child_ping inStr<s outStr>s", NULL };

/* Test14-  Interface defined with NONE security. */
static const char* const Test14_Interface1[] = { "org.alljoyn.test1", "?my_ping inStr<s outStr>s", NULL };

/* Test15-  Interface defined with NONE security. */
static const char* const Test15_Interface1[] = { "org.alljoyn.test1", "?my_ping inStr<s outStr>s", NULL };
static const char* const Test15_Interface2[] = { "org.alljoyn.test2", "@prop_int_val=i", NULL };

/* Test16a- Emitting signal from a disabled object */
static const char* const Test16a_Interface1[] = { "$org.alljoyn.test1", "!my_signal >s", "!my_return_signal >u", NULL };

/* Test17- Object hierarchy for DISABLED object. */
static const char* const Test17_grand_parent_Interface1[] = { "org.alljoyn.alljoyn_test.grand_parent.interface1", "?my_grand_parent_ping inStr<s outStr>s", NULL };
static const char* const Test17_parent_Interface1[] = { "#org.alljoyn.alljoyn_test.parent.interface1", "?my_parent_ping inStr<s outStr>s", NULL };

/* Test18-  HIDDEN OBJECT INTROSPECT */
static const char* const Test18_Interface1[] = { "org.alljoyn.test1", "?my_ping inStr<s outStr>s", NULL };

/* Test19- HIDDEN OBJECT CONSUMPTION. */
static const char* const Test19_Interface1[] = { "org.alljoyn.test1", "?my_ping inStr<s outStr>s", NULL };
static const char* const Test19_Interface2[] = { "org.alljoyn.test2", "@prop_int_val=i", NULL };

/* Test20- HIDDEN OBJECT CONSUMPTION - Signals */
static const char* const Test20_Interface1[] = { "org.alljoyn.test1", "!my_signal >s", "!my_return_signal >u", NULL };

/* Test21- Object hierarchy for HIDDEN object. */
static const char* const Test21_grand_parent_Interface1[] = { "org.alljoyn.alljoyn_test.grand_parent.interface1", "?my_grand_parent_ping inStr<s outStr>s", NULL };
static const char* const Test21_parent_Interface1[] = { "#org.alljoyn.alljoyn_test.parent.interface1", "?my_parent_ping inStr<s outStr>s", NULL };

/* Test22-  HIDDEN | SECURE OBJECT INTROSPECT */
static const char* const Test22_Interface1[] = { "org.alljoyn.test1", "?my_ping inStr<s outStr>s", NULL };

/* Test23-  HIDDEN | SECURE OBJECT C0NSUMPTION */
static const char* const Test23_Interface1[] = { "org.alljoyn.test1", "?my_ping inStr<s outStr>s", NULL };
static const char* const Test23_Interface2[] = { "org.alljoyn.test2", "@prop_int_val=i", NULL };


static const AJ_InterfaceDescription Test1_Interfaces[] = { AJ_PropertiesIface, Test1_Interface1, Test1_Interface2, NULL };
static const AJ_InterfaceDescription Test2_Interfaces[] = { AJ_PropertiesIface, Test2_Interface1, Test2_Interface2, NULL };
static const AJ_InterfaceDescription Test3_Interfaces[] = { AJ_PropertiesIface, Test3_Interface1, Test3_Interface2, NULL };
static const AJ_InterfaceDescription Test4_Interfaces[] = { AJ_PropertiesIface, Test4_Interface1, Test4_Interface2, NULL };
static const AJ_InterfaceDescription Test5_Interfaces[] = { AJ_PropertiesIface, Test5_Interface1, Test5_Interface2, NULL };
static const AJ_InterfaceDescription Test6_Interfaces[] = { AJ_PropertiesIface, Test6_Interface1, Test6_Interface2, NULL };
static const AJ_InterfaceDescription Test7_Interfaces[] = { Test7_Interface1, NULL };
static const AJ_InterfaceDescription Test8_Interfaces[] = { Test8_Interface1, NULL };
static const AJ_InterfaceDescription Test9_Interfaces[] = { Test9_Interface1, NULL };
static const AJ_InterfaceDescription Test10_Interfaces[] = { Test10_Interface1, NULL };
static const AJ_InterfaceDescription Test11_Interfaces[] = { Test11_Interface1, NULL };
static const AJ_InterfaceDescription Test12_Interfaces[] = { Test12_Interface1, NULL };

static const AJ_InterfaceDescription Test13_Interfaces_GrandParent[] = { Test13_grand_parent_Interface1, NULL };
static const AJ_InterfaceDescription Test13_Interfaces_Parent[] = { Test13_parent_Interface1, NULL };
static const AJ_InterfaceDescription Test13_Interfaces_Child[] = { Test13_child_Interface1, NULL };

static const AJ_InterfaceDescription Test14_Interfaces[] = { Test14_Interface1, NULL };
static const AJ_InterfaceDescription Test15_Interfaces[] = { AJ_PropertiesIface, Test15_Interface1, Test15_Interface2, NULL };

static const AJ_InterfaceDescription Test16a_Interfaces[] = { Test16a_Interface1, NULL };

static const AJ_InterfaceDescription Test17_Interfaces_GrandParent[] = { Test17_grand_parent_Interface1, NULL };
static const AJ_InterfaceDescription Test17_Interfaces_Parent[] = { Test17_parent_Interface1, NULL };

static const AJ_InterfaceDescription Test18_Interfaces[] = { Test18_Interface1, NULL };
static const AJ_InterfaceDescription Test19_Interfaces[] = { AJ_PropertiesIface, Test19_Interface1, Test19_Interface2, NULL };

static const AJ_InterfaceDescription Test20_Interfaces[] = { Test20_Interface1, NULL };

static const AJ_InterfaceDescription Test21_Interfaces_GrandParent[] = { Test21_grand_parent_Interface1, NULL };
static const AJ_InterfaceDescription Test21_Interfaces_Parent[] = { Test21_parent_Interface1, NULL };

static const AJ_InterfaceDescription Test22_Interfaces[] = { Test18_Interface1, NULL };

static const AJ_InterfaceDescription Test23_Interfaces[] = { AJ_PropertiesIface, Test23_Interface1, Test23_Interface2, NULL };

static AJ_Object AppObjects[] = {
    { "/test1", Test1_Interfaces },
    { "/test2", Test2_Interfaces },
    { "/test3", Test3_Interfaces },
    { "/test4", Test4_Interfaces, AJ_OBJ_FLAG_SECURE },
    { "/test5", Test5_Interfaces, AJ_OBJ_FLAG_SECURE },
    { "/test6", Test6_Interfaces, AJ_OBJ_FLAG_SECURE },
    { "/test7", Test7_Interfaces },
    { "/test8", Test8_Interfaces },
    { "/test9", Test9_Interfaces },
    { "/test10", Test10_Interfaces, AJ_OBJ_FLAG_SECURE },
    { "/test11", Test11_Interfaces, AJ_OBJ_FLAG_SECURE },
    { "/test12", Test12_Interfaces, AJ_OBJ_FLAG_SECURE },

    { "/test13/grandparent", Test13_Interfaces_GrandParent, AJ_OBJ_FLAG_SECURE },
    { "/test13/grandparent/parent", Test13_Interfaces_Parent },
    { "/test13/grandparent/parent/child", Test13_Interfaces_Child },

    { "/test14", Test14_Interfaces, AJ_OBJ_FLAG_DISABLED },
    { "/test15", Test15_Interfaces, AJ_OBJ_FLAG_DISABLED },

    //The client side has an object which is disabled, and it will emit a signal.
    { "/test16a", Test16a_Interfaces },

    { "/test17/grandparent", Test17_Interfaces_GrandParent, AJ_OBJ_FLAG_DISABLED },
    { "/test17/grandparent/parent", Test17_Interfaces_Parent },

    { "/test18", Test18_Interfaces, AJ_OBJ_FLAG_HIDDEN },
    { "/test19", Test19_Interfaces, AJ_OBJ_FLAG_HIDDEN },

    { "/test20", Test20_Interfaces, AJ_OBJ_FLAG_HIDDEN },

    { "/test21/grandparent", Test21_Interfaces_GrandParent, AJ_OBJ_FLAG_HIDDEN },
    { "/test21/grandparent/parent", Test21_Interfaces_Parent },

    { "/test22", Test22_Interfaces, AJ_OBJ_FLAG_HIDDEN | AJ_OBJ_FLAG_SECURE },

    { "/test23", Test23_Interfaces, AJ_OBJ_FLAG_HIDDEN | AJ_OBJ_FLAG_SECURE },

    { NULL }
};

/* Macros for test case 1. */
#define TEST1_APP_MY_PING   AJ_APP_MESSAGE_ID(0, 1, 0)
#define TEST1_APP_GET_PROP  AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_GET)
#define TEST1_APP_SET_PROP  AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_SET)
#define TEST1_PROP_INT      AJ_APP_PROPERTY_ID(0, 2, 0)

/* Macros for test case 2. */
#define TEST2_APP_MY_PING   AJ_APP_MESSAGE_ID(1, 1, 0)
#define TEST2_APP_GET_PROP  AJ_APP_MESSAGE_ID(1, 0, AJ_PROP_GET)
#define TEST2_APP_SET_PROP  AJ_APP_MESSAGE_ID(1, 0, AJ_PROP_SET)
#define TEST2_PROP_INT      AJ_APP_PROPERTY_ID(1, 2, 0)

/* Macros for test case 3. */
#define TEST3_APP_MY_PING   AJ_APP_MESSAGE_ID(2, 1, 0)
#define TEST3_APP_GET_PROP  AJ_APP_MESSAGE_ID(2, 0, AJ_PROP_GET)
#define TEST3_APP_SET_PROP  AJ_APP_MESSAGE_ID(2, 0, AJ_PROP_SET)
#define TEST3_PROP_INT      AJ_APP_PROPERTY_ID(2, 2, 0)

/* Macros for test case 4. */
#define TEST4_APP_MY_PING   AJ_APP_MESSAGE_ID(3, 1, 0)
#define TEST4_APP_GET_PROP  AJ_APP_MESSAGE_ID(3, 0, AJ_PROP_GET)
#define TEST4_APP_SET_PROP  AJ_APP_MESSAGE_ID(3, 0, AJ_PROP_SET)
#define TEST4_PROP_INT      AJ_APP_PROPERTY_ID(3, 2, 0)

/*  for test case 5. */
#define TEST5_APP_MY_PING   AJ_APP_MESSAGE_ID(4, 1, 0)
#define TEST5_APP_GET_PROP  AJ_APP_MESSAGE_ID(4, 0, AJ_PROP_GET)
#define TEST5_APP_SET_PROP  AJ_APP_MESSAGE_ID(4, 0, AJ_PROP_SET)
#define TEST5_PROP_INT      AJ_APP_PROPERTY_ID(4, 2, 0)

/* Macros for test case 6. */
#define TEST6_APP_MY_PING   AJ_APP_MESSAGE_ID(5, 1, 0)
#define TEST6_APP_GET_PROP  AJ_APP_MESSAGE_ID(5, 0, AJ_PROP_GET)
#define TEST6_APP_SET_PROP  AJ_APP_MESSAGE_ID(5, 0, AJ_PROP_SET)
#define TEST6_PROP_INT      AJ_APP_PROPERTY_ID(5, 2, 0)

/* Macros for test case 7. */
#define TEST7_APP_MY_SIGNAL   AJ_APP_MESSAGE_ID(6, 0, 0)
#define TEST7_APP_RETURN_MY_SIGNAL   AJ_APP_MESSAGE_ID(6, 0, 1)

/* Macros for test case 8. */
#define TEST8_APP_MY_SIGNAL   AJ_APP_MESSAGE_ID(7, 0, 0)
#define TEST8_APP_RETURN_MY_SIGNAL   AJ_APP_MESSAGE_ID(7, 0, 1)

/* Macros for test case 9. */
#define TEST9_APP_MY_SIGNAL   AJ_APP_MESSAGE_ID(8, 0, 0)
#define TEST9_APP_RETURN_MY_SIGNAL   AJ_APP_MESSAGE_ID(8, 0, 1)

/* Macros for test case 10. */
#define TEST10_APP_MY_SIGNAL   AJ_APP_MESSAGE_ID(9, 0, 0)
#define TEST10_APP_RETURN_MY_SIGNAL   AJ_APP_MESSAGE_ID(9, 0, 1)

/* Macros for test case 11. */
#define TEST11_APP_MY_SIGNAL   AJ_APP_MESSAGE_ID(10, 0, 0)
#define TEST11_APP_RETURN_MY_SIGNAL   AJ_APP_MESSAGE_ID(10, 0, 1)

/* Macros for test case 12. */
#define TEST12_APP_MY_SIGNAL   AJ_APP_MESSAGE_ID(11, 0, 0)
#define TEST12_APP_RETURN_MY_SIGNAL   AJ_APP_MESSAGE_ID(11, 0, 1)

/* Macros for test case 13. */
#define TEST13_APP_MY_GRAND_PARENT_PING   AJ_APP_MESSAGE_ID(12, 0, 0)
#define TEST13_APP_MY_PARENT_PING         AJ_APP_MESSAGE_ID(13, 0, 0)
#define TEST13_APP_MY_CHILD_PING          AJ_APP_MESSAGE_ID(14, 0, 0)

/* Macros for test case 14. */
#define TEST14_APP_MY_PING   AJ_APP_MESSAGE_ID(15, 1, 0)

/* Macros for test case 15. */
#define TEST15_APP_MY_PING   AJ_APP_MESSAGE_ID(16, 1, 0)
#define TEST15_APP_GET_PROP  AJ_APP_MESSAGE_ID(16, 0, AJ_PROP_GET)
#define TEST15_APP_SET_PROP  AJ_APP_MESSAGE_ID(16, 0, AJ_PROP_SET)
#define TEST15_PROP_INT      AJ_APP_PROPERTY_ID(16, 2, 0)

/* Macros for test case 16a. */
#define TEST16a_APP_MY_SIGNAL   AJ_APP_MESSAGE_ID(17, 0, 0)
#define TEST16a_APP_RETURN_MY_SIGNAL   AJ_APP_MESSAGE_ID(17, 0, 1)

/* Macros for test case 17. */
#define TEST17_APP_MY_GRAND_PARENT_PING   AJ_APP_MESSAGE_ID(18, 0, 0)
#define TEST17_APP_MY_PARENT_PING         AJ_APP_MESSAGE_ID(19, 0, 0)

/* Macros for test case 18. */
#define TEST18_APP_MY_PING   AJ_APP_MESSAGE_ID(20, 0, 0)

/* Macros for test case 19. */
#define TEST19_APP_MY_PING   AJ_APP_MESSAGE_ID(21, 1, 0)
#define TEST19_APP_GET_PROP  AJ_APP_MESSAGE_ID(21, 0, AJ_PROP_GET)
#define TEST19_APP_SET_PROP  AJ_APP_MESSAGE_ID(21, 0, AJ_PROP_SET)
#define TEST19_PROP_INT      AJ_APP_PROPERTY_ID(21, 2, 0)

/* Macros for test case 20. */
#define TEST20_APP_MY_SIGNAL   AJ_APP_MESSAGE_ID(22, 0, 0)
#define TEST20_APP_RETURN_MY_SIGNAL   AJ_APP_MESSAGE_ID(22, 0, 1)

/* Macros for test case 21. */
#define TEST21_APP_MY_GRAND_PARENT_PING   AJ_APP_MESSAGE_ID(23, 0, 0)
#define TEST21_APP_MY_PARENT_PING         AJ_APP_MESSAGE_ID(24, 0, 0)

/* Macros for test case 22. */
#define TEST22_APP_MY_PING   AJ_APP_MESSAGE_ID(25, 0, 0)

/* Macros for test case 23. */
#define TEST23_APP_MY_PING   AJ_APP_MESSAGE_ID(26, 1, 0)
#define TEST23_APP_GET_PROP  AJ_APP_MESSAGE_ID(26, 0, AJ_PROP_GET)
#define TEST23_APP_SET_PROP  AJ_APP_MESSAGE_ID(26, 0, AJ_PROP_SET)
#define TEST23_PROP_INT      AJ_APP_PROPERTY_ID(26, 2, 0)

int g_prop = 420;
static const char PWD[] = "ABCDEFGH";

static uint32_t PasswordCallback(uint8_t* buffer, uint32_t bufLen)
{
    memcpy(buffer, PWD, sizeof(PWD));
    return sizeof(PWD) - 1;
}

void AppHandlePing(AJ_Message* msg)
{
    AJ_Status status = AJ_OK;
    AJ_Message reply;
    char* value;
    AJ_UnmarshalArgs(msg, "s", &value);
    AJ_MarshalReplyMsg(msg, &reply);
    AJ_MarshalArgs(&reply, "s", value);
    status = AJ_DeliverMsg(&reply);
}

void AppHandleSignal(AJ_Message* msg, uint32_t ID)
{
    AJ_Status status = AJ_OK;
    uint32_t value = 0;
    char dest[50];
    value = (msg->hdr->flags & AJ_FLAG_ENCRYPTED) ? 1 : 0;
    strcpy(dest, msg->sender);
    AJ_CloseMsg(msg);

    AJ_MarshalSignal(&bus, msg, ID, dest, 0, 0, 5000);
    AJ_MarshalArgs(msg, "u", value);
    AJ_DeliverMsg(msg);
}


AJ_Status AppHandleGetProp(AJ_Message* replyMsg, uint32_t propId, void* context)
{
    AJ_Status status = AJ_ERR_UNEXPECTED;
    status = AJ_MarshalArgs(replyMsg, "i", g_prop);
    return status;
}

AJ_Status AppHandleSetProp(AJ_Message* replyMsg, uint32_t propId, void* context)
{
    AJ_Status status = AJ_ERR_UNEXPECTED;
    int value = 0;
    AJ_UnmarshalArgs(replyMsg, "i", &value);
    g_prop = value;
    status = AJ_OK;
    return status;
}


int AJ_Main()
{
    AJ_Status status =  AJ_OK;
    AJ_Initialize();
    AJ_RegisterObjects(AppObjects, NULL);

    /*For Test17*/
    /* This API will set the child object attributes with that of the parent. */
    status = AJ_SetObjectFlags("/test17/grandparent", AJ_OBJ_FLAG_DISABLED, 0);
    if (status != AJ_OK) {
        AJ_Printf("Error calling AJ_SetObjectFlags.. [%s] \n", AJ_StatusText(status));
        return -1;
    }

    /*For Test*/
    /* This API will set the child object attributes with that of the parent. */
    status = AJ_SetObjectFlags("/test21/grandparent", AJ_OBJ_FLAG_HIDDEN, 0);
    if (status != AJ_OK) {
        AJ_Printf("Error calling AJ_SetObjectFlags.. [%s] \n", AJ_StatusText(status));
        return -1;
    }


    AJ_PrintXML(AppObjects);
    status = AJ_Connect(&bus, NULL, CONNECT_TIMEOUT);
    if (AJ_OK != status) {
        AJ_Printf("Bus connect failed: %s \n", AJ_StatusText(status));
        return -1;
    }
    AJ_Printf("Connected to the Daemon and my GUID is  %s \n", AJ_GetUniqueName(&bus));
    AJ_BusSetPasswordCallback(&bus, PasswordCallback);
    status = AJ_BusRequestName(&bus, ServiceName, AJ_NAME_REQ_DO_NOT_QUEUE);
    AJ_BusAddSignalRule(&bus, "NameOwnerChanged", "org.freedesktop.DBus", AJ_BUS_SIGNAL_ALLOW);

    while (TRUE) {
        AJ_Message msg;

        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            sleep(1);
            continue;
        }

        switch (msg.msgId) {

        case AJ_REPLY_ID(AJ_METHOD_REQUEST_NAME):
            break;

        case TEST1_APP_MY_PING:
            AppHandlePing(&msg);
            break;

        case TEST1_APP_GET_PROP:
            status = AJ_BusPropGet(&msg, AppHandleGetProp, NULL);
            break;

        case TEST1_APP_SET_PROP:
            status = AJ_BusPropSet(&msg, AppHandleSetProp, NULL);
            break;

        case TEST2_APP_MY_PING:
            AppHandlePing(&msg);
            break;

        case TEST2_APP_GET_PROP:
            status = AJ_BusPropGet(&msg, AppHandleGetProp, NULL);
            break;

        case TEST2_APP_SET_PROP:
            status = AJ_BusPropSet(&msg, AppHandleSetProp, NULL);
            break;

        case TEST3_APP_MY_PING:
            AppHandlePing(&msg);
            break;

        case TEST3_APP_GET_PROP:
            status = AJ_BusPropGet(&msg, AppHandleGetProp, NULL);
            break;

        case TEST3_APP_SET_PROP:
            status = AJ_BusPropSet(&msg, AppHandleSetProp, NULL);
            break;

        case TEST4_APP_MY_PING:
            AppHandlePing(&msg);
            break;

        case TEST4_APP_GET_PROP:
            status = AJ_BusPropGet(&msg, AppHandleGetProp, NULL);
            break;

        case TEST4_APP_SET_PROP:
            status = AJ_BusPropSet(&msg, AppHandleSetProp, NULL);
            break;

        case TEST5_APP_MY_PING:
            AppHandlePing(&msg);
            break;

        case TEST5_APP_GET_PROP:
            status = AJ_BusPropGet(&msg, AppHandleGetProp, NULL);
            break;

        case TEST5_APP_SET_PROP:
            status = AJ_BusPropSet(&msg, AppHandleSetProp, NULL);
            break;

        case TEST6_APP_MY_PING:
            AppHandlePing(&msg);
            break;

        case TEST6_APP_GET_PROP:
            status = AJ_BusPropGet(&msg, AppHandleGetProp, NULL);
            break;

        case TEST6_APP_SET_PROP:
            status = AJ_BusPropSet(&msg, AppHandleSetProp, NULL);
            break;

        case TEST7_APP_MY_SIGNAL:
            AppHandleSignal(&msg, TEST7_APP_RETURN_MY_SIGNAL);
            break;

        case TEST8_APP_MY_SIGNAL:
            AppHandleSignal(&msg, TEST8_APP_RETURN_MY_SIGNAL);
            break;

        case TEST9_APP_MY_SIGNAL:
            AppHandleSignal(&msg, TEST9_APP_RETURN_MY_SIGNAL);
            break;

        case TEST10_APP_MY_SIGNAL:
            AppHandleSignal(&msg, TEST10_APP_RETURN_MY_SIGNAL);
            break;

        case TEST11_APP_MY_SIGNAL:
            AppHandleSignal(&msg, TEST11_APP_RETURN_MY_SIGNAL);
            break;

        case TEST12_APP_MY_SIGNAL:
            AppHandleSignal(&msg, TEST12_APP_RETURN_MY_SIGNAL);
            break;


        case TEST13_APP_MY_GRAND_PARENT_PING:
            AppHandlePing(&msg);
            break;

        case TEST13_APP_MY_PARENT_PING:
            AppHandlePing(&msg);
            break;

        case TEST13_APP_MY_CHILD_PING:
            AppHandlePing(&msg);
            break;

        //This switch case will never be called. This is because, this method call belongs to an object which is disabled.
        case TEST14_APP_MY_PING:
            AppHandlePing(&msg);
            break;

        //This switch case will never be called. This is because, this method call belongs to an object which is disabled.
        case TEST15_APP_MY_PING:
            AppHandlePing(&msg);
            break;

        case TEST15_APP_GET_PROP:
            status = AJ_BusPropGet(&msg, AppHandleGetProp, NULL);
            break;

        case TEST15_APP_SET_PROP:
            status = AJ_BusPropSet(&msg, AppHandleSetProp, NULL);
            break;

        case TEST16a_APP_MY_SIGNAL:
            AppHandleSignal(&msg, TEST16a_APP_RETURN_MY_SIGNAL);
            break;

        case TEST17_APP_MY_GRAND_PARENT_PING:
            AppHandlePing(&msg);
            break;

        case TEST17_APP_MY_PARENT_PING:
            AppHandlePing(&msg);
            break;

        case TEST18_APP_MY_PING:
            AppHandlePing(&msg);
            break;

        case TEST19_APP_MY_PING:
            AppHandlePing(&msg);
            break;

        case TEST19_APP_GET_PROP:
            status = AJ_BusPropGet(&msg, AppHandleGetProp, NULL);
            break;

        case TEST19_APP_SET_PROP:
            status = AJ_BusPropSet(&msg, AppHandleSetProp, NULL);
            break;

        case TEST20_APP_MY_SIGNAL:
            AppHandleSignal(&msg, TEST20_APP_RETURN_MY_SIGNAL);
            break;

        case TEST21_APP_MY_GRAND_PARENT_PING:
            AppHandlePing(&msg);
            break;

        case TEST21_APP_MY_PARENT_PING:
            AppHandlePing(&msg);
            break;

        case TEST22_APP_MY_PING:
            AppHandlePing(&msg);
            break;


        case TEST23_APP_MY_PING:
            AppHandlePing(&msg);
            break;

        case TEST23_APP_GET_PROP:
            status = AJ_BusPropGet(&msg, AppHandleGetProp, NULL);
            break;

        case TEST23_APP_SET_PROP:
            status = AJ_BusPropSet(&msg, AppHandleSetProp, NULL);
            break;

        default:
            status = AJ_BusHandleBusMessage(&msg);
        }

        AJ_CloseMsg(&msg);

    }
    return 0;
}

#ifdef AJ_MAIN
int main()
{
    return AJ_Main();
}
#endif
