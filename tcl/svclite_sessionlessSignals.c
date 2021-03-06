/**
 * @file
 */
/******************************************************************************
 *    Copyright (c) Open Connectivity Foundation (OCF), AllJoyn Open Source
 *    Project (AJOSP) Contributors and others.
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
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 *    WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 *    WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 *    AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 *    DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 *    PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 *    TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *    PERFORMANCE OF THIS SOFTWARE.
******************************************************************************/

/**
 * Per-module definition of the current module for debug logging.  Must be defined
 * prior to first inclusion of aj_debug.h
 */
#define AJ_MODULE SVCLITE

#include <aj_target.h>
#include <aj_link_timeout.h>
#include <aj_debug.h>
#include <alljoyn.h>
#include <aj_guid.h>
#include <aj_wifi_ctrl.h>


/**
 * Turn on per-module debug printing by setting this variable to non-zero value
 * (usually in debugger).
 */
uint8_t dbgSVCLITE = 1;
uint32_t sendTTL = 0;

/*
 * Modify these variables to change the service's behavior
 */
static const char ServiceName[] = "org.alljoyn.svclite";
static const uint16_t ServicePort = 24;
static const uint8_t CancelAdvertiseName = FALSE;
static const uint8_t ReflectSignal = FALSE;
static int8_t randByts;
AJ_GUID testGUID;

/*
 * An application property to SET or GET
 */
static int32_t propVal = 123456;

/*
 * To define a secure interface, prepend '$' before the interface name, eg., "$org.alljoyn.alljoyn_test"
 */
static const char* const testInterface[] = {
#ifdef SECURE_INTERFACE
    "$org.alljoyn.alljoyn_test",
#else
    "org.alljoyn.alljoyn_test",
#endif
    "?my_ping inStr<s outStr>s",
    "?delayed_ping inStr<s delay<u outStr>s",
    "?time_ping <u <q >u >q",
    "!my_signal >a{ys}",
    NULL
};

static const char* const testValuesInterface[] = {
#ifdef SECURE_INTERFACE
    "$org.alljoyn.alljoyn_test.values",
#else
    "org.alljoyn.alljoyn_test.values",
#endif
    "@int_val=i",
    "@str_val=s",
    "@ro_val>s",
    NULL
};

static const char* chatInterface[] = {
    "org.alljoyn.bus.test.sessions",
    "!Chat >s",
    NULL
};

static const AJ_InterfaceDescription testInterfaces[] = {
    AJ_PropertiesIface,
    testInterface,
    testValuesInterface,
    NULL
};

static const AJ_InterfaceDescription testInterfaces2[] = {
    chatInterface,
    NULL
};

static const AJ_Object AppObjects[] = {
    { "/org/alljoyn/alljoyn_test", testInterfaces },
    { "/sessions", testInterfaces2 },
    { NULL }
};

/*
 * Message identifiers for the method calls this application implements
 */
#define APP_GET_PROP  AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_GET)
#define APP_SET_PROP  AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_SET)
#define APP_MY_PING         AJ_APP_MESSAGE_ID(0, 1, 0)
#define APP_DELAYED_PING    AJ_APP_MESSAGE_ID(0, 1, 1)
#define APP_TIME_PING       AJ_APP_MESSAGE_ID(0, 1, 2)
#define APP_MY_SIGNAL       AJ_APP_MESSAGE_ID(0, 1, 3)
#define APP_CHAT_SIGNAL     AJ_APP_MESSAGE_ID(1, 0, 0)


/*
 * Property identifiers for the properies this application implements
 */
#define APP_INT_VAL_PROP AJ_APP_PROPERTY_ID(0, 2, 0)

/*
 * Let the application do some work
 */
static void AppDoWork()
{
    /*
     * This function is called if there are no messages to unmarshal
     */
    // AJ_RandBytes(&randByts, sizeof(&randByts));
    //   AJ_InfoPrintf(("%d\n", randByts));
    // AJ_GetLocalGUID(&testGUID);
    //  AJ_GUID_ToString(&testGUID, buffer , uint32_t bufLen );
    // AJ_InfoPrintf(("TEST GUID = %d\n", status));
    // AJ_InfoPrintf(("TEST GUID = %u\n",AJ_GetUniqueName(&testGUID)));
    // AJ_InfoPrintf(("TEST GUID = %u\n", testGUID.val));
    AJ_InfoPrintf(("do work\n"));
    //   char guidStr[33];
//    AJ_GetLocalGUID(&testGUID);
//    AJ_GUID_ToString(&testGUID, guidStr, sizeof(guidStr));
//    AJ_InfoPrintf(("TEST GUID = %s\n", guidStr));



}

//static void Alive()
//{
//    AJ_Status status = AJ_OK;
//   // char* chatMsg; // = "Hi This is SP144 and I am alive";
//   // const char chatMsg[] = "Hi, This is SP144 and I am alive";
//    AJ_BusAttachment bus;
//    char* chatMsg;
//
//    status = AppSendChatSignal(&bus, 0, chatMsg, ALLJOYN_FLAG_SESSIONLESS, sendTTL);
//
//
//}

static const char PWD[] = "ABCDEFGH";

static uint32_t PasswordCallback(uint8_t* buffer, uint32_t bufLen)
{
    memcpy(buffer, PWD, sizeof(PWD));
    return sizeof(PWD) - 1;
}

AJ_Status AppSendChatSignal(AJ_BusAttachment* bus, uint32_t sessionId, const char* chatString, uint8_t flags, uint32_t ttl)
{
    AJ_Status status = AJ_OK;
    AJ_Message msg;

    status = AJ_MarshalSignal(bus, &msg, APP_CHAT_SIGNAL, NULL, sessionId, flags, ttl);
    if (status == AJ_OK) {
        status = AJ_MarshalArgs(&msg, "s", chatString);
    }

    if (status == AJ_OK) {
        status = AJ_DeliverMsg(&msg);
    }
    AJ_Printf("TX chat: %s\n", chatString);
    return status;
}

AJ_Status AppHandleChatSignal(AJ_Message* msg)
{
    AJ_Status status = AJ_OK;
    char* chatString;

    AJ_UnmarshalArgs(msg, "s", &chatString);
    AJ_Printf("RX chat from %s[%u]: %s\n", msg->sender, msg->sessionId, chatString);
    return status;
}


static AJ_Status AppHandlePing(AJ_Message* msg)
{
    AJ_Message reply;
    AJ_Arg arg;

    AJ_UnmarshalArg(msg, &arg);
    AJ_MarshalReplyMsg(msg, &reply);
    /*
     * Just return the arg we received
     */
    AJ_MarshalArg(&reply, &arg);
    return AJ_DeliverMsg(&reply);
}

/*
 * Handles a property GET request so marshals the property value to return
 */
static AJ_Status PropGetHandler(AJ_Message* replyMsg, uint32_t propId, void* context)
{
    if (propId == APP_INT_VAL_PROP) {
        return AJ_MarshalArgs(replyMsg, "i", propVal);
    } else {
        return AJ_ERR_UNEXPECTED;
    }
}

/*
 * Handles a property SET request so unmarshals the property value to apply.
 */
static AJ_Status PropSetHandler(AJ_Message* replyMsg, uint32_t propId, void* context)
{
    if (propId == APP_INT_VAL_PROP) {
        return AJ_UnmarshalArgs(replyMsg, "i", &propVal);
    } else {
        return AJ_ERR_UNEXPECTED;
    }
}

uint32_t MyBusAuthPwdCB(uint8_t* buf, uint32_t bufLen)
{
    const char* myPwd = "1234";
    strncpy((char*)buf, myPwd, bufLen);
    return (uint32_t)strlen(myPwd);
}

#define CONNECT_TIMEOUT    (1000 * 1000)
#define UNMARSHAL_TIMEOUT  (1000 * 5)

int AJ_Main(void)
{
    AJ_Status status = AJ_OK;
    AJ_BusAttachment bus;
    uint8_t connected = FALSE;
    uint32_t sessionId = 0;
    char* chatMsg = "Hi there, this is svclite and I am alive";
    /*
     * One time initialization before calling any other AllJoyn APIs
     */
    AJ_Initialize();

    AJ_PrintXML(AppObjects);
    AJ_RegisterObjects(AppObjects, NULL);

    SetBusAuthPwdCallback(MyBusAuthPwdCB);

    while (TRUE) {
        AJ_Message msg;

        if (!connected) {
            status = AJ_StartService(&bus, NULL, CONNECT_TIMEOUT, FALSE, ServicePort, ServiceName, AJ_NAME_REQ_DO_NOT_QUEUE, NULL);
            if (status != AJ_OK) {
                continue;
            }
            AJ_InfoPrintf(("StartService returned AJ_OK\n"));
            AJ_InfoPrintf(("Connected to Daemon:%s\n", AJ_GetUniqueName(&bus)));


            connected = TRUE;

            /* Register a callback for providing bus authentication password */
            AJ_BusSetPasswordCallback(&bus, PasswordCallback);

            /* Configure timeout for the link to the daemon bus */
            AJ_SetBusLinkTimeout(&bus, 60); // 60 seconds
            AJ_BusAddSignalRule(&bus, "my_signal", "org.alljoyn.alljoyn_test", AJ_BUS_SIGNAL_ALLOW);
            AJ_BusSetSignalRule(&bus, "sessionless='t'", AJ_BUS_SIGNAL_ALLOW);

        }

        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);
        if (AJ_ERR_TIMEOUT == status && AJ_ERR_LINK_TIMEOUT == AJ_BusLinkStateProc(&bus)) {
            status = AJ_ERR_READ;
        }
        if (status != AJ_OK) {
            if (status == AJ_ERR_TIMEOUT) {
                AppDoWork();
                status = AppSendChatSignal(&bus, 0, chatMsg, ALLJOYN_FLAG_SESSIONLESS, sendTTL);
                continue;
            }
        }

        if (status == AJ_OK) {
            switch (msg.msgId) {

            case AJ_REPLY_ID(AJ_METHOD_ADD_MATCH):
                if (msg.hdr->msgType == AJ_MSG_ERROR) {
                    AJ_InfoPrintf(("Failed to add match\n"));
                    status = AJ_ERR_FAILURE;
                } else {
                    status = AJ_OK;
                }
                break;

            case AJ_METHOD_ACCEPT_SESSION:
                {
                    uint16_t port;
                    char* joiner;
                    AJ_UnmarshalArgs(&msg, "qus", &port, &sessionId, &joiner);
                    if (port == ServicePort) {
                        status = AJ_BusReplyAcceptSession(&msg, TRUE);
                        AJ_InfoPrintf(("Accepted session session_id=%u joiner=%s\n", sessionId, joiner));
                    } else {
                        status = AJ_BusReplyAcceptSession(&msg, FALSE);
                        AJ_InfoPrintf(("Accepted rejected session_id=%u joiner=%s\n", sessionId, joiner));
                    }
                }
                break;

            case APP_MY_PING:
                status = AppHandlePing(&msg);
                break;

            case APP_GET_PROP:
                status = AJ_BusPropGet(&msg, PropGetHandler, NULL);
                break;

            case APP_CHAT_SIGNAL:
                status = AppHandleChatSignal(&msg);
                break;

            case APP_SET_PROP:
                status = AJ_BusPropSet(&msg, PropSetHandler, NULL);
                if (status == AJ_OK) {
                    AJ_InfoPrintf(("Property successfully set to %d.\n", propVal));
                } else {
                    AJ_InfoPrintf(("Property set attempt unsuccessful. Status = 0x%04x.\n", status));
                }
                break;

            case AJ_SIGNAL_SESSION_LOST_WITH_REASON:
                {
                    uint32_t id, reason;
                    AJ_UnmarshalArgs(&msg, "uu", &id, &reason);
                    AJ_InfoPrintf(("Session lost. ID = %u, reason = %u", id, reason));
                    if (CancelAdvertiseName) {
                        status = AJ_BusAdvertiseName(&bus, ServiceName, AJ_TRANSPORT_ANY, AJ_BUS_START_ADVERTISING, 0);
                    }
                    status = AJ_ERR_SESSION_LOST;
                }
                break;

            case AJ_SIGNAL_SESSION_JOINED:
                if (CancelAdvertiseName) {
                    status = AJ_BusAdvertiseName(&bus, ServiceName, AJ_TRANSPORT_ANY, AJ_BUS_STOP_ADVERTISING, 0);
                }
                break;

            case AJ_REPLY_ID(AJ_METHOD_CANCEL_ADVERTISE):
            case AJ_REPLY_ID(AJ_METHOD_ADVERTISE_NAME):
                if (msg.hdr->msgType == AJ_MSG_ERROR) {
                    status = AJ_ERR_FAILURE;
                }
                break;

            case APP_MY_SIGNAL:
                AJ_InfoPrintf(("Received my_signal\n"));
                status = AJ_OK;

                if (ReflectSignal) {
                    AJ_Message out;
                    AJ_MarshalSignal(&bus, &out, APP_MY_SIGNAL, msg.destination, msg.sessionId, 0, 0);
                    AJ_MarshalArgs(&out, "a{ys}", 0, NULL);
                    AJ_DeliverMsg(&out);
                    AJ_CloseMsg(&out);
                }
                break;

            default:
                /*
                 * Pass to the built-in bus message handlers
                 */
                status = AJ_BusHandleBusMessage(&msg);
                break;
            }

            // Any received packets indicates the link is active, so call to reinforce the bus link state
            AJ_NotifyLinkActive();
        }
        /*
         * Unarshaled messages must be closed to free resources
         */
        AJ_CloseMsg(&msg);

        if ((status == AJ_ERR_READ) || (status == AJ_ERR_LINK_DEAD)) {
            AJ_InfoPrintf(("AllJoyn disconnect\n"));
            AJ_InfoPrintf(("Disconnected from Daemon:%s\n", AJ_GetUniqueName(&bus)));
            AJ_Disconnect(&bus);
            connected = FALSE;
            /*
             * Sleep a little while before trying to reconnect
             */
            AJ_Sleep(10 * 1000);
        }
    }
    AJ_WarnPrintf(("svclite EXIT %d\n", status));

    return status;
}


#ifdef AJ_MAIN
int main()
{
    return AJ_Main();
}
#endif