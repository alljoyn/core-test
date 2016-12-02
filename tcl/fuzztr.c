/**
 * @file
 */
/******************************************************************************
 *  * 
 *    Copyright (c) 2016 Open Connectivity Foundation and AllJoyn Open
 *    Source Project Contributors and others.
 *    
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0

 ******************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <alljoyn.h>

#define CONNECT_TIMEOUT    (1000ul * 60)
#define CONNECT_PAUSE      (1000ul * 10)
#define UNMARSHAL_TIMEOUT  (1000ul * 5)

/// globals
AJ_Status status = AJ_OK;
AJ_BusAttachment bus;
uint8_t connected = FALSE;


static const char* const testInterface[] = {
    "foo.bar",
    "!test >s",
    NULL
};

static const AJ_InterfaceDescription testInterfaces[] = {
    testInterface,
    NULL
};

/**
 * Objects implemented by the application
 */
static const AJ_Object AppObjects[] = {
    { "/foo/bar", testInterfaces },
    { NULL }
};

#define APP_TEST  AJ_APP_MESSAGE_ID(0, 0, 0)

/*
 * Let the application do some work
 */

void Do_Connect()
{
    while (!connected) {
        AJ_Status status;
        AJ_Printf("Attempting to connect to bus\n");
        status = AJ_Connect(&bus, NULL, CONNECT_TIMEOUT);
        if (status != AJ_OK) {
            AJ_Printf("Failed to connect to bus sleeping for %lu seconds\n", CONNECT_PAUSE / 1000);
            AJ_Sleep(CONNECT_PAUSE);
            continue;
        }
        connected = TRUE;
        AJ_Printf("Thin client app.connected to bus\n");
    }
}

static void AppDoWork()
{
    AJ_Printf(("do work\n"));
}

int AJ_Main()
{
    AJ_Status status = AJ_OK;
    AJ_Initialize();
    AJ_PrintXML(AppObjects);
    AJ_RegisterObjects(AppObjects, NULL);
    Do_Connect();

    while (TRUE) {
        AJ_Message msg;

        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            AppDoWork();
            continue;
        }
        if (status == AJ_OK) {
            printf("Message parsed. Id is %u, sender is %s , dest is %s \n", msg.msgId, msg.sender, msg.destination);
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