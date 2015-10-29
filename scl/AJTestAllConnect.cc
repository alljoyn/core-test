/**
 * @file
 * This app will connect to names that it finds in the vicinity. This app can be used with Android java app
 * AllJoynTestMultipleDevice
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

#include <qcc/platform.h>
#include <qcc/Debug.h>
#include <qcc/Thread.h>

#include <signal.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <vector>

#include <qcc/Environ.h>
#include <qcc/Event.h>
#include <qcc/String.h>
#include <qcc/StringUtil.h>
#include <qcc/Util.h>
#include <qcc/Crypto.h>
#include <qcc/time.h>

#include <alljoyn/BusAttachment.h>
#include <alljoyn/DBusStd.h>
#include <alljoyn/AllJoynStd.h>
#include <alljoyn/version.h>
#include <set>

#include <Status.h>

#define QCC_MODULE "ALLJOYN"

#define METHODCALL_TIMEOUT 30000

using namespace std;
using namespace qcc;
using namespace ajn;

/** Sample constants */
static const char*g_ServiceName = "com.alljoyn.test.allconnect";
static const char*g_ObjectPath = "/com/alljoyn/test/allconnect";
static const char*g_InterfaceName = "com.alljoyn.test.allconnect.ajtestInterface";
static SessionPort g_sessionPort = 24;

char g_wellKnownName[50];
char g_deviceId[20];

/** Static data */
static BusAttachment* g_msgBus = NULL;
static Event g_discoverEvent;

static set<String> s_deviceIds;
static Mutex s_lock;


static void DoList()
{
    printf("---------------- Device Ids -------------------\n");
    s_lock.Lock(MUTEX_CONTEXT);
    set<String>::const_iterator nit = s_deviceIds.begin();
    while (nit != s_deviceIds.end()) {
        QCC_SyncPrintf("  %s\n", nit++->c_str());
    }
    s_lock.Unlock(MUTEX_CONTEXT);
    printf("------------------------------------------------\n");
}


class MySessionListener : public SessionListener {

  public:
    void SessionLost(SessionId sessid, SessionListener::SessionLostReason reason)
    {
        /* Session Lost */
        QCC_UNUSED(sessid);
        QCC_UNUSED(reason);
    }
};
static MySessionListener g_sessionListener;

/* AllJoynListener receives discovery events from AllJoyn */
class MyBusListener : public BusListener, public BusAttachment::JoinSessionAsyncCB {
  public:

    MyBusListener() : BusListener() { }

    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix)
    {
        QCC_UNUSED(transport);
        QCC_UNUSED(namePrefix);
        if (0 != ::strcmp(name, g_wellKnownName)) {
            /* Proceed to Join Session */
            SessionOpts::TrafficType traffic = SessionOpts::TRAFFIC_MESSAGES;
            const SessionOpts opts(traffic, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);

            QStatus status = g_msgBus->JoinSessionAsync(name, g_sessionPort, &g_sessionListener, opts, this, ::strdup(name));
            if (ER_OK != status) {
                /* Join Session Error. Do Nothing */
            }

        }
    }

    void LostAdvertisedName(const char* name, TransportMask transport, const char* prefix)
    {
        QCC_UNUSED(transport);
        QCC_UNUSED(prefix);
        /* You need to get the device id from the name. Then remove it from the list. */
        /* Remove the device id from the list */
        String temp = name;
        String result = temp.substr(28);
        s_lock.Lock(MUTEX_CONTEXT);
        s_deviceIds.erase(result.c_str());
        s_lock.Unlock(MUTEX_CONTEXT);
        DoList();

    }

    void JoinSessionCB(QStatus status, SessionId sessionId, const SessionOpts& opts, void* context) {
        QCC_UNUSED(opts);
        if (status == ER_OK) {
            /* Obtain proxy Bus Object and make a method call, getDeviceInfo and Add to list */
            const char* name = reinterpret_cast<const char*>(context);
            ProxyBusObject remoteObj = ProxyBusObject(*g_msgBus, name, g_ObjectPath, sessionId);
            status = remoteObj.IntrospectRemoteObject();
            if (ER_OK != status) {
                /* Error during introspection. Do nothing. */
            } else {
                /* method call here. Get the reply and put it in a list. */
                Message reply(*g_msgBus);
                const InterfaceDescription::Member* pingMethod;
                const InterfaceDescription* ifc = remoteObj.GetInterface(g_InterfaceName);
                pingMethod = ifc->GetMember("getDeviceInfo");
                status = remoteObj.MethodCall(*pingMethod, NULL, 0, reply, 50000);

                if (ER_OK == status) {
                    /* Add to List */
                    s_lock.Lock(MUTEX_CONTEXT);
                    s_deviceIds.insert(reply->GetArg(0)->v_string.str);
                    s_lock.Unlock(MUTEX_CONTEXT);
                    DoList();
                } else {
                    /* Method Call error. Do nothing */
                }
            }

        } else {
            /* Join Session Error. Do Nothing */
        }
    }


};
static MyBusListener g_busListener;


class MySessionPortListener : public SessionPortListener {

    bool AcceptSessionJoiner(SessionPort sessionPort, const char* joiner, const SessionOpts& opts)
    {
        QCC_UNUSED(joiner);
        QCC_UNUSED(opts);
        return (sessionPort == g_sessionPort);
    }

    void SessionJoined(SessionPort sessionPort, SessionId sessionId, const char* joiner)
    {
        QCC_UNUSED(sessionPort);
        QCC_UNUSED(sessionId);
        QCC_UNUSED(joiner);
        /* print session joined */
    }

};
static MySessionPortListener g_sessPortListener;

class LocalTestObject : public BusObject {

  public:

    LocalTestObject(BusAttachment& bus, const char* path) : BusObject(path)
    {
        /* Add the test interface to this object */
        const InterfaceDescription* regTestIntf = bus.GetInterface(g_InterfaceName);
        assert(regTestIntf);
        AddInterface(*regTestIntf);

        /* Register the method handlers with the object */
        const MethodEntry methodEntries[] = {
            { regTestIntf->GetMember("getDeviceInfo"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::getDeviceInfo) }
        };

        QStatus status = AddMethodHandlers(methodEntries, ArraySize(methodEntries));
        if (ER_OK != status) {
            QCC_LogError(status, ("Failed to register method handlers for LocalTestObject"));
        }
    }

    void ObjectRegistered(void)
    {
        /*Object registsred */
    }

    void getDeviceInfo(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        /*TODO -  Reply with the device id i.e "hNARA123" */
        MsgArg arg;
        arg.Set("s", g_deviceId);
        QStatus status = MethodReply(msg, &arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Error sending reply"));
        }
    }

};

static volatile sig_atomic_t g_interrupt = false;

static void SigIntHandler(int sig)
{
    QCC_UNUSED(sig);
    g_interrupt = true;
}

/** Main entry point */
int main(int argc, char** argv)
{
    QStatus status = ER_OK;
    Environ* env;

#ifdef _WIN32
    WSADATA wsaData;
    WORD version = MAKEWORD(2, 0);
    int error = WSAStartup(version, &wsaData);
#endif


    /* Install SIGINT handler */
    signal(SIGINT, SigIntHandler);

    if (argc != 2) {
        QCC_SyncPrintf("\n Usage ./AJTestAllConnect NARA \n");
        exit(-1);
    }

    /* argv[1] has the device name stored. */

    /* Get env vars */
    env = Environ::GetAppEnviron();
#ifdef _WIN32
    qcc::String connectArgs = env->Find("BUS_ADDRESS", "tcp:addr=127.0.0.1,port=9955");
#else
    qcc::String connectArgs = env->Find("BUS_ADDRESS", "unix:abstract=alljoyn");
#endif

    /* Create message bus */
    g_msgBus = new BusAttachment("AJTestAllConnect", true);

    InterfaceDescription* testIntf = NULL;
    status = g_msgBus->CreateInterface(g_InterfaceName, testIntf, false);
    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to create Interface "));
        exit(-1);
    }

    /* Add 'getDeviceInfo' method to the interface */
    testIntf->AddMethod("getDeviceInfo", "", "s", "outStr,inStr", 0);
    testIntf->Activate();

    /* Register a bus listener in order to get discovery indications */
    g_msgBus->RegisterBusListener(g_busListener);

    /* Start the msg bus */
    status = g_msgBus->Start();
    if (ER_OK != status) {
        QCC_LogError(status, ("BusAttachment::Start failed"));
        exit(-1);
    }

    /* Connect to the bus */
    status = g_msgBus->Connect(connectArgs.c_str());
    if (ER_OK != status) {
        QCC_LogError(status, ("BusAttachment::Connect(\"%s\") failed", connectArgs.c_str()));
        exit(-1);
    }

    /* Register local objects and connect to the daemon */
    LocalTestObject testObj(*g_msgBus, g_ObjectPath);
    g_msgBus->RegisterBusObject(testObj);


    /* Populate the well known name */
    strcpy(g_wellKnownName, g_ServiceName);
    strcpy(g_deviceId, "h");
    strcat(g_deviceId, argv[1]);

    uint8_t data[2];
    qcc::Crypto_GetRandomBytes(data, 2);
    uint16_t no = data[0] + data[1];
    // time_t now;
    // time(&now);
    // srand ((unsigned int)now);
    //  double temp = (double) rand() * 1.0/RAND_MAX ;
    //   uint16_t no = (uint16_t) (temp*1000);

    qcc::String t_buf = qcc::U32ToString(no, 10);
    strcat(g_deviceId, t_buf.c_str());

    /* Finally, g_wellKnownName + g_deviceId */
    strcat(g_wellKnownName, ".");
    strcat(g_wellKnownName, g_deviceId);
    status = g_msgBus->RequestName(g_wellKnownName, DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE);
    if (status != ER_OK) {
        QCC_LogError(status, ("RequestName(%s) failed.", g_wellKnownName));
        exit(-1);
    }

    /* Begin Advertising the well-known name */
    status = g_msgBus->AdvertiseName(g_wellKnownName, TRANSPORT_ANY);
    if (ER_OK != status) {
        QCC_LogError(status, ("Sending org.alljoyn.Bus.Advertise failed"));
        exit(-1);
    }

    /* Bind Session */
    SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
    status = g_msgBus->BindSessionPort(g_sessionPort, opts, g_sessPortListener);
    if (status != ER_OK) {
        QCC_LogError(status, ("BindSessionPort failed"));
    }

    /* Advertise Name */
    status = g_msgBus->FindAdvertisedName(g_ServiceName);
    if (status != ER_OK) {
        QCC_LogError(status, ("FindAdvertisedName failed"));
        exit(-1);
    }

    /* Waiting for interrupt */
    while (g_interrupt == false) {
        qcc::Sleep(100);
    }

    /* Clean up activities */
    g_msgBus->UnregisterBusListener(g_busListener);
    g_msgBus->CancelAdvertiseName(g_wellKnownName, TRANSPORT_ANY);
    g_msgBus->ReleaseName(g_wellKnownName);
    /* Deallocate bus */
    BusAttachment* deleteMe = g_msgBus;
    g_msgBus = NULL;
    delete deleteMe;


    QCC_SyncPrintf("%s exiting with status %d (%s)\n", argv[0], status, QCC_StatusText(status));

    return 0;
}