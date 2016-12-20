/* This program will join all names with a  prefix and the side joining the session
 * will try to authenticate the other peer. The aim is to trigger authentications and
 * join sessions parallely and ensure that they complete.
 * The auth method used is SRP.
 * The discovery prefix is "auth"
 * This is one of my favorite programs. */

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
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 *    WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 *    WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 *    AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 *    DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 *    PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 *    TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *    PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/
#include <qcc/StringUtil.h>
#include <qcc/platform.h>

#include <signal.h>
#include <stdio.h>
#include <vector>
#include <map>

#include <qcc/Debug.h>
#include <qcc/Environ.h>
#include <qcc/String.h>
#include <qcc/Thread.h>
#include <qcc/time.h>
#include <qcc/Util.h>

#include <alljoyn/BusAttachment.h>
#include <alljoyn/BusObject.h>
#include <alljoyn/DBusStd.h>
#include <alljoyn/AllJoynStd.h>
#include <alljoyn/MsgArg.h>
#include <alljoyn/version.h>

#include <Status.h>


#define QCC_MODULE "ALLJOYN"

using namespace std;
using namespace qcc;
using namespace ajn;

/** Static top level message bus object */
static BusAttachment* g_msgBus = NULL;
static String g_wellKnownName = "";
static uint8_t g_noPeers = 0;
static uint8_t g_count = 0;
static bool g_debug = false;

SessionPort SESSION_PORT = 26;

static volatile sig_atomic_t g_interrupt = false;

static void SigIntHandler(int sig)
{
    g_interrupt = true;
}

/* Call back for Async Method Calls */
class MyMessageReceiver : public MessageReceiver {
  public:
    void MyResponseHandler(Message& message, void* context)
    {
        if (message->GetType() == MESSAGE_METHOD_RET) {
            QCC_SyncPrintf("+++++++++++++++++++++++++++++++ Method Call successfull +++++++++++++++++++++++++++++++++++ \n");
            g_count++;
            if (g_count == g_noPeers - 1) {
                QCC_SyncPrintf("\n\n\n\n ------------------------------------- PEER PASS ---------------------------------\n\n\n\n");
            }

        } else {
            qcc::String errMsg;
            const char* errName = message->GetErrorName(&errMsg);
            QCC_SyncPrintf("Method call returned error %s: %s\n", errName, errMsg.c_str());
        }
    }

};
static MyMessageReceiver msgReceiver;


class LocalTestObject : public BusObject {

  public:

    LocalTestObject(BusAttachment& bus, const char* path)
        : BusObject(bus, path)
    {
        /* Add the test interface to this object */
        const InterfaceDescription* regTestIntf = bus.GetInterface("org.alljoyn.bbjoin.interface");
        QCC_ASSERT(regTestIntf);
        AddInterface(*regTestIntf);

        const MethodEntry methodEntries[] = {
            { regTestIntf->GetMember("authinit"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::AuthInit) }
        };
        QStatus status = AddMethodHandlers(methodEntries, ArraySize(methodEntries));

        if (ER_OK != status) {
            QCC_LogError(status, ("Failed to register method handlers for LocalTestObject"));
        }
    }

    void ObjectRegistered(void)
    {
        BusObject::ObjectRegistered();
    }

    void AuthInit(const InterfaceDescription::Member* member, Message& msg)
    {
        /* Reply with same string that was sent to us */
        MsgArg arg(*(msg->GetArg(0)));
        if (g_debug) { QCC_SyncPrintf("Pinged with: %s\n", msg->GetArg(0)->ToString().c_str()); }
        QStatus status = MethodReply(msg, &arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Ping: Error sending reply"));
        }
    }

};
static LocalTestObject*testObj = NULL;

class MyAuthListener : public AuthListener {
  public:
    MyAuthListener() : AuthListener() { }

  private:
    bool RequestCredentials(const char* authMechanism, const char* authPeer, uint16_t authCount, const char* userId, uint16_t credMask, Credentials& creds) {

        if (authCount > 1) { return false; }

        if (strcmp(authMechanism, "ALLJOYN_SRP_KEYX") == 0) {
            if (credMask & AuthListener::CRED_PASSWORD) {
                creds.SetPassword("1232456");
            }
            return true;
        }

        return false;
    }

    bool VerifyCredentials(const char* authMechanism, const char* authPeer, const Credentials& creds) {
        return false;
    }

    void AuthenticationComplete(const char* authMechanism, const char* authPeer, bool success) {
        if (g_debug) { QCC_SyncPrintf("Authentication %s %s\n", authMechanism, success ? "===================================== succesful" : "************* FAILED"); }
    }

    void SecurityViolation(const char* error) {
        if (g_debug) { QCC_SyncPrintf("XX Security violation %s\n", error); }
    }
};
static MyAuthListener myAuthListener;

class MyBusListener : public BusListener, public SessionPortListener, public SessionListener, public BusAttachment::JoinSessionAsyncCB {

  public:
    MyBusListener() { }

    bool AcceptSessionJoiner(SessionPort sessionPort, const char* joiner, const SessionOpts& opts)
    {
        return true;
    }

    void SessionJoined(SessionPort sessionPort, SessionId sessionId, const char* joiner)
    {
        if (g_debug) { QCC_SyncPrintf("Session Established: joiner=%s, sessionId=%u ----------------------------------------------------------------------------- \n", joiner, sessionId); }
        QStatus status = g_msgBus->SetSessionListener(sessionId, this);
        if (ER_OK != status) {
            QCC_LogError(status, ("Failed to SetSessionListener(%u)", sessionId));
        }
    }

    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix)
    {
        if (g_debug) { QCC_SyncPrintf("FoundAdvertisedName(name=%s, transport=0x%x, prefix=%s)\n", name, transport, namePrefix); }
        if (strcmp(name, g_wellKnownName.c_str()) != 0) {
            SessionOpts::TrafficType traffic = SessionOpts::TRAFFIC_MESSAGES;
            SessionOpts opts(traffic, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);

            QStatus status = g_msgBus->JoinSessionAsync(name, 26, this, opts, this, ::strdup(name));
            if (ER_OK != status) {
                QCC_LogError(status, ("JoinSessionAsync(%s) failed \n", name));
                exit(1);
            }
        }
    }

    void JoinSessionCB(QStatus status, SessionId sessionId, const SessionOpts& opts, void* context)
    {
        const char* name = reinterpret_cast<const char*>(context);

        if (status == ER_OK) {
            if (g_debug) { QCC_SyncPrintf("JoinSessionAsync succeeded. SessionId=%u ------------------------------------------------------------------------------------ (%s) \n", sessionId, name); }

            /* Make Async method call */
            ProxyBusObject*remoteObj = new ProxyBusObject(*g_msgBus, name, "/org/alljoyn/bbjoin", sessionId);
            const InterfaceDescription* alljoynTestIntf = g_msgBus->GetInterface("org.alljoyn.bbjoin.interface");
            QCC_ASSERT(alljoynTestIntf);
            remoteObj->AddInterface(*alljoynTestIntf);
            /* Prepare to make the async method call */
            /* Grab the interface */
            Message reply(*g_msgBus);
            const InterfaceDescription::Member* myMethod;

            /* Set the arguments */
            MsgArg msgArgs;
            msgArgs.Set("s", "NeedAuth");
            myMethod = alljoynTestIntf->GetMember("authinit");

            /* Set the encryption flag to on.*/
            /* Now make the method call */
            status = remoteObj->MethodCallAsync(*myMethod,
                                                &msgReceiver,
                                                static_cast<MessageReceiver::ReplyHandler>(&MyMessageReceiver::MyResponseHandler),
                                                &msgArgs, 1,
                                                const_cast<void*>(static_cast<const void*>(myMethod)),
                                                5000000, 0 | ALLJOYN_FLAG_ENCRYPTED);
            if (status != ER_OK) {
                QCC_LogError(status, ("MethodCallAsync failed"));
            }

            delete remoteObj;

        } else {
            QCC_SyncPrintf("JoinSession failed with %s\n", QCC_StatusText(status));
        }

        free(context);
    }

    void LostAdvertisedName(const char* name, const TransportMask transport, const char* prefix)
    {
        if (g_debug) { QCC_SyncPrintf("LostAdvertisedName(name=%s, transport=0x%x,  prefix=%s)\n", name, transport, prefix); }
    }

    void SessionLost(SessionId sessid, SessionListener::SessionLostReason reason)
    {
        QCC_UNUSED(reason);
        QCC_SyncPrintf("Session Lost  %u\n", sessid);
    }

};

static void usage(void)
{
    printf("Usage: bbjoin -n auth.xxx -t -p 4\n\n");
    printf("Options:\n");
    printf("   -h           = Print this help message\n");
    printf("   -n  <wkn>    = well known name\n");
    printf("   -p  #p       = No of peers\n");
    printf("   -t           = Advertise over TCP (enables selective TCP advertising)\n");
    printf("   -i           = Advertise over ICE (enables selective ICE advertising)\n");
    printf("   -d           = More debug prints\n");
    printf("\n");
}

/** Main entry point */
int main(int argc, char** argv)
{
    QStatus status = ER_OK;
    uint32_t transportOpts = TRANSPORT_ANY;
    bool TCP = false;
    bool ICE = false;
    bool LOCAL = false;

    /* Install SIGINT handler */
    signal(SIGINT, SigIntHandler);

    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp("-h", argv[i])) {
            usage();
            exit(0);
        } else if (0 == strcmp("-n", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_wellKnownName = argv[i];
            }
        } else if (0 == strcmp("-d", argv[i])) {
            g_debug = true;
        } else if (0 == strcmp("-t", argv[i])) {
            TCP = true;
        } else if (0 == strcmp("-i", argv[i])) {
            ICE = true;
        } else if (0 == strcmp("-l", argv[i])) {
            LOCAL = true;
        } else if (0 == strcmp("-p", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_noPeers = strtoul(argv[i], NULL, 10);
            }
        } else {
            status = ER_FAIL;
            printf("Unknown option %s\n", argv[i]);
            usage();
            exit(1);
        }
    }

    if (g_wellKnownName.empty()) {
        QCC_SyncPrintf("Incorrect usage. Wellknown name not entered\n");
        usage();
        exit(-1);
    }

    if (g_noPeers == 0) {
        QCC_SyncPrintf("Incorrect usage. No of peers not entered. \n");
        usage();
        exit(-1);
    }


    /* If no transport option was specified, then make session options very open */
    if (TCP) {
        transportOpts = TRANSPORT_WLAN;
    } else if (ICE) {
        transportOpts = TRANSPORT_ICE;
    } else if (LOCAL) {
        transportOpts = TRANSPORT_LOCAL;
    }

    /* Get env vars */
    qcc::String clientArgs;
#ifdef _WIN32
    clientArgs = "tcp:addr=127.0.0.1,port=9956";
#else
    clientArgs = "unix:abstract=alljoyn";
#endif

    /* Create message bus */
    g_msgBus = new BusAttachment("bbjoin", true);

    /* Create an interface and add a method call */
    InterfaceDescription* testIntf = NULL;
    status = g_msgBus->CreateInterface("org.alljoyn.bbjoin.interface", testIntf);
    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to create interface %s", "org.alljoyn.bbjoin.interface"));
        return status;
    }

    testIntf->AddMethod("authinit",  "s", "s", "inStr,outStr", 0);
    testIntf->Activate();

    status = g_msgBus->Start();
    if (ER_OK != status) {
        QCC_LogError(status, ("BusAttachment::Start failed"));
        return status;
    }

    /* Connect to the daemon */
    status = g_msgBus->Connect(clientArgs.c_str());
    if (ER_OK != status) {
        QCC_LogError(status, ("BusAttachment::Connect failed"));
        return status;
    }


    /* Creating a service object and registering it with the bus */
    testObj = new LocalTestObject(*g_msgBus, "/org/alljoyn/bbjoin");
    g_msgBus->RegisterBusObject(*testObj);


    MyBusListener myBusListener;
    g_msgBus->RegisterBusListener(myBusListener);


    /* Create session opts */
    SessionOpts optsmp(SessionOpts::TRAFFIC_MESSAGES, false,  SessionOpts::PROXIMITY_ANY, transportOpts);

    /* Create a session for incoming client connections */
    status = g_msgBus->BindSessionPort(SESSION_PORT, optsmp, myBusListener);
    if (status != ER_OK) {
        QCC_LogError(status, ("BindSessionPort failed"));
        return status;
    }

    char keystore_file[50];
    strcpy(keystore_file, g_wellKnownName.c_str());
    g_msgBus->EnablePeerSecurity("ALLJOYN_SRP_KEYX", &myAuthListener, keystore_file, true);
    g_msgBus->ClearKeyStore();

    /* Request a well-known name */
    status = g_msgBus->RequestName(g_wellKnownName.c_str(), DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE);
    if (status != ER_OK) {
        QCC_LogError(status, ("RequestName(%s) failed. ", g_wellKnownName.c_str()));
        return status;
    }

    /* Begin Advertising the well-known name */
    status = g_msgBus->AdvertiseName(g_wellKnownName.c_str(), transportOpts);
    if (ER_OK != status) {
        QCC_LogError(status, ("Advertising well known name failed. "));
        return status;
    }

    status = g_msgBus->FindAdvertisedName("auth");
    if (status != ER_OK) {
        QCC_LogError(status, ("FindAdvertisedName failed "));
        return status;
    }


    while (g_interrupt == false) {
        qcc::Sleep(100);
    }

    /* Clean up msg bus */
    if (g_msgBus) {
        delete g_msgBus;
    }

    QCC_SyncPrintf("\n deleting auth files..\n");
    #ifdef _WIN32
    QCC_SyncPrintf("\n Windows. Not doing anything. \n");
    #else
    QCC_SyncPrintf("\n Linux. Deleting auth files from home directory. \n");
    system("rm -rf ~/auth.*");
    #endif
    QCC_SyncPrintf("\n Done deletion of auth files.. \n");

    QCC_SyncPrintf("\n %s exiting with status %d (%s)\n", argv[0], status, QCC_StatusText(status));

    return 0;
}