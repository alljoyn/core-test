/**
 * @file
 * Sample implementation of auth based test.
 */

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
#include <qcc/platform.h>

#include <signal.h>
#include <stdio.h>
#include <vector>

#include <qcc/Debug.h>
#include <qcc/Log.h>
#include <qcc/Environ.h>
#include <qcc/Mutex.h>
#include <qcc/String.h>
#include <qcc/Thread.h>
#include <qcc/time.h>
#include <qcc/Util.h>

#include <alljoyn/AboutObj.h>
#include <alljoyn/AllJoynStd.h>
#include <alljoyn/BusAttachment.h>
#include <alljoyn/BusObject.h>
#include <alljoyn/DBusStd.h>
#include <alljoyn/Init.h>
#include <alljoyn/MsgArg.h>
#include <alljoyn/version.h>

#include <alljoyn/Status.h>


#define QCC_MODULE "AUTH_TEST_PROGRAM"

using namespace std;
using namespace qcc;
using namespace ajn;


/* Static top level globals */
static BusAttachment* g_msgBus = NULL;
static SessionId g_sessionId = 0;
static bool g_server = true;
static TransportMask g_transport = TRANSPORT_NONE;
static bool g_waitTillClaimed = false;
static String g_proxyName;
static bool g_encryption = false;

static const char ecdsaPrivateKeyPEM[] = {
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MDECAQEEIICSqj3zTadctmGnwyC/SXLioO39pB1MlCbNEX04hjeioAoGCCqGSM49\n"
    "AwEH\n"
    "-----END EC PRIVATE KEY-----"
};

static const char ecdsaCertChainX509PEM[] = {
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBWjCCAQGgAwIBAgIHMTAxMDEwMTAKBggqhkjOPQQDAjArMSkwJwYDVQQDDCAw\n"
    "ZTE5YWZhNzlhMjliMjMwNDcyMGJkNGY2ZDVlMWIxOTAeFw0xNTAyMjYyMTU1MjVa\n"
    "Fw0xNjAyMjYyMTU1MjVaMCsxKTAnBgNVBAMMIDZhYWM5MjQwNDNjYjc5NmQ2ZGIy\n"
    "NmRlYmRkMGM5OWJkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEP/HbYga30Afm\n"
    "0fB6g7KaB5Vr5CDyEkgmlif/PTsgwM2KKCMiAfcfto0+L1N0kvyAUgff6sLtTHU3\n"
    "IdHzyBmKP6MQMA4wDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiAZmNVA\n"
    "m/H5EtJl/O9x0P4zt/UdrqiPg+gA+wm0yRY6KgIgetWANAE2otcrsj3ARZTY/aTI\n"
    "0GOQizWlQm8mpKaQ3uE=\n"
    "-----END CERTIFICATE-----"
};


class MyAuthListener : public AuthListener {

    QStatus RequestCredentialsAsync(const char* authMechanism, const char* authPeer, uint16_t authCount, const char* userId, uint16_t credMask, void* context)
    {
        QCC_UNUSED(authCount);
        QCC_UNUSED(userId);
        Credentials creds;
        printf("RequestCredentials for authenticating %s using mechanism %s\n", authPeer, authMechanism);

        if (strcmp(authMechanism, "ALLJOYN_ECDHE_NULL") == 0) {
            printf("AuthListener::RequestCredentials for key exchange %s\n", authMechanism);
            return RequestCredentialsResponse(context, true, creds);
        }
        if (strcmp(authMechanism, "ALLJOYN_ECDHE_PSK") == 0) {
            if ((credMask& AuthListener::CRED_USER_NAME) == AuthListener::CRED_USER_NAME) {
                printf("AuthListener::RequestCredentials for key exchange %s received psk ID %s\n", authMechanism, creds.GetUserName().c_str());
            }
            creds.SetPassword("abcdefghijklmnopqrstuvwxyz0123456789101112131415161718192021222324252627282930horror");
            return RequestCredentialsResponse(context, true, creds);
        }
        if (strcmp(authMechanism, "ALLJOYN_ECDHE_ECDSA") == 0) {
            printf("AuthListener::RequestCredentials for key exchange %s \n", authMechanism);

            if ((credMask& AuthListener::CRED_PRIVATE_KEY) == AuthListener::CRED_PRIVATE_KEY) {
                String pk(ecdsaPrivateKeyPEM, strlen(ecdsaPrivateKeyPEM));
                creds.SetPrivateKey(pk);
                printf("AuthListener::RequestCredentials for key exchange %s sends DSA private key \n %s\n", authMechanism, pk.c_str());
            }
            if ((credMask& AuthListener::CRED_CERT_CHAIN) == AuthListener::CRED_CERT_CHAIN) {
                String cert(ecdsaCertChainX509PEM, strlen(ecdsaCertChainX509PEM));
                creds.SetCertChain(cert);
                printf("AuthListener::RequestCredentials for key exchange %s sends DSA public cert \n %s\n", authMechanism, cert.c_str());
            }

            return RequestCredentialsResponse(context, false, creds);
        }
        printf("AuthListener::RequestCredentials for keyexchange returning false.. \n");
        return RequestCredentialsResponse(context, false, creds);
    }

    QStatus VerifyCredentialsAsync(const char* authMechanism, const char* authPeer, const Credentials& creds, void* context) {
        QCC_UNUSED(authPeer);
        if (strcmp(authMechanism, "ALLJOYN_ECDHE_ECDSA") == 0) {
            if (creds.IsSet(AuthListener::CRED_CERT_CHAIN)) {
                printf("AuthListener::VerifyCredentials for ECDSA auth. \n");
                return VerifyCredentialsResponse(context, true);
            }
        }
        return VerifyCredentialsResponse(context, false);
    }

    void AuthenticationComplete(const char* authMechanism, const char* authPeer, bool success) {
        QCC_UNUSED(authPeer);

        printf("Authentication %s %s\n", authMechanism, success ? "succesful" : "failed");
    }

    void SecurityViolation(QStatus status, const Message& msg) {
        QCC_UNUSED(msg);
        printf("Security violation %s\n", QCC_StatusText(status));
    }

};


class MySessionListener : public SessionPortListener, public SessionListener {

  public:
    bool AcceptSessionJoiner(SessionPort sessionPort, const char* joiner, const SessionOpts& opts)
    {
        QCC_UNUSED(sessionPort);
        QCC_UNUSED(joiner);
        QCC_UNUSED(opts);
        return true;
    }

    void SessionJoined(SessionPort sessionPort, SessionId sessionId, const char* joiner)
    {
        QCC_UNUSED(sessionPort);
        QCC_UNUSED(sessionId);
        g_proxyName = joiner;
        g_sessionId = sessionId;
        printf("Session Established: joiner=%s, sessionId=%u\n", joiner, sessionId);
    }

    void SessionLost(SessionId sessionId, SessionLostReason reason) {
        printf("SessionLost(%08x) was called. Reason = %u.\n", sessionId, reason);
    }

};

class MyBusListener : public BusListener {

    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix)
    {
        printf("FoundAdvertisedName(name=%s, transport=0x%x, prefix=%s)\n", name, transport, namePrefix);
        g_msgBus->EnableConcurrentCallbacks();
        SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, transport);
        QStatus status =  ER_OK;
        status = g_msgBus->JoinSession(name, 5, NULL, g_sessionId, opts);
        if (ER_OK != status) {
            QCC_LogError(status, ("JoinSession(%s) failed", name));
        }
    }
};

static MySessionListener* g_mySessionListener = NULL;
static MyBusListener* g_myBusListener = NULL;

class LocalTestObject : public BusObject {

  public:

    LocalTestObject(const char* path) : BusObject(path) {

        QStatus status = ER_OK;

        /* Add the test interface to this object */
        const InterfaceDescription* regTestIntf = g_msgBus->GetInterface("test.interface");
        QCC_ASSERT(regTestIntf);
        AddInterface(*regTestIntf);

        /* Register the signal handler with the bus */
        my_signal_member = regTestIntf->GetMember("my_signal");
        QCC_ASSERT(my_signal_member);
        status = g_msgBus->RegisterSignalHandler(this,
                                                 static_cast<MessageReceiver::SignalHandler>(&LocalTestObject::SignalHandler),
                                                 my_signal_member,
                                                 NULL);
        QCC_ASSERT(status == ER_OK);

        //Register method handler for method call
        const MethodEntry methodEntries[] = {
            { regTestIntf->GetMember("my_ping"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Ping) }
        };
        status = AddMethodHandlers(methodEntries, ArraySize(methodEntries));
        QCC_ASSERT(status == ER_OK);
        QCC_UNUSED(status);
    }

    void SignalHandler(const InterfaceDescription::Member* member, const char* sourcePath,  Message& msg)
    {

        QCC_UNUSED(member);
        printf("RxSignal: %s , from %s \n", sourcePath, msg->GetSender());
        if (msg->IsEncrypted()) {
            printf("Authenticated using %s\n", msg->GetAuthMechanism().c_str());
        }
    }

    void Ping(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);

        char* value = NULL;

        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("s", &value);
        printf("Pinged with: %s, from  %s \n", value, msg->GetSender());
        if (msg->IsEncrypted()) {
            printf("Authenticated using %s\n", msg->GetAuthMechanism().c_str());
        }
        QStatus status = MethodReply(msg, arg, 1);
        QCC_ASSERT(status == ER_OK);
        QCC_UNUSED(status);
    }

    QStatus Get(const char* ifcName, const char* propName, MsgArg& val)
    {
        QCC_UNUSED(ifcName);
        QStatus status = ER_OK;
        if (0 == strcmp("my_prop1", propName)) {
            val.Set("i", 120);
        } else if (0 == strcmp("my_prop2", propName)) {
            val.Set("s", "Hello");
        } else {
            status = ER_BUS_NO_SUCH_PROPERTY;
        }
        return status;
    }

    QStatus Set(const char* ifcName, const char* propName, MsgArg& val)
    {
        QCC_UNUSED(ifcName);
        QCC_UNUSED(val);

        QStatus status = ER_OK;
        if (0 == strcmp("my_prop1", propName)) {
            printf("Set the property 'my_prop1' \n");
        } else if (0 == strcmp("my_prop2", propName)) {
            printf("Set the property 'my_prop2' \n");
        } else {
            status = ER_BUS_NO_SUCH_PROPERTY;
        }
        return status;
    }

    QStatus SendSignal() {
        uint8_t flags = 0;
        QCC_ASSERT(my_signal_member);
        MsgArg arg("s", "Hello World Signal");
        return Signal(g_proxyName.c_str(), g_sessionId, *my_signal_member, &arg, 1, 0, flags);
    }

    const InterfaceDescription::Member* my_signal_member;
};



int CDECL_CALL main(int argc, char* argv[]) {

    QStatus status = ER_OK;
    bool clearks = false;
    String authMechanism = "";
    String iauthMechanism = "";
    if (AllJoynInit() != ER_OK) {
        return 1;
    }
#ifdef ROUTER
    if (AllJoynRouterInit() != ER_OK) {
        AllJoynShutdown();
        return 1;
    }
#endif

    /* Parse command line args */
    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp("-c", argv[i])) {
            g_server = false;
        } else if (0 == strcmp("-clearks", argv[i])) {
            clearks = true;
        } else if (0 == strcmp("-tcp", argv[i])) {
            g_transport = TRANSPORT_TCP;
        } else if (0 == ::strcmp("-udp", argv[i])) {
            g_transport = TRANSPORT_UDP;
        } else if ((0 == strcmp("-local", argv[i]))) {
            g_transport = TRANSPORT_LOCAL;
        } else if ((0 == strcmp("-waittillclaimed", argv[i]))) {
            g_waitTillClaimed  = true;
        } else if (0 == strcmp("-encrypt", argv[i])) {
            g_encryption = true;
        } else if (0 == strcmp("-psk", argv[i])) {
            authMechanism += "ALLJOYN_ECDHE_PSK ";
        } else if (0 == strcmp("-null", argv[i])) {
            authMechanism += "ALLJOYN_ECDHE_NULL ";
        } else if (0 == strcmp("-ecdsa", argv[i])) {
            authMechanism += "ALLJOYN_ECDHE_ECDSA ";
        }  else if (0 == strcmp("-ipsk", argv[i])) {
            iauthMechanism += "ALLJOYN_ECDHE_PSK ";
        } else if (0 == strcmp("-inull", argv[i])) {
            iauthMechanism += "ALLJOYN_ECDHE_NULL ";
        }  else if (0 == strcmp("-iecdsa", argv[i])) {
            iauthMechanism += "ALLJOYN_ECDHE_ECDSA ";
        } else {
            printf("Unknown option %s\n", argv[i]);
            exit(1);
        }
    }

    if (authMechanism.empty()) {
        printf("Auth mechanisms cannot be empty. Some auth mechanism should be specified \n");
        exit(1);
    } else {
        printf("Auth mechanism supported are: %s \n", authMechanism.c_str());
    }

    if (iauthMechanism.empty()) {
        printf("IAuth mechanisms cannot be empty. Some auth mechanism should be specified \n");
        exit(1);
    } else {
        printf("IAuth mechanism supported are: %s \n", iauthMechanism.c_str());
    }


    /* Create message bus */
    g_msgBus = new BusAttachment("authtest", true);
    status = g_msgBus->Start();
    QCC_ASSERT(status == ER_OK);
    status = g_msgBus->Connect();
    QCC_ASSERT(status == ER_OK);
    printf("Unique name is %s \n", g_msgBus->GetUniqueName().c_str());

    //Advertise the unique name and use the security management session port
    status = g_msgBus->AdvertiseName(g_msgBus->GetUniqueName().c_str(), g_transport);
    QCC_ASSERT(status == ER_OK);

    if (g_server) {
        status = g_msgBus->EnablePeerSecurity(authMechanism.c_str(), new MyAuthListener(), "authserver-keystore", false);
        QCC_ASSERT(status == ER_OK);
    } else {
        status = g_msgBus->EnablePeerSecurity(authMechanism.c_str(), new MyAuthListener(), "authclient-keystore", false);
        QCC_ASSERT(status == ER_OK);
    }

    if (clearks) {
        g_msgBus->ClearKeyStore();
    }

    if (g_server) {
        printf("Server mode \n");
        status = g_msgBus->RequestName("innocent.app", DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE);
        QCC_ASSERT(status == ER_OK);
        status = g_msgBus->AdvertiseName("innocent.app", g_transport);
        QCC_ASSERT(status == ER_OK);

        SessionPort sessionPort = 5;
        g_mySessionListener = new MySessionListener();
        SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, g_transport);
        status = g_msgBus->BindSessionPort(sessionPort, opts, *g_mySessionListener);
        QCC_ASSERT(status == ER_OK);
    }

    PermissionConfigurator& PC = g_msgBus->GetPermissionConfigurator();
    PermissionConfigurator::ApplicationState appState = PermissionConfigurator::NOT_CLAIMABLE;
    //Set the manifest template
    {
        PermissionPolicy::Rule::Member member[1];
        member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        const size_t manifestSize = 1;
        PermissionPolicy::Rule manifestTemplate[manifestSize];
        manifestTemplate[0].SetObjPath("*");
        manifestTemplate[0].SetInterfaceName("*");
        manifestTemplate[0].SetMembers(1, member);
        status = PC.SetPermissionManifest(manifestTemplate, manifestSize);
    }


    if (g_transport == TRANSPORT_NONE) {
        printf("Transport mask not selected \n");
        exit(1);
    }

    //Wait till claimed
    while ((appState != PermissionConfigurator::CLAIMED) && g_waitTillClaimed) {
        PC.GetApplicationState(appState);
        qcc::Sleep(100);
    }

    if (!g_server) {
        g_myBusListener = new MyBusListener();
        g_msgBus->RegisterBusListener(*g_myBusListener);
        printf("Client mode  \n");
        g_msgBus->FindAdvertisedNameByTransport("innocent.app", g_transport);
        printf("Waiting for the client to discover and join session with service \n");
    }

    while (g_sessionId == 0) {
        qcc::Sleep(100);
    }

    //Create Interfaces at BusAttachment level
    /* Add org.alljoyn.alljoyn_test interface */
    InterfaceDescription* testIntf = NULL;
    status = g_msgBus->CreateInterface("test.interface", testIntf, g_encryption);
    QCC_ASSERT(status == ER_OK);
    testIntf->AddSignal("my_signal", "s", NULL, 0);
    testIntf->AddMethod("my_ping", "s", "s", "inStr,outStr", 0);
    testIntf->AddProperty("my_prop1", "i", PROP_ACCESS_RW);
    testIntf->AddProperty("my_prop2", "s", PROP_ACCESS_RW);
    testIntf->Activate();

    //Register a busobject with this bus attachment
    LocalTestObject* testObj = new LocalTestObject("/a/b");
    g_msgBus->RegisterBusObject(*testObj);

    if (!g_server) {
        g_proxyName = "innocent.app";
    }


    //Clear the auth mechanism and Switch the auth mechanisms
    if (g_server) {
        printf("Press Y to EnablePeerSecurity for app-app \n");
        char option[2];
        int i = scanf("%s", option);
        QCC_UNUSED(i);
        status = g_msgBus->EnablePeerSecurity(iauthMechanism.c_str(), new MyAuthListener(), "authserver-keystore", false);
        QCC_ASSERT(status == ER_OK);
    } else {
        printf("Press Y to EnablePeerSecurity for app-app \n");
        char option[2];
        int i = scanf("%s", option);
        QCC_UNUSED(i);
        status = g_msgBus->EnablePeerSecurity(iauthMechanism.c_str(), new MyAuthListener(), "authclient-keystore", false);
        QCC_ASSERT(status == ER_OK);
    }

    if (!g_server) {
        printf("Press Y to start the message flow \n");
        char option[2];
        int i = scanf("%s", option);
        QCC_UNUSED(i);
        printf("----------------------------------------------- \n");
        //The client sends method call, get prop, set prop, GetAllPop signal to service
        ProxyBusObject clientProxy(*g_msgBus, g_proxyName.c_str(), "/a/b", g_sessionId);
        status = clientProxy.IntrospectRemoteObject();
        QCC_ASSERT(ER_OK == status);
        Message reply(*g_msgBus);
        const InterfaceDescription* ifc = clientProxy.GetInterface("test.interface");
        QCC_ASSERT(ifc != NULL);

        //Make the method call;
        const InterfaceDescription::Member* pingMethod;
        pingMethod = ifc->GetMember("my_ping");
        MsgArg pingArgs("s", "Hello World");
        status = clientProxy.MethodCall(*pingMethod, &pingArgs, 1, reply, 50000);
        printf("Method Call status is %s \n", QCC_StatusText(status));
        if (status == ER_OK) {
            printf("Method call returned '%s' \n", reply->GetArg(0)->v_string.str);
        }

        //Make GetProp(my_prop1) call
        MsgArg val;
        status = clientProxy.GetProperty("test.interface", "my_prop1", val);
        printf("GetProperty my_prop1 status is %s \n", QCC_StatusText(status));
        if (status == ER_OK) {
            int iVal = 0;
            val.Get("i", &iVal);
            printf("GetProp 'my_prop1' returned %d \n", iVal);
        }

        //Make GetProp(my_prop1) call
        status = clientProxy.GetProperty("test.interface", "my_prop2", val);
        printf("GetProperty my_prop2 status is %s \n", QCC_StatusText(status));
        if (status == ER_OK) {
            String sVal;
            val.Get("s", &sVal);
            printf("GetProp 'my_prop2' returned %s \n", sVal.c_str());
        }

        //Make SetProp(my_prop1) call
        status = val.Set("i", 421);
        QCC_ASSERT(ER_OK == status);
        status = clientProxy.SetProperty("test.interface", "my_prop1", val);
        printf("SetProperty my_prop1 status is %s \n", QCC_StatusText(status));

        //Make SetProp(my_prop2) call
        status = val.Set("s", "Set Property Business");
        QCC_ASSERT(ER_OK == status);
        status = clientProxy.SetProperty("test.interface", "my_prop2", val);
        printf("SetProperty my_prop2 status is %s \n", QCC_StatusText(status));

        //Make GetAllProperties call
        status = clientProxy.GetAllProperties("test.interface", val);
        printf("GetAllProperties status is %s \n", QCC_StatusText(status));
        if (status == ER_OK) {
            size_t numprops;
            MsgArg* props;
            MsgArg* propval;
            char*propname;
            status = val.Get("a{sv}", &numprops, &props);
            QCC_ASSERT(ER_OK == status);
            std::cout << "Num of props " << numprops << std::endl;
            status = props[0].Get("{sv}", &propname, &propval);
            QCC_ASSERT(ER_OK == status);
            printf("GAP Value of prop1 fetched is '%s' \n", propname);
            status = props[1].Get("{sv}", &propname, &propval);
            QCC_ASSERT(ER_OK == status);
            printf("GAP Value of prop2 fetched is '%s' \n", propname);
        }

        //Send a signal
        status = testObj->SendSignal();
        printf("Signal status is %s \n", QCC_StatusText(status));
        printf("----------------------------------------------- \n");
    } else if (g_server) {

        printf("Press Y to start the message flow \n");
        char option[2];
        int i = scanf("%s", option);
        QCC_UNUSED(i);
        printf("----------------------------------------------- \n");
        //The server side sends method call, get prop, set prop, GetAllPop signal to service
        ProxyBusObject clientProxy(*g_msgBus, g_proxyName.c_str(), "/a/b", g_sessionId);
        status = clientProxy.IntrospectRemoteObject();
        QCC_ASSERT(ER_OK == status);
        Message reply(*g_msgBus);
        const InterfaceDescription* ifc = clientProxy.GetInterface("test.interface");
        QCC_ASSERT(ifc != NULL);

        //Make the method call;
        const InterfaceDescription::Member* pingMethod;
        pingMethod = ifc->GetMember("my_ping");
        MsgArg pingArgs("s", "Hello World");
        status = clientProxy.MethodCall(*pingMethod, &pingArgs, 1, reply, 50000);
        printf("Method Call status is %s \n", QCC_StatusText(status));
        if (status == ER_OK) {
            printf("Method call returned '%s' \n", reply->GetArg(0)->v_string.str);
        }

        //Make GetProp(my_prop1) call
        MsgArg val;
        status = clientProxy.GetProperty("test.interface", "my_prop1", val);
        printf("GetProperty my_prop1 status is %s \n", QCC_StatusText(status));
        if (status == ER_OK) {
            int iVal = 0;
            val.Get("i", &iVal);
            printf("GetProp 'my_prop1' returned %d \n", iVal);
        }

        //Make GetProp(my_prop1) call
        status = clientProxy.GetProperty("test.interface", "my_prop2", val);
        printf("GetProperty my_prop2 status is %s \n", QCC_StatusText(status));
        if (status == ER_OK) {
            String sVal;
            val.Get("s", &sVal);
            printf("GetProp 'my_prop1' returned %s \n", sVal.c_str());
        }

        //Make SetProp(my_prop1) call
        status = val.Set("i", 421);
        QCC_ASSERT(ER_OK == status);
        status = clientProxy.SetProperty("test.interface", "my_prop1", val);
        printf("SetProperty my_prop1 status is %s \n", QCC_StatusText(status));

        //Make SetProp(my_prop2) call
        status = val.Set("s", "Set Property Business");
        QCC_ASSERT(ER_OK == status);
        status = clientProxy.SetProperty("test.interface", "my_prop2", val);
        printf("SetProperty my_prop2 status is %s \n", QCC_StatusText(status));

        //Make GetAllProperties call
        status = clientProxy.GetAllProperties("test.interface", val);
        printf("GetAllProperties status is %s \n", QCC_StatusText(status));
        if (status == ER_OK) {
            size_t numprops;
            MsgArg* props;
            MsgArg* propval;
            char*propname;
            status = val.Get("a{sv}", &numprops, &props);
            QCC_ASSERT(ER_OK == status);
            std::cout << "Num of props " << numprops << std::endl;
            status = props[0].Get("{sv}", &propname, &propval);
            QCC_ASSERT(ER_OK == status);
            printf("GAP Value of prop1 fetched is '%s' \n", propname);
            status = props[1].Get("{sv}", &propname, &propval);
            QCC_ASSERT(ER_OK == status);
            printf("GAP Value of prop2 fetched is '%s' \n", propname);
        }

        //Send a signal
        status = testObj->SendSignal();
        printf("Signal status is %s \n", QCC_StatusText(status));
        printf("----------------------------------------------- \n");
    }

    printf("Press Y to exit app. \n");
    char option[2];
    int i = scanf("%s", option);
    QCC_UNUSED(i);

    g_msgBus->Disconnect();
    g_msgBus->Stop();
    g_msgBus->Join();
    //TODO - Cleanup and exit

#ifdef ROUTER
    AllJoynRouterShutdown();
#endif
    AllJoynShutdown();
    return (int) status;
}