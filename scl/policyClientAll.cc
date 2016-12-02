/**
 * @file
 * Sample implementation of an AllJoyn client.
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
#include <qcc/platform.h>
#include <qcc/Debug.h>
#include <qcc/Thread.h>

#include <signal.h>
#include <stdio.h>
#include <vector>

#include <qcc/Environ.h>
#include <qcc/Event.h>
#include <qcc/String.h>
#include <qcc/StringUtil.h>
#include <qcc/Util.h>
#include <qcc/time.h>

#include <alljoyn/AllJoynStd.h>
#include <alljoyn/BusAttachment.h>
#include <alljoyn/DBusStd.h>
#include <alljoyn/Init.h>
#include <alljoyn/version.h>

#include <alljoyn/Status.h>

#define QCC_MODULE "ALLJOYN"

#define METHODCALL_TIMEOUT 30000

using namespace std;
using namespace qcc;
using namespace ajn;

/* setup for first test object */
namespace abcd {
const char* WellKnownName = "abcd.org";
const char* ObjectPath = "/abcd/org";
const char* InterfaceName1 = "ab.org";
const char* InterfaceName2 = "cd.org";

const char* MethodName1 = "aMethod";
const char* MethodName2 = "bMethod";
const char* MethodName3 = "cMethod";
const char* MethodName4 = "dMethod";

const char* ErrorMethod1 = "aError";
const char* ErrorMethod2 = "bError";
const char* ErrorMethod3 = "cError";
const char* ErrorMethod4 = "dError";

const char* SignalName1 = "a_signal";
const char* SignalName2 = "b_signal";
const char* SignalName3 = "c_signal";
const char* SignalName4 = "d_signal";
}

/* setup for 2nd test object */
namespace efgh {
const char* WellKnownName = "efgh.gov";
const char* ObjectPath = "/efgh/gov";
const char* InterfaceName1 = "ef.gov";
const char* InterfaceName2 = "gh.gov";

const char* MethodName1 = "eMethod";
const char* MethodName2 = "fMethod";
const char* MethodName3 = "gMethod";
const char* MethodName4 = "hMethod";

const char* ErrorMethod1 = "eError";
const char* ErrorMethod2 = "fError";
const char* ErrorMethod3 = "gError";
const char* ErrorMethod4 = "hError";

const char* SignalName1 = "e_signal";
const char* SignalName2 = "f_signal";
const char* SignalName3 = "g_signal";
const char* SignalName4 = "h_signal";

}

static const SessionPort mySessionPort = 30;    /**< Well-knwon session port value for policyClient/policyService */

static const char* g_objOutSpace = "***";
static const char* g_ifcOutSpace = "******";
static const char* g_methodOutSpace = "*********";
static const char* g_signalOutSpace = "*********";

/** Static data */
static BusAttachment* g_msgBus = NULL;

static unsigned long timeToLive = 0;

class LocalTestObject1 : public BusObject {

  public:

    LocalTestObject1(BusAttachment& bus, const char* path, unsigned long signalDelay, unsigned long disconnectDelay,
                     unsigned long reportInterval, unsigned long maxSignals, const InterfaceDescription* testIfc1,
                     const InterfaceDescription* testIfc2) :
        BusObject(path),
        signalDelay(signalDelay),
        disconnectDelay(disconnectDelay),
        reportInterval(reportInterval),
        maxSignals(maxSignals),
        ifc1(testIfc1),
        ifc2(testIfc2)
    {
        QCC_UNUSED(bus);
        QCC_ASSERT(ifc1);
        QCC_ASSERT(ifc2);

        a_signal_member = ifc1->GetMember("a_signal");
        b_signal_member = ifc1->GetMember("b_signal");
        c_signal_member = ifc2->GetMember("c_signal");
        d_signal_member = ifc2->GetMember("d_signal");

        QCC_ASSERT(a_signal_member);
        QCC_ASSERT(b_signal_member);
        QCC_ASSERT(c_signal_member);
        QCC_ASSERT(d_signal_member);
    }

    QStatus SendSignalA() {
        uint8_t flags = ALLJOYN_FLAG_GLOBAL_BROADCAST;

        MsgArg arg("a{ys}", 0, NULL);

        QCC_SyncPrintf("%s A Send signal\n", g_signalOutSpace);
        return Signal(NULL, 0, *a_signal_member, &arg, 1, timeToLive, flags);
    }

    QStatus SendSignalB() {
        uint8_t flags = ALLJOYN_FLAG_GLOBAL_BROADCAST;

        MsgArg arg("a{ys}", 0, NULL);

        QCC_SyncPrintf("%s B Send signal\n", g_signalOutSpace);
        return Signal(NULL, 0, *b_signal_member, &arg, 1, timeToLive, flags);
    }

    QStatus SendSignalC() {
        uint8_t flags = ALLJOYN_FLAG_GLOBAL_BROADCAST;

        MsgArg arg("a{ys}", 0, NULL);

        QCC_SyncPrintf("%s C Send signal\n", g_signalOutSpace);
        return Signal(NULL, 0, *c_signal_member, &arg, 1, timeToLive, flags);
    }

    QStatus SendSignalD() {
        uint8_t flags = ALLJOYN_FLAG_GLOBAL_BROADCAST;

        MsgArg arg("a{ys}", 0, NULL);

        QCC_SyncPrintf("%s D Send signal\n", g_signalOutSpace);
        return Signal(NULL, 0, *d_signal_member, &arg, 1, timeToLive, flags);
    }

    void ObjectRegistered(void)
    {

    }

    void NameAcquiredCB(Message& msg, void* context)
    {
        QCC_UNUSED(msg);
        QCC_UNUSED(context);
    }

    void AdvertiseRequestCB(Message& msg, void* context)
    {
        QCC_UNUSED(msg);
        QCC_UNUSED(context);
    }


    map<qcc::String, size_t> rxCounts;

    unsigned long signalDelay;
    unsigned long disconnectDelay;
    unsigned long reportInterval;
    unsigned long maxSignals;
    const InterfaceDescription* ifc1;
    const InterfaceDescription* ifc2;
    const InterfaceDescription::Member* a_signal_member;
    const InterfaceDescription::Member* b_signal_member;
    const InterfaceDescription::Member* c_signal_member;
    const InterfaceDescription::Member* d_signal_member;
};

class LocalTestObject2 : public BusObject {

  public:

    LocalTestObject2(BusAttachment& bus, const char* path, unsigned long signalDelay, unsigned long disconnectDelay,
                     unsigned long reportInterval, unsigned long maxSignals, const InterfaceDescription* testIfc1,
                     const InterfaceDescription* testIfc2) :
        BusObject(path),
        signalDelay(signalDelay),
        disconnectDelay(disconnectDelay),
        reportInterval(reportInterval),
        maxSignals(maxSignals),
        ifc1(testIfc1),
        ifc2(testIfc2)
    {
        QCC_UNUSED(bus);
        QCC_ASSERT(ifc1);
        QCC_ASSERT(ifc2);

        e_signal_member = ifc1->GetMember("e_signal");
        f_signal_member = ifc1->GetMember("f_signal");
        g_signal_member = ifc2->GetMember("g_signal");
        h_signal_member = ifc2->GetMember("h_signal");

        QCC_ASSERT(e_signal_member);
        QCC_ASSERT(f_signal_member);
        QCC_ASSERT(g_signal_member);
        QCC_ASSERT(h_signal_member);
    }

    QStatus SendSignalE() {
        uint8_t flags = ALLJOYN_FLAG_GLOBAL_BROADCAST;

        MsgArg arg("a{ys}", 0, NULL);

        QCC_SyncPrintf("%s E Send signal\n", g_signalOutSpace);
        return Signal(NULL, 0, *e_signal_member, &arg, 1, timeToLive, flags);
    }

    QStatus SendSignalF() {
        uint8_t flags = ALLJOYN_FLAG_GLOBAL_BROADCAST;

        MsgArg arg("a{ys}", 0, NULL);

        QCC_SyncPrintf("%s F Send signal\n", g_signalOutSpace);
        return Signal(NULL, 0, *f_signal_member, &arg, 1, timeToLive, flags);
    }
    QStatus SendSignalG() {
        uint8_t flags = ALLJOYN_FLAG_GLOBAL_BROADCAST;

        MsgArg arg("a{ys}", 0, NULL);

        QCC_SyncPrintf("%s G Send signal\n", g_signalOutSpace);
        return Signal(NULL, 0, *g_signal_member, &arg, 1, timeToLive, flags);
    }

    QStatus SendSignalH() {
        uint8_t flags = ALLJOYN_FLAG_GLOBAL_BROADCAST;

        MsgArg arg("a{ys}", 0, NULL);

        QCC_SyncPrintf("%s H Send signal\n", g_signalOutSpace);
        return Signal(NULL, 0, *h_signal_member, &arg, 1, timeToLive, flags);
    }
    void ObjectRegistered(void)
    {

    }

    void NameAcquiredCB(Message& msg, void* context)
    {
        QCC_UNUSED(msg);
        QCC_UNUSED(context);
    }

    void AdvertiseRequestCB(Message& msg, void* context)
    {
        QCC_UNUSED(msg);
        QCC_UNUSED(context);
    }


    map<qcc::String, size_t> rxCounts;

    unsigned long signalDelay;
    unsigned long disconnectDelay;
    unsigned long reportInterval;
    unsigned long maxSignals;
    const InterfaceDescription* ifc1;
    const InterfaceDescription* ifc2;
    const InterfaceDescription::Member* e_signal_member;
    const InterfaceDescription::Member* f_signal_member;
    const InterfaceDescription::Member* g_signal_member;
    const InterfaceDescription::Member* h_signal_member;
};

static volatile sig_atomic_t g_interrupt = false;

static void SigIntHandler(int sig)
{
    QCC_UNUSED(sig);
    g_interrupt = true;
}

/* Call one method or error from remote object */
static QStatus callMethodOrError(const char* wkName,
                                 const char* objPath,
                                 const char* ifcName,
                                 const char* methodName,
                                 bool callType)
{
    QCC_UNUSED(callType);
    QStatus status = ER_OK;
    bool objSecure = false;
    size_t cnt = 0;
    char buf[80];
    uint32_t pingDelay = 0;

    /* Create the remote objects that will be called */
    ProxyBusObject remoteObj1;


    /* 0 means no session id required, service and client are on same machine and talking on unix domain socket */
    remoteObj1 = ProxyBusObject(*g_msgBus, wkName, objPath, 0, objSecure);

    const InterfaceDescription* alljoynTestIntf1 = g_msgBus->GetInterface(ifcName);

    QCC_ASSERT(alljoynTestIntf1);
    remoteObj1.AddInterface(*alljoynTestIntf1);

    Message reply(*g_msgBus);
    MsgArg pingArgs[2];
    const InterfaceDescription::Member* pingMethod1;

    const InterfaceDescription* ifc1 = remoteObj1.GetInterface(ifcName);

    if (ifc1 == NULL) {
        status = ER_BUS_NO_SUCH_INTERFACE;
        QCC_SyncPrintf("Unable to Get InterfaceDecription for the %s interface\n",
                       ::abcd::InterfaceName1);
    }

    snprintf(buf, 80, "Ping String %u", static_cast<unsigned int>(++cnt));
    pingArgs[0].Set("s", buf);


    pingMethod1 = ifc1->GetMember(methodName);

    QCC_SyncPrintf("%s Calling %s \n",
                   g_methodOutSpace, methodName);

    status = remoteObj1.MethodCall(*pingMethod1, pingArgs, (pingDelay > 0) ? 2 : 1, reply, pingDelay + 50000);

    if (ER_OK == status) {
        QCC_SyncPrintf("%s %s:%s:%s ( path=%s ) returned \"%s\"\n",
                       g_methodOutSpace,
                       wkName,
                       ifcName,
                       pingMethod1->name.c_str(),
                       objPath,
                       reply->GetArg(0)->v_string.str);

    } else if (status == ER_BUS_REPLY_IS_ERROR_MESSAGE) {
        qcc::String errDescription;
        const char* errName = reply->GetErrorName(&errDescription);
        QCC_SyncPrintf("%s MethodCall on %s.%s reply was error %s %s\n",
                       g_methodOutSpace,
                       ifcName,
                       pingMethod1->name.c_str(),
                       errName,
                       errDescription.c_str());
        status = ER_OK;
    } else {
        QCC_LogError(status, ("%s MethodCall on %s.%s failed", g_methodOutSpace, ifcName, pingMethod1->name.c_str()));
    }

    return status;
}


/* Call all methods, errors and signals */
static QStatus CallAll(LocalTestObject1* testObj1,
                       LocalTestObject2* testObj2)
{
    QStatus status = ER_OK;

    QCC_SyncPrintf("\n\n%s Start object %s ...\n",
                   g_objOutSpace,
                   ::abcd::ObjectPath);

    QCC_SyncPrintf("\n%s Start interface %s ...\n\n",
                   g_ifcOutSpace,
                   ::abcd::InterfaceName1);


    /** Call method A from remote object 1 */
    status = callMethodOrError(::abcd::WellKnownName,
                               ::abcd::ObjectPath,
                               ::abcd::InterfaceName1,
                               ::abcd::MethodName1,
                               0);


    /** Call method B from remote object 1 */
    status = callMethodOrError(::abcd::WellKnownName,
                               ::abcd::ObjectPath,
                               ::abcd::InterfaceName1,
                               ::abcd::MethodName2,
                               0);

    /** Call error A from remote object 1 */
    status = callMethodOrError(::abcd::WellKnownName,
                               ::abcd::ObjectPath,
                               ::abcd::InterfaceName1,
                               ::abcd::ErrorMethod1,
                               0);


    /** Call error B from remote object 1 */
    status = callMethodOrError(::abcd::WellKnownName,
                               ::abcd::ObjectPath,
                               ::abcd::InterfaceName1,
                               ::abcd::ErrorMethod2,
                               0);

    status = testObj1->SendSignalA();

    if (ER_OK != status) {
        QCC_SyncPrintf("%s send A signal failed !\n", g_signalOutSpace);
    }

    status = testObj1->SendSignalB();

    if (ER_OK != status) {
        QCC_SyncPrintf("%s send B signal failed !\n", g_signalOutSpace);
    }


    QCC_SyncPrintf("\n%s Start interface %s ...\n\n",
                   g_ifcOutSpace,
                   ::abcd::InterfaceName2);

    /** Call method C from remote object 1 */
    status = callMethodOrError(::abcd::WellKnownName,
                               ::abcd::ObjectPath,
                               ::abcd::InterfaceName2,
                               ::abcd::MethodName3,
                               0);


    /** Call method D from remote object 1 */
    status = callMethodOrError(::abcd::WellKnownName,
                               ::abcd::ObjectPath,
                               ::abcd::InterfaceName2,
                               ::abcd::MethodName4,
                               0);


    /** Call error C from remote object 1 */
    status = callMethodOrError(::abcd::WellKnownName,
                               ::abcd::ObjectPath,
                               ::abcd::InterfaceName2,
                               ::abcd::ErrorMethod3,
                               0);

    /** Call error D from remote object 1 */
    status = callMethodOrError(::abcd::WellKnownName,
                               ::abcd::ObjectPath,
                               ::abcd::InterfaceName2,
                               ::abcd::ErrorMethod4,
                               0);

    /* Send signal C */
    status = testObj1->SendSignalC();

    if (ER_OK != status) {
        QCC_SyncPrintf("%s send C signal failed !\n", g_signalOutSpace);
    }

    status = testObj1->SendSignalD();

    if (ER_OK != status) {
        QCC_SyncPrintf("%s send D signal failed !\n", g_signalOutSpace);
    }


    QCC_SyncPrintf("\n\n%s Start object %s ...\n",
                   g_objOutSpace,
                   ::efgh::ObjectPath);

    QCC_SyncPrintf("\n%s Start interface %s ...\n\n",
                   g_ifcOutSpace,
                   ::efgh::InterfaceName1);

    /** Call method E from remote object 2 */
    status = callMethodOrError(::efgh::WellKnownName,
                               ::efgh::ObjectPath,
                               ::efgh::InterfaceName1,
                               ::efgh::MethodName1,
                               0);


    /** Call method F from remote object 2 */
    status = callMethodOrError(::efgh::WellKnownName,
                               ::efgh::ObjectPath,
                               ::efgh::InterfaceName1,
                               ::efgh::MethodName2,
                               0);

    /** Call error E from remote object 2 */
    status = callMethodOrError(::efgh::WellKnownName,
                               ::efgh::ObjectPath,
                               ::efgh::InterfaceName1,
                               ::efgh::ErrorMethod1,
                               0);

    /** Call error F from remote object 2 */
    status = callMethodOrError(::efgh::WellKnownName,
                               ::efgh::ObjectPath,
                               ::efgh::InterfaceName1,
                               ::efgh::ErrorMethod2,
                               0);

    /* Send signal E */
    status = testObj2->SendSignalE();

    if (ER_OK != status) {
        QCC_SyncPrintf("%s send E signal failed !\n", g_signalOutSpace);
    }

    /* Send signal F */
    status = testObj2->SendSignalF();

    if (ER_OK != status) {
        QCC_SyncPrintf("%s send F signal failed !\n", g_signalOutSpace);
    }

    QCC_SyncPrintf("\n%s Start interface %s ...\n\n",
                   g_ifcOutSpace,
                   ::efgh::InterfaceName2);


    /** Call method G from remote object 2 */
    status = callMethodOrError(::efgh::WellKnownName,
                               ::efgh::ObjectPath,
                               ::efgh::InterfaceName2,
                               ::efgh::MethodName3,
                               0);


    /** Call method H from remote object 2 */
    status = callMethodOrError(::efgh::WellKnownName,
                               ::efgh::ObjectPath,
                               ::efgh::InterfaceName2,
                               ::efgh::MethodName4,
                               0);

    /** Call error G from remote object 2 */
    status = callMethodOrError(::efgh::WellKnownName,
                               ::efgh::ObjectPath,
                               ::efgh::InterfaceName2,
                               ::efgh::ErrorMethod3,
                               0);

    /** Call error H from remote object 2 */
    status = callMethodOrError(::efgh::WellKnownName,
                               ::efgh::ObjectPath,
                               ::efgh::InterfaceName2,
                               ::efgh::ErrorMethod4,
                               0);

    /* Send signal G */
    status = testObj2->SendSignalG();

    if (ER_OK != status) {
        QCC_SyncPrintf("%s send G signal failed !\n", g_signalOutSpace);
    }

    /* Send signal H */
    status = testObj2->SendSignalH();

    if (ER_OK != status) {
        QCC_SyncPrintf("%s send H signal failed !\n", g_signalOutSpace);
    }

    return status;
}

/** Main entry point */
int main(int argc, char** argv)
{
    QCC_UNUSED(argc);
    QCC_UNUSED(argv);
    if (AllJoynInit() != ER_OK) {
        return 1;
    }
#ifdef ROUTER
    if (AllJoynRouterInit() != ER_OK) {
        AllJoynShutdown();
        return 1;
    }
#endif

    QStatus status = ER_OK;
    bool useIntrospection = false;
    InterfaceSecurityPolicy secPolicy = AJ_IFC_SECURITY_INHERIT;
    qcc::String pbusConnect;
    qcc::String userId;
    unsigned long repCount = 1;
    Environ* env;

    bool waitForSigint = false;
    unsigned long signalDelay = 0;
    unsigned long disconnectDelay = 0;
    unsigned long reportInterval = 1000;
    unsigned long maxSignals = 1;

    InterfaceDescription* testIntf1 = NULL;
    InterfaceDescription* testIntf2 = NULL;
    InterfaceDescription* testIntf3 = NULL;
    InterfaceDescription* testIntf4 = NULL;

    printf("AllJoyn Library version: %s\n", ajn::GetVersion());
    printf("AllJoyn Library build info: %s\n", ajn::GetBuildInfo());

    /* Install SIGINT handler */
    signal(SIGINT, SigIntHandler);


    /* Get env vars */
    env = Environ::GetAppEnviron();
    qcc::String connectArgs = env->Find("BUS_ADDRESS");

    for (unsigned long i = 0; i < repCount && !g_interrupt; i++) {

        /* Create message bus */
        g_msgBus = new BusAttachment("policyClient", true);

        if (!useIntrospection) {
            /* Add abcd interface */

            status = g_msgBus->CreateInterface(::abcd::InterfaceName1, testIntf1, secPolicy);
            if (ER_OK == status) {
                testIntf1->AddSignal("a_signal", "a{ys}", NULL, 0);
                testIntf1->AddSignal("b_signal", "a{ys}", NULL, 0);
                testIntf1->AddMethod("aMethod", "s", "s", "inStr,outStr", 0);
                testIntf1->AddMethod("bMethod", "s", "s", "inStr,outStr", 0);
                testIntf1->AddMethod("aError", "s", "s", "inStr,outStr", 0);
                testIntf1->AddMethod("bError", "s", "s", "inStr,outStr", 0);
                testIntf1->Activate();
            } else {
                QCC_LogError(status, ("Failed to create interface %s", ::abcd::InterfaceName1));
            }


            status = g_msgBus->CreateInterface(::abcd::InterfaceName2, testIntf2, secPolicy);
            if (ER_OK == status) {
                testIntf2->AddSignal("c_signal", "a{ys}", NULL, 0);
                testIntf2->AddSignal("d_signal", "a{ys}", NULL, 0);
                testIntf2->AddMethod("cMethod", "s", "s", "inStr,outStr", 0);
                testIntf2->AddMethod("dMethod", "s", "s", "inStr,outStr", 0);
                testIntf2->AddMethod("cError", "s", "s", "inStr,outStr", 0);
                testIntf2->AddMethod("dError", "s", "s", "inStr,outStr", 0);
                testIntf2->Activate();
            } else {
                QCC_LogError(status, ("Failed to create interface %s", ::abcd::InterfaceName2));
            }

            /* Add efgh interface */
            status = g_msgBus->CreateInterface(::efgh::InterfaceName1, testIntf3, secPolicy);
            if (ER_OK == status) {
                testIntf3->AddSignal("e_signal", "a{ys}", NULL, 0);
                testIntf3->AddSignal("f_signal", "a{ys}", NULL, 0);
                testIntf3->AddMethod("eMethod", "s", "s", "inStr,outStr", 0);
                testIntf3->AddMethod("fMethod", "s", "s", "inStr,outStr", 0);
                testIntf3->AddMethod("eError", "s", "s", "inStr,outStr", 0);
                testIntf3->AddMethod("fError", "s", "s", "inStr,outStr", 0);
                testIntf3->Activate();
            } else {
                QCC_LogError(status, ("Failed to create interface %s", ::efgh::InterfaceName1));
            }

            status = g_msgBus->CreateInterface(::efgh::InterfaceName2, testIntf4, secPolicy);
            if (ER_OK == status) {
                testIntf4->AddSignal("g_signal", "a{ys}", NULL, 0);
                testIntf4->AddSignal("h_signal", "a{ys}", NULL, 0);
                testIntf4->AddMethod("gMethod", "s", "s", "inStr,outStr", 0);
                testIntf4->AddMethod("hMethod", "s", "s", "inStr,outStr", 0);
                testIntf4->AddMethod("gError", "s", "s", "inStr,outStr", 0);
                testIntf4->AddMethod("hError", "s", "s", "inStr,outStr", 0);
                testIntf4->Activate();
            } else {
                QCC_LogError(status, ("Failed to create interface %s", ::efgh::InterfaceName2));
            }

        }


        /* Start the msg bus */
        if (ER_OK == status) {
            status = g_msgBus->Start();
            if (ER_OK != status) {
                QCC_LogError(status, ("BusAttachment::Start failed"));
            }
        }
        LocalTestObject1* testObj1 = NULL;
        LocalTestObject2* testObj2 = NULL;

        /* Register object for sending signal and start the bus */

        testObj1 = new LocalTestObject1(*g_msgBus, ::abcd::ObjectPath, signalDelay, disconnectDelay, reportInterval, maxSignals, testIntf1, testIntf2);
        g_msgBus->RegisterBusObject(*testObj1);

        testObj2 = new LocalTestObject2(*g_msgBus, ::efgh::ObjectPath, signalDelay, disconnectDelay, reportInterval, maxSignals, testIntf3, testIntf4);
        g_msgBus->RegisterBusObject(*testObj2);

        /* Connect to the bus */
        if (ER_OK == status) {
            if (connectArgs.empty()) {
                status = g_msgBus->Connect();
            } else {
                status = g_msgBus->Connect(connectArgs.c_str());
            }
            if (ER_OK != status) {
                QCC_LogError(status, ("BusAttachment::Connect(\"%s\") failed", connectArgs.c_str()));
            }
        }


        /* Call methods, errors and send signals */
        status = CallAll(testObj1, testObj2);

        if (ER_OK != status) {
            QCC_LogError(status, ("Method or Error calls failed"));
        }

        if (status == ER_OK && waitForSigint) {
            while (g_interrupt == false) {
                qcc::Sleep(100);
            }
        }

        /* Deallocate bus */
        delete g_msgBus;
        g_msgBus = NULL;

        if (status != ER_OK) {
            break;
        }
    }

#ifdef ROUTER
    AllJoynRouterShutdown();
#endif
    AllJoynShutdown();

    printf("policyClientAll exiting with status %d (%s)\n", status, QCC_StatusText(status));

    return (int) status;
}