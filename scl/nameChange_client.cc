/**
 * @file
 * @brief  Sample implementation of an AllJoyn client.
 *
 * This is a simple client that will run and change the 'name' property of the
 * 'org.alljoyn.Bus.signal_sample' service then exit.
 */
/******************************************************************************
 * Copyright AllSeen Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for any
 *    purpose with or without fee is hereby granted, provided that the above
 *    copyright notice and this permission notice appear in all copies.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/
#include <qcc/platform.h>

#include <signal.h>
#include <stdio.h>
#include <vector>

#include <qcc/String.h>

#include <alljoyn/BusAttachment.h>
#include <alljoyn/Init.h>
#include <alljoyn/version.h>
#include <alljoyn/AllJoynStd.h>
#include <alljoyn/Status.h>

using namespace std;
using namespace qcc;
using namespace ajn;

/** Static top level message bus object */
static BusAttachment* s_msgBus = NULL;

static const char* INTERFACE_NAME = "org.alljoyn.Bus.signal_sample";
static const char* SERVICE_NAME = "org.alljoyn.Bus.signal_sample";
static const char* SERVICE_PATH = "/";
static const SessionPort SERVICE_PORT = 25;

static bool s_joinComplete = false;
static SessionId s_sessionId = 0;

static bool withDescription = false;
static String introLang = "";

static volatile sig_atomic_t s_interrupt = false;

static void CDECL_CALL SigIntHandler(int sig)
{
    QCC_UNUSED(sig);
    s_interrupt = true;
}

/** AllJoynListener receives discovery events from AllJoyn */
class MyBusListener : public BusListener {
  public:
    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix)
    {
        QCC_UNUSED(transport);
        if (0 == strcmp(name, SERVICE_NAME)) {
            printf("FoundAdvertisedName(name='%s', prefix='%s')\n", name, namePrefix);

            /* We found a remote bus that is advertising basic service's well-known name so connect to it. */
            /* Since we are in a callback we must enable concurrent callbacks before calling a synchronous method. */
            s_msgBus->EnableConcurrentCallbacks();
            SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
            QStatus status = s_msgBus->JoinSession(name, SERVICE_PORT, NULL, s_sessionId, opts);
            if (ER_OK == status) {
                printf("JoinSession SUCCESS (Session id=%d).\n", s_sessionId);
            } else {
                printf("JoinSession failed (status=%s).\n", QCC_StatusText(status));
            }
        }
        s_joinComplete = true;
    }

    void NameOwnerChanged(const char* busName, const char* previousOwner, const char* newOwner)
    {
        if (newOwner && (0 == strcmp(busName, SERVICE_NAME))) {
            printf("NameOwnerChanged: name='%s', oldOwner='%s', newOwner='%s'.\n",
                   busName,
                   previousOwner ? previousOwner : "<none>",
                   newOwner ? newOwner : "<none>");
        }
    }
};

/** Start the message bus, report the result to stdout, and return the result status. */
QStatus StartMessageBus(void)
{
    QStatus status = s_msgBus->Start();

    if (ER_OK == status) {
        printf("BusAttachment started.\n");
    } else {
        printf("BusAttachment::Start failed.\n");
    }

    return status;
}

/** Handle the connection to the bus, report the result to stdout, and return the result status. */
QStatus ConnectToBus(void)
{
    QStatus status = s_msgBus->Connect();

    if (ER_OK == status) {
        printf("BusAttachment connected to '%s'.\n", s_msgBus->GetConnectSpec().c_str());
    } else {
        printf("BusAttachment::Connect('%s') failed.\n", s_msgBus->GetConnectSpec().c_str());
    }

    return status;
}

/** Register a bus listener in order to get discovery indications and report the event to stdout. */
void RegisterBusListener(void)
{
    /* Static bus listener */
    static MyBusListener s_busListener;

    s_msgBus->RegisterBusListener(s_busListener);
    printf("BusListener registered.\n");
}

/** Begin discovery on the well-known name of the service to be called, report the result to
 *  stdout, and return the result status.
 */
QStatus FindAdvertisedName(void)
{
    /* Begin discovery on the well-known name of the service to be called */
    QStatus status = s_msgBus->FindAdvertisedName(SERVICE_NAME);

    if (status == ER_OK) {
        printf("org.alljoyn.Bus.FindAdvertisedName ('%s') succeeded.\n", SERVICE_NAME);
    } else {
        printf("org.alljoyn.Bus.FindAdvertisedName ('%s') failed (%s).\n", SERVICE_NAME, QCC_StatusText(status));
    }

    return status;
}

/** Wait for join session to complete, report the event to stdout, and return the result status. */
QStatus WaitForJoinSessionCompletion(void)
{
    unsigned int count = 0;

    while (!s_joinComplete && !s_interrupt) {
        if (0 == (count++ % 10)) {
            printf("Waited %u seconds for JoinSession completion.\n", count / 10);
        }

#ifdef _WIN32
        Sleep(100);
#else
        usleep(100 * 1000);
#endif
    }

    return s_joinComplete && !s_interrupt ? ER_OK : ER_ALLJOYN_JOINSESSION_REPLY_CONNECT_FAILED;
}

/** Introspect the remote object, change the 'name' property, report the result to stdout, and return
 * the result status.
 */
QStatus DoNameChange(char* newName)
{
    ProxyBusObject remoteObj(*s_msgBus, SERVICE_NAME, SERVICE_PATH, s_sessionId);
    //QStatus status = remoteObj.IntrospectRemoteObject();
    QStatus status1;
    uint32_t timeout = 30000;

    if (withDescription) {

        /*Need to have introspectable interface in order to call Introspect */
        const InterfaceDescription* introIntf = remoteObj.GetInterface(org::allseen::Introspectable::InterfaceName);
        if (!introIntf) {
            introIntf = s_msgBus->GetInterface(org::allseen::Introspectable::InterfaceName);
            QCC_ASSERT(introIntf);
            remoteObj.AddInterface(*introIntf);

        }

        /* Attempt to retrieve introspection from the remote object using sync call*/
        Message reply(*s_msgBus);
        MsgArg lang("s", introLang.c_str());
        const InterfaceDescription::Member* introMember = introIntf->GetMember("IntrospectWithDescription");
        QCC_ASSERT(introMember);
        status1 = remoteObj.MethodCall(*introMember, &lang, 1, reply, timeout);
        if (ER_OK == status1) {
            printf("Introspection XML in sample: %s\n", reply->GetArg(0)->v_string.str);
        }


        /* Parse the XML reply */
        if (ER_OK == status1) {
            qcc::String ident = reply->GetSender();
            ident += " : ";
            ident += reply->GetObjectPath();
            status1 = remoteObj.ParseXml(reply->GetArg(0)->v_string.str, ident.c_str());
        }

    } else {

        /*Need to have introspectable interface in order to call Introspect */
        const InterfaceDescription* introIntf = remoteObj.GetInterface(org::freedesktop::DBus::Introspectable::InterfaceName);
        if (!introIntf) {
            introIntf = s_msgBus->GetInterface(org::freedesktop::DBus::Introspectable::InterfaceName);
            QCC_ASSERT(introIntf);
            remoteObj.AddInterface(*introIntf);

        }


        /* Attempt to retrieve introspection from the remote object using sync call */
        Message reply(*s_msgBus);
        const InterfaceDescription::Member* introMember = introIntf->GetMember("Introspect");
        QCC_ASSERT(introMember);
        status1 = remoteObj.MethodCall(*introMember, NULL, 0, reply, timeout);

        /* Parse the XML reply */
        if (ER_OK == status1) {
            printf("Introspection XML in sample: %s\n", reply->GetArg(0)->v_string.str);
            qcc::String ident = reply->GetSender();
            ident += " : ";
            ident += reply->GetObjectPath();
            status1 = remoteObj.ParseXml(reply->GetArg(0)->v_string.str, ident.c_str());
        }

    }
    if (ER_OK == status1) {
        if (newName) {
            status1 = remoteObj.SetProperty(INTERFACE_NAME, "name", newName);

            if (ER_OK == status1) {
                printf("SetProperty to change the 'name' property to '%s' was successful.\n", newName);
            } else {
                printf("Error calling SetProperty to change the 'name' property.\n");
            }
        } else {
            status1 = ER_END_OF_DATA;
            printf("Error new name not given: nameChange_client [new name].\n");
        }
    } else {
        printf("Introspection of '%s' (path='%s') failed.\n", SERVICE_NAME, SERVICE_PATH);
        printf("Make sure the service is running before launching the client.\n");
    }

    return status1;
}

static void usage(void)
{
    printf("Usage: nameChange_Client [-h <name>] [-slang] [-uslang] [-wd] [-d] \n\n");
    printf("Options:\n");
    printf("   -h                    = Print this help message\n");
    printf("   -?                    = Print this help message\n");
    printf("   -slang                = Introspect with translator supported language\n");
    printf("   -uslang               = Introspect with langugae not supported by translator\n");
    printf("   -wd                   = Introspect without description\n");
    printf("   -d                    = Introspect with description \n");
    printf("\n");
}

int TestAppMain(int argc, char** argv, char** envArg)
{
    QCC_UNUSED(envArg);
    printf("AllJoyn Library version: %s.\n", ajn::GetVersion());
    printf("AllJoyn Library build info: %s.\n", ajn::GetBuildInfo());

    /* Install SIGINT handler */
    signal(SIGINT, SigIntHandler);

    /* Parse command line args */
    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp("-h", argv[i]) || 0 == strcmp("-?", argv[i])) {
            usage();
            exit(0);
        } else if (0 == strcmp("-slang", argv[i])) {
            introLang = "de";
        } else if (0 == strcmp("-uslang", argv[i])) {
            introLang = "xyz";
        } else if (0 == strcmp("-wd", argv[i])) {
            withDescription = false;
        } else if (0 == strcmp("-d", argv[i])) {
            withDescription = true;
        } else {
            printf("Unknown option %s\n", argv[i]);
            usage();
            exit(1);
        }
    }


    QStatus status = ER_OK;

    /* Create message bus */
    s_msgBus = new BusAttachment("myApp", true);

    /* This test for NULL is only required if new() behavior is to return NULL
     * instead of throwing an exception upon an out of memory failure.
     */
    if (!s_msgBus) {
        status = ER_OUT_OF_MEMORY;
    }

    if (ER_OK == status) {
        status = StartMessageBus();
    }

    if (ER_OK == status) {
        status = ConnectToBus();
    }

    if (ER_OK == status) {
        RegisterBusListener();
        status = FindAdvertisedName();
    }

    if (ER_OK == status) {
        status = WaitForJoinSessionCompletion();
    }

    if (ER_OK == status) {
        status = DoNameChange(NULL);
    }

    /* Deallocate bus */
    delete s_msgBus;
    s_msgBus = NULL;

    printf("Name change client exiting with status 0x%04x (%s).\n", status, QCC_StatusText(status));

    return (int) status;
}

/** Main entry point */
int CDECL_CALL main(int argc, char** argv, char** envArg)
{
    QStatus status = AllJoynInit();
    if (ER_OK != status) {
        return 1;
    }
#ifdef ROUTER
    status = AllJoynRouterInit();
    if (ER_OK != status) {
        AllJoynShutdown();
        return 1;
    }
#endif

    int ret = TestAppMain(argc, argv, envArg);

#ifdef ROUTER
    AllJoynRouterShutdown();
#endif
    AllJoynShutdown();

    return ret;
}
