/**
 * @file
 * Sample implementation of an AllJoyn service for stress testing.
 * This service object implements TWO interfaces
 * INTERFACE1
       my_ping (7 input , 7 ouput params : udis ay au ai
       my_signal (ay)
 * INTERFACE2
       my_ping (7 input , 7 ouput params : udis ay au ai
       my_signal (ay)

 *  Method Call: (X + 4X + 4X) bytes
 *  Method Reply: (X + 4X + 4X) bytes
 *  On each Reply, two signals are emitted. Sitgnal size- 9X bytes

 * X = 12000 for TCP
 * X = 5000 for BT

 * Session  PORT = 560
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

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <vector>

#include <qcc/Debug.h>
#include <qcc/Environ.h>
#include <qcc/Mutex.h>
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

namespace org {
namespace alljoyn {
namespace alljoyn_test {
const char* InterfaceName1 = "org.alljoyn.alljoyn_test.Interface1";
const char* DefaultWellKnownName = "org.alljoyn.alljoyn_test";
const char* ObjectPath = "/org/alljoyn/alljoyn_test";
const char* InterfaceName2 = "org.alljoyn.alljoyn_test.Interface2";
}
}
}

/** Static top level message bus object */
static BusAttachment* g_msgBus = NULL;
static String g_wellKnownName = ::org::alljoyn::alljoyn_test::DefaultWellKnownName;
size_t num_elements = 130000;
static volatile sig_atomic_t g_interrupt = false;

/** Signal handler */
static void SigIntHandler(int sig)
{
    g_interrupt = true;
    printf("Pressed Ctrl-C..exiting \n");
    _exit(-1);
}

/** This is for the client AllJoynListener receives discovery events from AllJoyn */
class MyBusListener : public BusListener, public SessionPortListener, public SessionListener {
  public:
    MyBusListener() : BusListener(), SessionPortListener() { }

    bool AcceptSessionJoiner(SessionPort sessionPort, const char* joiner, const SessionOpts& opts)
    {
        printf("Session Joined with: joiner=%s opts.transport=%d \n", joiner, opts.transports);
        return true;
    }

    void SessionJoined(SessionPort sessionPort, SessionId sessionId, const char* joiner)
    {
        printf("Session Established: joiner=%s, sessionId=%u\n", joiner, sessionId);
        this->sessionId = sessionId;
    }

    void NameOwnerChanged(const char* name, const char* previousOwner, const char* newOwner)
    {
        printf("NameOwnerChanged(%s, %s, %s)\n",
               name,
               previousOwner ? previousOwner : "null",
               newOwner ? newOwner : "null");
    }

    SessionId getSessionId() { return sessionId; }

  private:
    SessionId sessionId;

};

/** Static bus listener */
static MyBusListener g_busListener;


class LocalTestObject : public BusObject {

  public:

    LocalTestObject(const char* path)
        : BusObject(path),
        my_signal_member1(NULL),
        my_signal_member2(NULL)
    {
        QStatus status;
        big_byte_chunk = new uint8_t[num_elements];

        /* Add the test interface to this object */
        const InterfaceDescription* regTestIntf = g_msgBus->GetInterface(::org::alljoyn::alljoyn_test::InterfaceName1);
        assert(regTestIntf);
        AddInterface(*regTestIntf);
        /* Add the values interface to this object */
        const InterfaceDescription* valuesIntf = g_msgBus->GetInterface(::org::alljoyn::alljoyn_test::InterfaceName2);
        assert(valuesIntf);
        AddInterface(*valuesIntf);

        my_signal_member1 = regTestIntf->GetMember("my_signal");
        assert(my_signal_member1);
        my_signal_member2 =  valuesIntf->GetMember("my_signal");
        assert(my_signal_member2);


        /* Register the method handlers with the object */
        const MethodEntry methodEntries[] = {
            { regTestIntf->GetMember("my_ping"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Ping) },
            {  valuesIntf->GetMember("my_ping"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Ping) }
        };
        status = AddMethodHandlers(methodEntries, ArraySize(methodEntries));
        if (ER_OK != status) {
            QCC_LogError(status, ("Failed to register method handlers for LocalTestObject"));
        }
    }

    void ObjectRegistered(void)
    {
        BusObject::ObjectRegistered();
    }

    void Ping(const InterfaceDescription::Member* member, Message& msg)
    {

        /* Reply with same string that was sent to us */
        MsgArg arg[7];
        arg[0] = (*(msg->GetArg(0)));
        arg[1] = (*(msg->GetArg(1)));
        arg[2] = (*(msg->GetArg(2)));
        arg[3] = (*(msg->GetArg(3)));
        arg[4] = (*(msg->GetArg(4)));
        arg[5] = (*(msg->GetArg(5)));
        arg[6] = (*(msg->GetArg(6)));

        printf("[%s].my_ping[%d]  Pinged from %s \n", msg->GetInterface(), 1, msg->GetDestination());
        QStatus status = MethodReply(msg, arg, 7);
        if (ER_OK != status) {
            QCC_LogError(status, ("Ping: Error sending reply"));
        }


        MsgArg arg1;
        status = arg1.Set("ay", num_elements, big_byte_chunk);

        /* Emitting Interface1.Signal */
        double i = (double)qcc::Rand8() / 255.0;
        uint8_t ttl = 0;
        if (i > 0.9) {
            ttl = 1;
            printf("Emitting Signal with ttl=1 \n");
        }
        status = Signal(NULL, msg->GetSessionId(), *my_signal_member1, &arg1, 1, ttl, 0);
        if (ER_OK != status) {
            QCC_LogError(status, ("Ping: Error sending Interface1.signal"));
        }

        /* Emitting Interface2.signal */
        status = Signal(NULL, msg->GetSessionId(), *my_signal_member2, &arg1, 1, 0, 0);
        if (ER_OK != status) {
            QCC_LogError(status, ("Ping: Error sending Interface2.signal"));
        }


    }

    uint8_t* big_byte_chunk;
    const InterfaceDescription::Member* my_signal_member1;
    const InterfaceDescription::Member* my_signal_member2;
};



static void usage(void)
{
    printf("Usage: ajtservice_stress  [-n] <name> \n\n");
    printf("\n");
}

/** Main entry point */
int main(int argc, char** argv)
{
    QStatus status = ER_OK;

    printf("AllJoyn Library version:- %s\n", ajn::GetVersion());
    printf("AllJoyn Library build info: %s\n", ajn::GetBuildInfo());

    /* Install SIGINT handler */
    signal(SIGINT, SigIntHandler);

    /* Parse command line args */
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
        } else {
            status = ER_FAIL;
            printf("Unknown option %s\n", argv[i]);
            usage();
            exit(1);
        }
    }


    /* Create message bus */
    g_msgBus = new BusAttachment("ajtservice_stress", true);

    /* Add org.alljoyn.alljoyn_test interface1 */
    InterfaceDescription* testIntf1 = NULL;
    status = g_msgBus->CreateInterface(::org::alljoyn::alljoyn_test::InterfaceName1, testIntf1);
    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to create interface %s", ::org::alljoyn::alljoyn_test::InterfaceName1));
        return -1;
    }

    /* Add method call and signal to Interface1 */
    testIntf1->AddSignal("my_signal", "ay", NULL, 0);
    testIntf1->AddMethod("my_ping", "udiayauais", "udiayauais", "i,i,i,i,i,i,i,o,o,o,o,o,o,o", 0);
    testIntf1->Activate();

    /* Add org.alljoyn.alljoyn_test.values interface2 */
    InterfaceDescription* testIntf2 = NULL;
    status = g_msgBus->CreateInterface(::org::alljoyn::alljoyn_test::InterfaceName2, testIntf2);
    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to create interface %s", ::org::alljoyn::alljoyn_test::InterfaceName2));
        return -1;
    }

    /* Add Method call and signal to Interface2 */
    testIntf2->AddSignal("my_signal", "ay", NULL, 0);
    testIntf2->AddMethod("my_ping", "udiayauais", "udiayauais", "i,i,i,i,i,i,i,o,o,o,o,o,o,o", 0);
    testIntf2->Activate();


    status = g_msgBus->Start();
    if (ER_OK != status) {
        QCC_LogError(status, ("BusAttachment::Start failed"));
        return -1;
    }

    /* Register local objects and connect to the daemon */
    LocalTestObject testObj(::org::alljoyn::alljoyn_test::ObjectPath);
    g_msgBus->RegisterBusObject(testObj);

    /* Register a bus listener in order to get discovery indications */
    g_msgBus->RegisterBusListener(g_busListener);

    /* Connect to the daemon */
    status = g_msgBus->Connect();
    if (ER_OK != status) {
        QCC_LogError(status, ("BusAttachment::connect failed"));
        return -1;
    }

    /* If service - request name, advertise it and create session */
    status = g_msgBus->RequestName(g_wellKnownName.c_str(), DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE);
    if (ER_OK != status) {
        QCC_LogError(status, ("Request Name failed for [%s]", g_wellKnownName.c_str()));
        return -1;
    }

    /* Begin Advertising the well-known name */
    status = g_msgBus->AdvertiseName(g_wellKnownName.c_str(), TRANSPORT_ANY);

    if (ER_OK != status) {
        QCC_LogError(status, ("Sending org.alljoyn.Bus.Advertise failed "));
        return status;
    }

    /* Create a session for incoming client connections */
    SessionOpts optspp(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
    SessionPort sessport = 560;
    status = g_msgBus->BindSessionPort(sessport, optspp, g_busListener);
    if (status != ER_OK) {
        QCC_LogError(status, ("BindSessionPort failed"));
        return status;
    }

    /* WaitSTop is deprecated. So, check for interuppt periodically */
    while (g_interrupt == false) {
        qcc::Sleep(100);
    }

    /* Deregister the bus object */
    g_msgBus->UnregisterBusObject(testObj);

    /* Clean up msg bus */
    if (g_msgBus) {
        delete g_msgBus;
    }

    printf("%s exiting with status %d (%s)\n", argv[0], status, QCC_StatusText(status));

    return (int) status;
}
