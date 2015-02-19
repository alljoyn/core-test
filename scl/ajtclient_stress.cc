/**
 * @file
 * Sample implementation of an AllJoyn client stress.
 * The client discovers the stress service and joins a session.
 * If a joinSession attempt fails, then the client backs off to sleep for 60 sec and tries again.
 * After three failures, an error is thrown.
 * Client then makes method calls and receives replies and signals from the service.
 * Also see service stress program for more details.
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
#include <qcc/Debug.h>
#include <qcc/Thread.h>

#include <signal.h>
#include <stdio.h>
#include <assert.h>
#include <vector>

#include <qcc/Environ.h>
#include <qcc/Event.h>
#include <qcc/String.h>
#include <qcc/StringUtil.h>
#include <qcc/Util.h>
#include <qcc/time.h>

#include <alljoyn/BusAttachment.h>
#include <alljoyn/DBusStd.h>
#include <alljoyn/AllJoynStd.h>
#include <alljoyn/version.h>

#include <Status.h>

#define QCC_MODULE "ALLJOYN"

#define METHODCALL_TIMEOUT 30000

using namespace std;
using namespace qcc;
using namespace ajn;

/** Sample constants */
namespace org {
namespace alljoyn {
namespace alljoyn_test {
const char* InterfaceName1 = "org.alljoyn.alljoyn_test.Interface1";
const char* InterfaceName2 = "org.alljoyn.alljoyn_test.Interface2";
const char* DefaultWellKnownName = "org.alljoyn.alljoyn_test";
const char* ObjectPath = "/org/alljoyn/alljoyn_test";
}
}
}

/** Static data */
static BusAttachment* g_msgBus = NULL;
static Event g_discoverEvent;
static String g_wellKnownName = ::org::alljoyn::alljoyn_test::DefaultWellKnownName;
size_t num_elements = 12000;
static volatile sig_atomic_t g_interrupt = false;
static bool UDP = false;
static bool TCP = false;
static bool LOCAL = false;

/** AllJoynListener receives discovery events from AllJoyn */
class MyBusListener : public BusListener, public SessionPortListener, public SessionListener {

  public:
    MyBusListener() : BusListener(), SessionPortListener() { }

    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix)
    {
        printf("FoundAdvertisedName(name=%s, transport=0x%x, prefix=%s)\n", name, transport, namePrefix);
        if (0 == strcmp(name, g_wellKnownName.c_str())) {
            if ((TCP && (transport == 4)) || (UDP && (transport == 256)) || (LOCAL && (transport == 1))) {
                g_discoverEvent.SetEvent();
            }
        }
    }

    void LostAdvertisedName(const char* name, const TransportMask transport, const char* prefix)
    {
        printf("LostAdvertisedName(name=%s, transport=0x%x,  prefix=%s)\n", name, transport, prefix);
    }

    void NameOwnerChanged(const char* name, const char* previousOwner, const char* newOwner)
    {
        printf("NameOwnerChanged(%s, %s, %s)\n",
               name,
               previousOwner ? previousOwner : "null",
               newOwner ? newOwner : "null");
    }
};

/** Static bus listener */
static MyBusListener g_busListener;

/** Signal handler */
static void SigIntHandler(int sig)
{
    g_interrupt = true;
    printf("Pressed Ctrl-C..exiting \n");
    _exit(-1);
}

static void usage(void)
{
    printf("Usage: ajtclient_stress [-h] [-c #] -d [-n <well-known name>] -TCP/-UDP/-LOC \n\n");
    printf("Options:\n");
    printf("\n");
}

class SignalListeningObject : public MessageReceiver {
  public:

    void SignalHandler(const InterfaceDescription::Member*member,
                       const char* sourcePath,
                       Message& msg)
    {
        printf("[SIGNAL] ++==## signalConsumer: Signal Received [%s] --- Session id is [%u]  ##==-- \n", msg->GetInterface(), msg->GetSessionId());
    }

};


int main(int argc, char** argv)
{
    QStatus status = ER_OK;
    unsigned long pingCount = 1;
    bool discoverRemote = false;

    printf("AllJoyn Library version: %s\n", ajn::GetVersion());
    printf("AllJoyn Library build info: %s\n", ajn::GetBuildInfo());

    /* Install SIGINT handler */
    signal(SIGINT, SigIntHandler);

    /* Parse command line args */
    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp("-c", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                pingCount = strtoul(argv[i], NULL, 10);
            }
        } else if (0 == strcmp("-n", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_wellKnownName = argv[i];
            }
        } else if (0 == strcmp("-h", argv[i])) {
            usage();
            exit(0);
        } else if (0 == strcmp("-d", argv[i])) {
            discoverRemote = true;
        } else if (0 == strcmp("-UDP", argv[i])) {
            UDP = true;
        } else if (0 == strcmp("-TCP", argv[i])) {
            TCP = true;
        } else if (0 == strcmp("-LOC", argv[i])) {
            LOCAL = true;
        } else {
            status = ER_FAIL;
            printf("Unknown option %s\n", argv[i]);
            usage();
            exit(1);
        }
    }

    /* Create message bus */
    g_msgBus = new BusAttachment("ajtclient_stress", true);


    /* Register a bus listener in order to get discovery indications */
    if (ER_OK == status) {
        g_msgBus->RegisterBusListener(g_busListener);
    }

    /* Start the msg bus */
    if (ER_OK == status) {
        status = g_msgBus->Start();
        if (ER_OK != status) {
            QCC_LogError(status, ("BusAttachment::Start failed"));
            return -1;
        }
    }

    /* Connect to the bus */
    if (ER_OK == status) {
        status = g_msgBus->Connect();
        if (ER_OK != status) {
            QCC_LogError(status, ("BusAttachment::Connect() failed"));
            return -1;
        }
    }

    SessionId sessionid;
    if (ER_OK == status) {
        if (discoverRemote) {
            /* Begin discovery on the well-known name of the service to be called */
            status = g_msgBus->FindAdvertisedName(g_wellKnownName.c_str());
            if (status != ER_OK) {
                QCC_LogError(status, ("FindAdvertisedName failed "));
                return -1;
            }

            //Wait for 2 mins for any advertisement
            status = Event::Wait(g_discoverEvent, 480000);
            if (status == ER_TIMEOUT) {
                printf("\n Did not receive appropriate advertisement. ");
                return -1;
            }

            /* Join the session */
            uint8_t count = 0;
            SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
            if (LOCAL) {
                opts.transports = TRANSPORT_LOCAL;
            } else if (TCP) {
                opts.transports = TRANSPORT_TCP;
            } else if (UDP) {
                opts.transports = TRANSPORT_UDP;
            }


            while (count < 3) {
                status = g_msgBus->JoinSession(g_wellKnownName.c_str(), 560, NULL, sessionid, opts);
                if (ER_ALLJOYN_JOINSESSION_REPLY_UNREACHABLE == status) {
                    /* Do nothing */
                }
                /* If JS fails, then backoff and sleep for 60 secs, before trying again */
                if (ER_OK != status) {
                    QCC_LogError(status, ("Join Session failed for %d attempt", count));
                    qcc::Sleep(60000);
                    count++;
                } else if (ER_OK == status) {
                    printf("\n Join Session successfull [%d]\n", count);
                    break;
                }

            }

            if (ER_OK != status) {
                QCC_LogError(status, ("JoinSession fails after 3 attempts"));
                return status;
            }

        }
    }     //End of discovery

    {
        //Introspect here and register signal handlers
        ProxyBusObject remoteObj = ProxyBusObject(*g_msgBus, g_wellKnownName.c_str(), ::org::alljoyn::alljoyn_test::ObjectPath, sessionid);
        status = remoteObj.IntrospectRemoteObject();
        if (ER_OK != status) {
            QCC_LogError(status, ("Introspection of %s (path=%s) failed\n", g_wellKnownName.c_str(), ::org::alljoyn::alljoyn_test::ObjectPath));
            return -1;
        }

        const InterfaceDescription* intf1 = remoteObj.GetInterface("org.alljoyn.alljoyn_test.Interface1");
        assert(intf1);
        const InterfaceDescription::Member* mysignal_intf1  = intf1->GetMember("my_signal");

        SignalListeningObject object;
        /* register the signal handler for Interface1.my_signal */
        status =  g_msgBus->RegisterSignalHandler(&object,
                                                  static_cast<MessageReceiver::SignalHandler>(&SignalListeningObject::SignalHandler),
                                                  mysignal_intf1, NULL);
        if (status != ER_OK) {
            printf("Failed to register signal handler for %s.nameChanged\n", g_wellKnownName.c_str());
            return -1;
        }

        const InterfaceDescription* intf2 = remoteObj.GetInterface("org.alljoyn.alljoyn_test.Interface2");
        assert(intf2);
        const InterfaceDescription::Member* mysignal_intf2  = intf2->GetMember("my_signal");

        status =  g_msgBus->RegisterSignalHandler(&object,
                                                  static_cast<MessageReceiver::SignalHandler>(&SignalListeningObject::SignalHandler),
                                                  mysignal_intf2, NULL);

        printf("\n INTROSPECTION COMPLETE \n");


        /* Give time for all devices to join each other */
        printf("\n Waiting for 2 minutes for all devices to Join/Introspect each other");
        qcc::Sleep(120000);


        /* Now proceed to send data */
        uint8_t*byte_array_chunk = new uint8_t[num_elements];
        uint32_t*unsigned_array_chunk = new uint32_t[num_elements];
        int32_t*signed_array_chunk = new int32_t[num_elements];

        /* Count the no of pings */
        uint16_t ist = 0;
        uint8_t flags = 0;


        /* Call the remote method */
        while ((ER_OK == status) && pingCount--) {
            ist++;
            Message reply(*g_msgBus);

            double d = 3.14159265L;
            MsgArg pingArgs[7];
            pingArgs[2].Set("i", 50);
            pingArgs[1].Set("d", d);
            pingArgs[0].Set("u", ist);
            pingArgs[3].Set("ay", num_elements, byte_array_chunk);
            pingArgs[4].Set("au", num_elements, unsigned_array_chunk);
            pingArgs[5].Set("ai", num_elements, signed_array_chunk);
            pingArgs[6].Set("s", "qwertyuiop[]asdfghjjkkl;'zxcvbnnm,./1234567890-=!@#$%^&*()_+~QWETYUOPPLKJHGFDSAXZVNM<>?");

            const InterfaceDescription::Member* pingMethod;
            const InterfaceDescription* ifc1 = remoteObj.GetInterface(::org::alljoyn::alljoyn_test::InterfaceName1);
            const InterfaceDescription* ifc2 = remoteObj.GetInterface(::org::alljoyn::alljoyn_test::InterfaceName2);

            /* Interface1.Method Call 1 */
            pingMethod = ifc1->GetMember("my_ping");
            status = remoteObj.MethodCall(*pingMethod, pingArgs, 7, reply, 120000, flags);
            if (ER_OK == status) {
                printf("[METHOD-RET] [Ping No   %u] %s.%s (Interface1) ( path=%s ) returned %d %lf  \"%s\"\n", reply->GetArg(0)->v_int32,
                       g_wellKnownName.c_str(), pingMethod->name.c_str(),
                       ::org::alljoyn::alljoyn_test::ObjectPath,
                       reply->GetArg(2)->v_uint32,
                       reply->GetArg(1)->v_double,
                       reply->GetArg(6)->v_string.str);
            } else if (status == ER_BUS_REPLY_IS_ERROR_MESSAGE) {
                qcc::String errDescription;
                const char* errName = reply->GetErrorName(&errDescription);
                printf("[ERROR-MESSAGE] Interface1.MethodCall on %s.%s reply was error %s %s\n", ::org::alljoyn::alljoyn_test::InterfaceName1, pingMethod->name.c_str(), errName, errDescription.c_str());
                status = ER_OK;
            } else {
                QCC_LogError(status, ("[METHOD-CALL-FAILED] Interface1.MethodCall on %s.%s failed", ::org::alljoyn::alljoyn_test::InterfaceName1, pingMethod->name.c_str()));
            }

            /* Interface2.Method Call */
            pingMethod = ifc2->GetMember("my_ping");
            status = remoteObj.MethodCall(*pingMethod, pingArgs, 7, reply, 120000, flags);
            if (ER_OK == status) {
                printf("[METHOD-RET] [Ping No   %u] %s.%s (Interface2) ( path=%s ) returned %d %lf \"%s\"\n", reply->GetArg(0)->v_int32,
                       g_wellKnownName.c_str(), pingMethod->name.c_str(),
                       ::org::alljoyn::alljoyn_test::ObjectPath,
                       reply->GetArg(2)->v_uint32,
                       reply->GetArg(1)->v_double,
                       reply->GetArg(6)->v_string.str);
            } else if (status == ER_BUS_REPLY_IS_ERROR_MESSAGE) {
                qcc::String errDescription;
                const char* errName = reply->GetErrorName(&errDescription);
                printf("[ERROR-MESSAGE] Interface2.MethodCall on %s.%s reply was error %s %s\n", ::org::alljoyn::alljoyn_test::InterfaceName2, pingMethod->name.c_str(), errName, errDescription.c_str());
                status = ER_OK;
            } else {
                QCC_LogError(status, ("[METHOD-CALL-FAILED] Interface2.MethodCall on %s.%s failed", ::org::alljoyn::alljoyn_test::InterfaceName2, pingMethod->name.c_str()));
                status = ER_OK;
            }

        }
    }

    /* Sleep till you receive the signals */
    qcc::Sleep(5000);


    /* Deallocate bus */
    if (g_msgBus) {
        delete g_msgBus;
    }

    printf("%s exiting with status %d (%s)\n", argv[0], status, QCC_StatusText(status));

    return 0;
}
