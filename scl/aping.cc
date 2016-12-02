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
#include <qcc/StringUtil.h>
#include <signal.h>
#include <stdio.h>
#include <vector>
#include <map>
#include <fstream>
#include <string>
#include <streambuf>

#include <qcc/Debug.h>
#include <qcc/Environ.h>
#include <qcc/String.h>
#include <qcc/Thread.h>
#include <qcc/time.h>
#include <qcc/Util.h>
#include <qcc/Mutex.h>

#include <alljoyn/BusAttachment.h>
#include <alljoyn/Init.h>
#include <alljoyn/BusObject.h>
#include <alljoyn/DBusStd.h>
#include <alljoyn/AllJoynStd.h>
#include <alljoyn/MsgArg.h>
#include <alljoyn/version.h>

#include <alljoyn/Status.h>

#define QCC_MODULE "APING TEST PROGRAM"

using namespace std;
using namespace qcc;
using namespace ajn;

namespace org {
namespace alljoyn {
namespace alljoyn_test {
const char* DefaultWellKnownName = "some.name";
}
}
}

/** Static top level message bus object */
static BusAttachment* g_msgBus = nullptr;
static String g_wellKnownName = ::org::alljoyn::alljoyn_test::DefaultWellKnownName;
static const char* g_findPrefix = ::org::alljoyn::alljoyn_test::DefaultWellKnownName;

static bool g_stressTest = false; // flag to enable sending repeated pings
static int g_sleepBeforeReping = 0; // duration to wait between ping attempts
static bool g_keep_retrying_in_failure = false;
static uint32_t g_concurrent_threads = 4;
static uint32_t g_sleepTime = 10000; //Default duration to run
static uint32_t g_asyncPingTimeout = 10000; // Timeout value passed to ping method call
static string g_customRouterConfig;

static Mutex g_lock;

static volatile sig_atomic_t g_interrupt = false; // Keeps track of Ctrl-C sig

static std::vector<qcc::String> myNames;
static uint32_t g_index = 0; // Incremented for every name found
// sentinal is used to keep track of arguments to async method calls across
// callbacks.
static uint8_t g_sentinal = 0;

// Keep track of stats
uint32_t num_pings_attempted = 0; // Number of times PingAsync was invoked
uint32_t num_pings_successful = 0; // Number of times Ping was successful
uint32_t num_pings_timedout = 0; // Number of times Ping timed out
uint32_t num_pings_failed = 0; // Number of times Ping failed due to othr errors

static void CDECL_CALL SigIntHandler(int sig)
{
    QCC_UNUSED(sig);
    g_interrupt = true;
}

class MyBusListener : public BusListener,  public BusAttachment::PingAsyncCB {

  public:

    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix)
    {
        cout << "FoundAdvertisedName(name=" << name << ", transport=0x" << hex << transport << dec << ", prefix=" << namePrefix << ")" << endl;
        // Don't ping ourselves, even if we did discover ourself
        if (strcmp(name, g_wellKnownName.c_str()) != 0) {
            myNames.push_back(name);
            QStatus status = g_msgBus->PingAsync(name, g_asyncPingTimeout,  this, static_cast<void*>(&g_sentinal + g_index));
            num_pings_attempted++;
            g_index++;
            if (ER_OK != status) {
                QCC_LogError(status, ("PingAsync(%s) failed", name));
                num_pings_failed++;
                return;
            }
        }
    }

    void PingCB(QStatus status, void* context) {
        uint32_t index = (static_cast<uint8_t*>(context) - &g_sentinal);
        qcc::String name  = myNames[index];

        // Return early, if failed

        // It isn't terribly useful when we try to re-attempt ping
        // in some cases, viz. the name is lost or when one ping attempt
        // is already in progress.
        // In fact, the only time it makes sense to re-attempt ping is
        // when ping times out
        if (ER_OK != status) {
            QCC_LogError(status, ("PingCB failure for name: %s", name.c_str()));
            if (ER_ALLJOYN_PING_REPLY_TIMEOUT != status) {
                num_pings_failed++;
                return;
            }
            num_pings_timedout++;
        } else {
            num_pings_successful++;
            cout << "PingAsync succeeded (count = " << num_pings_successful << "). ===========================>  " << name.c_str() << endl;
        }

        // Issue the ping request again, if we are in stress mode and the flag
        // to keep trying inspite of failure is set
        if (g_stressTest) {
            // Wait for sometime, if indicated in the sleep-before-re-ping is on
            // Note that we don't want to wait if the ping timed out (that is
            // already a wait of sorts)
            if (ER_OK == status && g_sleepBeforeReping) {
                qcc::Sleep(g_sleepBeforeReping);
            }

            if (ER_OK == status || (ER_ALLJOYN_PING_REPLY_TIMEOUT == status && g_keep_retrying_in_failure)) {
                QStatus status1 = g_msgBus->PingAsync(name.c_str(), g_asyncPingTimeout, this, context);
                num_pings_attempted++;
                if (status1 != ER_OK) {
                    QCC_LogError(status1, ("PingAsync retry failure for name: %s", name.c_str()));
                    num_pings_failed++;
                }
            }
        }
    }

    void LostAdvertisedName(const char* name, TransportMask transport, const char* prefix)
    {
        cout << "LostAdvertisedName(name=" << name << ", transport=0x" << hex << transport << dec << ",  prefix=" << prefix << ")" << endl;
    }
};

static void usage(void)
{
    cout << endl << "Usage: aping " << endl << endl <<
        "Options:" << endl <<
        "   -?               = Print this help message" << endl <<
        "   -h               = Print this help message" << endl <<
        "   -n <name>        = Well-known name to advertise" << endl <<
        "   -s               = Send pings continuously (stress mode)" << endl <<
        "   -f <prefix>      = FindAdvertisedName prefix" << endl <<
        "   -u               = Advertise/Discover over UDP" << endl <<
        "   -t               = Advertise/Discover over TCP" << endl <<
        "   -l               = Advertise/Discover over LOCAL" << endl <<
        "   -dpr <ms>        = Number of ms to delay between two ping attempts" << endl <<
        "   -fa              = Retry ping even during failure" << endl <<
        "   -ct  #           = Set concurrency level" << endl <<
        "   -sleep  #        = Sleep Time" << endl <<
        "   -timeout  #      = AsyncPing timeout" << endl <<
        "   -router <config> = Router config file path (for bundled router)" << endl;
}

int TestAppMain(int argc, char** argv)
{
    const uint64_t startTime = GetTimestamp64(); // timestamp in milliseconds
    QStatus status = ER_OK;
    uint32_t transportOpts = TRANSPORT_NONE;

    cout << "AllJoyn Library version: " << ajn::GetVersion() << endl;
    cout << "AllJoyn Library build info: " << ajn::GetBuildInfo() << endl;

    // echo command line to provide distinguishing information within multipoint session
    cout << "\nINFO: The command line arguments passed to this test program are: ";
    for (int i = 0; i < argc; i++) {
        cout << argv[i] << " ";
    }
    cout << endl;

    /* Install SIGINT handler */
    signal(SIGINT, SigIntHandler);

    // Parse command-line parameters
    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp("-h", argv[i]) || 0 == strcmp("-?", argv[i])) {
            usage();
            return 0;
        } else if (0 == strcmp("-n", argv[i])) {
            ++i;
            if (i == argc) {
                cout << "option " << argv[i - 1] << " requires a parameter" << endl;
                usage();
                return 1;
            } else {
                g_wellKnownName = argv[i];
            }
        } else if (0 == strcmp("-s", argv[i])) {
            g_stressTest = true;
        } else if (0 == strcmp("-f", argv[i])) {
            ++i; // Looking for prefix to find
            if (i == argc) {
                cout << "option " << argv[i - 1] << " requires a parameter" << endl;
                usage();
                return 1;
            } else {
                g_findPrefix = argv[i];
            }
        } else if (0 == strcmp("-u", argv[i])) {
            transportOpts = TRANSPORT_UDP;
        } else if (0 == strcmp("-t", argv[i])) {
            transportOpts = TRANSPORT_TCP;
        } else if (0 == strcmp("-l", argv[i])) {
            transportOpts = TRANSPORT_LOCAL;
        } else if (0 == strcmp("-dpr", argv[i])) {
            g_sleepBeforeReping = qcc::StringToU32(argv[++i], 0);
        } else if (0 == strcmp("-fa", argv[i])) {
            g_keep_retrying_in_failure = true;
        } else if (0 == strcmp("-timeout", argv[i])) {
            ++i;
            if (i == argc) {
                cout << "option " << argv[i - 1] << " requires a parameter" << endl;
                usage();
                return 1;
            } else {
                g_asyncPingTimeout = qcc::StringToU32(argv[i], 0);
            }
        } else if (0 == strcmp("-ct", argv[i])) {
            ++i;
            if (i == argc) {
                cout << "option " << argv[i - 1] << " requires a parameter" << endl;
                usage();
                return 1;
            } else {
                g_concurrent_threads = qcc::StringToU32(argv[i], 0);
            }
        } else if (0 == strcmp("-sleep", argv[i])) {
            ++i;
            if (i == argc) {
                cout << "option " << argv[i - 1] << " requires a parameter" << endl;
                usage();
                return 1;
            } else {
                g_sleepTime = qcc::StringToU32(argv[i], 0);
            }
        }  else if (0 == strcmp("-router", argv[i])) {
            ++i;
            if (i == argc) {
                cout << "option \"-router\" requires a parameter" << endl;
                usage();
                return 1;
            } else {
#ifndef ROUTER
                cout << "Ignoring option \"-router\" for standalone router" << endl;
#else
                ifstream in(argv[i]);
                if (!in) {
                    cout << "Error: failed to open router config file " << argv[i] << endl;
                    return 1;
                } else {
                    g_customRouterConfig = string(istreambuf_iterator<char>(in), istreambuf_iterator<char>());
                }
#endif
            }
        } else {
            cout << "Unknown option " << argv[i] << endl;
            usage();
            return 1;
        }
    }

    if (AllJoynInit() != ER_OK) {
        return 1;
    }
#ifdef ROUTER
    if (g_customRouterConfig.empty()) {
        status = AllJoynRouterInit();
    } else {
        status = AllJoynRouterInitWithConfig(g_customRouterConfig.c_str());
    }
    if (status != ER_OK) {
        AllJoynShutdown();
        return 1;
    }
#endif

    /* Get env vars */
    Environ* env = Environ::GetAppEnviron();
    qcc::String clientArgs = env->Find("BUS_ADDRESS");

    MyBusListener myBusListener;
    /* Create message bus */
    g_msgBus = new BusAttachment("ajoin", true, g_concurrent_threads);
    if (g_msgBus != nullptr) {
        status = g_msgBus->Start();
        if (ER_OK != status) {
            QCC_LogError(status, ("BusAttachment::Start failed"));
            goto Exit;
        }

        /* Connect to the daemon */
        if (clientArgs.empty()) {
            status = g_msgBus->Connect();
        } else {
            status = g_msgBus->Connect(clientArgs.c_str());
        }
        if (ER_OK != status) {
            QCC_LogError(status, ("BusAttachment::Connect failed"));
            goto Exit;
        }

        g_msgBus->RegisterBusListener(myBusListener);

        /* Register local objects and connect to the daemon */
        if (ER_OK == status) {
            // Add a unique-i-fier to the well-known name
            g_wellKnownName += ".guid" + g_msgBus->GetGlobalGUIDShortString();
            /* Request a well-known name */
            QStatus status = g_msgBus->RequestName(g_wellKnownName.c_str(), DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE);
            if (status != ER_OK) {
                QCC_LogError(status, ("RequestName(%s) failed. ", g_wellKnownName.c_str()));
                goto Exit;
            }

            /* Begin Advertising the well-known name */
            status = g_msgBus->AdvertiseName(g_wellKnownName.c_str(), transportOpts);
            if (ER_OK != status) {
                QCC_LogError(status, ("Advertise name(%s) failed ", g_wellKnownName.c_str()));
                goto Exit;
            }

            status = g_msgBus->FindAdvertisedNameByTransport(g_findPrefix ? g_findPrefix : "com", transportOpts);
            if (status != ER_OK) {
                QCC_LogError(status, ("FindAdvertisedName failed "));
                goto Exit;
            }
        }

        uint32_t currentTime = GetTimestamp();
        while (!g_interrupt) {
            currentTime = GetTimestamp();
            uint32_t timeElapsed = currentTime - startTime;
            uint32_t timeRemaining = (g_sleepTime > timeElapsed) ? (g_sleepTime - timeElapsed) : 0;
            if (0 == timeRemaining) {
                cout << "Specified duration " << g_sleepTime << " has elapsed. Exiting..." << endl;
                break;
            }
            uint32_t timeToSleep = (timeRemaining > 100) ? 100 : timeRemaining;
            qcc::Sleep(timeToSleep);
        }

        if (g_interrupt) {
            cout << "Ctrl-C has been issued. Exiting..." << endl;
        }
    }

Exit:
    if (g_msgBus != nullptr) {
        g_msgBus->Stop();
        g_msgBus->Join();
        cout << "Deleting the bus attachment..." << endl;
        delete g_msgBus;
        g_msgBus = nullptr;
        cout << "Done." << endl;
    }

    cout << "Ping statistics" << endl;
    cout << "---------------" << endl;
    cout << "Number of pings attempted  = " << num_pings_attempted << endl;
    cout << "Number of pings successful = " << num_pings_successful << endl;
    cout << "Number of pings timedout   = " << num_pings_timedout << endl;
    cout << "Number of pings failed     = " << num_pings_failed << endl;

    cout << "Elapsed time is " << (GetTimestamp() - startTime) << " milliseconds" << endl;

#ifdef ROUTER
    AllJoynRouterShutdown();
#endif
    AllJoynShutdown();
    return (int) status;
}

/** Main entry point */
int CDECL_CALL main(int argc, char** argv)
{
    int ret = TestAppMain(argc, argv);
    return ret;
}