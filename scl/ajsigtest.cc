/**
 * @file
 * Sessionless signal sender app
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
#include <assert.h>

#include <vector>

#include <qcc/Debug.h>
#include <qcc/String.h>
#include <qcc/Environ.h>
#include <qcc/Util.h>
#include <qcc/StringUtil.h>
#include <qcc/Thread.h>
#include <qcc/time.h>

#include <alljoyn/BusAttachment.h>
#include <alljoyn/BusObject.h>
#include <alljoyn/DBusStd.h>
#include <alljoyn/AllJoynStd.h>
#include <alljoyn/version.h>

#include <alljoyn/Status.h>

#ifdef _WIN32
#include <sys/timeb.h>
#include <time.h>
#endif

#define QCC_MODULE "ALLJOYN"

using namespace std;
using namespace qcc;
using namespace ajn;

static char g_ObjectPath[] = "/org/alljoyn/bbsigtest";
static char g_InterfaceName[] = "org.alljoyn.bbsigtest";
static String g_WellKnownName = "org.alljoyn.signaltest";
static String g_Prefix = "sigtest";

/** Static top level message bus object */
static BusAttachment* g_msgBus = NULL;

static unsigned long g_timeToLive = 30;
static bool g_debug = false;
static TransportMask g_transport = TRANSPORT_IP;
static SessionId g_SessionId = 0;
static uint32_t g_sleepTime = 60000;  //default of 1 minute
static uint32_t g_payload = 50;
static bool g_random = false;
static bool g_random_ttl = false;
static uint32_t StartTime = 0;
static uint32_t SignalArrivalTime = 0;

static uint32_t g_member_count = 0;
static uint32_t g_total_participants = 0;
static bool g_server = false;

std::map<qcc::String, std::pair<uint32_t, uint32_t> > SignalList;

static volatile sig_atomic_t g_interrupt = false;

static void GetMyTimeNow(Timespec* ts)
{
#ifdef _WIN32
    struct _timeb timebuffer;
    _ftime(&timebuffer);
    ts->seconds = timebuffer.time;
    ts->mseconds = timebuffer.millitm;
#else
    struct timespec _ts;
    clock_gettime(CLOCK_REALTIME, &_ts);
    ts->seconds = _ts.tv_sec;
    ts->mseconds = _ts.tv_nsec / 1000000;
#endif
}

static void PrintInfo() {

    printf("----------------------------------- \n");
    static uint32_t total_sig_count = 0;
    std::map<qcc::String, std::pair<uint32_t, uint32_t> >::iterator it;
    for (it = SignalList.begin(); it != SignalList.end(); ++it) {
        printf("From %s - Total signal count- %u, Last signal #- %u, Missed signals- %u  \n",  it->first.c_str(), it->second.first, it->second.second, it->second.second - it->second.first);
        total_sig_count += (it->second.second - it->second.first);
    }
    printf("Total signals missed = %u \n", total_sig_count);
    printf("----------------------------------- \n");
}


static void SigIntHandler(int sig)
{
    g_interrupt = true;
    printf("Interrupted by Ctl-C..bye\n");
    PrintInfo();
    _exit(-1);
}

class MyBusListener : public BusListener, public SessionPortListener, public SessionListener {

  public:

    bool AcceptSessionJoiner(SessionPort sessionPort, const char* joiner, const SessionOpts& opts)
    {
        return true;
    }

    void SessionJoined(SessionPort sessionPort, SessionId sessionId, const char* joiner)
    {
        g_SessionId = sessionId;
        printf("=============> Session Established: joiner=%s, sessionId=%u\n", joiner, sessionId);
        QStatus status = g_msgBus->SetSessionListener(sessionId, this);
        if (ER_OK != status) {
            QCC_LogError(status, ("Failed to SetSessionListener(%u)", sessionId));
        }
    }

    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix)
    {
        printf("FoundAdvertisedName(name=%s, transport=0x%x, prefix=%s)\n", name, transport, namePrefix);
        g_msgBus->EnableConcurrentCallbacks();
        if (strcmp(namePrefix, g_Prefix.c_str()) == 0) {
            SessionId sessionId = 0;
            SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, true, SessionOpts::PROXIMITY_ANY, transport);
            QStatus status = g_msgBus->JoinSession(name, 545, this, sessionId, opts);
            if (ER_OK != status) {
                QCC_LogError(status, ("JoinSession(%s) failed", name));
                exit(-1);
            } else {
                g_SessionId = sessionId;
            }
        }
    }

    void LostAdvertisedName(const char* name, const TransportMask transport, const char* prefix)
    {
        printf("LostAdvertisedName(name=%s, transport=0x%x,  prefix=%s)\n", name, transport, prefix);
    }

    void SessionLost(SessionId sessid)
    {
        printf("Session Lost  %u\n", sessid);
        PrintInfo();
        _exit(-1);
    }

    void SessionMemberAdded(SessionId id, const char* uniqueName)
    {
        printf("%s was added to session %u\n", uniqueName, id);
        g_member_count++;
    }

};

class LocalTestObject : public BusObject {

  public:
    LocalTestObject(const char* path) :
        BusObject(path),
        sls_signal_member(NULL)
    {
        QStatus status = ER_OK;

        /* Add org.alljoyn.alljoyn_test interface */
        InterfaceDescription* testIntf = NULL;
        status = g_msgBus->CreateInterface(g_InterfaceName, testIntf);
        if ((ER_OK == status) && testIntf) {
            testIntf->AddSignal("sls_signal", "utqayuu", NULL, 0);
            testIntf->Activate();
            AddInterface(*testIntf);
        } else {
            QCC_LogError(status, ("Failed to create interface %s", g_InterfaceName));
            return;
        }

        /* Get sls_signal member */
        if (ER_OK == status) {
            sls_signal_member = testIntf->GetMember("sls_signal");
            assert(sls_signal_member);
        }
    }

    QStatus SendSignal() {

        static uint32_t count = 1;
        static uint32_t count_infinite_ttl = 1;
        QStatus status = ER_OK;
        uint8_t flags = 0;
        Message msg(*g_msgBus);
        assert(sls_signal_member);

        Timespec ts;
        GetMyTimeNow(&ts);
        MsgArg arg[6];

        uint32_t tbufsize = 0;

        //if random only then random payload
        if (!g_random) {
            tbufsize = g_payload;
        } else {
            tbufsize = 50 + random() % g_payload;
        }

        uint32_t ttimeToLive = g_timeToLive;
        //Set infinite ttl if you want to interleave ttl and infinite ttl packets. Set it with 50% probablity
        if ((g_random_ttl) && (random() % 2 == 0)) {
            ttimeToLive = 0;
        }

        uint8_t*buf = new uint8_t[tbufsize];
        arg[0].Set("u", count);
        arg[1].Set("t", ts.seconds);
        arg[2].Set("q", ts.mseconds);
        arg[3].Set("ay", tbufsize, buf);
        arg[4].Set("u", ttimeToLive);
        arg[5].Set("u", count_infinite_ttl);

        if (g_debug) { printf("Sec is %lu, ms is %u \n", ts.seconds, ts.mseconds); }
        printf("SendSignal #: %u %x\n", count, count);
        fflush(stdout);
        status = Signal(NULL, g_SessionId, *sls_signal_member, arg, 6, ttimeToLive, flags, &msg);
        count++;
        if (ttimeToLive == 0) {
            count_infinite_ttl++;
        }
        delete buf;
        return status;
    }

    const InterfaceDescription::Member* sls_signal_member;
};

class SignalReceiver : public MessageReceiver {

  public:

    void SignalHandler(const InterfaceDescription::Member* member, const char* sourcePath, Message& msg) {

        static uint32_t expected_infinite_ttl_count = 1;
        uint32_t c = 0;
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("u", &c);
        uint64_t receivedSeconds = 0;
        const MsgArg* arg1((msg->GetArg(1)));
        arg1->Get("t", &receivedSeconds);
        uint16_t receivedMseconds = 0;
        const MsgArg* arg2((msg->GetArg(2)));
        arg2->Get("q", &receivedMseconds);

        uint32_t ttl = 0;
        const MsgArg* arg3((msg->GetArg(4)));
        arg3->Get("u", &ttl);
        uint32_t received_infinite_ttl_count = 0;
        const MsgArg* arg4((msg->GetArg(5)));
        arg4->Get("u", &received_infinite_ttl_count);

        uint32_t length = msg->GetArg(3)->v_scalarArray.numElements;

        if (ttl == 0) {
            if (expected_infinite_ttl_count != received_infinite_ttl_count) {
                printf("Missed infinite ttl signal. Expected %u, received %u \n", expected_infinite_ttl_count, received_infinite_ttl_count);
                assert(false);
            }
            expected_infinite_ttl_count++;
        }

        Timespec ts;
        GetMyTimeNow(&ts);
        uint32_t diff = (ts.seconds - receivedSeconds);

        SignalList[msg->GetSender()].first++;
        SignalList[msg->GetSender()].second = c;
        if (g_debug) {
            printf("Receiver- CTS: %lu, RTS: %lu  \n", ts.seconds, receivedSeconds);
            printf("Receiver- CTmS: %u, RTmS: %u  \n", ts.mseconds, receivedMseconds);
        }
        SignalArrivalTime = GetTimestamp();
        printf("[%u] RxSignal:me: %s, ttl=%u ms, length=%u from: %s - %u %x in %u ms\n", (SignalArrivalTime - StartTime), g_msgBus->GetUniqueName().c_str(), ttl, length,  msg->GetSender(), c, c,  diff * 1000 + (ts.mseconds - receivedMseconds));
        fflush(stdout);
        fflush(stderr);
    }

};


static void usage(void)
{
    printf("Mode 1: The program can send signals interleaved with infinite ttl and finite ttl and with random payload. This works only for two peers \n");
    printf("-----------------------------------------------------------------------\n");
    printf("./ajsigtest -n sigtest.one -f sigtest -udp -r 0 -t 30 -sleep 300000 -mem 2 -random -payload 129000 -randomttl -s \n");
    printf("./ajsigtest -n sigtest.two -f sigtest -udp -r 0 -t 30 -sleep 300000 -mem 2 -random -payload 129000 -randomttl \n");
    printf("-----------------------------------------------------------------------\n");

    printf("Mode 2: Multiple peers are involved in a multipoint session and they can send signals with a specified ttl and a payload of 50 bytes only. \n");
    printf("-----------------------------------------------------------------------\n");
    printf("./ajsigtest -n sigtest.one -f sigtest -tcp -r 500 -t 30 -sleep 120000 -mem 3 -s\n");
    printf("./ajsigtest -n sigtest.two -f sigtest -tcp -r 500 -t 30 -sleep 120000 -mem 3\n");
    printf("./ajsigtest -n sigtest.three -f sigtest -tcp -r 500 -t 30 -sleep 120000 -mem 3\n");
    printf("-----------------------------------------------------------------------\n");

    printf("Options:\n");
    printf("   -h              = Print this help message\n");
    printf("   -?              = Print this help message\n");
    printf("   -r #            = Signal rate (delay in ms between signals sent; default = 0)\n");
    printf("   -payload #      = Payload will be between 50 and <payload> bytes \n");
    printf("   -t #            = TTL for the signals (in s)\n");
    printf("   -n <wkn>        = WKN to be used.\n");
    printf("   -d              = put debug timer prints.\n");
    printf("   -f              = prefix for discovery\n");
    printf("   -random         = randomize payload \n");
    printf("   -randomttl      = infinite ttl and finite ttl interleaved (50 pc packets are infinite ttl and vice versa \n");
}


/** Main entry point */
int main(int argc, char** argv)
{
    QStatus status = ER_OK;
    unsigned long signalDelay = 0;

    printf("AllJoyn Library version: %s\n", ajn::GetVersion());
    printf("AllJoyn Library build info: %s\n", ajn::GetBuildInfo());

    /* Install SIGINT handler */
    signal(SIGINT, SigIntHandler);

    //Start the timer
    StartTime = GetTimestamp();

    /* Parse command line args */
    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp("-h", argv[i]) || 0 == strcmp("-?", argv[i])) {
            usage();
            exit(0);
        } else if (0 == strcmp("-r", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                signalDelay = strtoul(argv[i], NULL, 10);
            }
        } else if (0 == strcmp("-t", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_timeToLive = qcc::StringToU32(argv[i], 0, 30);
            }
        } else if (0 == strcmp("-payload", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_payload = qcc::StringToU32(argv[i], 0, 50);
            }

        } else if (0 == strcmp("-n", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_WellKnownName = argv[i];
            }
        } else if (0 == strcmp("-f", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_Prefix = argv[i];
            }
        } else if (0 == strcmp("-sleep", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_sleepTime = qcc::StringToU32(argv[i], 0, 60000);
            }
        } else if (0 == strcmp("-mem", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_total_participants = qcc::StringToU32(argv[i], 0, 0);
            }
        } else if (0 == strcmp("-d", argv[i])) {
            g_debug = true;
        } else if (0 == strcmp("-tcp", argv[i])) {
            g_transport = TRANSPORT_TCP;
        } else if (0 == strcmp("-s", argv[i])) {
            g_server = true;
        } else if (0 == strcmp("-udp", argv[i])) {
            g_transport = TRANSPORT_UDP;
        } else if (0 == strcmp("-random", argv[i])) {
            g_random = true;
        } else if (0 == strcmp("-randomttl", argv[i])) {
            g_random_ttl = true;
        } else {
            status = ER_FAIL;
            printf("Unknown option %s\n", argv[i]);
            usage();
            exit(1);
        }
    }

    if ((g_random) && (g_total_participants > 2)) {
        printf("In the random payload mode, you cannot have more than 2 participants. \n");
        usage();
        exit(1);
    }

    if ((g_random_ttl) && (g_total_participants > 2)) {
        printf("In the interleaved mode, you cannot have more than 2 participants. \n");
        usage();
        exit(1);
    }

    if ((g_payload < 50) || (g_payload > 130000)) {
        printf("Payload cannot be less than 50 or greater than 130000 %u \n", g_payload);
        usage();
        exit(-1);
    }

    if (g_total_participants == 0) {
        printf("Total participants not set \n");
        usage();
        exit(-1);
    }

    printf("Payload is %u \n", g_payload);
    printf("Payload is %s \n", (g_random) ? "Random" : "Fixed");

    /* Create message bus */
    g_msgBus = new BusAttachment("ajsigtest", true);

    /* Start the msg bus */
    status = g_msgBus->Start();
    if (ER_OK != status) {
        QCC_LogError(status, ("Bus::Start failed"));
        exit(1);
    }

    /* Register object and start the bus */
    LocalTestObject* testObj = new LocalTestObject(g_ObjectPath);
    g_msgBus->RegisterBusObject(*testObj);

    /* Get env vars */
    Environ* env = Environ::GetAppEnviron();
    qcc::String clientArgs = env->Find("BUS_ADDRESS");
    if (!clientArgs.empty()) {
        status = g_msgBus->Connect(clientArgs.c_str());
    } else {
        status = g_msgBus->Connect();
    }

    if (ER_OK != status) {
        QCC_LogError(status, ("Connect to bus failed"));
        exit(1);
    }

    printf("Unique name is %s  \n", g_msgBus->GetUniqueName().c_str());
    MyBusListener myBusListener;
    g_msgBus->RegisterBusListener(myBusListener);

    if (g_server) {
        /* Create a session for incoming client connections */
        SessionPort SESSION_PORT = 545;
        SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, true, SessionOpts::PROXIMITY_ANY, g_transport);
        status = g_msgBus->BindSessionPort(SESSION_PORT, opts, myBusListener);
        if (status != ER_OK) {
            QCC_LogError(status, ("BindSessionPort failed"));
            exit(-1);
        }

        /* Request a well-known name */
        status = g_msgBus->RequestName(g_WellKnownName.c_str(), DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE);
        if (status != ER_OK) {
            QCC_LogError(status, ("RequestName(%s) failed. ", g_WellKnownName.c_str()));
            exit(-1);
        }

        /* Begin Advertising the well-known name */
        status = g_msgBus->AdvertiseName(g_WellKnownName.c_str(), g_transport);
        if (ER_OK != status) {
            QCC_LogError(status, ("Advertise name(%s) failed ", g_WellKnownName.c_str()));
            exit(-1);
        }
    }

    if (!g_server) {
        status = g_msgBus->FindAdvertisedNameByTransport(g_Prefix.c_str(), g_transport);
        if (status != ER_OK) {
            QCC_LogError(status, ("FindAdvertisedName failed "));
            exit(-1);
        }
    }

    const InterfaceDescription* Intf1 = g_msgBus->GetInterface(g_InterfaceName);
    const InterfaceDescription::Member*  signal_member = Intf1->GetMember("sls_signal");
    SignalReceiver signalReceiver;
    status = g_msgBus->RegisterSignalHandler(&signalReceiver,
                                             static_cast<MessageReceiver::SignalHandler>(&SignalReceiver::SignalHandler),
                                             signal_member,
                                             NULL);

    printf("Waiting for %u participants to join the session \n", g_total_participants);
    while (g_total_participants != (g_member_count + 1)) {
        qcc::Sleep(1000);
    }
    if (g_server) {
        qcc::Sleep(20);
    }

    uint32_t startTime = GetTimestamp();
    uint32_t endTime = GetTimestamp();
    while (true) {

        endTime = GetTimestamp();
        if ((endTime - startTime) > g_sleepTime) {
            printf("Time  %u exceeds  %u specified. program exits  \n", (endTime - startTime), g_sleepTime);
            break;
        }
        QStatus status = testObj->SendSignal();
        if (status != ER_OK) {
            QCC_LogError(status, ("Failed to send signal"));
        }
        if (signalDelay > 0) {
            qcc::Sleep(signalDelay);
        }
        if (g_interrupt) {
            break;
        }
    }

    /* Clean up time */
    delete testObj;
    delete g_msgBus;
    PrintInfo();
    printf("ajsigtest exiting with %d (%s)\n", status, QCC_StatusText(status));

    return (int) status;
}
