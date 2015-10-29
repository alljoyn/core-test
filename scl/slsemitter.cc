/**
 * @file
 * Sessionless signal sender app
 */
/******************************************************************************
 * Copyright (c) Open Connectivity Foundation (OCF) and AllJoyn Open
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
#include <assert.h>

#include <vector>

#include <qcc/Debug.h>
#include <qcc/String.h>
#include <qcc/Environ.h>
#include <qcc/Util.h>
#include <qcc/Thread.h>
#include <qcc/time.h>

#include <alljoyn/BusAttachment.h>
#include <alljoyn/Init.h>
#include <alljoyn/BusObject.h>
#include <alljoyn/DBusStd.h>
#include <alljoyn/AllJoynStd.h>
#include <alljoyn/version.h>

#include <alljoyn/Status.h>

#ifdef _WIN32
#include <sys/timeb.h>
#include <time.h>
#endif

#define QCC_MODULE "SLSEMITTER TEST PROGRAM"

using namespace std;
using namespace qcc;
using namespace ajn;

/** Constants */
namespace org {
namespace alljoyn {
namespace alljoyn_test {
const char* InterfaceName = "org.alljoyn.alljoyn_test";
const char* ObjectPath = "/org/alljoyn/alljoyn_test";
}
}
}

/** Static top level message bus object */
static BusAttachment* g_msgBus = NULL;
static String g_ObjectPath = ::org::alljoyn::alljoyn_test::ObjectPath;

static bool bothSenderReceiver = false;
static unsigned long timeToLive = 0;
static bool g_debug = false;

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

static void CDECL_CALL SigIntHandler(int sig)
{
    QCC_UNUSED(sig);
    g_interrupt = true;
}

class LocalTestObject : public BusObject {

  public:
    LocalTestObject(const char* path) :
        BusObject(path),
        sls_signal_member(NULL)
    {
        QStatus status = ER_OK;

        /* Add org.alljoyn.alljoyn_test interface */
        InterfaceDescription* testIntf = NULL;
        status = g_msgBus->CreateInterface(::org::alljoyn::alljoyn_test::InterfaceName, testIntf);
        if ((ER_OK == status) && testIntf) {
            testIntf->AddSignal("sls_signal", "utq", NULL, 0);
            testIntf->Activate();
            AddInterface(*testIntf);
        } else {
            QCC_LogError(status, ("Failed to create interface %s", ::org::alljoyn::alljoyn_test::InterfaceName));
            return;
        }

        /* Get sls_signal member */
        if (ER_OK == status) {
            sls_signal_member = testIntf->GetMember("sls_signal");
            assert(sls_signal_member);
        }
    }

    QStatus SendSignal() {

        static uint32_t count = 0;
        QStatus status = ER_OK;
        uint8_t flags = ALLJOYN_FLAG_SESSIONLESS;
        Message msg(*g_msgBus);
        assert(sls_signal_member);

        Timespec ts;
        GetMyTimeNow(&ts);
        MsgArg arg[3];
        arg[0].Set("u", count);
        arg[1].Set("t", ts.seconds);
        arg[2].Set("q", ts.mseconds);
        if (g_debug) {
            std::cout << "Sec is" << ts.seconds << ", ms is " << ts.mseconds << std::endl;
        }
        std::cout << "SendSignal #: " << count << " " << std::hex << count << std::dec << std::endl;
        status = Signal(NULL, 0, *sls_signal_member, arg, 3, timeToLive, flags, &msg);
        count++;
        return status;
    }

    const InterfaceDescription::Member* sls_signal_member;
};

class SignalReceiver : public MessageReceiver {

  public:

    void SignalHandler(const InterfaceDescription::Member* member, const char* sourcePath, Message& msg) {
        QCC_UNUSED(member);
        uint32_t c = 0;
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("u", &c);
        uint64_t receivedSeconds = 0;
        const MsgArg* arg1((msg->GetArg(1)));
        arg1->Get("t", &receivedSeconds);
        uint16_t receivedMseconds = 0;
        const MsgArg* arg2((msg->GetArg(2)));
        arg2->Get("q", &receivedMseconds);
        Timespec ts;
        GetMyTimeNow(&ts);
        uint32_t diff = (ts.seconds - receivedSeconds);
        std::cout << "RxSignal: " << sourcePath << " - " << c << std::hex << c << std::dec << " in " << diff * 1000 + (ts.mseconds - receivedMseconds) << std::endl;
    }

};


static void usage(void)
{
    printf("Usage: slsemitter  [-h] [-?] [-r #] [-t #] [-o <obj path>]\n\n");
    printf("Options:\n");
    printf("   -h              = Print this help message\n");
    printf("   -?              = Print this help message\n");
    printf("   -r #            = Signal rate (delay in ms between signals sent; default = 0)\n");
    printf("   -t #            = TTL for the signals (in s)\n");
    printf("   -o <objectpath> = OjectPath to be used.\n");
    printf("   -b              = Sender and Receiver both.\n");
    printf("   -d              = put debug timer prints.\n");

}


/** Main entry point */
int TestAppMain(int argc, char** argv)
{
    QStatus status = ER_OK;
    unsigned long signalDelay = 0;

    std::cout << "AllJoyn Library version: " << ajn::GetVersion() << std::endl;
    std::cout << "AllJoyn Library build info: " << ajn::GetBuildInfo() << std::endl;

    /* Install SIGINT handler */
    signal(SIGINT, SigIntHandler);

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
                timeToLive = strtoul(argv[i], NULL, 10);
            }
        } else if (0 == strcmp("-o", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_ObjectPath = argv[i];
            }
        } else if (0 == strcmp("-b", argv[i])) {
            bothSenderReceiver = true;
        } else if (0 == strcmp("-d", argv[i])) {
            g_debug = true;
        } else {
            status = ER_FAIL;
            printf("Unknown option %s\n", argv[i]);
            usage();
            exit(1);
        }
    }

    /* Create message bus */
    g_msgBus = new BusAttachment("sessionless", true);

    /* Start the msg bus */
    status = g_msgBus->Start();
    if (ER_OK != status) {
        QCC_LogError(status, ("Bus::Start failed"));
        exit(1);
    }

    /* Register object and start the bus */
    LocalTestObject* testObj = new LocalTestObject(g_ObjectPath.c_str());
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

    const InterfaceDescription* Intf1 = g_msgBus->GetInterface(::org::alljoyn::alljoyn_test::InterfaceName);
    const InterfaceDescription::Member*  signal_member = Intf1->GetMember("sls_signal");
    SignalReceiver signalReceiver;
    if (bothSenderReceiver) {
        status = g_msgBus->RegisterSignalHandler(&signalReceiver,
                                                 static_cast<MessageReceiver::SignalHandler>(&SignalReceiver::SignalHandler),
                                                 signal_member,
                                                 NULL);
        status = g_msgBus->AddMatch("sessionless='t'");
    }

    qcc::Sleep(10);

    while (true) {
        QStatus status = testObj->SendSignal();
        if (status != ER_OK) {
            QCC_LogError(status, ("Failed to send signal"));
        }
        if (signalDelay > 0) {
            qcc::Sleep(signalDelay);
        }
        while ((!g_interrupt) && (bothSenderReceiver)) {
            qcc::Sleep(100);
        }
        if (g_interrupt) {
            break;
        }

    }

    /* Clean up time */
    delete testObj;
    delete g_msgBus;

    std::cout << argv[0] << " exiting with " << status << "(" << QCC_StatusText(status) << ")" << std::endl;

    return (int) status;
}

/** Main entry point */
int CDECL_CALL main(int argc, char** argv)
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

    int ret = TestAppMain(argc, argv);

#ifdef ROUTER
    AllJoynRouterShutdown();
#endif
    AllJoynShutdown();

    return ret;
}