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

#include <qcc/Thread.h>

#include <alljoyn/AboutData.h>
#include <alljoyn/AboutListener.h>
#include <alljoyn/AboutObjectDescription.h>
#include <alljoyn/AboutProxy.h>
#include <alljoyn/BusAttachment.h>
#include <alljoyn/Session.h>
#include <alljoyn/SessionListener.h>

#include <signal.h>
#include <stdio.h>

using namespace ajn;
using namespace std;
using namespace qcc;

enum InterfaceOptions {
    AllInterest = 0, // interested in all 20 interfaces
    Obj1Interest = 1, // only interested in 10 interfaces from object1
    Obj2Interest = 2,  // only interested in 10 interfaces from object2
    MixedInterest = 3,  // Some interfaces from object1 and some from object2
    BadInterest = 4  // Some interfaces not-existing from service
};

static InterfaceOptions g_interfaceOpt = AllInterest;

namespace allInterfaces {

const char* inf1Name = "org.alljoyn.test1";

const char* inf2Name = "org.alljoyn.test2";

const char* inf3Name = "org.alljoyn.test3";

const char* inf4Name = "org.alljoyn.test4";

const char* inf5Name = "org.alljoyn.test5";

const char* inf6Name = "org.alljoyn.test6";

const char* inf7Name = "org.alljoyn.test7";

const char* inf8Name = "org.alljoyn.test8";

const char* inf9Name = "org.alljoyn.test9";

const char* inf10Name = "org.alljoyn.test10";

const char* inf11Name = "org.alljoyn.test11";

const char* inf12Name = "org.alljoyn.test12";

const char* inf13Name = "org.alljoyn.test13";

const char* inf14Name = "org.alljoyn.test14";

const char* inf15Name = "org.alljoyn.test15";

const char* inf16Name = "org.alljoyn.test16";

const char* inf17Name = "org.alljoyn.test17";

const char* inf18Name = "org.alljoyn.test18";

const char* inf19Name = "org.alljoyn.test19";

const char* inf20Name = "org.alljoyn.test20";

const char* noexistingInfName = "org.alljoyn.noexisting";

const char* allInfNames[] = {
    inf1Name,
    inf2Name,
    inf3Name,
    inf4Name,
    inf5Name,
    inf6Name,
    inf7Name,
    inf8Name,
    inf9Name,
    inf10Name,
    inf11Name,
    inf12Name,
    inf13Name,
    inf14Name,
    inf15Name,
    inf16Name,
    inf17Name,
    inf18Name,
    inf19Name,
    inf20Name
};
size_t allInfCount = sizeof(allInfNames) / sizeof(allInfNames[0]);

const char* obj1InfNames[] = {
    inf1Name,
    inf2Name,
    inf3Name,
    inf4Name,
    inf5Name,
    inf6Name,
    inf7Name,
    inf8Name,
    inf9Name,
    inf10Name
};
size_t obj1InfCount = sizeof(obj1InfNames) / sizeof(obj1InfNames[0]);

const char* obj2InfNames[] = {
    inf11Name,
    inf12Name,
    inf13Name,
    inf14Name,
    inf15Name,
    inf16Name,
    inf17Name,
    inf18Name,
    inf19Name,
    inf20Name
};
size_t obj2InfCount = sizeof(obj2InfNames) / sizeof(obj2InfNames[0]);

const char* mixedInfNames[] = {
    inf1Name,
    inf2Name,
    inf3Name,
    inf4Name,
    inf5Name,
    inf6Name,
    inf7Name,
    inf8Name,
    inf9Name,
    inf10Name
};
size_t mixedInfCount = sizeof(mixedInfNames) / sizeof(mixedInfNames[0]);

const char* badInfNames[] = {
    inf3Name,
    inf4Name,
    inf5Name,
    noexistingInfName
};
size_t badInfCount = sizeof(badInfNames) / sizeof(badInfNames[0]);

}

static volatile sig_atomic_t s_interrupt = false;

static void SigIntHandler(int sig) {
    s_interrupt = true;
}

BusAttachment* g_bus;

class AboutThread : public Thread, public ThreadListener {
  public:
    static AboutThread* Launch(const char* busName, SessionPort port)
    {
        AboutThread* bgThread = new AboutThread(busName, port);
        bgThread->Start();

        return bgThread;
    }

    AboutThread(const char* busName, SessionPort port)
        : sender(busName), sessionPort(port) { }

    void ThreadExit(Thread* thread)
    {
        printf("Thread exit...\n");

        thread->Join();
        delete thread;
    }

  protected:

    ThreadReturn STDCALL Run(void* args)
    {
        QStatus status = ER_OK;

        SessionListener sessionListener;
        SessionId sessionId;
        SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);

        printf("Sender%s\n", sender);

        status = g_bus->JoinSession(sender, sessionPort, &sessionListener, sessionId, opts);

        if (ER_OK == status) {
            AboutProxy aboutProxy(*g_bus, sender, sessionId);

            MsgArg objArg;
            status = aboutProxy.GetObjectDescription(objArg);

            if (status == ER_OK) {
                printf("AboutProxy.GetObjectDescription:\n%s\n", objArg.ToString().c_str());
                printf("*********************************************************************************\n");

                MsgArg aArg;
                status = aboutProxy.GetAboutData("en", aArg);

                if (status == ER_OK) {
                    printf("AboutProxy.GetAboutData:\n%s\n", aArg.ToString().c_str());
                    printf("*********************************************************************************\n");

                    uint16_t ver;
                    status = aboutProxy.GetVersion(ver);

                    if (status == ER_OK) {
                        printf("*********************************************************************************\n");
                        printf("AboutProxy.GetVersion %hd\n", ver);
                        printf("*********************************************************************************\n");
                    } else {
                        printf("AboutProxy.GetVersion failed(%s)\n", QCC_StatusText(status));
                    }
                } else {
                    printf("AboutProxy.GetAboutData failed(%s)\n", QCC_StatusText(status));
                }
            } else {
                printf("AboutProxy.GetObjectDescription failed(%s)\n", QCC_StatusText(status));
            }

            g_bus->LeaveSession(sessionId);

        } else {
            printf("JoinSession failed(%s)\n", QCC_StatusText(status));
        }
        return 0;
    }

  private:
    const char* sender;
    SessionPort sessionPort;

};

class MyAboutListener : public AboutListener {
    void Announced(const char* busName, uint16_t version, SessionPort port, const MsgArg& objectDescriptionArg, const MsgArg& aboutDataArg) {
        printf("*********************************************************************************\n");
        printf("Anounce signal discovered\n");
        printf("\tFrom bus %s\n", busName);
        printf("\tAbout version %hu\n", version);
        printf("\tSessionPort %hu\n", port);

        printf("*********************************************************************************\n");

        if (g_bus != NULL) {

            SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);

            // Launch joinSession and GetAboutData in seperate thread
            AboutThread::Launch(::strdup(busName), port);

        } else {
            printf("BusAttachment is NULL\n");
        }
    }
};

static void usage(void)
{
    printf("Usage: aclientStress [-h] [-1] [-2] [-m] \n\n");
    printf("Options:\n");
    printf("   -h                    = Print this help message\n");
    printf("   -?                    = Print this help message\n");
    printf("   -1                    = Only interfaces from object1 interested\n");
    printf("   -2                    = Only interfaces from object2 interested\n");
    printf("   -m                    = Mixed interfaces from object1 and object2\n");
    printf("   -b                    = Unexisting interfaces from object1 and object2\n");
}

int main(int argc, char** argv)
{
    QStatus status;

    /* Install SIGINT handler so Ctrl + C deallocates memory properly */
    signal(SIGINT, SigIntHandler);

    /* Parse command line args */
    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp("-h", argv[i]) || 0 == strcmp("-?", argv[i])) {
            usage();
            exit(0);
        } else if (0 == strcmp("-1", argv[i])) {
            g_interfaceOpt = Obj1Interest;
        } else if (0 == strcmp("-2", argv[i])) {
            g_interfaceOpt = Obj2Interest;
        } else if (0 == strcmp("-m", argv[i])) {
            g_interfaceOpt = MixedInterest;
        } else if (0 == strcmp("-b", argv[i])) {
            g_interfaceOpt = BadInterest;
        } else {
            usage();
            exit(1);
        }
    }

    BusAttachment bus("AboutClientStress");

    g_bus = &bus;

    status = bus.Start();
    if (ER_OK == status) {
        printf("BusAttachment started.\n");
    } else {
        printf("FAILED to start BusAttachment (%s)\n", QCC_StatusText(status));
        exit(1);
    }

    status = bus.Connect();
    if (ER_OK == status) {
        printf("BusAttachment connect succeeded.\n");
    } else {
        printf("FAILED to connect to router node (%s)\n", QCC_StatusText(status));
        exit(1);
    }

    MyAboutListener aboutListener;

    bus.RegisterAboutListener(aboutListener);

    if (AllInterest == g_interfaceOpt) {
        // Client interested in all 20 interfaces
        printf("Client interested in all interfaces\n");
        status = bus.WhoImplements(::allInterfaces::allInfNames, ::allInterfaces::allInfCount);
    } else if (Obj1Interest == g_interfaceOpt) {
        // Client only interested in object1 interfaces
        printf("Client only interested in object1 interfaces\n");
        status = bus.WhoImplements(::allInterfaces::obj1InfNames, ::allInterfaces::obj1InfCount);
    } else if (Obj2Interest == g_interfaceOpt) {
        // Client only interested in object2 interfaces
        printf("Client only interested in object2 interfaces\n");
        status = bus.WhoImplements(::allInterfaces::obj2InfNames, ::allInterfaces::obj2InfCount);
    } else if (MixedInterest == g_interfaceOpt) {
        // Client interested in some interfaces from object1 and some from object2
        printf("Client interested in mixed interfaces from object1 and object2\n");
        status = bus.WhoImplements(::allInterfaces::mixedInfNames, ::allInterfaces::mixedInfCount);
    } else {
        // Client interested in unexisting interfaces
        printf("Client interested in not-existing interfaces \n");
        status = bus.WhoImplements(::allInterfaces::badInfNames, ::allInterfaces::badInfCount);
    }

    if (ER_OK == status) {
        printf("AboutListener WhoImplements succeed.\n");
    } else {
        printf("FAILED WhoImplements the AboutListener (%s)\n", QCC_StatusText(status));
        exit(1);
    }
    /* Perform the service asynchronously until the user signals for an exit. */
    if (ER_OK == status) {
        while (s_interrupt == false) {
            qcc::Sleep(100);
        }
    }
}