/******************************************************************************
 * Copyright (c) 2016 Open Connectivity Foundation (OCF) and AllJoyn Open
 *    Source Project (AJOSP) Contributors and others.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Copyright 2016 Open Connectivity Foundation and Contributors to
 *    AllSeen Alliance. All rights reserved.
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

#include <alljoyn/AboutData.h>
#include <alljoyn/AboutListener.h>
#include <alljoyn/AboutObjectDescription.h>
#include <alljoyn/AboutProxy.h>
#include <alljoyn/BusAttachment.h>
#include <alljoyn/Init.h>
#include <alljoyn/Session.h>
#include <alljoyn/SessionListener.h>

#include <qcc/String.h>
#include <qcc/time.h>
#include <qcc/Debug.h>
#include <qcc/Thread.h>

#include <signal.h>
#include <stdio.h>
 #include <iomanip>
#include <map>


#define QCC_MODULE "ALLJOYN"

/*
 * Note the removal of almost all Error handling to make the sample code more
 * straight forward to read.  This is only used here for demonstration actual
 * programs should check the return values of all method calls.
 */
using namespace ajn;
using namespace std;
using namespace qcc;

static volatile sig_atomic_t s_interrupt = false;

// The interface name should be the only thing required to find and form a
// connection between the service and the client using the about feature.
static String interface_name = "com.example.about.feature.interface.sample";

static uint32_t count_fifty_percentile = 0;
static uint32_t count_ninety_five_percentile = 0;
static uint32_t count_remaining = 0;
static uint32_t startTimeStamp = 0;


static bool joinsession = false;

static void CDECL_CALL SigIntHandler(int sig) {
    QCC_UNUSED(sig);
    s_interrupt = true;
}

BusAttachment* g_bus = NULL;

class MySessionListener : public SessionListener {
    void SessionLost(SessionId sessionId, SessionLostReason reason) {
        cout << "SessionLost sessionId = " << sessionId << ", Reason = " << reason << endl;
    }
};


/*Map to store the announcements*/
static std::map<String, uint32_t> announcementMap;

// Print out the fields found in the AboutData. Only fields with known signatures
// are printed out.  All others will be treated as an unknown field.

void printAboutData(AboutData& aboutData, const char* language, int tabNum)
{
    size_t count = aboutData.GetFields();

    const char** fields = new const char*[count];
    aboutData.GetFields(fields, count);

    for (size_t i = 0; i < count; ++i) {
        for (int j = 0; j < tabNum; ++j) {
            cout << "\t";
        }
        cout << "Key: " << fields[i];

        MsgArg* tmp;
        aboutData.GetField(fields[i], tmp, language);
        cout << "\t";
        if (tmp->Signature() == "s") {
            const char* tmp_s;
            tmp->Get("s", &tmp_s);
            cout << tmp_s;
        } else if (tmp->Signature() == "as") {
            size_t las;
            MsgArg* as_arg;
            tmp->Get("as", &las, &as_arg);
            for (size_t j = 0; j < las; ++j) {
                const char* tmp_s;
                as_arg[j].Get("s", &tmp_s);
                cout << tmp_s;
            }
        } else if (tmp->Signature() == "ay") {
            size_t lay;
            uint8_t* pay;
            tmp->Get("ay", &lay, &pay);
            for (size_t j = 0; j < lay; ++j) {
                cout << hex << static_cast<int>(pay[j]) << " ";
            }
        } else {
            cout << "User Defined Value\tSignature: " << tmp->Signature().c_str();
        }
        cout << "\n";
    }
    delete [] fields;
}

void printAboutConnectionsData() {
    cout << "*********************************************************************************\n";
    cout << "Total No of Announcements Received " << dec << announcementMap.size() << "\n";
    cout << "No of announcements received within 1.25s =" << dec << count_fifty_percentile << "\n";
    cout << "No of announcements received within 10.25s =" << dec << count_ninety_five_percentile << "\n";
    cout << "No of announcements received after 10.25s =" << dec << count_remaining << "\n";
}

class MyAboutListener : public AboutListener {
    void Announced(const char* busName, uint16_t version, SessionPort port, const MsgArg& objectDescriptionArg, const MsgArg& aboutDataArg) {
        /*Printing Time Stap Upon Receiving the announcement*/
        uint32_t curTimestamp = GetTimestamp();
        uint32_t diff = curTimestamp - startTimeStamp;
        static int count = 0;
        count++;

        QCC_LogError(ER_OK, ("ANNOUNCEMENT RECEIVED: %u with interface %s", count, interface_name.c_str()));

        String busString(busName);

        if (!announcementMap.empty()) {
            if (announcementMap.find(busString) != announcementMap.end()) {
                cerr << "\n\n\nDUPLICATE with " << busString << "\n\n\n";
                s_interrupt = true;
                return;
            }
        }

        if (diff <= 1250) {
            count_fifty_percentile++;
        } else if ((diff > 1250) && (diff < 10250)) {
            count_ninety_five_percentile++;
        } else {
            count_remaining++;
        }

        AboutData aboutData(aboutDataArg);

        AboutObjectDescription aod(objectDescriptionArg);

        std::pair<String, uint32_t> currentAnnouncement(busString, diff);
        announcementMap.insert(currentAnnouncement);

        AboutObjectDescription objectDescription;
        objectDescription.CreateFromMsgArg(objectDescriptionArg);
        cout << "*********************************************************************************\n";
        cout << "Announce signal discovered\n";
        cout << "\tFrom bus " <<  busName << endl;
        cout << "\tAnnouncements Received Number: " << dec << count << endl;
        cout << "\tAbout version " << version << endl;
        cout << "\tSessionPort " << port << endl;
        cout << "\tObjectDescription:" << endl;
        size_t path_num = aod.GetPaths(NULL, 0);
        const char** paths = new const char*[path_num];
        aod.GetPaths(paths, path_num);
        for (size_t i = 0; i < path_num; ++i) {
            cout << "\t\t" << paths[i] << endl;
            size_t intf_num = aod.GetInterfaces(paths[i], NULL, 0);
            const char** intfs = new const char*[intf_num];
            aod.GetInterfaces(paths[i], intfs, intf_num);
            for (size_t j = 0; j < intf_num; ++j) {
                cout << "\t\t\t" << intfs[j] << endl;
            }
            delete [] intfs;
        }
        delete [] paths;
        cout << "\tAboutData:" << endl;
        printAboutData(aboutData, NULL, 2);
        cout << "*********************************************************************************" << endl;
        QStatus status = ER_OK;

        if (g_bus != NULL && joinsession) {
            SessionId sessionId;
            SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
            g_bus->EnableConcurrentCallbacks();
            status = g_bus->JoinSession(busName, port, &sessionListener, sessionId, opts);
            cout << "SessionJoined sessionId = " << sessionId << ", status = " << QCC_StatusText(status) << endl;
            if (ER_OK == status && 0 != sessionId) {
                AboutProxy aboutProxy(*g_bus, busName, sessionId);

                MsgArg objArg;
                aboutProxy.GetObjectDescription(objArg);
                cout << "*********************************************************************************" << endl;
                cout << "AboutProxy.GetObjectDescription:" << endl;
                AboutObjectDescription aod(objArg);
                size_t path_num = aod.GetPaths(NULL, 0);
                const char** paths = new const char*[path_num];
                aod.GetPaths(paths, path_num);
                for (size_t i = 0; i < path_num; ++i) {
                    cout << "\t" << paths[i] << endl;
                    size_t intf_num = aod.GetInterfaces(paths[i], NULL, 0);
                    const char** intfs = new const char*[intf_num];
                    aod.GetInterfaces(paths[i], intfs, intf_num);
                    for (size_t j = 0; j < intf_num; ++j) {
                        cout << "\t\t" << intfs[j] << endl;
                    }
                    delete [] intfs;
                }
                delete [] paths;

                MsgArg aArg;
                aboutProxy.GetAboutData("en", aArg);
                cout << "*********************************************************************************" << endl;
                cout << "AboutProxy.GetAboutData: (Default Language)" << endl;
                AboutData aboutData(aArg);
                printAboutData(aboutData, NULL, 1);
                size_t lang_num;
                lang_num = aboutData.GetSupportedLanguages();
                // If the lang_num == 1 we only have a default language
                if (lang_num > 1) {
                    const char** langs = new const char*[lang_num];
                    aboutData.GetSupportedLanguages(langs, lang_num);
                    char* defaultLanguage;
                    aboutData.GetDefaultLanguage(&defaultLanguage);
                    // print out the AboutData for every language but the
                    // default it has already been printed.
                    for (size_t i = 0; i < lang_num; ++i) {
                        if (strcmp(defaultLanguage, langs[i]) != 0) {
                            status = aboutProxy.GetAboutData(langs[i], aArg);
                            if (ER_OK == status) {
                                aboutData.CreatefromMsgArg(aArg, langs[i]);
                                cout << "AboutProxy.GetAboutData: (" << langs[i] << ")" << endl;
                                printAboutData(aboutData, langs[i], 1);
                            }
                        }
                    }
                    delete [] langs;
                }

                uint16_t ver;
                aboutProxy.GetVersion(ver);
                cout << "*********************************************************************************" << endl;
                cout << "AboutProxy.GetVersion " << ver << endl;
                cout << "*********************************************************************************" << endl;

                const char* path;
                objectDescription.GetInterfacePaths(interface_name.c_str(), &path, 1);
                cout << "Calling " << path << "/" << interface_name.c_str() << endl;
                ProxyBusObject proxyObject(*g_bus, busName, path, sessionId);
                status = proxyObject.IntrospectRemoteObject();
                if (status != ER_OK) {
                    cout << "Failed to introspect remote object." << endl;
                }
                MsgArg arg("s", "ECHO Echo echo...\n");
                Message replyMsg(*g_bus);
                status = proxyObject.MethodCall(interface_name.c_str(), "Echo", &arg, 1, replyMsg);
                if (status != ER_OK) {
                    cout << "Failed to call Echo method." << endl;
                    return;
                }
                char* echoReply;
                status = replyMsg->GetArg(0)->Get("s", &echoReply);
                if (status != ER_OK) {
                    cout << "Failed to read Echo method reply." << endl;
                }
                cout << "Echo method reply: " << echoReply << endl;
            }
        } else if (joinsession) {
            cout << "BusAttachment is NULL" << endl;
        }
    }
    MySessionListener sessionListener;
};

static void usage(void)
{
    cout << "Usage: AboutClient_test \n" << endl;
    cout << "Options:" << endl;
    cout << "   -f <interface-name> = Interface name to be found" << endl;
    cout << "   -s                  = Join session accept announcement is received" << endl;
    cout << "   -time <time of execution> = Assign time limit of the for the program to execute in miliseconds." << endl;
    cout << "\n\t\t(com.example.about.feature.interface.sample by default)" << endl;
}


int CDECL_CALL main(int argc, char** argv)
{
    uint32_t executionTime = 0;

    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp("-h", argv[i])) {
            usage();
            exit(0);
        } else if (0 == strcmp("-f", argv[i])) {
            ++i;
            if (i == argc) {
                cout << "option " << argv[i - 1] << " requires a parameter" << endl;
                usage();
                exit(1);
            } else {
                interface_name = argv[i];
            }
        } else if (0 == strcmp("-time", argv[i])) {
            ++i;
            if (i == argc) {
                cout << "option " << argv[i - 1] << " requires a parameter" << endl;
                usage();
                exit(1);
            } else {
                executionTime = atoi(argv[i]);
            }
        } else if (0 == strcmp("-s", argv[i])) {
            ++i;
            joinsession = true;
        } else {
            cout << "Unknown option " << argv[i] << endl;
            usage();
            exit(1);
        }
    }

    if (AllJoynInit() != ER_OK) {
        return 1;
    }
#ifdef ROUTER
    if (AllJoynRouterInit() != ER_OK) {
        AllJoynShutdown();
        return 1;
    }
#endif

    cout << "INTERFACE NAME " <<  interface_name.c_str() << endl;
    /* Install SIGINT handler so Ctrl + C deallocates memory properly */
    signal(SIGINT, SigIntHandler);


    QStatus status;

    g_bus = new BusAttachment("AboutServiceTest", true);

    status = g_bus->Start();
    if (ER_OK == status) {
        cout << "BusAttachment started." << endl;
    } else {
        cout << "FAILED to start BusAttachment (" << QCC_StatusText(status) << ")" << endl;
        exit(1);
    }

    status = g_bus->Connect();
    if (ER_OK == status) {
        cout << "BusAttachment connect succeeded." << endl;
    } else {
        cout << "FAILED to connect to router node (" << QCC_StatusText(status) << ")" << endl;
        exit(1);
    }

    MyAboutListener aboutListener;
    g_bus->RegisterAboutListener(aboutListener);

    const char* interfaces[] = { interface_name.c_str() };
    status = g_bus->WhoImplements(interfaces, sizeof(interfaces) / sizeof(interfaces[0]));
    startTimeStamp =  g_bus->GetTimestamp();

    if (ER_OK == status) {
        cout << "WhoImplements called." << endl;
    } else {
        cout << "WhoImplements call FAILED with status " << QCC_StatusText(status) << endl;
        exit(1);
    }

    /* Perform the service asynchronously until the user signals for an exit. */
    if (ER_OK == status) {
        while (s_interrupt == false) {
            qcc::Sleep(100);

            if (executionTime > 0 && ((g_bus->GetTimestamp() - startTimeStamp) >= executionTime)) {
                cout << "Exiting after " << dec << executionTime << "ms have elapsed as specified." << endl;
                s_interrupt = true;
            }
        }
    }

    printAboutConnectionsData();

    g_bus->UnregisterAboutListener(aboutListener);
    delete g_bus;
#ifdef ROUTER
    AllJoynRouterShutdown();
#endif
    AllJoynShutdown();
    return 0;
}