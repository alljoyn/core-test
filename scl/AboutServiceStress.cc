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
#include <qcc/Thread.h>
#include <alljoyn/BusAttachment.h>
#include <alljoyn/BusListener.h>
#include <alljoyn/BusObject.h>
#include <alljoyn/AboutObj.h>

#include <signal.h>
#include <stdio.h>
#include <set>

using namespace ajn;
using namespace std;
using namespace qcc;

// Object1 interfaces
namespace obj1Interfaces {
const char* obj1Path = "/test/alljoyn/obj1";

String inf1Name = "org.alljoyn.test1";
String interface1 = "<node>"
                    "<interface name='" + inf1Name + "'>"
                    "</interface>"
                    "</node>";

String inf2Name = "org.alljoyn.test2";
String interface2 = "<node>"
                    "<interface name='" + inf2Name + "'>"
                    "</interface>"
                    "</node>";

String inf3Name = "org.alljoyn.test3";
String interface3 = "<node>"
                    "<interface name='" + inf3Name + "'>"
                    "</interface>"
                    "</node>";

String inf4Name = "org.alljoyn.test4";
String interface4 = "<node>"
                    "<interface name='" + inf4Name + "'>"
                    "</interface>"
                    "</node>";

String inf5Name = "org.alljoyn.test5";
String interface5 = "<node>"
                    "<interface name='" + inf5Name + "'>"
                    "</interface>"
                    "</node>";

String inf6Name = "org.alljoyn.test6";
String interface6 = "<node>"
                    "<interface name='" + inf6Name + "'>"
                    "</interface>"
                    "</node>";

String inf7Name = "org.alljoyn.test7";
String interface7 = "<node>"
                    "<interface name='" + inf7Name + "'>"
                    "</interface>"
                    "</node>";

String inf8Name = "org.alljoyn.test8";
String interface8 = "<node>"
                    "<interface name='" + inf8Name + "'>"
                    "</interface>"
                    "</node>";

String inf9Name = "org.alljoyn.test9";
String interface9 = "<node>"
                    "<interface name='" + inf9Name + "'>"
                    "</interface>"
                    "</node>";

String inf10Name = "org.alljoyn.test10";
String interface10 = "<node>"
                     "<interface name='" + inf10Name + "'>"
                     "</interface>"
                     "</node>";

String obj1InfNames[] = {
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

// Consistent with C98 compiler
pair<String, String> obj1_data[] = {
    std::make_pair(inf1Name, interface1),
    std::make_pair(inf2Name, interface2),
    std::make_pair(inf3Name, interface3),
    std::make_pair(inf4Name, interface4),
    std::make_pair(inf5Name, interface5),
    std::make_pair(inf6Name, interface6),
    std::make_pair(inf7Name, interface7),
    std::make_pair(inf8Name, interface8),
    std::make_pair(inf9Name, interface9),
    std::make_pair(inf10Name, interface10)
};

set<pair<String, String> > obj1NameXmlSet(obj1_data, obj1_data + obj1InfCount);

}

// Object2 interfaces
namespace obj2Interfaces {

const char* obj2Path = "/test/alljoyn/obj2";

String inf11Name = "org.alljoyn.test11";
String interface11 = "<node>"
                     "<interface name='" + inf11Name + "'>"
                     "</interface>"
                     "</node>";

String inf12Name = "org.alljoyn.test12";
String interface12 = "<node>"
                     "<interface name='" + inf12Name + "'>"
                     "</interface>"
                     "</node>";

String inf13Name = "org.alljoyn.test13";
String interface13 = "<node>"
                     "<interface name='" + inf13Name + "'>"
                     "</interface>"
                     "</node>";

String inf14Name = "org.alljoyn.test14";
String interface14 = "<node>"
                     "<interface name='" + inf14Name + "'>"
                     "</interface>"
                     "</node>";

String inf15Name = "org.alljoyn.test15";
String interface15 = "<node>"
                     "<interface name='" + inf15Name + "'>"
                     "</interface>"
                     "</node>";

String inf16Name = "org.alljoyn.test16";
String interface16 = "<node>"
                     "<interface name='" + inf16Name + "'>"
                     "</interface>"
                     "</node>";

String inf17Name = "org.alljoyn.test17";
String interface17 = "<node>"
                     "<interface name='" + inf17Name + "'>"
                     "</interface>"
                     "</node>";

String inf18Name = "org.alljoyn.test18";
String interface18 = "<node>"
                     "<interface name='" + inf18Name + "'>"
                     "</interface>"
                     "</node>";

String inf19Name = "org.alljoyn.test19";
String interface19 = "<node>"
                     "<interface name='" + inf19Name + "'>"
                     "</interface>"
                     "</node>";

String inf20Name = "org.alljoyn.test20";
String interface20 = "<node>"
                     "<interface name='" + inf20Name + "'>"
                     "</interface>"
                     "</node>";

String obj2InfNames[] = {
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

// Consistent with C98 compiler
pair<String, String> obj2_data[] = {
    std::make_pair(inf11Name, interface11),
    std::make_pair(inf12Name, interface12),
    std::make_pair(inf13Name, interface13),
    std::make_pair(inf14Name, interface14),
    std::make_pair(inf15Name, interface15),
    std::make_pair(inf16Name, interface16),
    std::make_pair(inf17Name, interface17),
    std::make_pair(inf18Name, interface18),
    std::make_pair(inf19Name, interface19),
    std::make_pair(inf20Name, interface20)
};

set<pair<String, String> > obj2NameXmlSet(obj2_data, obj2_data + obj2InfCount);

}

static volatile sig_atomic_t s_interrupt = false;

static void SigIntHandler(int sig) {
    s_interrupt = true;
}

static SessionPort ASSIGNED_SESSION_PORT = 900;

class MySessionPortListener : public SessionPortListener {
    bool AcceptSessionJoiner(ajn::SessionPort sessionPort, const char* joiner, const ajn::SessionOpts& opts)
    {
        if (sessionPort != ASSIGNED_SESSION_PORT) {
            printf("Rejecting join attempt on unexpected session port %d\n", sessionPort);
            return false;
        }

//        std::cout << "Accepting JoinSessionRequest from " << joiner << " (opts.proximity= " << opts.proximity
//                << ", opts.traffic=" << opts.traffic << ", opts.transports=" << opts.transports << ")." << std::endl;
        return true;
    }
    void SessionJoined(SessionPort sessionPort, SessionId id, const char* joiner)
    {
        printf("Session Joined SessionId = %u\n", id);
    }
};

class BusObject1 : public BusObject {
  public:
    BusObject1(BusAttachment& bus, const char* path)
        : BusObject(path) {
        const InterfaceDescription* iface;

        size_t index = 0;

        printf("Object1 interfaces %" PRIuSIZET " \n", ::obj1Interfaces::obj1InfCount);

        for (index = 0; index < ::obj1Interfaces::obj1InfCount; index++) {
            const char* interfaceName = ::obj1Interfaces::obj1InfNames[index].c_str();
            printf("Interface %s \n", interfaceName);
            iface = bus.GetInterface(interfaceName);

            if (iface == NULL) {
                printf("The interfaceDescription pointer for %s was NULL when it should not have been.", interfaceName);
                return;
            }
            AddInterface(*iface, ANNOUNCED);

        }

    }

};

class BusObject2 : public BusObject {
  public:
    BusObject2(BusAttachment& bus, const char* path)
        : BusObject(path) {
        const InterfaceDescription* iface;

        size_t index = 0;

        printf("Object2 interfaces %" PRIuSIZET " \n", ::obj2Interfaces::obj2InfCount);

        for (index = 0; index < ::obj2Interfaces::obj2InfCount; index++) {
            const char* interfaceName = ::obj2Interfaces::obj2InfNames[index].c_str();
            printf("Interface %s \n", interfaceName);
            iface = bus.GetInterface(interfaceName);

            if (iface == NULL) {
                printf("The interfaceDescription pointer for %s was NULL when it should not have been.", interfaceName);
                return;
            }
            AddInterface(*iface, ANNOUNCED);

        }

    }

};
/** Main entry point */
int main(int argc, char** argv)
{
    /* Install SIGINT handler so Ctrl + C deallocates memory properly */
    signal(SIGINT, SigIntHandler);

    QStatus status;

    BusAttachment bus("AboutServiceTest");

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

    SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
    SessionPort sp = ASSIGNED_SESSION_PORT;
    MySessionPortListener sessionPortListener;
    status = bus.BindSessionPort(sp, opts, sessionPortListener);
    if (ER_OK == status) {
        printf("BindSessionPort succeeded.\n");
    } else {
        printf("BindSessionPort failed (%s)\n", QCC_StatusText(status));
        exit(1);
    }

    status = bus.AdvertiseName(bus.GetUniqueName().c_str(), TRANSPORT_ANY);
    printf("AdvertiseName %s (%s)\n", bus.GetUniqueName().c_str(), QCC_StatusText(status));

    // Setup the about data
    AboutData aboutData("en");

    uint8_t appId[] = { 0, 1, 2, 3, 4, 5 };
    status = aboutData.SetAppId(appId, 6);
    status = aboutData.SetDeviceName("My Device Name");
    status = aboutData.SetDeviceId("fakeID");
    status = aboutData.SetAppName("Application");
    status = aboutData.SetManufacturer("Manufacturer");
    status = aboutData.SetModelNumber("123456");
    status = aboutData.SetDescription("A poetic description of this application");
    status = aboutData.SetDateOfManufacture("2014-03-24");
    status = aboutData.SetSoftwareVersion("0.1.2");
    status = aboutData.SetHardwareVersion("0.0.1");
    status = aboutData.SetSupportUrl("http://www.alljoyn.org");
    if (!aboutData.IsValid()) {
        printf("failed to setup about data.\n");
    }

    set<pair<String, String> >::const_iterator ait = ::obj1Interfaces::obj1NameXmlSet.begin();

    while (ait != ::obj1Interfaces::obj1NameXmlSet.end()) {
        const char* iName = ait->first.c_str();
        const char* iXml = ait->second.c_str();

        printf("Create interface %s from xml (%s)\n", iName, iXml);

        status = bus.CreateInterfacesFromXml(iXml);
        ait++;
    }

    ait = ::obj2Interfaces::obj2NameXmlSet.begin();

    while (ait != ::obj2Interfaces::obj2NameXmlSet.end()) {
        const char* iName = ait->first.c_str();
        const char* iXml = ait->second.c_str();

        printf("Create interface %s from xml (%s)\n", iName, iXml);

        status = bus.CreateInterfacesFromXml(iXml);
        ait++;
    }

    BusObject1 busObject1(bus, ::obj1Interfaces::obj1Path);
    status = bus.RegisterBusObject(busObject1);

    BusObject2 busObject2(bus, ::obj2Interfaces::obj2Path);
    status = bus.RegisterBusObject(busObject2);

    // Announce about signal
    AboutObj aboutObj(bus);
    status = aboutObj.Announce(ASSIGNED_SESSION_PORT, aboutData);

    if (ER_OK == status) {
        printf("AboutObj Announce Succeeded.\n");
    } else {
        printf("AboutObj Announce failed (%s)\n", QCC_StatusText(status));
    }
    /* Perform the service asynchronously until the user signals for an exit. */
    if (ER_OK == status) {
        while (s_interrupt == false) {
            qcc::Sleep(100);
        }
    }
}