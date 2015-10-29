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

#include <alljoyn/AboutObj.h>
#include <alljoyn/BusAttachment.h>
#include <alljoyn/BusListener.h>
#include <alljoyn/BusObject.h>
#include <alljoyn/Init.h>

#include <qcc/String.h>
#include <qcc/Thread.h>

#include <signal.h>
#include <stdio.h>

using namespace ajn;
using namespace std;
using namespace qcc;

static volatile sig_atomic_t s_interrupt = false;

static void CDECL_CALL SigIntHandler(int sig) {
    QCC_UNUSED(sig);
    s_interrupt = true;
}

static SessionPort ASSIGNED_SESSION_PORT = 900;
static String interface_name = "com.example.about.feature.interface.sample";

class MySessionPortListener : public SessionPortListener {
    bool AcceptSessionJoiner(ajn::SessionPort sessionPort, const char* joiner, const ajn::SessionOpts& opts)
    {
        QCC_UNUSED(joiner);
        QCC_UNUSED(opts);

        if (sessionPort != ASSIGNED_SESSION_PORT) {
            cout << "Rejecting join attempt on unexpected session port " << sessionPort << endl;
            return false;
        }
        return true;
    }
    void SessionJoined(SessionPort sessionPort, SessionId id, const char* joiner)
    {
        QCC_UNUSED(sessionPort);
        QCC_UNUSED(joiner);

        cout << "Session Joined SessionId = " << hex << id << endl;
    }
};

class MyBusObject : public BusObject {
  public:
    MyBusObject(BusAttachment& bus, const char* path)
        : BusObject(path) {
        QStatus status;
        const InterfaceDescription* iface = bus.GetInterface(interface_name.c_str());
        assert(iface != NULL);

        // Here the value ANNOUNCED tells AllJoyn that this interface
        // should be announced
        status = AddInterface(*iface, ANNOUNCED);
        if (status != ER_OK) {
            cout << "Failed to add " << interface_name.c_str() << " interface to the BusObject" << endl;
        }

        /* Register the method handlers with the object */
        const MethodEntry methodEntries[] = {
            { iface->GetMember("Echo"), static_cast<MessageReceiver::MethodHandler>(&MyBusObject::Echo) }
        };
        AddMethodHandlers(methodEntries, sizeof(methodEntries) / sizeof(methodEntries[0]));
    }

    // Respond to remote method call `Echo` by returning the string back to the
    // sender.
    void Echo(const InterfaceDescription::Member* member, Message& msg) {
        QCC_UNUSED(member);

        cout << "Echo method called: " << msg->GetArg(0)->v_string.str;
        const MsgArg* arg((msg->GetArg(0)));
        QStatus status = MethodReply(msg, arg, 1);
        if (status != ER_OK) {
            cout << "Failed to created MethodReply." << endl;
        }
    }
};

static void usage(void)
{
    cout << "Usage: AboutService_test \n" << endl;
    cout << "Options:" << endl;
    cout << "   -n <interface-name> = Interface name to be announced" << endl;
    cout << "   -time <time of execution> = Assign time limit of the for the program to execute in miliseconds." << endl;
    cout << "\n\t\t(com.example.about.feature.interface.sample by default)" << endl;
}

/** Main entry point */
int CDECL_CALL main(int argc, char** argv)
{
    uint32_t startTimeStamp;
    uint32_t executionTime = 0;

    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp("-h", argv[i])) {
            usage();
            exit(0);
        } else if (0 == strcmp("-n", argv[i])) {
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

    cout << "INTERFACE NAME " << interface_name.c_str() << endl;

    /* Install SIGINT handler so Ctrl + C deallocates memory properly */
    signal(SIGINT, SigIntHandler);

    QStatus status;

    BusAttachment* bus = new BusAttachment("About Service Example", true);
    status = bus->Start();
    startTimeStamp =  bus->GetTimestamp();

    if (ER_OK == status) {
        cout << "BusAttachment started." << endl;
    } else {
        cout << "FAILED to start BusAttachment (" << QCC_StatusText(status) << ")" << endl;
        exit(1);
    }

    status = bus->Connect();
    if (ER_OK == status) {
        cout << "BusAttachment connect succeeded. BusName " << bus->GetUniqueName().c_str() << endl;
    } else {
        cout << "FAILED to connect to router node (" << QCC_StatusText(status) << ")" << endl;
        exit(1);
    }


    SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
    SessionPort sessionPort = ASSIGNED_SESSION_PORT;
    MySessionPortListener sessionPortListener;
    status = bus->BindSessionPort(sessionPort, opts, sessionPortListener);
    if (ER_OK != status) {
        cout << "Failed to BindSessionPort (" << QCC_StatusText(status) << ")" << endl;
        exit(1);
    }

    // Setup the about data
    // The default language is specified in the constructor. If the default language
    // is not specified any Field that should be localized will return an error
    AboutData aboutData("en");
    //AppId is a 128bit uuid
    uint8_t appId[] = { 0x01, 0xB3, 0xBA, 0x14,
                        0x1E, 0x82, 0x11, 0xE4,
                        0x86, 0x51, 0xD1, 0x56,
                        0x1D, 0x5D, 0x46, 0xB0 };
    status = aboutData.SetAppId(appId, 16);
    status = aboutData.SetDeviceName("My Device Name");
    //DeviceId is a string encoded 128bit UUID
    status = aboutData.SetDeviceId("93c06771-c725-48c2-b1ff-6a2a59d445b8");
    status = aboutData.SetAppName("Application");
    status = aboutData.SetManufacturer("Manufacturer");
    status = aboutData.SetModelNumber("123456");
    status = aboutData.SetDescription("A poetic description of this application");
    status = aboutData.SetDateOfManufacture("2014-03-24");
    status = aboutData.SetSoftwareVersion("0.1.2");
    status = aboutData.SetHardwareVersion("0.0.1");
    status = aboutData.SetSupportUrl("http://www.example.org");

    // The default language is automatically added to the `SupportedLanguages`
    // Users don't have to specify the AJSoftwareVersion its automatically added
    // to the AboutData

    // Adding Spanish Localization values to the AboutData. All strings MUST be
    // UTF-8 encoded.
    status = aboutData.SetDeviceName("Mi dispositivo Nombre", "es");
    status = aboutData.SetAppName("aplicación", "es");
    status = aboutData.SetManufacturer("fabricante", "es");
    status = aboutData.SetDescription("Una descripción poética de esta aplicación", "es");

    // Check to see if the aboutData is valid before sending the About Announcement
    if (!aboutData.IsValid()) {
        cout << "failed to setup about data." << endl;
    }

    qcc::String iface = "<node>"
                        "<interface name='" + qcc::String(interface_name.c_str()) + "'>"
                        "  <method name='Echo'>"
                        "    <arg name='out_arg' type='s' direction='in' />"
                        "    <arg name='return_arg' type='s' direction='out' />"
                        "  </method>"
                        "</interface>"
                        "</node>";

    status = bus->CreateInterfacesFromXml(iface.c_str());
    if (ER_OK != status) {
        cout << "Failed to parse the xml interface definition (" << QCC_StatusText(status) << ")" << endl;
        exit(1);
    }

    MyBusObject* busObject = new MyBusObject(*bus, "/example/path");

    status = bus->RegisterBusObject(*busObject);
    if (ER_OK != status) {
        cout << "Failed to register BusObject (" << QCC_StatusText(status) << ")" << endl;
        exit(1);
    }

    // Announce about signal
    AboutObj* aboutObj = new AboutObj(*bus);
    // Note the ObjectDescription that is part of the Announce signal is found
    // automatically by introspecting the BusObjects registered with the bus
    // attachment.
    status = aboutObj->Announce(sessionPort, aboutData);
    if (ER_OK == status) {
        cout << "AboutObj Announce Succeeded." << endl;
    } else {
        cout << "AboutObj Announce failed (" << QCC_StatusText(status) << ")" << endl;
        exit(1);
    }

    /* Perform the service asynchronously until the user signals for an exit. */
    if (ER_OK == status) {
        while (s_interrupt == false) {
            qcc::Sleep(100);

            if (executionTime > 0 && ((bus->GetTimestamp() - startTimeStamp) >= executionTime)) {
                cout << "Exiting after " << dec << executionTime << "ms have elapsed as specified." << endl;
                s_interrupt = true;
            }
        }
    }

    delete aboutObj;
    delete busObject;
    delete bus;
#ifdef ROUTER
    AllJoynRouterShutdown();
#endif
    AllJoynShutdown();
    return 0;
}