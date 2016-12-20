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
#include <qcc/Debug.h>
#include <alljoyn/BusAttachment.h>
#include <qcc/Thread.h>
#include <qcc/Util.h>
#include <signal.h>

#define QCC_MODULE "ALLJOYN"

using namespace std;
using namespace qcc;
using namespace ajn;

static const char* rule = "interface='org.alljoyn.bus.test.sessions',sessionless='t'";
static const uint32_t waitTimeoutMs = 10000;

static const char* InterfaceName = "org.alljoyn.bus.test.sessions";
static const char* ObjectPath = "/sessions";

static volatile sig_atomic_t running = true;

static void SigIntHandler(int sig)
{
    running = false;
}

static InterfaceDescription* CreateInterface(BusAttachment* bus, size_t numSignals = 10)
{
    InterfaceDescription* intf = NULL;
    bus->CreateInterface(InterfaceName, intf);
    intf->AddSignal("Chat", "s",  "str", 0);
    for (size_t i = 0; i < numSignals; ++i) {
        char member[] = "Chat00";
        sprintf(member, "Chat%02ld", i);
        intf->AddSignal(member, "s",  "str", 0);
    }
    intf->Activate();
    return intf;
}

class Sender : public BusObject {
  public:
    BusAttachment* bus;

    Sender(const char* connectSpec)
        : BusObject(ObjectPath)
        , bus(new BusAttachment("Sender", true))
    {
        InterfaceDescription* intf = CreateInterface(bus);
        AddInterface(*intf);
        bus->RegisterBusObject(*this);

        bus->Start();
        bus->Connect(connectSpec ? connectSpec : "null:");
    }

    virtual ~Sender() {
        delete bus;
    }

    void SendSignal(const char* signal = "Chat00", const char* s = "schat") {
        const InterfaceDescription* intf = bus->GetInterface(InterfaceName);
        const InterfaceDescription::Member* member = intf->GetMember(signal);

        MsgArg arg("s", s);
        Message msg(*bus);
        Signal(NULL, 0, *member, &arg, 1, 0, ALLJOYN_FLAG_SESSIONLESS, &msg);
    }
};

class Receiver : public MessageReceiver {
  public:
    BusAttachment* bus;
    volatile unsigned int signalled;

    Receiver(const char* connectSpec)
        : bus(new BusAttachment("Receiver", true))
        , signalled(0)
    {
        InterfaceDescription* intf = CreateInterface(bus);

        size_t numMembers = intf->GetMembers();
        const ajn::InterfaceDescription::Member** members = new const ajn::InterfaceDescription::Member* [numMembers];
        intf->GetMembers(members, numMembers);
        for (size_t i = 0; i < numMembers; ++i) {
            bus->RegisterSignalHandler(this, static_cast<MessageReceiver::SignalHandler>(&Receiver::SignalHandler),
                                       members[i], NULL);
        }
        delete[] members;

        bus->Start();
        bus->Connect(connectSpec ? connectSpec : "null:");
    }

    virtual ~Receiver() {
        delete bus;
    }

    void SignalHandler(const InterfaceDescription::Member* member, const char* path, Message& message) {
        QCC_LogError(ER_OK, ("[%p] Received sender='%s',interface='%s',member='%s',path='%s'\n", this,
                             message->GetSender(),
                             message->GetInterface(),
                             message->GetMemberName(),
                             message->GetObjectPath()));
        ++signalled;
    }

    QStatus WaitForSignal(uint32_t msecs = waitTimeoutMs) {
        for (uint32_t i = 0; !signalled && (i < msecs); i += 100) {
            qcc::Sleep(100);
        }
        QStatus status = signalled ? ER_OK : ER_TIMEOUT;
        --signalled;
        return status;
    }
};

int main(int argc, char* argv[])
{
    int ret = 0;
    const char* role;
    const char* behavior;
    Sender* sender = NULL;
    Receiver* receiver = NULL;

    signal(SIGINT, SigIntHandler);

    if (argc < 2) {
        ret = 1;
        goto exit;
    }
    role = argv[1];
    behavior = (argc < 3) ? "simple" : argv[2];

    if (!strcmp(role, "sender")) {
        sender = new Sender(getenv("BUS_ADDRESS"));
        if (!strcmp(behavior, "simple")) {
            sender->SendSignal("Chat");
            while (running) {
                Sleep(500);
            }
        } else if (!strcmp(behavior, "random")) {
            uint32_t n = 0;
            while (running) {
                sender->SendSignal("Chat");
                fprintf(stderr, "Sent %u signals\n", ++n);
                Sleep(Rand8() / 16 * 1000);
            }
        }

    } else if (!strcmp(role, "receiver")) {
        receiver = new Receiver(getenv("BUS_ADDRESS"));
        receiver->bus->AddMatch(rule);
        while (running) {
            Sleep(500);
        }

    } else {
        ret = 1;
        goto exit;
    }

exit:
    delete receiver;
    delete sender;
    return ret;
};