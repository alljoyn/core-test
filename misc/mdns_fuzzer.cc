/* MDNS PacketFuzzer */
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

#include <qcc/Socket.h>
#include <qcc/SocketTypes.h>
#include <qcc/Thread.h>
#include <alljoyn/BusAttachment.h>
#include <alljoyn/Init.h>

#define QCC_MODULE "MDNS FUZZER TEST PROGRAM"

using namespace std;
using namespace qcc;
using namespace ajn;

#define MAXBUFSIZE 65536 // Max UDP Packet size is 64 Kbyte

//The name advertised is "fuzzing.testing.purpose.only.do.not.use.this.name"
const uint8_t advertise_name_is_at[] = { 0x00, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x08, 0x5f, 0x61, 0x6c, 0x6c, 0x6a, 0x6f, 0x79, 0x6e, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x23, 0x20, 0x36, 0x61, 0x66, 0x65, 0x66, 0x63, 0x66, 0x66, 0x35, 0x39, 0x61, 0x66, 0x32, 0x33, 0x66, 0x36, 0x65, 0x63, 0x35, 0x32, 0x61, 0x35, 0x37, 0x30, 0x62, 0x33, 0x35, 0x38, 0x37, 0x66, 0x63, 0x32, 0xc0, 0x0c, 0xc0, 0x2b, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x29, 0x00, 0x01, 0x00, 0x01, 0x26, 0xe3, 0x20, 0x36, 0x61, 0x66, 0x65, 0x66, 0x63, 0x66, 0x66, 0x35, 0x39, 0x61, 0x66, 0x32, 0x33, 0x66, 0x36, 0x65, 0x63, 0x35, 0x32, 0x61, 0x35, 0x37, 0x30, 0x62, 0x33, 0x35, 0x38, 0x37, 0x66, 0x63, 0x32, 0xc0, 0x1a, 0xc0, 0x2b, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x0a, 0x09, 0x74, 0x78, 0x74, 0x76, 0x65, 0x72, 0x73, 0x3d, 0x30, 0x09, 0x61, 0x64, 0x76, 0x65, 0x72, 0x74, 0x69, 0x73, 0x65, 0xc0, 0x60, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x46, 0x09, 0x74, 0x78, 0x74, 0x76, 0x65, 0x72, 0x73, 0x3d, 0x30, 0x05, 0x74, 0x5f, 0x31, 0x3d, 0x34, 0x35, 0x6e, 0x5f, 0x32, 0x3d, 0x66, 0x75, 0x7a, 0x7a, 0x69, 0x6e, 0x67, 0x2e, 0x74, 0x65, 0x73, 0x74, 0x69, 0x6e, 0x67, 0x2e, 0x70, 0x75, 0x72, 0x70, 0x6f, 0x73, 0x65, 0x2e, 0x6f, 0x6e, 0x6c, 0x79, 0x2e, 0x64, 0x6f, 0x2e, 0x6e, 0x6f, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x2e, 0x74, 0x68, 0x69, 0x73, 0x2e, 0x6e, 0x61, 0x6d, 0x65, 0x0b, 0x73, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x2d, 0x69, 0x6e, 0x66, 0x6f, 0xc0, 0x60, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x2d, 0x09, 0x74, 0x78, 0x74, 0x76, 0x65, 0x72, 0x73, 0x3d, 0x30, 0x04, 0x70, 0x76, 0x3d, 0x32, 0x05, 0x73, 0x69, 0x64, 0x3d, 0x31, 0x0b, 0x75, 0x70, 0x63, 0x76, 0x34, 0x3d, 0x35, 0x37, 0x33, 0x32, 0x36, 0x0b, 0x75, 0x70, 0x63, 0x76, 0x36, 0x3d, 0x33, 0x37, 0x36, 0x31, 0x37, 0xc0, 0x60, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04, 0x7f, 0x00, 0x00, 0x01, 0xc0, 0x60, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x10, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x8a, 0x51, 0xfb, 0xff, 0xfe, 0x6e, 0x95, 0x21 };
const uint32_t advertise_name_is_at_zone1 = 12;
const uint32_t advertise_name_is_at_zone2 = 153;

//The name to be found is discovery.of.fuzzed.packet.do.not.use.this.name"
const uint8_t find_name_who_has[] = { 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x08, 0x5f, 0x61, 0x6c, 0x6c, 0x6a, 0x6f, 0x79, 0x6e, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x0c, 0x80, 0x01, 0x08, 0x5f, 0x61, 0x6c, 0x6c, 0x6a, 0x6f, 0x79, 0x6e, 0x04, 0x5f, 0x75, 0x64, 0x70, 0xc0, 0x1a, 0x00, 0x0c, 0x80, 0x01, 0x06, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68, 0x20, 0x39, 0x32, 0x32, 0x66, 0x37, 0x33, 0x35, 0x35, 0x61, 0x38, 0x32, 0x31, 0x36, 0x37, 0x37, 0x63, 0x30, 0x34, 0x61, 0x64, 0x32, 0x64, 0x36, 0x31, 0x63, 0x64, 0x61, 0x39, 0x39, 0x31, 0x63, 0x37, 0xc0, 0x1a, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x3f, 0x09, 0x74, 0x78, 0x74, 0x76, 0x65, 0x72, 0x73, 0x3d, 0x30, 0x34, 0x6e, 0x5f, 0x31, 0x3d, 0x64, 0x69, 0x73, 0x63, 0x6f, 0x76, 0x65, 0x72, 0x79, 0x2e, 0x6f, 0x66, 0x2e, 0x66, 0x75, 0x7a, 0x7a, 0x65, 0x64, 0x2e, 0x70, 0x61, 0x63, 0x6b, 0x65, 0x74, 0x2e, 0x64, 0x6f, 0x2e, 0x6e, 0x6f, 0x74, 0x2e, 0x75, 0x73, 0x65, 0x2e, 0x74, 0x68, 0x69, 0x73, 0x2e, 0x6e, 0x61, 0x6d, 0x65, 0x2a, 0x0b, 0x73, 0x65, 0x6e, 0x64, 0x65, 0x72, 0x2d, 0x69, 0x6e, 0x66, 0x6f, 0xc0, 0x40, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x30, 0x09, 0x74, 0x78, 0x74, 0x76, 0x65, 0x72, 0x73, 0x3d, 0x30, 0x0e, 0x69, 0x70, 0x76, 0x34, 0x3d, 0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, 0x04, 0x70, 0x76, 0x3d, 0x32, 0x05, 0x73, 0x69, 0x64, 0x3d, 0x31, 0x0b, 0x75, 0x70, 0x63, 0x76, 0x34, 0x3d, 0x34, 0x38, 0x39, 0x33, 0x30 };
const uint32_t find_name_who_has_zone1 = 12;
const uint32_t find_name_who_has_zone2 = 57;


static bool g_foundName = false;

class MyBusListener : public BusListener {
  public:
    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix)
    {
        QCC_UNUSED(name);
        QCC_UNUSED(transport);
        QCC_UNUSED(namePrefix);
        g_foundName = true;
    }
};
static MyBusListener g_busListener;

int TestAppMain(int argc, char** argv)
{
    QStatus status = ER_OK;
    size_t sent = 0;
    qcc::IPAddress destinationMulticast("224.0.0.251");
    qcc::SocketFd sock;
    uint32_t iterationCount = 0;

    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp("-c", argv[i])) {
            ++i;
            if (i == argc) {
                cout << "option %s requires a parameter" << argv[i - 1] << endl;
                return 30;
            } else {
                iterationCount = strtoul(argv[i], NULL, 10);
            }
        }
    }

    status = qcc::Socket(qcc::QCC_AF_INET, qcc::QCC_SOCK_DGRAM, sock);
    if (status != ER_OK) {
        QCC_LogError(status, ("Socket(): Failed"));
        return 31;
    }

    //Set the soskcte to reusable.
    status = qcc::SetReuseAddress(sock, true);
    if (status != ER_OK) {
        QCC_LogError(status, ("SetReuseAddress Failed"));
        return 32;
    }

    //set the TTL.
    status = qcc::SetMulticastHops(sock, qcc::QCC_AF_INET, 3);
    if (status != ER_OK) {
        QCC_LogError(status, ("IP_MULTICAST_TTL Failed"));
        return 33;
    }

    //Set the interface for multicast
    status = qcc::SetMulticastInterface(sock, qcc::QCC_AF_INET, "lo");
    if (status != ER_OK) {
        QCC_LogError(status, ("IP_MULTICAST_IF Failed"));
        return 34;
    }

    //Bind to 127.0.0.1 and 50001 as it is an auspicious port.
    status = qcc::Bind(sock, qcc::IPAddress("127.0.0.1"), 50001);
    if (status != ER_OK) {
        QCC_LogError(status, ("Bind(): Failed"));
        return 35;
    }

    //Do the AllJoyn part here
    BusAttachment ba("mdns-fuzzer", true, 4);
    ba.RegisterBusListener(g_busListener);
    status = ba.Start();
    if (status != ER_OK) {
        cout << "BS start failed. Exiting.." << endl;
        return 36;
    }
    status = ba.Connect();
    if (status != ER_OK) {
        cout << "BS Connect failed. Exiting.." << endl;
        return 37;
    }
    status = ba.FindAdvertisedName("fuzzing");
    if (status != ER_OK) {
        cout << "BS FAN failed. Exiting.." << endl;
        return 38;
    }
    status = ba.AdvertiseName("discovery.of.fuzzed.packet.do.not.use.this.name", TRANSPORT_ANY);
    if (status != ER_OK) {
        cout << "BS AN failed. Exiting.." << endl;
        return 39;
    }

    //Send the good packet as is
    uint8_t temp_buffer[MAXBUFSIZE];
    memcpy(temp_buffer, advertise_name_is_at, sizeof(advertise_name_is_at));
    size_t send_size = sizeof(advertise_name_is_at);
    status = qcc::SendTo(sock, destinationMulticast, 5353, temp_buffer, send_size, sent);
    qcc::Sleep(5000);
    if (!g_foundName) {
        cout << "The good packet didnt result in FoundAdvertisedName. Exiting.. " << endl;
        return 40;
    }

    //Fuzz the packet
    for (uint32_t i = 0; i < iterationCount; i++) {
        uint32_t lower_boundary = 0;
        uint32_t upper_boundary = 0;
        uint32_t probablity = 0;

        memcpy(temp_buffer, advertise_name_is_at, sizeof(advertise_name_is_at));
        size_t send_size = sizeof(advertise_name_is_at);

        uint32_t t_rand = random() % 10;
        if (t_rand == 0) {
            lower_boundary = 0; upper_boundary = 60000; probablity = 1; send_size = 60000;
        } else if (t_rand == 1) {
            lower_boundary = 0; upper_boundary = 0; probablity = 10; send_size = 0;
        } else if (t_rand == 2) {
            lower_boundary = 0; upper_boundary = advertise_name_is_at_zone1; probablity = 2;
        } else if ((t_rand >= 3) && (t_rand <= 4)) {
            lower_boundary = advertise_name_is_at_zone1; upper_boundary = advertise_name_is_at_zone2; probablity = (random() % 135 + 1);
        } else if ((t_rand >= 5) && (t_rand <= 9)) {
            lower_boundary = advertise_name_is_at_zone2; upper_boundary = send_size; probablity = (random() % 100) + 1;
        }

        //Fuzz byte according to probablity
        for (size_t i = lower_boundary; i < upper_boundary; i++) {
            if (0 == random() % probablity) {
                temp_buffer[i] = random() % 255;
            }
        }

        status = qcc::SendTo(sock, destinationMulticast, 5353, temp_buffer, send_size, sent);
    }
    cout << "PASSED1" << endl;

    //Send the good packet as is
    memset(temp_buffer, '\0', MAXBUFSIZE);
    memcpy(temp_buffer, find_name_who_has, sizeof(find_name_who_has));
    send_size = sizeof(find_name_who_has);
    status = qcc::SendTo(sock, destinationMulticast, 5353, temp_buffer, send_size, sent);
    qcc::Sleep(50);

    //Fuzz the packet
    for (uint32_t i = 0; i < iterationCount; i++) {
        uint32_t lower_boundary = 0;
        uint32_t upper_boundary = 0;
        uint32_t probablity = 0;

        memcpy(temp_buffer, find_name_who_has, sizeof(find_name_who_has));
        size_t send_size = sizeof(find_name_who_has);

        uint32_t t_rand = random() % 10;
        if (t_rand == 0) {
            lower_boundary = 0; upper_boundary = 60000; probablity = 1; send_size = 60000;
        } else if (t_rand == 1) {
            lower_boundary = 0; upper_boundary = 0; probablity = 10; send_size = 0;
        } else if (t_rand == 2) {
            lower_boundary = 0; upper_boundary = find_name_who_has_zone1; probablity = 2;
        } else if ((t_rand >= 3) && (t_rand <= 4)) {
            lower_boundary = find_name_who_has_zone1; upper_boundary = find_name_who_has_zone2; probablity = (random() % 45) + 1;
        } else if ((t_rand >= 5) && (t_rand <= 9)) {
            lower_boundary = find_name_who_has_zone2; upper_boundary = send_size; probablity = (random() % 180) + 1;
        }

        //Fuzz byte according to probablity
        for (size_t i = lower_boundary; i < upper_boundary; i++) {
            if (0 == random() % probablity) {
                temp_buffer[i] = random() % 255;
            }
        }

        status = qcc::SendTo(sock, destinationMulticast, 5353, temp_buffer, send_size, sent);
    }

    cout << "PASSED2" << endl;
    // shutdown socket
    qcc::Close(sock);
    return 0;
}

int main(int argc, char** argv)
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