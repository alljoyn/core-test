/**
 * @file
 * Stress test for discovery
 */
/******************************************************************************
 *  *    Copyright (c) Open Connectivity Foundation (OCF) and AllJoyn Open
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
#include <qcc/Debug.h>
#include <qcc/Thread.h>

#include <signal.h>
#include <stdio.h>
#include <vector>
#include <inttypes.h>
#include <qcc/Environ.h>
#include <qcc/Event.h>
#include <qcc/String.h>
#include <qcc/StringUtil.h>
#include <qcc/Util.h>
#include <qcc/time.h>
#include <qcc/Mutex.h>

#include <alljoyn/BusAttachment.h>
#include <alljoyn/DBusStd.h>
#include <alljoyn/AllJoynStd.h>
#include <alljoyn/version.h>

#include <alljoyn/Status.h>

#define QCC_MODULE "ALLJOYN"


using namespace std;
using namespace qcc;
using namespace ajn;

/** Static data */
static BusAttachment* g_msgBus = NULL;
static uint32_t g_count = 0;
static Mutex lock;

class MyBusListener : public BusListener {
  public:

    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix)
    {
        lock.Lock();
        g_count++;
        printf("FoundAdvertisedName(name=%s, transport=0x%x, prefix=%s, count=%u)\n", name, transport, namePrefix, g_count);
        lock.Unlock();
    }

    void LostAdvertisedName(const char* name, TransportMask transport, const char* prefix)
    {
        lock.Lock();
        g_count--;
        printf("LostAdvertisedName(name=%s, transport=0x%x, prefix=%s, count=%lu)\n", name, transport, prefix, (unsigned long) g_count);
        lock.Unlock();
    }
};

/** Static bus listener */
static MyBusListener* g_busListener;

static volatile sig_atomic_t g_interrupt = false;
static bool g_discovery = false;

static void SigIntHandler(int sig)
{
    g_interrupt = true;
}

static void usage(void)
{
    printf("Usage: discovery\n\n");
    printf("Options:\n");
    printf("   -d                        = Discovery mode\n");
    printf("\n");
}


int main(int argc, char** argv)
{
    QStatus status = ER_OK;

    printf("AllJoyn Library version: %s\n", ajn::GetVersion());
    printf("AllJoyn Library build info: %s\n", ajn::GetBuildInfo());

    /* Install SIGINT handler */
    signal(SIGINT, SigIntHandler);

    /* Parse command line args */
    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp("-d", argv[i])) {
            g_discovery = true;
        } else {
            status = ER_FAIL;
            printf("Unknown option %s\n", argv[i]);
            usage();
            exit(1);
        }
    }

    g_msgBus = new BusAttachment("discoverytest", true);
    if (g_discovery) {
        g_busListener = new MyBusListener();
        g_msgBus->RegisterBusListener(*g_busListener);
    }
    status = g_msgBus->Start();
    if (ER_OK != status) {
        QCC_LogError(status, ("BusAttachment::Start failed"));
        return status;
    }

    /* Connect to the bus */
    status = g_msgBus->Connect();
    if (ER_OK != status) {
        QCC_LogError(status, ("BusAttachment::Connect() failed"));
        return status;
    }

    if (!g_discovery) {
        //Advertise names
        for (int i = 0; i < 500 && !g_interrupt; i++) {
            char buf[512];
            sprintf(buf, "discovery.abcdefghijklmnopqrstuvwxyz%d.zyxwvutsrqponmlkjihgfedcab%d.alljoyn_core%d.common%d.build_core%d", i, i, i, i, i);
            status = g_msgBus->AdvertiseName(buf, TRANSPORT_WLAN);
            if (status  != ER_OK) {
                QCC_LogError(status, ("Failed to advertise name %s", buf));
            }
        }
    }

    if (g_discovery) {
        status = g_msgBus->FindAdvertisedNameByTransport("discovery", TRANSPORT_WLAN);
        if (status != ER_OK) {
            QCC_LogError(status, ("FindAdvertisedName failed"));
            return status;
        }
    }

    while (g_interrupt == false) {
        qcc::Sleep(100);
    }

    /* Deallocate bus */
    delete g_msgBus;

    if (g_discovery) {
        delete g_busListener;
    }

    printf("discovery exiting with status %d (%s)\n", status, QCC_StatusText(status));
    return (int) status;
}