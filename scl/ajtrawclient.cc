/**
 * @file
 * Sample implementation of an AllJoyn client that uses raw sockets.
 * The client receives data from 'ajtrawservice' and then we compare the total
 * bytes sent v/s total bytes received to decide the pass fail criteria.
 */

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
#include <qcc/platform.h>
#include <qcc/Debug.h>
#include <qcc/Thread.h>

#include <signal.h>
#include <stdio.h>
#include <assert.h>
#include <vector>
#include <errno.h>

#include <qcc/Environ.h>
#include <qcc/Event.h>
#include <qcc/String.h>
#include <qcc/StringUtil.h>
#include <qcc/Util.h>
#include <qcc/time.h>

#include <alljoyn/BusAttachment.h>
#include <alljoyn/Init.h>
#include <alljoyn/DBusStd.h>
#include <alljoyn/AllJoynStd.h>
#include <alljoyn/version.h>

#include <Status.h>

#define QCC_MODULE "RAWCLIENT TEST PROGRAM"

using namespace std;
using namespace qcc;
using namespace ajn;

/** Sample constants */
static const SessionPort SESSION_PORT = 33;

/** Static data */
static BusAttachment* g_msgBus = NULL;
static Event* g_discoverEvent = NULL;
static String g_wellKnownName = "org.alljoyn.ajtraw_test";

/** AllJoynListener receives discovery events from AllJoyn */
class MyBusListener : public BusListener {
  public:

    MyBusListener() : BusListener(), sessionId(0) { }

    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix)
    {
        QCC_SyncPrintf("FoundAdvertisedName(name=%s, transport=0x%x, prefix=%s)\n", name, transport, namePrefix);

        if (0 == strcmp(name, g_wellKnownName.c_str())) {
            /* Release the main thread */
            g_discoverEvent->SetEvent();
        }
    }

    void LostAdvertisedName(const char* name, TransportMask transport, const char* prefix)
    {
        QCC_SyncPrintf("LostAdvertisedName(name=%s, transport=0x%x, prefix=%s)\n", name, transport, prefix);
    }

    void NameOwnerChanged(const char* name, const char* previousOwner, const char* newOwner)
    {
        QCC_SyncPrintf("NameOwnerChanged(%s, %s, %s)\n",
                       name,
                       previousOwner ? previousOwner : "null",
                       newOwner ? newOwner : "null");
    }

  private:
    SessionId sessionId;
};

/** Static bus listener */
static MyBusListener g_busListener;

static volatile sig_atomic_t g_interrupt = false;

static void CDECL_CALL SigIntHandler(int sig)
{
    QCC_UNUSED(sig);
    g_interrupt = true;
}

static void usage(void)
{
    QCC_SyncPrintf("Usage: ajtrawclient [-h] [-n <well-known name>]\n\n");
    QCC_SyncPrintf("Options:\n");
    QCC_SyncPrintf("   -h                    = Print this help message\n");
    QCC_SyncPrintf("   -n <well-known name>  = Well-known bus name advertised by bbservice\n");
    QCC_SyncPrintf("\n");
}

int TestAppMain(int argc, char** argv)
{
    QStatus status = ER_OK;
    Environ* env;

    QCC_SyncPrintf("AllJoyn Library version: %s\n", ajn::GetVersion());
    QCC_SyncPrintf("AllJoyn Library build info: %s\n", ajn::GetBuildInfo());

    /* Install SIGINT handler */
    signal(SIGINT, SigIntHandler);

    /* Parse command line args */
    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp("-n", argv[i])) {
            ++i;
            if (i == argc) {
                QCC_SyncPrintf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_wellKnownName = argv[i];
            }
        } else if (0 == strcmp("-h", argv[i])) {
            usage();
            exit(0);
        } else {
            status = ER_FAIL;
            QCC_SyncPrintf("Unknown option %s\n", argv[i]);
            usage();
            exit(1);
        }
    }

    g_discoverEvent = new Event();

    /* Get env vars */
    env = Environ::GetAppEnviron();
    qcc::String connectArgs = env->Find("BUS_ADDRESS");

    /* Create message bus */
    g_msgBus = new BusAttachment("ajtrawclient", true);

    /* Register a bus listener in order to get discovery indications */
    g_msgBus->RegisterBusListener(g_busListener);

    /* Start the msg bus */
    status = g_msgBus->Start();
    if (ER_OK != status) {
        QCC_LogError(status, ("BusAttachment::Start failed"));
    }

    /* Connect to the bus */
    if (ER_OK == status) {
        if (connectArgs.empty()) {
            status = g_msgBus->Connect();
        } else {
            status = g_msgBus->Connect(connectArgs.c_str());
        }

        if (ER_OK != status) {
            QCC_LogError(status, ("BusAttachment::Connect(\"%s\") failed", connectArgs.c_str()));
        }
    }

    /* Begin discovery for the well-known name of the service */
    if (ER_OK == status) {
        status = g_msgBus->FindAdvertisedName(g_wellKnownName.c_str());
        if (status != ER_OK) {
            QCC_LogError(status, ("%s.FindAdvertisedName failed", g_wellKnownName.c_str()));
        }
    }

    /* Wait till you find a name */
    status = Event::Wait(*g_discoverEvent);

    /* Join Session Now */
    SessionOpts opts(SessionOpts::TRAFFIC_RAW_RELIABLE, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_TCP);
    SessionId sessionId = 0;

    status = g_msgBus->JoinSession(g_wellKnownName.c_str(), SESSION_PORT, NULL, sessionId, opts);
    if (ER_OK != status) {
        QCC_LogError(status, ("JoinSession(%s) failed", g_wellKnownName.c_str()));
        exit(-1);
    }


    /* Get the socket descriptor */
    SocketFd sockFd;
    status = g_msgBus->GetSessionFd(sessionId, sockFd);
    if (status != ER_OK) {
        QCC_LogError(status, ("Failed to get socket from GetSessionFd args"));
        exit(-1);
    }

    /* Set it to blocking */
    status = qcc::SetBlocking(sockFd, true);
    if (status != ER_OK) {
        QCC_LogError(status, ("Failed to set socket to blocking"));
        exit(-1);
    }

    /* Read some bytes from this socket */
    uint16_t messageLen = 0;
    uint8_t*payload = NULL;
    uint32_t bytes = 0;
    size_t recvd = 0;

    while (true) {
        messageLen = 0;
        status = qcc::Recv(sockFd, &messageLen, sizeof(uint16_t), recvd);
        if ((status != ER_OK) || (recvd <= 0)) {
            QCC_SyncPrintf("\n Error is receiving the messageLen. Bytes recd: %u. It should be %u ", recvd, sizeof(uint16_t));
            status = ER_FAIL;
            break;
        }

        QCC_SyncPrintf("\n Data len to be received is %u. Recvd %u bytes ", messageLen, recvd);

        /* Now send the actual data of size(messageLen) */
        payload = new uint8_t[messageLen];
        if (payload == NULL) {
            QCC_SyncPrintf("\n Error while allocating memory");
            status = ER_FAIL;
            break;
        }
        /* Set the payload to number '0' */
        memset(payload, 0, messageLen);

        /* Receive the actual data now */
        recvd = 0;
        size_t temp = 0;

        while (temp != messageLen) {

            status = qcc::Recv(sockFd, (payload + recvd), messageLen - temp, recvd);
            temp += recvd;
            bytes += recvd;
            QCC_SyncPrintf("\n Recv is %u, messageLen is %u , remaining is %u", recvd, messageLen, messageLen - temp);
            if ((status != ER_OK) || (g_interrupt) || (recvd <= 0)) {
                QCC_SyncPrintf("\n Failed to recv full message. Recvd only %u bytes. Expected was %u bytes", recvd, messageLen);
                status = ER_FAIL;
                break;
            }
        }


        /* Clear buffer. Gear up for next iteration */
        delete payload;
        payload = NULL;

        if (messageLen == 10000) {
            break;
        }
        if (status == ER_FAIL) {
            break;
        }
        if (g_interrupt) {
            break;
        }
    }

    /* Receive the total no of bytes */
    recvd = 0;
    uint32_t recv_total_bytes = 0;

    status = qcc::Recv(sockFd, &recv_total_bytes, sizeof(bytes), recvd);
    if ((status != ER_OK) || (g_interrupt) || (recvd != sizeof(bytes))) {
        QCC_SyncPrintf("\n Failed to recv full message. Recvd only %u bytes. Expected was %u bytes", recvd, messageLen);
        status = ER_FAIL;
    }


/* Close socket */
#ifdef WIN32
    closesocket(sockFd);
#else
    ::shutdown(sockFd, SHUT_RDWR);
    ::close(sockFd);
#endif

    QCC_SyncPrintf("\n Bytes sent is %u ", bytes);
    QCC_SyncPrintf("\n Bytes recd is %u ", recv_total_bytes);

    if (bytes == recv_total_bytes) {
        QCC_SyncPrintf("\n RAW SOCKET TEST PASSED ");
    } else {
        QCC_SyncPrintf("\n RAW SOCKET TEST FAILED ");
    }


    /* Stop the bus */
    delete g_msgBus;
    delete g_discoverEvent;

    QCC_SyncPrintf("\n [%s]", QCC_StatusText(status));
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