/**
 * @file
 * Sample implementation of an AllJoyn service that provides a raw socket.
 * This program shows how to use a raw socket to send a byte stream.
 * Service sends 10000-50000 bytes of data in each iteration for 100 iteration.
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

#include <signal.h>
#include <stdio.h>
#include <vector>
#include <errno.h>
#include <stdlib.h>

#include <qcc/Debug.h>
#include <qcc/Environ.h>
#include <qcc/Mutex.h>
#include <qcc/String.h>
#include <qcc/Thread.h>
#include <qcc/time.h>
#include <qcc/Util.h>

#include <alljoyn/BusAttachment.h>
#include <alljoyn/Init.h>
#include <alljoyn/DBusStd.h>
#include <alljoyn/AllJoynStd.h>
#include <alljoyn/MsgArg.h>
#include <alljoyn/version.h>

#include <Status.h>


#define QCC_MODULE "RAWSERVICE TEST PROGRAM"

using namespace std;
using namespace qcc;
using namespace ajn;

/** Sample constants */
static const SessionPort SESSION_PORT = 33;

/** Static top level message bus object */
static BusAttachment* g_msgBus = NULL;
static String g_wellKnownName = "org.alljoyn.ajtraw_test";
static Event* g_joinedSessionEvent = NULL;

static volatile sig_atomic_t g_interrupt = false;

static void CDECL_CALL SigIntHandler(int sig)
{
    QCC_UNUSED(sig);
    g_interrupt = true;
}

class MySessionPortListener : public SessionPortListener {

  public:
    MySessionPortListener() : SessionPortListener(), sessionId(0) { }

    bool AcceptSessionJoiner(SessionPort sessionPort, const char* joiner, const SessionOpts& opts)
    {
        QCC_UNUSED(opts);
        if (sessionPort != SESSION_PORT) {
            QCC_SyncPrintf("Rejecting join request for unknown session port %d from %s\n", sessionPort, joiner);
            return false;
        }

        /* Allow the join attempt */
        QCC_SyncPrintf("Accepting JoinSession request from %s\n", joiner);
        return true;
    }

    void SessionJoined(SessionPort sessionPort, SessionId sessionId, const char* joiner)
    {
        QCC_UNUSED(sessionPort);
        QCC_SyncPrintf("SessionJoined with %s (id=%d)\n", joiner, sessionId);
        this->sessionId = sessionId;
        g_joinedSessionEvent->SetEvent();
    }

    SocketFd GetSessionId() { return sessionId; }

  private:
    SessionId sessionId;
};

static void usage(void)
{
    QCC_SyncPrintf("Usage: ajtrawservice [-h] [-n <name>]\n\n");
    QCC_SyncPrintf("Options:\n");
    QCC_SyncPrintf("   -h         = Print this help message\n");
    QCC_SyncPrintf("   -n <name>  = Well-known name to advertise\n");
}

int TestAppMain(int argc, char** argv)
{
    QStatus status = ER_OK;

    QCC_SyncPrintf("AllJoyn Library version: %s\n", ajn::GetVersion());
    QCC_SyncPrintf("AllJoyn Library build info: %s\n", ajn::GetBuildInfo());

    /* Install SIGINT handler */
    signal(SIGINT, SigIntHandler);

    /* Parse command line args */
    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp("-h", argv[i])) {
            usage();
            exit(0);
        } else if (0 == strcmp("-n", argv[i])) {
            ++i;
            if (i == argc) {
                QCC_SyncPrintf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_wellKnownName = argv[i];
            }
        } else {
            status = ER_FAIL;
            QCC_SyncPrintf("Unknown option %s\n", argv[i]);
            usage();
            exit(1);
        }
    }

    g_joinedSessionEvent = new Event();

    /* Get env vars */
    Environ* env = Environ::GetAppEnviron();
    qcc::String clientArgs = env->Find("DBUS_STARTER_ADDRESS");

    if (clientArgs.empty()) {
        clientArgs = env->Find("BUS_ADDRESS");
    }

    /* Create message bus */
    g_msgBus = new BusAttachment("ajtrawservice", true);
    MySessionPortListener mySessionPortListener;

    /* Start the msg bus */
    status = g_msgBus->Start();
    if (status != ER_OK) {
        QCC_LogError(status, ("BusAttachment::Start failed"));
    }

    /* Create a bus listener and connect to the local daemon */
    if (status == ER_OK) {
        /* Connect to the daemon */
        if (clientArgs.empty()) {
            status = g_msgBus->Connect();
        } else {
            status = g_msgBus->Connect(clientArgs.c_str());
        }
        if (status != ER_OK) {
            QCC_LogError(status, ("Failed to connect to \"%s\"", clientArgs.c_str()));
        }
    }

    /* Request a well-known name */
    if (status == ER_OK) {
        QStatus status = g_msgBus->RequestName(g_wellKnownName.c_str(), DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE);
        if (status != ER_OK) {
            QCC_LogError(status, ("Failed to request name %s", g_wellKnownName.c_str()));
        }
    }

    /* Bind the session port */
    SessionOpts opts(SessionOpts::TRAFFIC_RAW_RELIABLE, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
    SessionPort sp = SESSION_PORT;
    status = g_msgBus->BindSessionPort(sp, opts, mySessionPortListener);
    if (status != ER_OK) {
        QCC_LogError(status, ("BindSessionOpts failed"));
    }

    /* Begin Advertising the well-known name */
    if (status == ER_OK) {
        status = g_msgBus->AdvertiseName(g_wellKnownName.c_str(), opts.transports);
        if (status != ER_OK) {
            QCC_LogError(status, ("AdvertiseName failed"));
        }
    }

    /* Wait till you have successfully joined a session */
    status = Event::Wait(*g_joinedSessionEvent);

    SessionId id = mySessionPortListener.GetSessionId();

    /* Get the socket */
    SocketFd sockFd;
    status = g_msgBus->GetSessionFd(id, sockFd);
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

    /* ready to write message on the socket */
    size_t sent;

    uint16_t messageLen = 0;
    uint8_t*payload = NULL;
    uint32_t bytes = 0;

    /* While sending, send the number of bytes first in a send and then send the payload */
    /* Send variable number of bytes 100 times in a loop */
    for (int i = 0; i < 100; i++) {
        if (i == 99) {
            messageLen = 10000;
        } else {
            messageLen = ((double)rand() / RAND_MAX * 1.0) * 65535;
        }
        if (messageLen == 0) {
            continue;
        }
        status = qcc::Send(sockFd, &messageLen, sizeof(messageLen), sent);

        if ((status != ER_OK) || (sent != sizeof(messageLen))) {
            QCC_SyncPrintf("Failed to send messageLen \n");
            status = ER_FAIL;
            break;
        }

        QCC_SyncPrintf("\n [%u] - Data length to be sent is is %u. Sent %u bytes.", i, messageLen, sent);

        /* Now send the actual data of size(messageLen) */
        payload = new uint8_t[messageLen];
        if (payload == NULL) {
            QCC_SyncPrintf("\n Error while allocating memory");
            status = ER_FAIL;
            break;
        }
        /* Set the payload to number '5' */
        memset(payload, 5, messageLen);

        /* Send the payload */
        status = qcc::Send(sockFd, payload, messageLen, sent);

        if ((status != ER_OK) || (sent != messageLen)) {
            QCC_SyncPrintf("\n Failed to send message. Sent only %u bytes. Status is %s.", sent, QCC_StatusText(status));
            status = ER_FAIL;
            break;
        } else if (status == ER_OK) {
            QCC_SyncPrintf("\n[%d] - Sent %u bytes", i, sent);
            bytes += sent;
        }

        /* Clear buffer. Gear up for next iteration */
        delete payload;
        payload = NULL;

        if (g_interrupt) {
            break;
        }
    }

    QCC_SyncPrintf("\nOperation Complete.");
    qcc::Sleep(5000);

    /* Send the total no of bytes transferred */
    status = qcc::Send(sockFd, &bytes, sizeof(bytes), sent);

    if ((status != ER_OK) || (sent != sizeof(bytes))) {
        QCC_SyncPrintf("Failed to send total no of bytes. \n");
        status = ER_FAIL;
    }

/* Close socket */
#ifdef WIN32
    closesocket(sockFd);
#else
    ::shutdown(sockFd, SHUT_RDWR);
    ::close(sockFd);
#endif


    /* Delete the bus */
    delete g_msgBus;
    delete g_joinedSessionEvent;

    QCC_SyncPrintf("\n%s exiting with status %d (%s)\n", argv[0], status, QCC_StatusText(status));

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