/**
 * @file
 * The FuzzedDaemon program listens on a port 9955 for thin client.
 * Once a thin client is connected, it sends out Fuzzed alljoyn messages
 * The thin client is supposed to handle all invalid messages gracefully without crashing
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

#include <qcc/Pipe.h>
#include <qcc/SocketStream.h>
#include <qcc/ManagedObj.h>

#include <alljoyn/BusAttachment.h>
#include <alljoyn/Init.h>
#include <alljoyn/Message.h>
#include <RemoteEndpoint.h>

#define QCC_MODULE "FUZZED ROUTING NODE"

using namespace std;
using namespace ajn;

const bool falsiness = false;
static BusAttachment*g_msgBus = NULL;

class TestPipe : public qcc::Pipe {
  public:
    TestPipe() : qcc::Pipe() { }
};

typedef struct {
    char endian;           ///< The endian-ness of this message
    uint8_t msgType;       ///< Indicates if the message is method call, signal, etc.
    uint8_t flags;         ///< Flag bits
    uint8_t majorVersion;  ///< Major version of this message
    uint32_t bodyLen;      ///< Length of the body data
    uint32_t serialNum;    ///< serial of this message
    uint32_t headerLen;    ///< Length of the header fields
} MsgHeader;


class _MyMessage : public _Message {
  public:

    _MyMessage() : _Message(*g_msgBus) { };

    QStatus MethodCall(const char* destination,
                       const char* objPath,
                       const char* interface,
                       const char* methodName,
                       const MsgArg* argList,
                       size_t numArgs,
                       uint8_t flags = 0)
    {
        qcc::String sig = MsgArg::Signature(argList, numArgs);
        return CallMsg(sig, destination, 0, objPath, interface, methodName, argList, numArgs, flags);
    }

    QStatus Signal(const char* destination,
                   const char* objPath,
                   const char* interface,
                   const char* signalName,
                   const MsgArg* argList,
                   size_t numArgs)
    {
        qcc::String sig = MsgArg::Signature(argList, numArgs);
        return SignalMsg(sig, destination, 0, objPath, interface, signalName, argList, numArgs, 0, 0);
    }

    QStatus Deliver(RemoteEndpoint& ep)
    {
        return _Message::Deliver(ep);
    }
};

typedef qcc::ManagedObj<_MyMessage> MyMessage;

void Randfuzzing(void* buf, size_t len, uint8_t percent)
{
    uint8_t* p = (uint8_t*)buf;
    if (percent > 100) {
        percent = 100;
    }
    while (len--) {
        if (percent > ((100 * qcc::Rand8()) / 256)) {
            *p = qcc::Rand8();
        }
        ++p;
    }
}

static void Fuzz(TestPipe& stream)
{
    uint8_t* fuzzBuf;
    size_t size = stream.AvailBytes();
    size_t offset;

    fuzzBuf = new uint8_t[size];
    stream.PullBytes(fuzzBuf, size, size);
    MsgHeader* hdr = (MsgHeader*)(fuzzBuf);

    uint8_t test = qcc::Rand8() % 16;

    switch (test) {
    case 0:
        /*
         * Protect fixed header from fuzzing
         */
        offset = sizeof(MsgHeader);
        Randfuzzing(fuzzBuf + offset, size - offset, 5);
        break;

    case 1:
        /*
         * Protect entire header from fuzzing
         */
        offset = sizeof(MsgHeader) + hdr->headerLen;
        Randfuzzing(fuzzBuf + offset, size - offset, 5);
        break;

    case 2:
        /*
         * Toggle endianess
         */
        hdr->endian = (hdr->endian == ALLJOYN_BIG_ENDIAN) ? ALLJOYN_LITTLE_ENDIAN : ALLJOYN_BIG_ENDIAN;
        break;

    case 3:
        /*
         * Toggle flag bits
         */
        {
            uint8_t bit = (1 << qcc::Rand8() % 8);
            hdr->flags ^= bit;
        }
        break;

    case 4:
        /*
         * Mess with header len a little
         */
        hdr->headerLen += (qcc::Rand8() % 8) - 4;
        break;

    case 5:
        /*
         * Randomly set header len
         */
        hdr->headerLen = qcc::Rand16() - 0x7FFF;
        break;

    case 6:
        /*
         * Mess with body len a little
         */
        hdr->bodyLen += (qcc::Rand8() % 8) - 4;
        break;

    case 7:
        /*
         * Randomly set body len
         */
        hdr->headerLen = qcc::Rand16() - 0x7FFF;
        break;

    case 9:
        /* Dont fuzz */
        break;

    case 8:
        /*
         * Change message type (includes invalid types)
         */
        hdr->msgType = qcc::Rand8() % 6;
        break;

    default:
        /*
         * Fuzz the entire message
         */
        Randfuzzing(fuzzBuf, size, 1 + (qcc::Rand8() % 10));
        break;
    }
    stream.PushBytes(fuzzBuf, size, size);
    delete [] fuzzBuf;
    /*
     * Sometimes append garbage
     */
    if (qcc::Rand8() > 2) {
        size_t len = qcc::Rand8();
        while (len--) {
            uint8_t b = qcc::Rand8();
            stream.PushBytes(&b, 1, size);
        }
    }
}

int TestAppMain() {
    QStatus status = ER_FAIL;
    qcc::SocketFd listenfd;

    status = qcc::Socket(qcc::QCC_AF_INET, qcc::QCC_SOCK_STREAM, listenfd);
    if (ER_OK != status) {
        QCC_LogError(status, ("Unable to create socket"));
        return 1;
    }

    qcc::IPAddress all_interfaces_on_this_host("0.0.0.0");
    status = qcc::Bind(listenfd, all_interfaces_on_this_host, 9955);
    if (ER_OK != status) {
        QCC_LogError(status, ("Unable to bind socket to port 9955"));
        return 1;
    }

    status = qcc::Listen(listenfd, 1);
    if (ER_OK != status) {
        QCC_LogError(status, ("Unable to listen on socket bound to port 9955"));
        return 1;
    }

    qcc::SocketFd connfd;
    status = qcc::Accept(listenfd, connfd);
    if (ER_OK != status) {
        QCC_LogError(status, ("Unable to accept incoming connection"));
        return 1;
    }

    g_msgBus = new BusAttachment("FuzzedDaemon");
    status = g_msgBus->Start();
    if (ER_OK != status) {
        QCC_LogError(status, ("Unable to start bus attachment"));
        return 1;
    }
    status = g_msgBus->Connect("null:");
    if (ER_OK != status) {
        QCC_LogError(status, ("Unable to connect to routing node"));
        return 1;
    }

    //create a sock stream out of connfd
    qcc::SocketStream* socketStream = new qcc::SocketStream(connfd);

    //Create a RemoteEndpoint using a pipe
    TestPipe stream;
    TestPipe* pStream = &stream;
    RemoteEndpoint rep(*g_msgBus, falsiness, qcc::String::Empty, pStream);
    uint8_t* buf = NULL;
    size_t actualBytes = 0;

    for (;;) {
        //Construct alljoyn message and send to thin client.
        MyMessage msg;
        MsgArg arg("s", "Hello");
        //status = msg->MethodCall("desti.nations", "/foo/bar", "foo.bar", "test", &arg, 1);
        status = msg->Signal("desti.nations", "/foo/bar", "foo.bar", "test", &arg, 1);
        status = msg->Deliver(rep);

        //The remote endpoint is associated with a stream. The stream contains the data. Fuzz that data.
        Fuzz(stream);

        // The stream should now be pushed to the socket stream so that it goes to the other side.
        // So, pullbytes from pipe and push it into socket stream.
        size_t size = pStream->AvailBytes();
        buf = new uint8_t[size];
        status = pStream->PullBytes(buf, size, actualBytes);

        //push buf into socketstream
        actualBytes = 0;
        status = socketStream->PushBytes(buf, size, actualBytes);
        if (status != ER_OK) {
            delete socketStream;
            status = qcc::Accept(listenfd, connfd);
            socketStream = new qcc::SocketStream(connfd);
        }

        delete [] buf;
    }
}

int CDECL_CALL main()
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

    int ret = TestAppMain();

#ifdef ROUTER
    AllJoynRouterShutdown();
#endif
    AllJoynShutdown();

    return ret;
}