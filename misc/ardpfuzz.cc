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
 *
 ******************************************************************************/

#include <qcc/Debug.h>
#include <qcc/Log.h>
#include <qcc/Environ.h>

#include <stdlib.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <vector>
#include <queue>
#include <qcc/Mutex.h>
#include <qcc/Util.h>
#include <qcc/Event.h>
#include <qcc/Socket.h>
#include <qcc/SocketTypes.h>
#include <qcc/Thread.h>
#include <qcc/StringUtil.h>
#include <alljoyn/Status.h>
#include <qcc/time.h>
#include <ArdpProtocol.h>

#define ARDP_TESTHOOKS 1
#if ARDP_TESTHOOKS
#include "ScatterGatherList.h"
#endif

#define QCC_MODULE "ALLJOYN"

using namespace std;
using namespace qcc;
using namespace ajn;

const uint32_t UDP_CONNECT_TIMEOUT = 1000;  /**< How long before we expect a connection to complete */
const uint32_t UDP_CONNECT_RETRIES = 10;  /**< How many times do we retry a connection before giving up */
const uint32_t UDP_INITIAL_DATA_TIMEOUT = 1000;  /**< Initial value for how long do we wait before retrying sending data */
const uint32_t UDP_TOTAL_DATA_RETRY_TIMEOUT = 5000;  /**< Total amount of time to try and send data before giving up */
const uint32_t UDP_MIN_DATA_RETRIES = 5;  /**< Minimum number of times to try and send data before giving up */
const uint32_t UDP_PERSIST_INTERVAL = 1000;  /**< How long do we wait before pinging the other side due to a zero window */
const uint32_t UDP_TOTAL_APP_TIMEOUT = 30000;  /**< How long to we try to ping for window opening before deciding app is not pulling data */
const uint32_t UDP_LINK_TIMEOUT = 30000;  /**< How long before we decide a link is down (with no reponses to keepalive probes */
const uint32_t UDP_KEEPALIVE_RETRIES = 5;  /**< How many times do we try to probe on an idle link before terminating the connection */
const uint32_t UDP_FAST_RETRANSMIT_ACK_COUNTER = 1; /**< How many duplicate acknowledgements to we need to trigger a data retransmission */
const uint32_t UDP_TIMEWAIT = 1000;         /**< How long do we stay in TIMWAIT state before releasing the per-connection resources */
const uint32_t UDP_SEGBMAX = 65507;  /**< Maximum size of an ARDP message (for receive buffer sizing) */
const uint32_t UDP_SEGMAX = 16;      /**< Maximum number of ARDP messages in-flight (bandwidth-delay product sizing) */

char const* g_local_port = "9954";
char const* g_foreign_port = "9955";
char const* g_local_address = "127.0.0.1";
char const* g_foreign_address = "127.0.0.1";

char const* g_ajnConnString = "AUTH ANONYMOUS; BEGIN THE CONNECTION; Bus Hello; Bellevue";
char const* g_ajnAcceptString = "OK 123455678; Hello; Redmond";
char const* g_ajnAcknowledgeString = "Acking: WE ARE ON!";

static ArdpConnRecord* g_conn;
std::queue<ArdpRcvBuf*> RecvQueue;

static int g_sender_delay = 10;
static int g_receiver_delay = 10;
static Mutex g_lock;
static uint32_t g_sleepTime = 60000;
static uint32_t g_payloadLength = 135000;
static uint32_t g_ttl = 0;
static bool g_ttlSet = false;
static uint32_t g_percent = 50;
static bool g_debug = false;
static bool g_connect = true;
static bool sender = false;
static bool receiver = false;

static volatile sig_atomic_t g_interrupt = false;
uint32_t*PAYLOAD;


static void SigIntHandler(int sig)
{
    g_interrupt = true;
}

void GetData(ArdpRcvBuf* rcv) {

    static uint32_t infinite_ttl_packet_count = 0;
    static uint32_t hole = 0;

    ArdpRcvBuf*buf = rcv;
    uint32_t len = 0;
    uint16_t fragment = rcv->fcnt;


    uint32_t*data = (uint32_t*)buf->data;

    printf("RecvCB: Received count is %u, infinite_ttl_count=%u, ttl= %u, length is %u \n", htonl(data[3]), htonl(data[0]), htonl(data[2]), htonl(data[1]));

    /* Detect holes in the receiving side. */
    if (htonl(data[3]) > hole) {
        printf(" %u packets lost at receiver \n", htonl(data[3]) - hole);
        hole = htonl(data[3]) + 1;
    } else {
        hole++;
    }

    /* Consume data buffers */
    for (uint16_t i = 0; i < fragment; i++) {
        //QCC_DbgPrintf(("RecvCb(): got %d bytes of data \n", buf->datalen));
        len += buf->datalen;
        buf = buf->next;
    }

    //infinite_ttl_count should match when there is no ttl.
    if ((htonl(data[2]) == 0) && (htonl(data[0]) != infinite_ttl_packet_count)) {
        printf("RECEIVER: Count not matching. count: %u, infinite_ttl_packet_count: %u  Alert!. Program FAILED \n", htonl(data[0]), infinite_ttl_packet_count);
    }
    if (len != htonl(data[1])) {
        printf("RECEIVER: Data length not matching. length: %u, callback length: %u Alert!. Program FAILED \n", htonl(data[1]), len);
    }

    //If ttl==0, only then increment the infinite_ttl_packet_count
    if (htonl(data[2]) == 0) {
        infinite_ttl_packet_count++;
    }
    printf("RCBUSERDATA %u\n", len);

}

bool AcceptCb(ArdpHandle* handle, qcc::IPAddress ipAddr, uint16_t ipPort, ArdpConnRecord* conn, uint8_t* buf, uint16_t len, QStatus status)
{
    printf("Inside Accept callback, we received a SYN from %s:%d, the message is  %s, status %s \n", ipAddr.ToString().c_str(), ipPort, (char*)buf, QCC_StatusText(status));
    printf("Connection pointer is   %p \n", g_conn);
    g_lock.Lock();
    status = ARDP_Accept(handle, conn, UDP_SEGMAX, UDP_SEGBMAX, (uint8_t* )g_ajnAcceptString, strlen(g_ajnAcceptString) + 1);
    g_lock.Unlock();
    if (status != ER_OK) {
        printf("Error while ARDP_Accept.. %s \n", QCC_StatusText(status));
        return false;
    }
    return true;
}

void ConnectCb(ArdpHandle* handle, ArdpConnRecord* conn, bool passive, uint8_t* buf, uint16_t len, QStatus status)
{
    printf("Looks like I have connected... conn=%p is passive=%s , the message is  %s, status is %s \n", conn, (passive) ? "true" : "false", (char*)buf, QCC_StatusText(status));
    g_lock.Lock();
    if (status == ER_OK) {
        g_conn = conn;
        g_connect = true;
    } else {
        //If the connection is not successful, we should not save this anymore and we should clean it up.
        ARDP_ReleaseConnection(handle, conn);
    }
    g_lock.Unlock();
}

void DisconnectCb(ArdpHandle* handle, ArdpConnRecord* conn, QStatus status)
{
    printf("Looks like I have disconnected conn = %p..reason = %s \n", conn, QCC_StatusText(status));
    g_lock.Lock();
    g_connect = false;
    printf("Clearing up the Recv buffer \n");
    while (!RecvQueue.empty()) {
        RecvQueue.pop();
    }
    g_lock.Unlock();
}

void RecvCb(ArdpHandle* handle, ArdpConnRecord* conn, ArdpRcvBuf* rcv, QStatus status)
{
    g_lock.Lock(MUTEX_CONTEXT);
    GetData(rcv);
    RecvQueue.push(rcv);
    g_lock.Unlock(MUTEX_CONTEXT);
}

void SendCb(ArdpHandle* handle, ArdpConnRecord* conn, uint8_t* buf, uint32_t len, QStatus status)
{
    static uint32_t sender_infinite_ttl_count = 0;

    uint32_t*data = (uint32_t*)buf;
    printf("SendCB: sender_infinite_count is %u, length is %u sender_count is %u ttl is %u status is %s \n", htonl(data[0]), htonl(data[1]), htonl(data[3]), htonl(data[2]), QCC_StatusText(status));

    //Sender count should match for infinite_ttl
    if (htonl(data[0]) != sender_infinite_ttl_count) {
        printf("SendCB: Count not matching. Real count: %u, expected count: %u Alert!. Program FAILED \n", htonl(data[0]), sender_infinite_ttl_count);
    }
    if (len != htonl(data[1])) {
        printf("SendCB: Data length not matching Real length: %u, length from callback: %u . Alert!. Program FAILED \n", htonl(data[1]), len);
    }

    //If ttl==0, only then increase the sender_infinite_ttl_count
    if (htonl(data[2]) == 0) {
        sender_infinite_ttl_count++;
    }

    printf("SCBUSERDATA %u\n", len);
    free(buf);
}

void SendWindowCb(ArdpHandle* handle, ArdpConnRecord* conn, uint16_t window, QStatus status)
{
    QCC_DbgPrintf(("WINDOW RECEIVED-  %u, conn = %p \n", window, conn));
}

void ArdpSendToSGHook(ArdpHandle* handle, ArdpConnRecord* conn, TesthookSource source, qcc::ScatterGatherList& msgSG)
{
    if (SEND_MSG_DATA == source) {

        std::list<IOVec>::iterator start(msgSG.Begin());
        std::list<IOVec>::iterator end(msgSG.End());

        //Fuzz the header
        uint32_t len = start->len;
        uint8_t*buf = (uint8_t*)(start)->buf;

        uint32_t toss = random() % 6;
        if (toss == 0) {
            //just change the length
            printf("SEN DATA RAND: header length changed \n");
            (start)->len = random() % 50;
        } else if (toss == 1) {
            //change every 2 bytes of the header
            printf("SEN DATA RAND: every 2 bytes fuzzed \n");
            for (uint32_t i = random() % 2; i < len; i = i + 2) {
                buf[i] = random() % 255;
            }
        } else if (toss == 2) {
            //change every 4 bytes of the header
            printf("SEN DATA RAND: every 4 bytes fuzzed \n");
            for (uint32_t i = random() % 4; i < len; i = i + 4) {
                buf[i] = random() % 255;
            }
        } else if (toss == 3) {
            //change every 8 bytes of the header
            printf("SEN DATA RAND: every 8 bytes fuzzed \n");
            for (uint32_t i = random() % 8; i < len; i = i + 8) {
                buf[i] = random() % 255;
            }
        } else if (toss == 4) {
            //change every 16 bytes of the header
            printf("SEN DATA RAND: every 16 bytes fuzzed \n");
            for (uint32_t i = random() % 16; i < len; i = i + 16) {
                buf[i] = random() % 255;
            }
        } else {
            //send it as it is
            printf("SEN DATA RAND: Sent as it is \n");
        }

        start++;
        std::list<IOVec>::iterator temp(start);

        if (++temp == end) {
            printf("SEN DATA No middle layer.\n");
            if (random() % 10 == 9) {
                printf("SEN DATA Changing the data length mod 130000 \n");
                start->len = random() % 130000;
            } else if (random() % 10 == 8) {
                printf("SEN DATA Changing the data length mod 10 \n");
                start->len = random() % 10;
            } else {
                printf("SEN DATA Not changing data length \n");
            }
        } else {
            printf("SEN DATA Yes middle layer exists. \n");
            exit(-1);
        }

    }

    if ((receiver) && (SEND_MSG_HEADER == source) && (g_connect)) {

        std::list<IOVec>::iterator start(msgSG.Begin());
        std::list<IOVec>::iterator end(msgSG.End());

        //Fuzz the header
        uint32_t len = start->len;
        uint8_t*buf = (uint8_t*)(start)->buf;

        uint32_t toss = random() % 6;
        if (toss == 0) {
            //just change the length
            printf("RECV RAND: header length changed \n");
            (start)->len = random() % 50;
        } else if (toss == 1) {
            //change every 2 bytes of the header
            printf("RECV RAND: every 2 bytes fuzzed \n");
            for (uint32_t i = random() % 2; i < len; i = i + 2) {
                buf[i] = random() % 255;
            }
        } else if (toss == 2) {
            //change every 4 bytes of the header
            printf("RECV RAND: every 4 bytes fuzzed \n");
            for (uint32_t i = random() % 4; i < len; i = i + 4) {
                buf[i] = random() % 255;
            }
        } else if (toss == 3) {
            //change every 8 bytes of the header
            printf("RCEV RAND: every 8 bytes fuzzed \n");
            for (uint32_t i = random() % 8; i < len; i = i + 8) {
                buf[i] = random() % 255;
            }
        } else if (toss == 4) {
            //change every 16 bytes of the header
            printf("RECV RAND: every 16 bytes fuzzed \n");
            for (uint32_t i = random() % 16; i < len; i = i + 16) {
                buf[i] = random() % 255;
            }
        } else {
            //send it as it is
            printf("RECV RAND: Sent as it is \n");
        }


    }
}

void ArdpSendToHook(ArdpHandle* handle, ArdpConnRecord* conn, TesthookSource source, void* buf, uint32_t len)
{
    //used only for sending RST. less likely to be used.
    printf("SendTo: Just about to send. You have control of data. \n");
}

void ArdpRecvFromHook(ArdpHandle* handle, ArdpConnRecord* conn, TesthookSource source, void* buf, uint32_t len)
{
    //less likely used
    printf("RecvFrom: You received something from the socket. This is your chance to manipulate the fresh data.\n");
}

class RecvClass : public Thread {

  public:
    RecvClass(char*name, ArdpHandle* handle, qcc::SocketFd sock) : Thread(name) {
        m_handle = handle;
        m_sock = sock;
    }

  protected:
    qcc::ThreadReturn STDCALL Run(void* arg) {

        while ((!g_interrupt) && (IsRunning())) {

            while (!RecvQueue.empty()) {
                ArdpRcvBuf*rcv = NULL;
                g_lock.Lock(MUTEX_CONTEXT);
                rcv = RecvQueue.front();
                RecvQueue.pop();
                if (RecvQueue.empty()) {
                    g_lock.Unlock(MUTEX_CONTEXT);
                    break;
                }
                QStatus status = ARDP_RecvReady(m_handle, g_conn, rcv);
                g_lock.Unlock(MUTEX_CONTEXT);
                if (status != ER_OK) {
                    QCC_LogError(status, ("Error while ARDP_Recv.. %s \n", QCC_StatusText(status)));
                    break;
                }
                qcc::Sleep(g_receiver_delay);
            }

        }

        return this;
    }

  private:
    ArdpHandle* m_handle;
    qcc::SocketFd m_sock;

};

class SendClass : public Thread {

  public:
    SendClass(char*name, ArdpHandle* handle, qcc::SocketFd sock) : Thread(name) {
        m_handle = handle;
        m_sock = sock;
    }

  protected:
    qcc::ThreadReturn STDCALL Run(void* arg) {

        while ((!g_interrupt) && (IsRunning())) {
            static uint32_t sender_infinite_ttl_count = 0;
            static uint32_t sender_count = 0;
            static uint32_t ttl_expired_at_sender = 0;

            //We need atleast 16 bytes. 4 for infinite_ttl_count, 4 for uint32_t length and 4 for TTL, 4 for sender_count;
            uint32_t length = 16 + qcc::Rand32() % (g_payloadLength);
            uint32_t ttl = 0;

            //double a = (double)qcc::Rand8()/255.0;
            double a = (double)rand() / (RAND_MAX * 1.0);
            double b = (double)g_percent / 100.0;

            if (g_debug) { printf("a is %lf, b is %lf \n", a, b); }

            //Set the ttl
            if (g_ttlSet) {
                if (a < b) {
                    ttl = g_ttl;
                }
            } else {
                ttl = 0;
            }

            PAYLOAD = (uint32_t*)malloc(40000 * sizeof(uint32_t));
            //set the infinite ttl count
            PAYLOAD[0] = ntohl(sender_infinite_ttl_count);
            //set the length
            PAYLOAD[1] = ntohl(length);
            //keep the ttl as it is because it is not multi byte.
            PAYLOAD[2] = ntohl(ttl);
            //set the sender count
            PAYLOAD[3] = ntohl(sender_count);

            g_lock.Lock(MUTEX_CONTEXT);
            QStatus status = ARDP_Send(m_handle, g_conn, (uint8_t*)PAYLOAD, length, ttl);
            g_lock.Unlock(MUTEX_CONTEXT);
            if ((status != ER_OK) && (status != ER_ARDP_TTL_EXPIRED)) {
                if (g_debug) { printf("ARDP_Send Error: sender_count is  %u, sender_infinite_ttl_count is %u, ttl= %u, length is %u status is %s \n", sender_count, sender_infinite_ttl_count, ttl, length, QCC_StatusText(status)); }
                free(PAYLOAD);
            } else {
                if (a < b) {
                    if (g_debug) { printf("Setting ttl as random number %lf < percent %lf \n", a, b); }
                }

                printf("ARDP_Send: sender_count is  %u, sender_infinite_ttl_count is %u, ttl= %u, length is %u ttl_expired_packets_so_far: %u Status is %s \n", sender_count, sender_infinite_ttl_count, ttl, length, ttl_expired_at_sender, QCC_StatusText(status));

                if (status == ER_ARDP_TTL_EXPIRED) {
                    //just to keep a count of ttl expired packets at the sender
                    ttl_expired_at_sender++;
                } else {
                    //packet was sent sucecssfully.
                    sender_count++;
                }

                if (ttl == 0) {
                    //if ttl=0, increment the infinite ttl count
                    sender_infinite_ttl_count++;
                }
            }
            qcc::Sleep(g_sender_delay);
        }

        return this;
    }

  private:
    ArdpHandle* m_handle;
    qcc::SocketFd m_sock;

};


class ThreadClass : public Thread {

  public:
    ThreadClass(char*name, ArdpHandle* handle, qcc::SocketFd sock) : Thread(name) {
        m_handle = handle;
        m_sock = sock;
    }

  protected:
    qcc::ThreadReturn STDCALL Run(void* arg) {

        while ((!g_interrupt) && (IsRunning())) {
            uint32_t ms;
            g_lock.Lock(MUTEX_CONTEXT);
            ARDP_Run(m_handle, m_sock, true, true, &ms);
            g_lock.Unlock(MUTEX_CONTEXT);
            qcc::Sleep(1);
        }

        return this;
    }

  private:
    ArdpHandle* m_handle;
    qcc::SocketFd m_sock;

};

static void usage() {
    printf("./ardpstress -lp 9955 -fp 9954 -s -sd 50 -c -sleep 60000 \n");
    printf("./ardpstress -lp 9954 -fp 9955 -r -rd 40  -sleep 60000 \n");
    printf("./ardpstress -lp 9954 -fp 9955 -r -rd 40 -la 10.0.0.1 -fa 10.0.0.2 -sleep 60000 \n");
    printf(" -lp #: local port\n");
    printf(" -fp #: foreign port\n");
    printf(" -la #: local address\n");
    printf(" -fa #: foreign address\n");
    printf(" -s: sender\n");
    printf(" -sd #: sender delay\n");
    printf(" -r: receiver\n");
    printf(" -rd # : receiver delay\n");
    printf(" -c:  side calling connect\n");
    printf(" -payload #:  Max payload length: default is 135000\n");
    printf(" -ttl #:  ttl, default is 0\n");
    printf(" -percent #: percentage of packets with TTL\n");
    printf(" -sleep # :  program run time\n");
    printf(" -d :  Enable program debug\n");
}

int main(int argc, char** argv)
{
    QStatus status = ER_OK;
    bool connector = false;
    srandom(time(NULL));
    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp("-lp", argv[i])) {
            g_local_port = argv[i + 1];
            i++;
        } else if (0 == strcmp("-h", argv[i])) {
            usage();
        } else if (0 == strcmp("-fp", argv[i])) {
            g_foreign_port = argv[i + 1];
            i++;
        } else if (0 == strcmp("-la", argv[i])) {
            g_local_address = argv[i + 1];
            i++;
        } else if (0 == strcmp("-fa", argv[i])) {
            g_foreign_address = argv[i + 1];
            i++;
        } else if (0 == strcmp("-d", argv[i])) {
            g_debug = true;
        } else if (0 == strcmp("-c", argv[i])) {
            connector = true;
        } else if (0 == strcmp("-r", argv[i])) {
            receiver = true;
        } else if (0 == strcmp("-s", argv[i])) {
            sender = true;
        } else if (0 == strcmp("-sd", argv[i])) {
            g_sender_delay = atoi(argv[i + 1]);
            i++;
        } else if (0 == strcmp("-rd", argv[i])) {
            g_receiver_delay = atoi(argv[i + 1]);
            i++;
        } else if (0 == strcmp("-sleep", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_sleepTime = qcc::StringToU32(argv[i], 0);;
            }
        } else if (0 == strcmp("-payload", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_payloadLength = qcc::StringToU32(argv[i], 0);;
            }
        } else if (0 == strcmp("-ttl", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_ttl = qcc::StringToU32(argv[i], 0);
                g_ttlSet = true;
            }
        } else if (0 == strcmp("-percent", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_percent = qcc::StringToU32(argv[i], 0);;
            }
        } else {
            printf("Unknown option %s\n", argv[i]);
            exit(0);
        }
    }

    if (!sender && !receiver) {
        printf("Use -s or -r option \n");
        exit(0);
    }

    signal(SIGINT, SigIntHandler);

    //One time activity- Create a socket, set to blocking, bind it to local port, local address
    qcc::SocketFd sock;

    status = qcc::Socket(qcc::QCC_AF_INET, qcc::QCC_SOCK_DGRAM, sock);
    if (status != ER_OK) {
        QCC_LogError(status, ("Test::Run(): Socket(): Failed"));
        return 0;
    }

    status = qcc::SetBlocking(sock, false);
    if (status != ER_OK) {
        QCC_LogError(status, ("Test::Run(): SetBlocking(): Failed"));
        return 0;
    }

    status = qcc::Bind(sock, qcc::IPAddress(g_local_address), atoi(g_local_port));
    if (status != ER_OK) {
        QCC_LogError(status, ("Test::Run(): Bind(): Failed"));
        return 0;
    }

    //Populate default values for timers, couters, etc.
    ArdpGlobalConfig ardpConfig;
    ardpConfig.connectTimeout = UDP_CONNECT_TIMEOUT;
    ardpConfig.connectRetries = UDP_CONNECT_RETRIES;
    ardpConfig.initialDataTimeout = UDP_INITIAL_DATA_TIMEOUT;
    ardpConfig.totalDataRetryTimeout = UDP_TOTAL_DATA_RETRY_TIMEOUT;
    ardpConfig.minDataRetries = UDP_MIN_DATA_RETRIES;
    ardpConfig.persistInterval = UDP_PERSIST_INTERVAL;
    ardpConfig.totalAppTimeout = UDP_TOTAL_APP_TIMEOUT;
    ardpConfig.linkTimeout = UDP_LINK_TIMEOUT;
    ardpConfig.keepaliveRetries = UDP_KEEPALIVE_RETRIES;
    ardpConfig.fastRetransmitAckCounter = UDP_FAST_RETRANSMIT_ACK_COUNTER;
    ardpConfig.timewait = UDP_TIMEWAIT;
    ardpConfig.segbmax = UDP_SEGBMAX;
    ardpConfig.segmax = UDP_SEGMAX;

    //Allocate a handle (ARDP protocol instance).
    ArdpHandle* handle = ARDP_AllocHandle(&ardpConfig);

    //Set the callbacks- accept, connect, disconnectcb, recv, send, sendwindow
    ARDP_SetAcceptCb(handle, AcceptCb);
    ARDP_SetConnectCb(handle, ConnectCb);
    ARDP_SetDisconnectCb(handle, DisconnectCb);
    ARDP_SetRecvCb(handle, RecvCb);
    ARDP_SetSendCb(handle, SendCb);
    ARDP_SetSendWindowCb(handle, SendWindowCb);

#if ARDP_TESTHOOKS
    ARDP_HookSendToSG(handle, ArdpSendToSGHook);
    //ARDP_HookSendTo(handle, ArdpSendToHook);
    //ARDP_HookRecvFrom(handle, ArdpRecvFromHook);
#endif

    ArdpConnRecord* conn;

    //The side can behave as a server or client. Teach it to behave as a server.
    // This API is only for server side.
    ARDP_StartPassive(handle);
    if (connector) {
        g_lock.Lock();
        status = ARDP_Connect(handle, sock, qcc::IPAddress(g_foreign_address), atoi(g_foreign_port), UDP_SEGMAX, UDP_SEGBMAX, &conn, (uint8_t* )g_ajnConnString, strlen(g_ajnConnString) + 1, NULL); \
        g_lock.Unlock();
        if (status != ER_OK) {
            printf("Error while calling ARDP_Connect..  %s \n", QCC_StatusText(status));
            return 0;
        }
    }


    ThreadClass t1((char*)"t1", handle, sock);
    t1.Start();

    SendClass s1((char*)"s1", handle, sock);
    if (sender) {
        s1.Start();
    }

    RecvClass r1((char*)"r1", handle, sock);
    if (receiver) {
        r1.Start();
    }

    uint32_t startTime = GetTimestamp();
    uint32_t endTime = GetTimestamp();
    while (!g_interrupt) {
        endTime = GetTimestamp();
        if ((!g_connect) && (connector)) {
            //re-connect again
            printf("Connecting again..\n");
            g_lock.Lock();
            status = ARDP_Connect(handle, sock, qcc::IPAddress(g_foreign_address), atoi(g_foreign_port), UDP_SEGMAX, UDP_SEGBMAX, &conn, (uint8_t* )g_ajnConnString, strlen(g_ajnConnString) + 1, NULL); \
            g_lock.Unlock();
            if (status != ER_OK) {
                printf("Error while calling ARDP_Connect..  %s \n", QCC_StatusText(status));
                return 0;
            }
        }

        if ((endTime - startTime) > g_sleepTime) {
            printf("Time  %u exceeds  %u specified. program exits  \n", (endTime - startTime), g_sleepTime);
            g_interrupt = true;
            break;
        }
        qcc::Sleep(100);
    }

    t1.Stop();
    t1.Join();

    s1.Stop();
    s1.Join();

    r1.Stop();
    r1.Join();

    return 0;
}