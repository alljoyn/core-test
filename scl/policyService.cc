/**
 * @file
 * Sample implementation of an AllJoyn service.
 */
/******************************************************************************
 *    Copyright (c) Open Connectivity Foundation (OCF), AllJoyn Open Source
 *    Project (AJOSP) Contributors and others.
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
#include <qcc/platform.h>

#ifdef _WIN32
#include <Crtdbg.h>
#endif

#include <signal.h>
#include <stdio.h>
#include <vector>

#include <qcc/Debug.h>
#include <qcc/Environ.h>
#include <qcc/Mutex.h>
#include <qcc/String.h>
#include <qcc/Thread.h>
#include <qcc/time.h>
#include <qcc/Util.h>

#include <alljoyn/AllJoynStd.h>
#include <alljoyn/BusAttachment.h>
#include <alljoyn/BusObject.h>
#include <alljoyn/DBusStd.h>
#include <alljoyn/MsgArg.h>
#include <alljoyn/Init.h>
#include <alljoyn/version.h>

#include <alljoyn/Status.h>


#define QCC_MODULE "ALLJOYN"

using namespace std;
using namespace qcc;
using namespace ajn;

/* setup for first test object */
namespace abcd {
const char* WellKnownName = "abcd.org";
const char* ObjectPath = "/abcd/org";
const char* InterfaceName1 = "ab.org";
const char* InterfaceName2 = "cd.org";

const char* Method1 = "aMethod";
const char* Method2 = "bMethod";
const char* Method3 = "cMethod";
const char* Method4 = "dMethod";

const char* Error1 = "aError";
const char* Error2 = "bError";
const char* Error3 = "cError";
const char* Error4 = "dError";

const char* ErrorName1 = "a.error";
const char* ErrorName2 = "b.error";
const char* ErrorName3 = "c.error";
const char* ErrorName4 = "d.error";

const char* Signal1 = "a_signal";
const char* Signal2 = "b_signal";
const char* Signal3 = "c_signal";
const char* Signal4 = "d_signal";
}

/* setup for 2nd test object */
namespace efgh {
const char* WellKnownName = "efgh.gov";
const char* ObjectPath = "/efgh/gov";
const char* InterfaceName1 = "ef.gov";
const char* InterfaceName2 = "gh.gov";

const char* Method1 = "eMethod";
const char* Method2 = "fMethod";
const char* Method3 = "gMethod";
const char* Method4 = "hMethod";

const char* Error1 = "eError";
const char* Error2 = "fError";
const char* Error3 = "gError";
const char* Error4 = "hError";

const char* ErrorName1 = "e.error";
const char* ErrorName2 = "f.error";
const char* ErrorName3 = "g.error";
const char* ErrorName4 = "h.error";

const char* Signal1 = "e_signal";
const char* Signal2 = "f_signal";
const char* Signal3 = "g_signal";
const char* Signal4 = "h_signal";
}

static const SessionPort mySessionPort = 30;    /**< Well-knwon session port value for policyClient/policyService */
static String g_wellKnownName1 = ::abcd::WellKnownName;
static String g_wellKnownName2 = ::efgh::WellKnownName;

/* Forward declaration */
class MyBusListener;


/* Static top level globals */
static BusAttachment* g_msgBus = NULL;
static MyBusListener* g_myBusListener = NULL;

static bool g_cancelAdvertise = false;


static Event* g_object1_registeredEvent = NULL;
static Event* g_object2_registeredEvent = NULL;

static volatile sig_atomic_t g_interrupt = false;

static void SigIntHandler(int sig)
{
    QCC_UNUSED(sig);
    g_interrupt = true;
}


class MyBusListener : public SessionPortListener, public SessionListener {

  public:
    MyBusListener(BusAttachment& bus, const SessionOpts& opts) : bus(bus), opts(opts) { }

    bool AcceptSessionJoiner(SessionPort sessionPort, const char* joiner, const SessionOpts& opts)
    {
        /* Reject join attetmpt to unknwown session port */
        if (sessionPort != mySessionPort) {
            QCC_SyncPrintf("Received JoinSession request for non-bound port\n");
            return false;
        }

        if (this->opts.IsCompatible(opts)) {
            /* Allow the join attempt */
            QCC_SyncPrintf("Accepting JoinSession request from %s\n", joiner);
            return true;
        } else {
            /* Reject incompatible transports */
            QCC_SyncPrintf("Rejecting joiner %s with incompatible session options\n", joiner);
            return false;
        }
    }

    void SessionJoined(SessionPort sessionPort, SessionId sessionId, const char* joiner)
    {
        QCC_UNUSED(sessionPort);
        QCC_SyncPrintf("Session Established: joiner=%s, sessionId=%08x\n", joiner, sessionId);

        /* Enable concurrent callbacks since some of the calls below could block */
        g_msgBus->EnableConcurrentCallbacks();

        QStatus status = bus.SetSessionListener(sessionId, this);
        if (status != ER_OK) {
            QCC_LogError(status, ("SetSessionListener failed"));
            return;
        }

        /* Set the link timeout */
        uint32_t timeout = 10;
        status = bus.SetLinkTimeout(sessionId, timeout);
        if (status == ER_OK) {
            QCC_SyncPrintf("Link timeout was successfully set to %d\n", timeout);
        } else {
            QCC_LogError(status, ("SetLinkTimeout failed"));
        }

        /* cancel advertisment */
        if (g_cancelAdvertise) {
            status = bus.CancelAdvertiseName(g_wellKnownName1.c_str(), opts.transports);
            if (status != ER_OK) {
                QCC_LogError(status, ("CancelAdvertiseName(%s) failed", g_wellKnownName1.c_str()));
            }
            status = bus.CancelAdvertiseName(g_wellKnownName2.c_str(), opts.transports);
            if (status != ER_OK) {
                QCC_LogError(status, ("CancelAdvertiseName(%s) failed", g_wellKnownName2.c_str()));
            }
        }
    }

    void SessionLost(SessionId sessionId, SessionLostReason reason) {
        QCC_SyncPrintf("SessionLost(%08x) was called. Reason = %u.\n", sessionId, reason);

        /* Enable concurrent callbacks since some of the calls below could block */
        g_msgBus->EnableConcurrentCallbacks();

        if (g_cancelAdvertise) {
            QStatus status = bus.AdvertiseName(g_wellKnownName1.c_str(), opts.transports);
            if (status != ER_OK) {
                QCC_LogError(status, ("AdvertiseName(%s) failed", g_wellKnownName1.c_str()));
            }
            status = bus.AdvertiseName(g_wellKnownName2.c_str(), opts.transports);
            if (status != ER_OK) {
                QCC_LogError(status, ("AdvertiseName(%s) failed", g_wellKnownName2.c_str()));
            }
        }
    }

  private:
    BusAttachment& bus;
    SessionOpts opts;
};

/* Test object 1 */
class LocalTestObject1 : public BusObject {

    class DelayedResponse : public Thread, public ThreadListener {
        struct DelayedResponseInfo {
            Message msg;
            MsgArg* argList;
            size_t argCount;
            DelayedResponseInfo(Message& msg, MsgArg* argList, size_t argCount) :
                msg(msg), argList(argList), argCount(argCount)
            { }
        };

      public:
        DelayedResponse(LocalTestObject1& lto) : Thread("DelayedResponse"), lto(lto) { }

        static void AddResponse(LocalTestObject1& lto, uint32_t delay, Message& msg, MsgArg* args, size_t argCount)
        {
            Timespec<MonotonicTime> future;
            GetTimeNow(&future);
            future += delay;
            DelayedResponseInfo* respInfo = new DelayedResponseInfo(msg, args, argCount);
            delayedResponseLock1.Lock(MUTEX_CONTEXT);
            delayedResponses1.insert(pair<uint64_t, DelayedResponseInfo*>(future.GetMillis(), respInfo));
            delayedResponseLock1.Unlock(MUTEX_CONTEXT);

            delayedResponseThreadLock1.Lock(MUTEX_CONTEXT);
            if (!thread1) {
                thread1 = new DelayedResponse(lto);
                thread1->Start(NULL, thread1);
            }
            delayedResponseThreadLock1.Unlock(MUTEX_CONTEXT);

        }

        void ThreadExit(Thread* thread1)
        {
            delayedResponseThreadLock1.Lock(MUTEX_CONTEXT);
            this->thread1 = NULL;
            delete thread1;
            delayedResponseThreadLock1.Unlock(MUTEX_CONTEXT);
        }

      protected:
        ThreadReturn STDCALL Run(void* arg)
        {
            QCC_UNUSED(arg);
            delayedResponseLock1.Lock(MUTEX_CONTEXT);
            bool done = delayedResponses1.empty();
            delayedResponseLock1.Unlock(MUTEX_CONTEXT);

            while (!done) {
                delayedResponseLock1.Lock(MUTEX_CONTEXT);
                Timespec<MonotonicTime> now;
                GetTimeNow(&now);
                uint64_t nowms = now.GetMillis();
                multimap<uint64_t, DelayedResponseInfo*>::iterator it = delayedResponses1.begin();
                uint64_t nextms = it->first;
                delayedResponseLock1.Unlock(MUTEX_CONTEXT);

                if (nextms > nowms) {
                    uint64_t delay = nextms - nowms;
                    if (delay >= (1ULL << 32)) {
                        delay = (1ULL << 32) - 1;
                    }
                    qcc::Sleep(static_cast<uint32_t>(delay));
                }

                delayedResponseLock1.Lock(MUTEX_CONTEXT);
                GetTimeNow(&now);
                nowms = now.GetMillis();
                it = delayedResponses1.begin();
                while ((it != delayedResponses1.end()) && (nextms <= nowms)) {
                    Message msg = it->second->msg;
                    MsgArg* args = it->second->argList;
                    size_t argCount = it->second->argCount;
                    delete it->second;
                    delayedResponses1.erase(it);
                    delayedResponseLock1.Unlock(MUTEX_CONTEXT);
                    QStatus status = lto.WrappedReply(msg, args, argCount);
                    if (ER_OK != status) {
                        QCC_LogError(status, ("Error sending delayed response"));
                    }
                    delete [] args;
                    delayedResponseLock1.Lock(MUTEX_CONTEXT);
                    it = delayedResponses1.begin();
                }
                if (it == delayedResponses1.end()) {
                    done = true;
                }
                delayedResponseLock1.Unlock(MUTEX_CONTEXT);
            }

            return static_cast<ThreadReturn>(0);
        }

      private:
        LocalTestObject1& lto;
        static DelayedResponse* thread1;
        static multimap<uint64_t, DelayedResponseInfo*> delayedResponses1;
        static Mutex delayedResponseLock1;
        static Mutex delayedResponseThreadLock1;
    };


  public:

    LocalTestObject1(BusAttachment& bus, const char* path, unsigned long reportInterval, const SessionOpts& opts) :
        BusObject(path),
        reportInterval(reportInterval),
        prop_str_val("hello world"),
        prop_ro_str("I cannot be written"),
        prop_int_val(100),
        opts(opts)
    {
        QStatus status;

        /* Add the test interface1 to this object */
        const InterfaceDescription* regTestIntf1 = bus.GetInterface(::abcd::InterfaceName1);
        QCC_ASSERT(regTestIntf1);
        AddInterface(*regTestIntf1);

        /* Add the test interface2 to this object */
        const InterfaceDescription* regTestIntf2 = bus.GetInterface(::abcd::InterfaceName2);
        QCC_ASSERT(regTestIntf2);
        AddInterface(*regTestIntf2);

        /* Register the signal handler A with the bus */
        const InterfaceDescription::Member* member1 = regTestIntf1->GetMember(::abcd::Signal1);
        QCC_ASSERT(member1);
        status = bus.RegisterSignalHandler(this,
                                           static_cast<MessageReceiver::SignalHandler>(&LocalTestObject1::SignalHandlerA),
                                           member1,
                                           NULL);
        if (ER_OK != status) {
            QCC_LogError(status, ("Failed to register signal handler A"));
        }

        /* Register the signal handler B with the bus */
        const InterfaceDescription::Member* member2 = regTestIntf1->GetMember(::abcd::Signal2);
        QCC_ASSERT(member2);
        status = bus.RegisterSignalHandler(this,
                                           static_cast<MessageReceiver::SignalHandler>(&LocalTestObject1::SignalHandlerB),
                                           member2,
                                           NULL);

        if (ER_OK != status) {
            QCC_LogError(status, ("Failed to register signal handler B"));
        }

        /* Register the signal handler C with the bus */
        const InterfaceDescription::Member* member3 = regTestIntf2->GetMember(::abcd::Signal3);
        QCC_ASSERT(member3);
        status = bus.RegisterSignalHandler(this,
                                           static_cast<MessageReceiver::SignalHandler>(&LocalTestObject1::SignalHandlerC),
                                           member3,
                                           NULL);
        if (ER_OK != status) {
            QCC_LogError(status, ("Failed to register signal handler C"));
        }

        /* Register the signal handler D with the bus */
        const InterfaceDescription::Member* member4 = regTestIntf2->GetMember(::abcd::Signal4);
        QCC_ASSERT(member4);
        status = bus.RegisterSignalHandler(this,
                                           static_cast<MessageReceiver::SignalHandler>(&LocalTestObject1::SignalHandlerD),
                                           member4,
                                           NULL);

        if (ER_OK != status) {
            QCC_LogError(status, ("Failed to register signal handler D"));
        }

        /* Register the method handlers with the object */
        const MethodEntry methodEntries[] = {
            { regTestIntf1->GetMember(::abcd::Method1), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject1::aMethod) },
            { regTestIntf1->GetMember(::abcd::Method2), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject1::bMethod) },
            { regTestIntf2->GetMember(::abcd::Method3), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject1::cMethod) },
            { regTestIntf2->GetMember(::abcd::Method4), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject1::dMethod) },
            { regTestIntf1->GetMember(::abcd::Error1), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject1::aError) },
            { regTestIntf1->GetMember(::abcd::Error2), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject1::bError) },
            { regTestIntf2->GetMember(::abcd::Error3), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject1::cError) },
            { regTestIntf2->GetMember(::abcd::Error4), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject1::dError) }
        };
        status = AddMethodHandlers(methodEntries, ArraySize(methodEntries));
        if (ER_OK != status) {
            QCC_LogError(status, ("Failed to register method handlers for LocalTestObject1"));
        }
    }

    void ObjectRegistered(void)
    {
        Message reply(*g_msgBus);

        QCC_SyncPrintf("1st bus object registered \n");

        g_object1_registeredEvent->SetEvent();

    }
    /* signal handler from a_signal */
    void SignalHandlerA(const InterfaceDescription::Member* member,
                        const char* sourcePath,
                        Message& msg)
    {
        QCC_UNUSED(member);
        QCC_UNUSED(msg);
        QCC_SyncPrintf("A RxSignal: %s - %u\n", sourcePath, rxCounts[sourcePath]);

    }

    /* signal handler for b_signal */
    void SignalHandlerB(const InterfaceDescription::Member* member,
                        const char* sourcePath,
                        Message& msg)
    {
        QCC_UNUSED(member);
        QCC_UNUSED(msg);
        QCC_SyncPrintf("B RxSignal: %s - %u\n", sourcePath, rxCounts[sourcePath]);

    }

    /* signal handler for c_signal */
    void SignalHandlerC(const InterfaceDescription::Member* member,
                        const char* sourcePath,
                        Message& msg)
    {
        QCC_UNUSED(member);
        QCC_UNUSED(msg);
        /* Enable concurrent signal handling */
        g_msgBus->EnableConcurrentCallbacks();

        QCC_SyncPrintf("C RxSignal: %s - %u\n", sourcePath, rxCounts[sourcePath]);

    }

    /* signal handler for d_signal */
    void SignalHandlerD(const InterfaceDescription::Member* member,
                        const char* sourcePath,
                        Message& msg)
    {
        QCC_UNUSED(member);
        QCC_UNUSED(msg);
        /* Enable concurrent signal handling */
        g_msgBus->EnableConcurrentCallbacks();

        QCC_SyncPrintf("D RxSignal: %s - %u\n", sourcePath, rxCounts[sourcePath]);

    }
    void aMethod(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        char* value = NULL;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("s", &value);
        printf("A method running with ping: %s\n", value);
        if (msg->IsEncrypted()) {
            printf("Authenticated using %s\n", msg->GetAuthMechanism().c_str());
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("A method ping: Error sending reply"));
        }
    }

    void bMethod(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        char* value = NULL;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("s", &value);
        printf("B method running with ping: %s\n", value);
        if (msg->IsEncrypted()) {
            printf("Authenticated using %s\n", msg->GetAuthMechanism().c_str());
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("B method ping: Error sending reply"));
        }
    }

    void cMethod(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        char* value = NULL;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("s", &value);
        printf("C method running with ping: %s\n", value);
        if (msg->IsEncrypted()) {
            printf("Authenticated using %s\n", msg->GetAuthMechanism().c_str());
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("C method ping: Error sending reply"));
        }
    }

    void dMethod(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        char* value = NULL;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("s", &value);
        printf("D method running with ping: %s\n", value);
        if (msg->IsEncrypted()) {
            printf("Authenticated using %s\n", msg->GetAuthMechanism().c_str());
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("D method ping: Error sending reply"));
        }
    }

    void aError(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        char* value = NULL;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("s", &value);
        printf("A error running with name: %s \n", ::abcd::ErrorName1);

        QStatus status = MethodReply(msg, ::abcd::ErrorName1, NULL);
        if (ER_OK != status) {
            QCC_LogError(status, ("A error ping: Error sending reply"));
        }
    }

    void bError(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        char* value = NULL;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("s", &value);
        printf("B error running with name: %s \n", ::abcd::ErrorName2);

        QStatus status = MethodReply(msg, ::abcd::ErrorName2, NULL);
        if (ER_OK != status) {
            QCC_LogError(status, ("B error ping: Error sending reply"));
        }
    }

    void cError(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        char* value = NULL;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("s", &value);
        printf("C error running with name: %s \n", ::abcd::ErrorName3);

        QStatus status = MethodReply(msg, ::abcd::ErrorName3, NULL);
        if (ER_OK != status) {
            QCC_LogError(status, ("C error ping: Error sending reply"));
        }
    }

    void dError(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        char* value = NULL;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("s", &value);
        printf("D error running with name: %s \n", ::abcd::ErrorName4);

        QStatus status = MethodReply(msg, ::abcd::ErrorName4, NULL);
        if (ER_OK != status) {
            QCC_LogError(status, ("D error ping: Error sending reply"));
        }
    }

    QStatus WrappedReply(Message& msg, MsgArg* args, size_t argCount)
    {
        return MethodReply(msg, args, argCount);
    }

  private:

    map<qcc::String, int32_t> rxCounts;

    unsigned long signalDelay;
    unsigned long reportInterval;

    qcc::String prop_str_val;
    qcc::String prop_ro_str;
    int32_t prop_int_val;
    SessionOpts opts;
};



LocalTestObject1::DelayedResponse* LocalTestObject1::DelayedResponse::thread1 = NULL;
multimap<uint64_t, LocalTestObject1::DelayedResponse::DelayedResponseInfo*> LocalTestObject1::DelayedResponse::delayedResponses1;
Mutex LocalTestObject1::DelayedResponse::delayedResponseLock1;
Mutex LocalTestObject1::DelayedResponse::delayedResponseThreadLock1;

/* Test object 2 */
class LocalTestObject2 : public BusObject {

    class DelayedResponse : public Thread, public ThreadListener {
        struct DelayedResponseInfo {
            Message msg;
            MsgArg* argList;
            size_t argCount;
            DelayedResponseInfo(Message& msg, MsgArg* argList, size_t argCount) :
                msg(msg), argList(argList), argCount(argCount)
            { }
        };

      public:
        DelayedResponse(LocalTestObject2& lto) : Thread("DelayedResponse"), lto(lto) { }

        static void AddResponse(LocalTestObject2& lto, uint32_t delay, Message& msg, MsgArg* args, size_t argCount)
        {
            Timespec<MonotonicTime> future;
            GetTimeNow(&future);
            future += delay;
            DelayedResponseInfo* respInfo = new DelayedResponseInfo(msg, args, argCount);
            delayedResponseLock2.Lock(MUTEX_CONTEXT);
            delayedResponses2.insert(pair<uint64_t, DelayedResponseInfo*>(future.GetMillis(), respInfo));
            delayedResponseLock2.Unlock(MUTEX_CONTEXT);

            delayedResponseThreadLock2.Lock(MUTEX_CONTEXT);
            if (!thread2) {
                thread2 = new DelayedResponse(lto);
                thread2->Start(NULL, thread2);
            }
            delayedResponseThreadLock2.Unlock(MUTEX_CONTEXT);

        }

        void ThreadExit(Thread* thread2)
        {
            delayedResponseThreadLock2.Lock(MUTEX_CONTEXT);
            this->thread2 = NULL;
            delete thread2;
            delayedResponseThreadLock2.Unlock(MUTEX_CONTEXT);
        }

      protected:
        ThreadReturn STDCALL Run(void* arg)
        {
            QCC_UNUSED(arg);
            delayedResponseLock2.Lock(MUTEX_CONTEXT);
            bool done = delayedResponses2.empty();
            delayedResponseLock2.Unlock(MUTEX_CONTEXT);

            while (!done) {
                delayedResponseLock2.Lock(MUTEX_CONTEXT);
                Timespec<MonotonicTime> now;
                GetTimeNow(&now);
                uint64_t nowms = now.GetMillis();
                multimap<uint64_t, DelayedResponseInfo*>::iterator it = delayedResponses2.begin();
                uint64_t nextms = it->first;
                delayedResponseLock2.Unlock(MUTEX_CONTEXT);

                if (nextms > nowms) {
                    uint64_t delay = nextms - nowms;
                    if (delay >= (1ULL << 32)) {
                        delay = (1ULL << 32) - 1;
                    }
                    qcc::Sleep(static_cast<uint32_t>(delay));
                }

                delayedResponseLock2.Lock(MUTEX_CONTEXT);
                GetTimeNow(&now);
                nowms = now.GetMillis();
                it = delayedResponses2.begin();
                while ((it != delayedResponses2.end()) && (nextms <= nowms)) {
                    Message msg = it->second->msg;
                    MsgArg* args = it->second->argList;
                    size_t argCount = it->second->argCount;
                    delete it->second;
                    delayedResponses2.erase(it);
                    delayedResponseLock2.Unlock(MUTEX_CONTEXT);
                    QStatus status = lto.WrappedReply(msg, args, argCount);
                    if (ER_OK != status) {
                        QCC_LogError(status, ("Error sending delayed response"));
                    }
                    delete [] args;
                    delayedResponseLock2.Lock(MUTEX_CONTEXT);
                    it = delayedResponses2.begin();
                }
                if (it == delayedResponses2.end()) {
                    done = true;
                }
                delayedResponseLock2.Unlock(MUTEX_CONTEXT);
            }

            return static_cast<ThreadReturn>(0);
        }

      private:
        LocalTestObject2& lto;
        static DelayedResponse* thread2;
        static multimap<uint64_t, DelayedResponseInfo*> delayedResponses2;
        static Mutex delayedResponseLock2;
        static Mutex delayedResponseThreadLock2;
    };


  public:

    LocalTestObject2(BusAttachment& bus, const char* path, unsigned long reportInterval, const SessionOpts& opts) :
        BusObject(path),
        reportInterval(reportInterval),
        prop_str_val("hello world"),
        prop_ro_str("I cannot be written"),
        prop_int_val(100),
        opts(opts)
    {
        QStatus status;

        /* Add the test interface1 to this object */
        const InterfaceDescription* regTestIntf1 = bus.GetInterface(::efgh::InterfaceName1);
        QCC_ASSERT(regTestIntf1);
        AddInterface(*regTestIntf1);

        /* Add the test interface2 to this object */
        const InterfaceDescription* regTestIntf2 = bus.GetInterface(::efgh::InterfaceName2);
        QCC_ASSERT(regTestIntf2);
        AddInterface(*regTestIntf2);

        /* Register the signal handler E with the bus */
        const InterfaceDescription::Member* member1 = regTestIntf1->GetMember(::efgh::Signal1);
        QCC_ASSERT(member1);
        status = bus.RegisterSignalHandler(this,
                                           static_cast<MessageReceiver::SignalHandler>(&LocalTestObject2::SignalHandlerE),
                                           member1,
                                           NULL);
        if (ER_OK != status) {
            QCC_LogError(status, ("Failed to register signal handler E"));
        }

        /* Register the signal handler F with the bus */
        const InterfaceDescription::Member* member2 = regTestIntf1->GetMember(::efgh::Signal2);
        QCC_ASSERT(member2);
        status = bus.RegisterSignalHandler(this,
                                           static_cast<MessageReceiver::SignalHandler>(&LocalTestObject2::SignalHandlerF),
                                           member2,
                                           NULL);
        if (ER_OK != status) {
            QCC_LogError(status, ("Failed to register signal handler F"));
        }

        /* Register the signal handler G with the bus */
        const InterfaceDescription::Member* member3 = regTestIntf2->GetMember(::efgh::Signal3);
        QCC_ASSERT(member3);
        status = bus.RegisterSignalHandler(this,
                                           static_cast<MessageReceiver::SignalHandler>(&LocalTestObject2::SignalHandlerG),
                                           member3,
                                           NULL);
        if (ER_OK != status) {
            QCC_LogError(status, ("Failed to register signal handler G"));
        }

        /* Register the signal handler D with the bus */
        const InterfaceDescription::Member* member4 = regTestIntf2->GetMember(::efgh::Signal4);
        QCC_ASSERT(member4);
        status = bus.RegisterSignalHandler(this,
                                           static_cast<MessageReceiver::SignalHandler>(&LocalTestObject2::SignalHandlerH),
                                           member4,
                                           NULL);
        if (ER_OK != status) {
            QCC_LogError(status, ("Failed to register signal handler H"));
        }

        /* Register the method handlers with the object */
        const MethodEntry methodEntries[] = {
            { regTestIntf1->GetMember(::efgh::Method1), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject2::eMethod) },
            { regTestIntf1->GetMember(::efgh::Method2), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject2::fMethod) },
            { regTestIntf2->GetMember(::efgh::Method3), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject2::gMethod) },
            { regTestIntf2->GetMember(::efgh::Method4), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject2::hMethod) },
            { regTestIntf1->GetMember("eError"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject2::eError) },
            { regTestIntf1->GetMember("fError"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject2::fError) },
            { regTestIntf2->GetMember("gError"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject2::gError) },
            { regTestIntf2->GetMember("hError"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject2::hError) },
        };
        status = AddMethodHandlers(methodEntries, ArraySize(methodEntries));
        if (ER_OK != status) {
            QCC_LogError(status, ("Failed to register method handlers for LocalTestObject1"));
        }
    }

    void ObjectRegistered(void)
    {
        Message reply(*g_msgBus);

        QCC_SyncPrintf("2nd bus object registered \n");

        g_object2_registeredEvent->SetEvent();


    }
    /* signal handler for e_signal */
    void SignalHandlerE(const InterfaceDescription::Member* member,
                        const char* sourcePath,
                        Message& msg)
    {
        QCC_UNUSED(member);
        QCC_UNUSED(msg);
        /* Enable concurrent signal handling */
        g_msgBus->EnableConcurrentCallbacks();

        QCC_SyncPrintf("E RxSignal: %s - %u\n", sourcePath, rxCounts[sourcePath]);

    }

    /* signal handler for f_signal */
    void SignalHandlerF(const InterfaceDescription::Member* member,
                        const char* sourcePath,
                        Message& msg)
    {
        QCC_UNUSED(member);
        QCC_UNUSED(msg);
        /* Enable concurrent signal handling */
        g_msgBus->EnableConcurrentCallbacks();

        QCC_SyncPrintf("F RxSignal: %s - %u\n", sourcePath, rxCounts[sourcePath]);

    }

    /* signal handler for g_signal */
    void SignalHandlerG(const InterfaceDescription::Member* member,
                        const char* sourcePath,
                        Message& msg)
    {
        QCC_UNUSED(member);
        QCC_UNUSED(msg);
        /* Enable concurrent signal handling */
        g_msgBus->EnableConcurrentCallbacks();

        QCC_SyncPrintf("G RxSignal: %s - %u\n", sourcePath, rxCounts[sourcePath]);

    }

    /* signal handler for h_signal */
    void SignalHandlerH(const InterfaceDescription::Member* member,
                        const char* sourcePath,
                        Message& msg)
    {
        QCC_UNUSED(member);
        QCC_UNUSED(msg);
        /* Enable concurrent signal handling */
        g_msgBus->EnableConcurrentCallbacks();

        QCC_SyncPrintf("H RxSignal: %s - %u\n", sourcePath, rxCounts[sourcePath]);

    }
    void eMethod(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        char* value = NULL;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("s", &value);
        printf("E method running with ping: %s\n", value);
        if (msg->IsEncrypted()) {
            printf("Authenticated using %s\n", msg->GetAuthMechanism().c_str());
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("E method ping: Error sending reply"));
        }
    }

    void fMethod(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        char* value = NULL;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("s", &value);
        printf("F method running with ping: %s\n", value);
        if (msg->IsEncrypted()) {
            printf("Authenticated using %s\n", msg->GetAuthMechanism().c_str());
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("F method ping: Error sending reply"));
        }
    }

    void gMethod(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        char* value = NULL;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("s", &value);
        printf("G method running with ping: %s\n", value);
        if (msg->IsEncrypted()) {
            printf("Authenticated using %s\n", msg->GetAuthMechanism().c_str());
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("G method ping: Error sending reply"));
        }
    }

    void hMethod(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        char* value = NULL;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("s", &value);
        printf("H method running with ping: %s\n", value);
        if (msg->IsEncrypted()) {
            printf("Authenticated using %s\n", msg->GetAuthMechanism().c_str());
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("H method ping: Error sending reply"));
        }
    }
    void eError(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        char* value = NULL;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("s", &value);
        printf("E error running with name: %s \n", ::efgh::ErrorName1);

        QStatus status = MethodReply(msg, ::efgh::ErrorName1, NULL);
        if (ER_OK != status) {
            QCC_LogError(status, ("E error ping: Error sending reply"));
        }
    }

    void fError(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        char* value = NULL;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("s", &value);
        printf("F error running with name: %s \n", ::efgh::ErrorName2);

        QStatus status = MethodReply(msg, ::efgh::ErrorName2, NULL);
        if (ER_OK != status) {
            QCC_LogError(status, ("F error ping: Error sending reply"));
        }
    }

    void gError(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        char* value = NULL;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("s", &value);
        printf("G error running with name: %s \n", ::efgh::ErrorName3);

        QStatus status = MethodReply(msg, ::efgh::ErrorName3, NULL);
        if (ER_OK != status) {
            QCC_LogError(status, ("G error ping: Error sending reply"));
        }
    }

    void hError(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        char* value = NULL;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("s", &value);
        printf("H error running with name: %s \n", ::efgh::ErrorName4);

        QStatus status = MethodReply(msg, ::efgh::ErrorName4, NULL);
        if (ER_OK != status) {
            QCC_LogError(status, ("H error ping: Error sending reply"));
        }
    }

    QStatus WrappedReply(Message& msg, MsgArg* args, size_t argCount)
    {
        return MethodReply(msg, args, argCount);
    }

  private:

    map<qcc::String, int32_t> rxCounts;

    unsigned long signalDelay;
    unsigned long reportInterval;

    qcc::String prop_str_val;
    qcc::String prop_ro_str;
    int32_t prop_int_val;
    SessionOpts opts;
};

LocalTestObject2::DelayedResponse* LocalTestObject2::DelayedResponse::thread2 = NULL;
multimap<uint64_t, LocalTestObject2::DelayedResponse::DelayedResponseInfo*> LocalTestObject2::DelayedResponse::delayedResponses2;
Mutex LocalTestObject2::DelayedResponse::delayedResponseLock2;
Mutex LocalTestObject2::DelayedResponse::delayedResponseThreadLock2;

static void usage(void)
{
    printf("Usage: bbservice [-h <name>] [-m] [-x] [-i #] [-n <name>] [-b] [-t] [-l]\n\n");
    printf("Options:\n");
    printf("   -h                    = Print this help message\n");
    printf("   -?                    = Print this help message\n");
    printf("   -kx #                 = Authentication key expiration (seconds)\n");
    printf("   -m                    = Session is a multi-point session\n");
    printf("   -s                    = Require the test interface to be secure\n");
    printf("   -x                    = Compress signals echoed back to sender\n");
    printf("   -i #                  = Signal report interval (number of signals rx per update; default = 1000)\n");
    printf("   -n <well-known name>  = Well-known name to advertise\n");
    printf("   -t                    = Advertise over TCP (enables selective advertising)\n");
    printf("   -l                    = Advertise locally (enables selective advertising)\n");
    printf("   -a                    = Cancel advertising while servicing a single client (causes rediscovery between iterations)\n");
    printf("   -sn                   = Interface security is not applicable\n");
    printf("   -sr                   = Interface security is required\n");
    printf("   -so                   = Enable object security\n");
}

/** Main entry point */
int main(int argc, char** argv)
{
    if (AllJoynInit() != ER_OK) {
        return 1;
    }
#ifdef ROUTER
    if (AllJoynRouterInit() != ER_OK) {
        AllJoynShutdown();
        return 1;
    }
#endif

#ifdef _WIN32
    _CrtMemDumpAllObjectsSince(NULL);
#endif
    QStatus status = ER_OK;
    InterfaceSecurityPolicy secPolicy = AJ_IFC_SECURITY_INHERIT;
    bool objSecure = false;
    unsigned long reportInterval = 1000;
    SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);

    printf("AllJoyn Library version: %s\n", ajn::GetVersion());
    printf("AllJoyn Library build info: %s\n", ajn::GetBuildInfo());

    /* Install SIGINT handler */
    signal(SIGINT, SigIntHandler);

    /* Parse command line args */
    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp("-h", argv[i]) || 0 == strcmp("-?", argv[i])) {
            usage();
            exit(0);
        } else if (0 == strcmp("-s", argv[i])) {
        } else if (0 == strcmp("-i", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                reportInterval = strtoul(argv[i], NULL, 10);
            }
        } else if (0 == strcmp("-n", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_wellKnownName1 = argv[i];
            }
        } else if (0 == strcmp("-m", argv[i])) {
            opts.isMultipoint = true;
        } else if (0 == strcmp("-t", argv[i])) {
            opts.transports |= TRANSPORT_TCP;
        } else if (0 == strcmp("-l", argv[i])) {
            opts.transports |= TRANSPORT_LOCAL;
        } else if (0 == strcmp("-a", argv[i])) {
            g_cancelAdvertise = true;
        } else if (0 == strcmp("-sn", argv[i])) {
            secPolicy = AJ_IFC_SECURITY_OFF;
        } else if (0 == strcmp("-sr", argv[i])) {
            secPolicy = AJ_IFC_SECURITY_REQUIRED;
        } else if (0 == strcmp("-so", argv[i])) {
            objSecure = true;
        } else {
            status = ER_FAIL;
            printf("Unknown option %s\n", argv[i]);
            usage();
            exit(1);
        }
    }

    /* If no transport option was specifie, then make session options very open */
    if (opts.transports == 0) {
        opts.transports = TRANSPORT_ANY;
    }

    QCC_SyncPrintf("opts.transports = 0x%x\n", opts.transports);

    /* Get env vars */
    Environ* env = Environ::GetAppEnviron();
    qcc::String clientArgs = env->Find("DBUS_STARTER_ADDRESS");

    if (clientArgs.empty()) {
        clientArgs = env->Find("BUS_ADDRESS");
    }

    g_object1_registeredEvent = new Event();
    g_object2_registeredEvent = new Event();

    /* Create message bus */
    g_msgBus = new BusAttachment("bbservice", true);

    /* Add abcd interface */
    InterfaceDescription* testIntf1 = NULL;
    status = g_msgBus->CreateInterface(::abcd::InterfaceName1, testIntf1, secPolicy);
    if (ER_OK == status) {
        testIntf1->AddSignal(::abcd::Signal1, "a{ys}", NULL, 0);
        testIntf1->AddSignal(::abcd::Signal2, "a{ys}", NULL, 0);
        testIntf1->AddMethod(::abcd::Method1, "s", "s", "inStr,outStr", 0);
        testIntf1->AddMethod(::abcd::Method2, "s", "s", "inStr,outStr", 0);
        // Error is a special method with an error name in method reply
        testIntf1->AddMethod(::abcd::Error1, "s", "s", "inStr,outStr", 0);
        testIntf1->AddMethod(::abcd::Error2, "s", "s", "inStr,outStr", 0);
        testIntf1->Activate();
    } else {
        QCC_LogError(status, ("Failed to create interface %s", ::abcd::InterfaceName1));
    }

    InterfaceDescription* testIntf2 = NULL;
    status = g_msgBus->CreateInterface(::abcd::InterfaceName2, testIntf2, secPolicy);
    if (ER_OK == status) {
        testIntf2->AddSignal(::abcd::Signal3, "a{ys}", NULL, 0);
        testIntf2->AddSignal(::abcd::Signal4, "a{ys}", NULL, 0);
        testIntf2->AddMethod(::abcd::Method3, "s", "s", "inStr,outStr", 0);
        testIntf2->AddMethod(::abcd::Method4, "s", "s", "inStr,outStr", 0);
        testIntf2->AddMethod(::abcd::Error3, "s", "s", "inStr,outStr", 0);
        testIntf2->AddMethod(::abcd::Error4, "s", "s", "inStr,outStr", 0);
        testIntf2->Activate();
    } else {
        QCC_LogError(status, ("Failed to create interface %s", ::abcd::InterfaceName2));
    }

    /* Add efgh interface */
    InterfaceDescription* testIntf3 = NULL;
    status = g_msgBus->CreateInterface(::efgh::InterfaceName1, testIntf3, secPolicy);
    if (ER_OK == status) {
        testIntf3->AddSignal(::efgh::Signal1, "a{ys}", NULL, 0);
        testIntf3->AddSignal(::efgh::Signal2, "a{ys}", NULL, 0);
        testIntf3->AddMethod(::efgh::Method1, "s", "s", "inStr,outStr", 0);
        testIntf3->AddMethod(::efgh::Method2, "s", "s", "inStr,outStr", 0);
        testIntf3->AddMethod(::efgh::Error1, "s", "s", "inStr,outStr", 0);
        testIntf3->AddMethod(::efgh::Error2, "s", "s", "inStr,outStr", 0);
        testIntf3->Activate();
    } else {
        QCC_LogError(status, ("Failed to create interface %s", ::efgh::InterfaceName1));
    }

    InterfaceDescription* testIntf4 = NULL;
    status = g_msgBus->CreateInterface(::efgh::InterfaceName2, testIntf4, secPolicy);
    if (ER_OK == status) {
        testIntf4->AddSignal(::efgh::Signal3, "a{ys}", NULL, 0);
        testIntf4->AddSignal(::efgh::Signal4, "a{ys}", NULL, 0);
        testIntf4->AddMethod(::efgh::Method3, "s", "s", "inStr,outStr", 0);
        testIntf4->AddMethod(::efgh::Method4, "s", "s", "inStr,outStr", 0);
        testIntf4->AddMethod(::efgh::Error3, "s", "s", "inStr,outStr", 0);
        testIntf4->AddMethod(::efgh::Error4, "s", "s", "inStr,outStr", 0);
        testIntf4->Activate();
    } else {
        QCC_LogError(status, ("Failed to create interface %s", ::efgh::InterfaceName2));
    }


    /* Start the msg bus */
    if (ER_OK == status) {
        status = g_msgBus->Start();
    } else {
        QCC_LogError(status, ("BusAttachment::Start failed"));
        exit(1);
    }

    /* Create a bus listener to be used to accept incoming session requests */
    g_myBusListener = new MyBusListener(*g_msgBus, opts);

    /* prepare to register both bus objects */
    g_object1_registeredEvent->ResetEvent();
    g_object2_registeredEvent->ResetEvent();

    /* Register local objects and connect to the daemon */
    LocalTestObject1 testObj1(*g_msgBus, ::abcd::ObjectPath, reportInterval, opts);
    status = g_msgBus->RegisterBusObject(testObj1, objSecure);

    if (ER_OK != status) {
        QCC_LogError(status, ("Register object 1 failed!"));
    }

    LocalTestObject2 testObj2(*g_msgBus, ::efgh::ObjectPath, reportInterval, opts);
    status = g_msgBus->RegisterBusObject(testObj2, objSecure);

    if (ER_OK != status) {
        QCC_LogError(status, ("Register object 2 failed!"));
    }

    /* Connect to the daemon */
    if (clientArgs.empty()) {
        status = g_msgBus->Connect();
    } else {
        status = g_msgBus->Connect(clientArgs.c_str());
    }
    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to connect to \"%s\"", clientArgs.c_str()));
    }


    /* TODO: Wait both objects are registered then call BindSessionPort */
    bool obj1_registered = false;
    bool obj2_registered = false;

    QCC_SyncPrintf("Wait both bus objects registered...\n");

    // FIXME: does NOT work
    for (; !obj1_registered && !obj2_registered;) {

        qcc::Event timerEvent(100, 100);
        vector<qcc::Event*> checkEvents, signaledEvents;
        checkEvents.push_back(g_object1_registeredEvent);
        checkEvents.push_back(g_object2_registeredEvent);

        checkEvents.push_back(&timerEvent);
        status = qcc::Event::Wait(checkEvents, signaledEvents);
        if (status != ER_OK && status != ER_TIMEOUT) {
            break;
        }

        for (vector<qcc::Event*>::iterator i = signaledEvents.begin(); i != signaledEvents.end(); ++i) {
            if (*i == g_object1_registeredEvent) {
                obj1_registered = true;
            } else if (*i == g_object2_registeredEvent) {
                obj2_registered = true;
            }

        }
    }

    //qcc::Sleep(200);

    QCC_SyncPrintf("Both bus objects registered.\n");

    /*
     * Bind a well-known session port for incoming client connections. This must be done before
     * we request or start advertising a well known name because a client can try to connect
     * immediately and with a bundled daemon this can happen very quickly.
     */
    SessionPort sessionPort = mySessionPort;
    status = g_msgBus->BindSessionPort(sessionPort, opts, *g_myBusListener);
    if (status != ER_OK) {
        QCC_LogError(status, ("BindSessionPort failed"));
    }
    /* Add rule for receiving test signals */
    status = g_msgBus->AddMatch("type='signal',interface='ab.org',member='a_signal'");
    if (status != ER_OK) {
        QCC_LogError(status, ("Failed to register Match rule for 'ab.a_signal'"));
    }
    status = g_msgBus->AddMatch("type='signal',interface='ab.org',member='b_signal'");
    if (status != ER_OK) {
        QCC_LogError(status, ("Failed to register Match rule for 'ab.b_signal'"));
    }
    status = g_msgBus->AddMatch("type='signal',interface='cd.org',member='c_signal'");
    if (status != ER_OK) {
        QCC_LogError(status, ("Failed to register Match rule for 'cd.c_signal'"));
    }
    status = g_msgBus->AddMatch("type='signal',interface='cd.org',member='d_signal'");
    if (status != ER_OK) {
        QCC_LogError(status, ("Failed to register Match rule for 'cd.d_signal'"));
    }

    /* Request a well-known name */
    status = g_msgBus->RequestName(g_wellKnownName1.c_str(), DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE);
    if (status != ER_OK) {
        QCC_LogError(status, ("RequestName(%s) failed.", g_wellKnownName1.c_str()));
    }
    /* Begin Advertising the well-known name */
    status = g_msgBus->AdvertiseName(g_wellKnownName1.c_str(), opts.transports);
    if (ER_OK != status) {
        QCC_LogError(status, ("Sending org.alljoyn.Bus.Advertise failed"));
    }


    /* Add rule for receiving test signals */
    status = g_msgBus->AddMatch("type='signal',interface='ef.gov',member='e_signal'");
    if (status != ER_OK) {
        QCC_LogError(status, ("Failed to register Match rule for 'ef.e_signal'"));
    }
    status = g_msgBus->AddMatch("type='signal',interface='ef.gov',member='f_signal'");
    if (status != ER_OK) {
        QCC_LogError(status, ("Failed to register Match rule for 'ef.f_signal'"));
    }
    status = g_msgBus->AddMatch("type='signal',interface='gh.gov',member='g_signal'");
    if (status != ER_OK) {
        QCC_LogError(status, ("Failed to register Match rule for 'gh.g_signal'"));
    }
    status = g_msgBus->AddMatch("type='signal',interface='gh.gov',member='h_signal'");
    if (status != ER_OK) {
        QCC_LogError(status, ("Failed to register Match rule for 'gh.h_signal'"));
    }

    /* Request a well-known name */
    status = g_msgBus->RequestName(g_wellKnownName2.c_str(), DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE);
    if (status != ER_OK) {
        QCC_LogError(status, ("RequestName(%s) failed.", g_wellKnownName2.c_str()));
    }
    /* Begin Advertising the well-known name */
    status = g_msgBus->AdvertiseName(g_wellKnownName2.c_str(), opts.transports);
    if (ER_OK != status) {
        QCC_LogError(status, ("Sending org.alljoyn.Bus.Advertise failed"));
    }

    if (ER_OK == status) {
        QCC_SyncPrintf("policyService %s ready to accept connections\n", g_wellKnownName1.c_str());
        while (g_interrupt == false) {
            qcc::Sleep(100);
        }
    }

    g_msgBus->UnregisterBusObject(testObj1);

    g_msgBus->UnregisterBusObject(testObj2);

    /* Clean up msg bus */
    delete g_msgBus;
    delete g_myBusListener;

    if (g_object1_registeredEvent) {
        delete g_object1_registeredEvent;
        g_object1_registeredEvent = NULL;
    }

    if (g_object2_registeredEvent) {
        delete g_object2_registeredEvent;
        g_object2_registeredEvent = NULL;
    }

    printf("%s exiting with status %d (%s)\n", argv[0], status, QCC_StatusText(status));


#ifdef ROUTER
    AllJoynRouterShutdown();
#endif
    AllJoynShutdown();

    return (int) status;
}