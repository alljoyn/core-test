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
#ifndef _AJTCSCTESTCOMMON_H
#define _AJTCSCTESTCOMMON_H

#if defined(QCC_OS_GROUP_WINDOWS)
#if !defined(NDEBUG) && !defined(_DEBUG)
#define _DEBUG
#include <windows.h>
#include <crtdbg.h>
#undef _DEBUG // Once crtdbg is included, we no longer need _DEBUG
#endif // !NDEBUG && !_DEBUG
#endif // QCC_OS_GROUP_WINDOWS

#include <gtest/gtest.h>

#include <queue>
#include <functional>
#include <mutex>

extern "C" {
#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_crypto.h>
#include <ajtcl/aj_authentication.h>
#include <ajtcl/aj_authorisation.h>
#include <ajtcl/aj_cert.h>
#include <ajtcl/aj_creds.h>
#include <ajtcl/aj_security.h>
#include <ajtcl/aj_link_timeout.h>
#include <ajtcl/aj_peer.h>

/* Undefine a TC deprecated flag that causes conflicts with SC headers */
#ifdef ALLJOYN_FLAG_SESSIONLESS
#undef ALLJOYN_FLAG_SESSIONLESS
#endif

/* Undefine all SC conflicting macros defined by Thin Library */

#ifdef min
#undef min
#endif

#ifdef max
#undef max
#endif

#ifdef KEYLEN
#undef KEYLEN
#endif

#ifdef OUTLEN
#undef OUTLEN
#endif

#ifdef SEEDLEN
#undef SEEDLEN
#endif

#ifdef SIGNAL
#undef SIGNAL
#endif

#ifdef PROPERTY
#undef PROPERTY
#endif
}

#include <qcc/Util.h>
#include <qcc/StringUtil.h>
#include <qcc/Thread.h>

#include <alljoyn/AllJoynStd.h>
#include <alljoyn/DBusStd.h>

#include <alljoyn/Message.h>
#include <alljoyn/TransportMask.h>

#include <alljoyn/BusAttachment.h>
#include <alljoyn/Init.h>

#include <alljoyn/BusObject.h>
#include <alljoyn/ProxyBusObject.h>
#include <alljoyn/InterfaceDescription.h>

#include <alljoyn/AboutData.h>
#include <alljoyn/AboutObjectDescription.h>
#include <alljoyn/AboutProxy.h>
#include <alljoyn/AboutListener.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

/**
 * Macro used to avoid the need for a local variable just for an assert. Using a local
 * variable just for assert, instead of this macro, can cause compiler warnings on
 * NDEBUG builds.
 * Example: AJ_VERIFY(foo() == 0); instead of {int local = foo(); AJ_ASSERT(local == 0);}
 *
 * @param _cmd  Statement to be executed on both types of builds, and asserted just
 *              on non-NDEBUG builds.
 */

#if defined(NDEBUG)
#define AJ_VERIFY(_cmd) ((void)(_cmd))
#else
#define AJ_VERIFY(_cmd) AJ_ASSERT(_cmd)
#endif

// The parameter passed to AJ_FindBusAndConnect API (value in milliseconds)
const uint16_t TC_LEAFNODE_CONNECT_TIMEOUT = 1500;

// The parameter passed to AJ_UnmarshalMsg API (value in milliseconds)
const uint16_t TC_UNMARSHAL_TIMEOUT = 100;

// The duration for which the test waits for an event before declaring a failure
const uint16_t WAIT_TIME  = 3000;
const uint16_t WAIT_MSECS = 5;

template<class T>
class Promise {
public:
    Promise() {}

    void SetResult(T value) {
        result = value;
        event.SetEvent();
    }

    T Wait(uint32_t maxMs, T defaultResult) {
        if (ER_OK == qcc::Event::Wait(event, maxMs)) {
            return result;
        }
        return defaultResult;
    }

private:
    qcc::Event event;
    T result;
};

/* MSVC doesn't think DefaultAuthListener and DefaultAuthCallback are referenced, even though
 * they're used later as function pointers. Suppress the warning that causes a build break on Windows.
 */
#if defined(_MSC_VER)
#pragma warning(disable:4505)
#endif
static AJ_Status DefaultAuthListener(uint32_t mechanism, uint32_t command, AJ_Credential* cred)
{
    AJ_Status status = AJ_ERR_INVALID;

    AJ_AlwaysPrintf(("DefaultAuthListener mechanism %x command %x\n", mechanism, command));

    switch (mechanism) {
    case AUTH_SUITE_ECDHE_NULL:
        cred->expiration = 0;
        status = AJ_OK;
        break;

    default:
        break;
    }
    return status;
}

static void DefaultAuthCallback(const void* context, AJ_Status status)
{
    Promise<AJ_Status>* p = (Promise<AJ_Status>*) context;
    AJ_AlwaysPrintf(("Auth status provided to DefaultAuthCallback: %x\n", status));
    p->SetResult(status);
}

class TCProperties {
  public:
    TCProperties() { }
    void SetElement(qcc::String name, int32_t value);
    QStatus GetElement(qcc::String name, int32_t& value);
    void Clear();
    size_t GetNumElements();
    void HandleReply(AJ_Message* msg);

  private:
    std::map<qcc::String, int32_t> props;
};

class TCBusAttachment : public qcc::Thread {
    typedef std::function<void (void)> Function;
    typedef std::map<int, Function> MsgHandlerMap;

  public:
    TCBusAttachment(const char* name, AJ_AuthListenerFunc listener = DefaultAuthListener, AJ_PeerAuthenticateCallback callback = DefaultAuthCallback) : qcc::Thread(name), running(true), authlistener(listener), authcallback(callback) { }
    void Connect(const char* router);
    qcc::ThreadReturn STDCALL Run(void* arg);
    QStatus Stop();
    void Enqueue(Function f);
    void SendMessage();
    virtual void RecvMessage(AJ_Message* msg);
    void HandleMessage(AJ_Message* msg);
    qcc::String GetUniqueName();
    QStatus EnablePeerSecurity(const char* mechanisms);
    void SetApplicationState(uint16_t state);
    void SetPermissionManifest(AJ_PermissionRule* manifest);
    QStatus BindSessionPort(uint16_t port);
    QStatus JoinSession(const char* host, uint16_t port, uint32_t& id);
    QStatus AuthenticatePeer(const char* host);
    QStatus MethodCall(const char* peer, uint32_t id, const char* str = NULL);
    QStatus Signal(const char* peer, uint32_t id, const char* str = NULL);
    QStatus GetProperty(const char* peer, uint32_t mid, uint32_t pid, int32_t& val);
    QStatus SetProperty(const char* peer, uint32_t mid, uint32_t pid, int32_t val);
    QStatus GetAllProperties(const char* peer, uint32_t mid, const char* ifn, TCProperties& val, bool secure = true);

    QStatus GetGuid(qcc::GUID128& guid);

    const char* GetErrorName() {
        return response.c_str();
    }
    const char* GetResponse() {
        return response.c_str();
    }

    std::queue<Function> funcs;
    qcc::Mutex funcs_lock;

    MsgHandlerMap message_handlers;

    bool running;
    AJ_AuthListenerFunc authlistener;
    AJ_PeerAuthenticateCallback authcallback;
    AJ_BusAttachment bus;
    bool bound;
    uint32_t session;
    uint16_t sessionPort;
    QStatus SCStatus;
    qcc::String response;
    uint32_t propid;
    int32_t propval;
    TCProperties properties;
};

#endif // _AJTCSCTESTCOMMON_H