/******************************************************************************
 * Copyright (c) Open Connectivity Foundation (OCF) and AllJoyn Open
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
#include "ajtcscTestCommon.h"

#include <iostream>

#include <gtest/gtest.h>
#include <qcc/Event.h>

int CDECL_CALL main(int argc, char* argv[])
{
    int status = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    // Note: This test is built with BundledRouter
    if (ER_OK != AllJoynInit()) {
        return 1;
    }
    if (ER_OK != AllJoynRouterInit()) {
        AllJoynShutdown();
        return 1;
    }

    std::cout << std::endl << " Running ajtcsc unit test" << std::endl;
    testing::InitGoogleTest(&argc, argv);
    status = RUN_ALL_TESTS();

    AllJoynRouterShutdown();
    AllJoynShutdown();

    std::cout << argv[0] << " exiting with status " << status << std::endl;

    return status;
}

void TCProperties::SetElement(qcc::String name, int32_t value)
{
    props[name] = value;
}

QStatus TCProperties::GetElement(qcc::String name, int32_t& value)
{
    std::map<qcc::String, int32_t>::iterator it;
    it = props.find(name);
    if (it == props.end()) {
        return ER_BUS_ELEMENT_NOT_FOUND;
    }
    value = it->second;
    return ER_OK;
}

void TCProperties::Clear()
{
    props.clear();
}

size_t TCProperties::GetNumElements()
{
    return props.size();
}

void TCProperties::HandleReply(AJ_Message* msg)
{
    AJ_Status status;
    AJ_Arg array;
    const char* str;
    int32_t val;
    status = AJ_UnmarshalContainer(msg, &array, AJ_ARG_ARRAY);
    while (AJ_OK == status) {
        status = AJ_UnmarshalArgs(msg, "{sv}", &str, "i", &val);
        if (AJ_OK != status) {
            break;
        }
        SetElement(str, val);
    }
    AJ_ASSERT(AJ_ERR_NO_MORE == status);
    status = AJ_UnmarshalCloseContainer(msg, &array);
    AJ_ASSERT(AJ_OK == status);
}

void TCBusAttachment::Connect(const char* router)
{
    AJ_Initialize();

    // Ensure that a routing node is found as quickly as possible
    AJ_SetSelectionTimeout(0);

    AJ_VERIFY(AJ_OK == AJ_FindBusAndConnect(&bus, router, TC_LEAFNODE_CONNECT_TIMEOUT));
    AJ_ClearCredentials(0);
    AJ_BusSetAuthListenerCallback(&bus, authlistener);
}

qcc::ThreadReturn TCBusAttachment::Run(void* arg)
{
    QCC_UNUSED(arg);
    AJ_Status status;
    AJ_Message msg;

    while (running) {
        /* Send queued messages */
        SendMessage();
        status = AJ_UnmarshalMsg(&bus, &msg, TC_UNMARSHAL_TIMEOUT);
        if (AJ_ERR_TIMEOUT == status && AJ_ERR_LINK_TIMEOUT == AJ_BusLinkStateProc(&bus)) {
            status = AJ_ERR_READ;
        }
        if (AJ_ERR_READ == status) {
            running = FALSE;
            break;
        } else if (AJ_OK == status) {
            RecvMessage(&msg);
        }
        AJ_CloseMsg(&msg);
    }

    AJ_Disconnect(&bus);
    return this;
}

QStatus TCBusAttachment::Stop()
{
    running = FALSE;
    AJ_Net_Interrupt();
    return Thread::Stop();
}

void TCBusAttachment::Enqueue(Function f)
{
    funcs_lock.Lock();
    funcs.push(f);
    AJ_Net_Interrupt();
    funcs_lock.Unlock();
}

void TCBusAttachment::SendMessage()
{
    funcs_lock.Lock();
    while (!funcs.empty()) {
        Function f = funcs.front();
        f();
        funcs.pop();
    }
    funcs_lock.Unlock();
}

void TCBusAttachment::RecvMessage(AJ_Message* msg)
{
    AJ_Status status;
    bool handled = TRUE;

    uint16_t port;
    switch (msg->msgId) {
    case AJ_METHOD_ACCEPT_SESSION:
        uint32_t id;
        const char* str;
        status = AJ_UnmarshalArgs(msg, "qus", &port, &id, &str);
        EXPECT_EQ(AJ_OK, status);
        if (port == sessionPort) {
            printf("AcceptSession(bus=%p): AJ_METHOD_ACCEPT_SESSION %d %d %s OK\n", &bus, port, id, str);
            AJ_BusReplyAcceptSession(msg, TRUE);
        } else {
            printf("AcceptSession(bus=%p): AJ_METHOD_ACCEPT_SESSION %d %d %s BUS\n", &bus, port, id, str);
            AJ_ResetArgs(msg);
            handled = FALSE;
        }
        break;

    case AJ_REPLY_ID(AJ_METHOD_BIND_SESSION_PORT):
        AJ_ASSERT(AJ_MSG_ERROR != msg->hdr->msgType);
        uint32_t disposition;
        status = AJ_UnmarshalArgs(msg, "uq", &disposition, &port);
        AJ_ASSERT(AJ_OK == status);
        if (port == sessionPort) {
            printf("BindSessionPortReply(bus=%p): AJ_METHOD_BIND_SESSION_PORT %d OK\n", &bus, port);
            bound = TRUE;
        } else {
            printf("BindSessionPortReply(bus=%p): AJ_METHOD_BIND_SESSION_PORT %d BUS\n", &bus, port);
            AJ_ResetArgs(msg);
            handled = FALSE;
        }
        break;

    case AJ_REPLY_ID(AJ_METHOD_JOIN_SESSION):
        if (AJ_MSG_ERROR == msg->hdr->msgType) {
            SCStatus = ER_BUS_REPLY_IS_ERROR_MESSAGE;
            response = msg->error;
        } else {
            uint32_t code;
            uint32_t id;
            status = AJ_UnmarshalArgs(msg, "uu", &code, &id);
            AJ_ASSERT(AJ_OK == status);
            if (code == AJ_JOINSESSION_REPLY_SUCCESS) {
                printf("JoinSessionReply(bus=%p): AJ_METHOD_JOIN_SESSION %d OK\n", &bus, id);
                session = id;
            } else {
                printf("JoinSessionReply(bus=%p): AJ_METHOD_JOIN_SESSION %d FAIL\n", &bus, id);
            }
        }
        break;

    default:
        handled = FALSE;
        break;
    }
    if (handled) {
        HandleMessage(msg);
    } else {
        AJ_BusHandleBusMessage(msg);
    }
}

void TCBusAttachment::HandleMessage(AJ_Message* msg)
{
    auto it = message_handlers.find(msg->msgId);

    if (it != message_handlers.end()) {
        Function handler = it->second;
        handler();
        message_handlers.erase(it);
    }
}

qcc::String TCBusAttachment::GetUniqueName()
{
    /* May have to wait for the hello message */
    for (int msec = 0; msec < WAIT_TIME; msec += WAIT_MSECS) {
        if (bus.uniqueName[0] != '\0') {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    return qcc::String(bus.uniqueName);
}

QStatus TCBusAttachment::EnablePeerSecurity(const char* mechanisms)
{
    qcc::String str(mechanisms);
    qcc::Event e;

    auto func = [this, &e, str] () {
                    uint32_t suites[AJ_AUTH_SUITES_NUM] = { 0 };
                    size_t numsuites = 0;
                    if (qcc::String::npos != str.find("ALLJOYN_ECDHE_NULL")) {
                        suites[numsuites++] = AUTH_SUITE_ECDHE_NULL;
                    }
                    if (qcc::String::npos != str.find("ALLJOYN_ECDHE_PSK")) {
                        suites[numsuites++] = AUTH_SUITE_ECDHE_PSK;
                    }
                    if (qcc::String::npos != str.find("ALLJOYN_ECDHE_SPEKE")) {
                        suites[numsuites++] = AUTH_SUITE_ECDHE_SPEKE;
                    }
                    if (qcc::String::npos != str.find("ALLJOYN_ECDHE_ECDSA")) {
                        suites[numsuites++] = AUTH_SUITE_ECDHE_ECDSA;
                    }
                    AJ_BusEnableSecurity(&bus, suites, numsuites);
                    e.SetEvent();
                };

    Enqueue(func);
    qcc::Event::Wait(e, qcc::Event::WAIT_FOREVER);
    return ER_OK;
}

void TCBusAttachment::SetApplicationState(uint16_t state)
{
    qcc::Event e;

    auto func = [this, &e, state] () {
                    AJ_SecuritySetClaimConfig(&bus, state, CLAIM_CAPABILITY_ECDHE_PSK | CLAIM_CAPABILITY_ECDHE_SPEKE | CLAIM_CAPABILITY_ECDHE_NULL, 0);
                    e.SetEvent();
                };

    Enqueue(func);
    qcc::Event::Wait(e, qcc::Event::WAIT_FOREVER);
}

void TCBusAttachment::SetPermissionManifest(AJ_PermissionRule* manifest)
{
    qcc::Event e;

    auto func = [this, &e, manifest] () {
                    uint16_t state;
                    uint16_t cap;
                    uint16_t info;
                    AJ_SecurityGetClaimConfig(&state, &cap, &info);
                    /* Only change if already claimed */
                    if (APP_STATE_CLAIMED == state) {
                        AJ_ManifestTemplateSet(manifest);
                        AJ_SecuritySetClaimConfig(&bus, APP_STATE_NEED_UPDATE, cap, info);
                    }
                    e.SetEvent();
                };

    Enqueue(func);
    qcc::Event::Wait(e, qcc::Event::WAIT_FOREVER);
}

QStatus TCBusAttachment::BindSessionPort(uint16_t port)
{
    Promise<bool> p;

    auto func = [this, &p, port] () {
                    sessionPort = port;
                    AJ_BusBindSessionPort(&bus, port, NULL, 0);
                    message_handlers[AJ_REPLY_ID(AJ_METHOD_BIND_SESSION_PORT)] = [this, &p] () {
                                                                                     p.SetResult(true);
                                                                                 };
                };

    Enqueue(func);

    /* Wait for reply */
    bool result = p.Wait(WAIT_TIME, false);

    if (bound && result) {
        return ER_OK;
    } else {
        return ER_FAIL;
    }
}

QStatus TCBusAttachment::JoinSession(const char* host, uint16_t port, uint32_t& id)
{
    qcc::Event e;

    auto func = [this, &e, host, port] () {
                    this->session = 0;
                    this->sessionPort = port;
                    AJ_BusJoinSession(&bus, host, port, NULL);
                    message_handlers[AJ_REPLY_ID(AJ_METHOD_JOIN_SESSION)] = [this, &e] () {
                                                                                e.SetEvent();
                                                                            };
                };

    Enqueue(func);

    /* Wait for reply */
    qcc::Event::Wait(e, WAIT_TIME);

    if (!session) {
        return ER_FAIL;
    }
    id = session;

    return ER_OK;
}

QStatus TCBusAttachment::AuthenticatePeer(const char* host)
{
    Promise<AJ_Status> p;

    auto func = [this, &p, host]() {
        /* AuthCallback will set p's value (but it doesn't get called; see ASACORE-2716) */
        AJ_Status status = AJ_BusAuthenticatePeer(&bus, host, authcallback, &p);
        if (status != AJ_OK) {
            AJ_AlwaysPrintf(("ERROR: AJ_BusAuthenticatePeer failed with status: %x\n", status));
            p.SetResult(status);
        }
    };

    Enqueue(func);

    /* Wait for reply */
    AJ_Status status = p.Wait(WAIT_TIME, AJ_ERR_NULL);
    return (AJ_OK == status) ? ER_OK : ER_AUTH_FAIL;
}

QStatus TCBusAttachment::MethodCall(const char* peer, uint32_t id, const char* str)
{
    Promise<QStatus> p;

    auto func = [this, &p, peer, id, str] () {
                    AJ_Status status;
                    AJ_Message msg;
                    SCStatus = ER_FAIL;
                    response = "";

                    AJ_VERIFY(AJ_OK == AJ_MarshalMethodCall(&bus, &msg, id, peer, session, 0, 25000));
                    if (str) {
                        AJ_VERIFY(AJ_OK == AJ_MarshalArgs(&msg, "s", str));
                    }

                    /* Access control is on AJ_DeliverMsg */
                    status = AJ_DeliverMsg(&msg);
                    if (AJ_OK != status) {
                        if (AJ_ERR_ACCESS == status) {
                            SCStatus = ER_PERMISSION_DENIED;
                        }
                        AJ_CloseMsg(&msg);
                        p.SetResult(SCStatus);
                        return;
                    }

                    message_handlers[AJ_REPLY_ID(id)] = [this, &p] () {
                                                            p.SetResult(SCStatus);
                                                        };
                };

    Enqueue(func);

    QStatus status = p.Wait(WAIT_TIME, ER_FAIL);
    return status;
}

QStatus TCBusAttachment::Signal(const char* peer, uint32_t id, const char* str)
{
    Promise<QStatus> p;

    auto func = [this, &p, peer, id, str] () {
                    AJ_Status status;
                    AJ_Message msg;
                    SCStatus = ER_FAIL;

                    AJ_VERIFY(AJ_OK == AJ_MarshalSignal(&bus, &msg, id, peer, session, 0, 0));
                    if (str) {
                        AJ_VERIFY(AJ_OK == AJ_MarshalArgs(&msg, "s", str));
                    }

                    /* Access control is on AJ_DeliverMsg */
                    status = AJ_DeliverMsg(&msg);
                    if (AJ_OK != status) {
                        if (AJ_ERR_ACCESS == status) {
                            SCStatus = ER_PERMISSION_DENIED;
                        }
                        AJ_CloseMsg(&msg);
                        p.SetResult(SCStatus);
                        return;
                    }
                    SCStatus = ER_OK;

                    p.SetResult(SCStatus);
                };

    Enqueue(func);
    return p.Wait(qcc::Event::WAIT_FOREVER, ER_FAIL);
}

QStatus TCBusAttachment::GetGuid(qcc::GUID128& guid)
{
    AJ_GUID tc_guid;
    Promise<AJ_Status> p;

    auto func = [this, &tc_guid, &p] () {
                    AJ_Status status = AJ_GetLocalGUID(&tc_guid);
                    p.SetResult(status);
                };

    Enqueue(func);

    AJ_Status status = p.Wait(qcc::Event::WAIT_FOREVER, AJ_ERR_FAILURE);
    if (status == AJ_OK) {
        char buf[128];
        AJ_GUID_ToString(&tc_guid, buf, sizeof(buf));

        qcc::GUID128 g(buf);
        guid = g;
        return ER_OK;
    }

    return ER_FAIL;
}

QStatus TCBusAttachment::GetProperty(const char* peer, uint32_t mid, uint32_t pid, int32_t& val)
{
    struct RetVal {
        int32_t val;
        QStatus status;
    };

    Promise<RetVal> p;

    auto func = [this, &p, peer, mid, pid] () {
                    AJ_Status status;
                    AJ_Message msg;
                    SCStatus = ER_FAIL;
                    response = "";
                    propval = 0;
                    RetVal rv = { propval, ER_FAIL };
                    propid = pid;

                    AJ_VERIFY(AJ_OK == AJ_MarshalMethodCall(&bus, &msg, mid, peer, session, 0, 25000));

                    /* Access control is on AJ_MarshalPropertyArgs */
                    status = AJ_MarshalPropertyArgs(&msg, propid);
                    if (AJ_OK != status) {
                        if (AJ_ERR_ACCESS == status) {
                            rv.status = ER_PERMISSION_DENIED;
                        }
                        AJ_CloseMsg(&msg);
                        p.SetResult(rv);
                        return;
                    }

                    AJ_VERIFY(AJ_OK == AJ_DeliverMsg(&msg));

                    message_handlers[AJ_REPLY_ID(mid)] = [this, &p] () {
                                                             RetVal rv = { propval, SCStatus };
                                                             p.SetResult(rv);
                                                         };
                };

    Enqueue(func);

    RetVal ret = p.Wait(WAIT_TIME, { 0, ER_FAIL });
    val = ret.val;
    return ret.status;
}

QStatus TCBusAttachment::SetProperty(const char* peer, uint32_t mid, uint32_t pid, int32_t val)
{
    Promise<QStatus> p;

    auto func = [this, &p, peer, mid, pid, val] () {
                    AJ_Status status;
                    AJ_Message msg;
                    SCStatus = ER_FAIL;
                    response = "";
                    propid = pid;

                    AJ_VERIFY(AJ_OK == AJ_MarshalMethodCall(&bus, &msg, mid, peer, session, 0, 25000));

                    /* Access control is on AJ_MarshalPropertyArgs */
                    status = AJ_MarshalPropertyArgs(&msg, propid);
                    if (AJ_OK != status) {
                        if (AJ_ERR_ACCESS == status) {
                            SCStatus = ER_PERMISSION_DENIED;
                        }
                        AJ_CloseMsg(&msg);
                        p.SetResult(SCStatus);
                        return;
                    }

                    AJ_VERIFY(AJ_OK == AJ_MarshalArgs(&msg, "i", val));
                    AJ_VERIFY(AJ_OK == AJ_DeliverMsg(&msg));

                    message_handlers[AJ_REPLY_ID(mid)] = [this, &p] () {
                                                             p.SetResult(SCStatus);
                                                         };
                };

    Enqueue(func);

    // wait for the results to come back!
    QStatus status = p.Wait(WAIT_TIME, ER_FAIL);
    return status;
}

QStatus TCBusAttachment::GetAllProperties(const char* peer, uint32_t mid, const char* ifn, TCProperties& val, bool secure)
{
    struct RetVal {
        TCProperties properties;
        QStatus status;
    };

    Promise<RetVal> p;

    auto func = [this, &p, peer, mid, ifn, secure] () {
                    AJ_Status status;
                    AJ_Message msg;
                    SCStatus = ER_FAIL;
                    response = "";
                    properties.Clear();
                    RetVal rv;

                    /* Need to explicitly turn encrypt flag on */
                    if (secure) {
                        AJ_VERIFY(AJ_OK == AJ_MarshalMethodCall(&bus, &msg, mid, peer, session, AJ_FLAG_ENCRYPTED, 25000));
                    } else {
                        AJ_VERIFY(AJ_OK == AJ_MarshalMethodCall(&bus, &msg, mid, peer, session, 0, 25000));
                    }
                    AJ_VERIFY(AJ_OK == AJ_MarshalArgs(&msg, "s", ifn));

                    /* Access control is on AJ_DeliverMsg */
                    status = AJ_DeliverMsg(&msg);
                    rv.status = ER_FAIL;
                    if (AJ_OK != status) {
                        if (AJ_ERR_ACCESS == status) {
                            rv.status = ER_PERMISSION_DENIED;
                        }
                        p.SetResult(rv);
                        AJ_CloseMsg(&msg);
                        return;
                    }

                    message_handlers[AJ_REPLY_ID(mid)] = [this, &p] () {
                                                             RetVal rv = { properties, SCStatus };
                                                             p.SetResult(rv);
                                                         };
                };

    Enqueue(func);
    TCProperties defaultProperties;
    RetVal ret = p.Wait(WAIT_TIME, { defaultProperties, ER_FAIL });
    val = ret.properties;
    return ret.status;
}
