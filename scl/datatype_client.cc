/**
 * @file
 * Alljoyn client that marshals different data types.
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
#include <signal.h>
#include <qcc/Util.h>
#include <alljoyn/BusAttachment.h>
#include <alljoyn/Init.h>
#include <alljoyn/version.h>

#define QCC_MODULE "DATATYPECLIENT"

using namespace std;
using namespace qcc;
using namespace ajn;

const char* g_WellKnownName = "org.datatypes.test";
const char* g_InterfaceName = "org.datatypes.test.interface";
const char* g_PaddingInterfaceName = "org.datatypes.test.padding.interface";
const char* g_ObjectPath = "/datatypes";
static SessionPort g_SessionPort = 25;

typedef struct {
    uint8_t byte;
    int32_t int32;
    uint32_t uint32;
    double doubleValue;
    bool boolValue;
    char* stringValue;
    uint16_t uint16;
    int16_t int16;
    int64_t int64;
    uint64_t uint64;
}Structure;

typedef struct {
    uint8_t byte;
    uint16_t uint16;
    uint32_t uint32;
    uint64_t uint64;
}Padding1;


/** Static data */
static BusAttachment* g_msgBus = nullptr;
static Event* g_discoverEvent = nullptr;
static TransportMask g_Transport = TRANSPORT_ANY;
/** AllJoynListener receives discovery events from AllJoyn */
class MyBusListener : public BusListener, public SessionListener {
  public:

    MyBusListener() { sessionId = 0; }

    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix)
    {
        QStatus status = ER_OK;
        cout << "FoundAdvertisedName(name=" << name << ", transport=" << transport << ", prefix=" << namePrefix << ")" << endl;

        /* We must enable concurrent callbacks since some of the calls below are blocking */
        g_msgBus->EnableConcurrentCallbacks();

        if (0 == ::strcmp(name, g_WellKnownName)) {
            SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, g_Transport);

            status = g_msgBus->JoinSession(name, g_SessionPort, this, sessionId, opts);
            if (ER_OK != status) {
                QCC_LogError(status, ("JoinSession(%s) failed", name));
            }

            /* Release the main thread */
            if (ER_OK == status) {
                g_discoverEvent->SetEvent();
            }
        }
    }

    SessionId GetSessionId() const { return sessionId; }

  private:
    SessionId sessionId;
};

/** Static bus listener */
static MyBusListener* g_busListener;

static volatile sig_atomic_t g_interrupt = false;

static void CDECL_CALL SigIntHandler(int sig)
{
    QCC_UNUSED(sig);
    g_interrupt = true;
}

static void usage(void)
{
    cout << "Usage: datatype_client [-h] [-d] [-n <well-known name>] [-u/-t/-l]" << endl << endl;
    cout << "Options:" << endl;
    cout << "   -h                        = Print this help message" << endl;
    cout << "   -n <well-known name>      = Well-known bus name advertised by datatype_service" << endl;
    cout << "   -d                        = discover remote bus with test service" << endl;
    cout << "   -p                        = Run additional data padding test cases" << endl;
    cout << "   -l                        = Use TRANSPORT_LOCAL" << endl;
    cout << "   -t                        = Use TRANSPORT_TCP" << endl;
    cout << "   -u                        = Use TRANSPORT_UDP" << endl;
    cout << endl;
}

int TestAppMain(int argc, char** argv)
{
    QStatus status = ER_OK;
    g_discoverEvent = nullptr;
    bool discoverRemote = false;
    bool paddingTest = false;

    cout << "AllJoyn Library version: " << ajn::GetVersion() << endl;
    cout << "AllJoyn Library build info: " << ajn::GetBuildInfo() << endl;

    /* Install SIGINT handler */
    signal(SIGINT, SigIntHandler);

    /* Parse command line args */
    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp("-n", argv[i])) {
            ++i;
            if (i == argc) {
                cout << "option " << argv[i - 1] << " requires a parameter" << endl;
                usage();
                exit(1);
            } else {
                g_WellKnownName = argv[i];
            }
        } else if (0 == strcmp("-h", argv[i])) {
            usage();
            exit(0);
        } else if (0 == strcmp("-d", argv[i])) {
            discoverRemote = true;
        } else if (0 == strcmp("-p", argv[i])) {
            paddingTest = true;
        } else if (0 == strcmp("-l", argv[i])) {
            g_Transport = TRANSPORT_LOCAL;
        } else if (0 == strcmp("-t", argv[i])) {
            g_Transport = TRANSPORT_TCP;
        } else if (0 == strcmp("-u", argv[i])) {
            g_Transport = TRANSPORT_UDP;
        } else {
            status = ER_FAIL;
            cout << "Unknown option " << argv[i] << endl;
            usage();
            exit(1);
        }
    }

    do {
        g_discoverEvent = new Event();
        /* Create message bus */
        g_msgBus = new BusAttachment("datatype_client", true);
        /* Register a bus listener in order to get discovery indications */
        g_busListener = new MyBusListener();
        g_msgBus->RegisterBusListener(*g_busListener);

        status = g_msgBus->Start();
        if (ER_OK != status) {
            QCC_LogError(status, ("BusAttachment::Start failed"));
            break;
        }

        status = g_msgBus->Connect();
        if (ER_OK != status) {
            QCC_LogError(status, ("BusAttachment::Connect failed"));
            break;
        }

        if (discoverRemote) {
            g_discoverEvent->ResetEvent();
            status = g_msgBus->FindAdvertisedName(g_WellKnownName);
            if (ER_OK != status) {
                QCC_LogError(status, ("BusAttachment::FindAdvertisedName failed"));
                break;
            }
        }

        bool hasOwner = false;
        status = g_msgBus->NameHasOwner(g_WellKnownName, hasOwner);
        if ((ER_OK == status) && !hasOwner) {
            cout << "Waiting for name " << g_WellKnownName << " to appear on the bus" << endl;
            status = Event::Wait(*g_discoverEvent);
            if (ER_OK != status) {
                QCC_LogError(status, ("Event::Wait failed"));
            }
        }
    } while (0);

    if (ER_OK == status) {
        /* Create the remote object that will be called */
        ProxyBusObject* remoteObj = nullptr;
        remoteObj = new ProxyBusObject(*g_msgBus, g_WellKnownName, g_ObjectPath, g_busListener->GetSessionId());
        status = remoteObj->IntrospectRemoteObject();
        if (ER_OK != status) {
            QCC_LogError(status, ("Introspection of %s (path=%s) failed", g_WellKnownName, g_ObjectPath));
        } else {
            Message reply(*g_msgBus);

            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                MsgArg byte;
                byte.Set("y", 255);
                status = remoteObj->MethodCall(g_InterfaceName, "byte", &byte, 1, reply, 50000);
                if (ER_OK == status) {
                    cout << "byte returned " << (int)reply->GetArg(0)->v_byte << endl;
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "byte"));
                }
            }

            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                MsgArg integer;
                integer.Set("i", -65540);
                status = remoteObj->MethodCall(g_InterfaceName, "int", &integer, 1, reply, 50000);
                if (ER_OK == status) {
                    cout << "int returned " << reply->GetArg(0)->v_int32 << endl;
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "int"));
                }
            }

            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                MsgArg unsignedInteger;
                unsignedInteger.Set("u", 65540);
                status = remoteObj->MethodCall(g_InterfaceName, "unsignedint", &unsignedInteger, 1, reply, 50000);
                if (ER_OK == status) {
                    cout << "unsignedint returned " << reply->GetArg(0)->v_uint32 << endl;
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "unsignedint"));
                }
            }

            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                MsgArg doubleType;
                doubleType.Set("d", 3.1423);
                status = remoteObj->MethodCall(g_InterfaceName, "double", &doubleType, 1, reply, 50000);
                if (ER_OK == status) {
                    cout << "double returned " << reply->GetArg(0)->v_double << endl;
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "double"));
                }
            }

            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                MsgArg boolType;
                bool temp = true;
                boolType.Set("b", temp);
                status = remoteObj->MethodCall(g_InterfaceName, "bool", &boolType, 1, reply, 50000);
                if (ER_OK == status) {
                    cout << "bool returned " << ((reply->GetArg(0)->v_bool) ? "true" : "false") << endl;
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "bool"));
                }
            }

            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                MsgArg stringType;
                stringType.Set("s", "Hello");
                status = remoteObj->MethodCall(g_InterfaceName, "string", &stringType, 1, reply, 50000);
                if (ER_OK == status) {
                    cout << "string returned " << reply->GetArg(0)->v_string.str << endl;
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "string"));
                }
            }

            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                MsgArg uint16Type;
                uint16Type.Set("q", 65535);
                status = remoteObj->MethodCall(g_InterfaceName, "uint16", &uint16Type, 1, reply, 50000);
                if (ER_OK == status) {
                    cout << "uint16 returned " << reply->GetArg(0)->v_uint16 << endl;
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "uint16"));
                }
            }


            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                MsgArg int16Type;
                int16Type.Set("n", -32768);
                status = remoteObj->MethodCall(g_InterfaceName, "int16", &int16Type, 1, reply, 50000);
                if (ER_OK == status) {
                    cout << "int16 returned " << reply->GetArg(0)->v_int16 << endl;
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "int16"));
                }
            }

            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                MsgArg int64Type;
        #if _WIN32
                int64Type.Set("x", -9223372036854775808i64);
        #else
                int64Type.Set("x", -9223372036854775808LLU);
        #endif
                status = remoteObj->MethodCall(g_InterfaceName, "int64", &int64Type, 1, reply, 50000);
                if (ER_OK == status) {
                    cout << "int64 returned " << reply->GetArg(0)->v_int64 << endl;
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "int64"));
                }
            }

            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                MsgArg uint64Type;
        #if _WIN32
                uint64Type.Set("t", 7223372036854775808ui64);
        #else
                uint64Type.Set("t", 7223372036854775808LLU);
        #endif
                status = remoteObj->MethodCall(g_InterfaceName, "uint64", &uint64Type, 1, reply, 50000);
                if (ER_OK == status) {
                    cout << "uint64 returned " << reply->GetArg(0)->v_uint64 << endl;
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "uint64"));
                }
            }

            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                Structure structData;
                structData.byte = 254;
                structData.int32 = -65541;
                structData.uint32 = 65541;
                structData.doubleValue = 3.14908765;
                structData.boolValue = false;
                structData.stringValue = (char*)"Hello Struct";
                structData.uint16 = 65535;
                structData.int16 = -32768;
        #if _WIN32
                structData.int64 = -5223372036854775808i64;
                structData.uint64 = 6223372036854775808ui64;
        #else
                structData.int64 = -5223372036854775808LLU;
                structData.uint64 = 6223372036854775808LLU;
        #endif

                MsgArg structType;
                structType.Set("(yiudbsqnxt)", structData.byte, structData.int32, structData.uint32, structData.doubleValue, structData.boolValue, structData.stringValue, structData.uint16, structData.int16, structData.int64, structData.uint64);
                status = remoteObj->MethodCall(g_InterfaceName, "struct", &structType, 1, reply, 50000);
                if (ER_OK == status) {
                    cout << "struct members " << reply->GetArg(0)->v_struct.numMembers << endl;
                    cout << "struct returned " << (int)reply->GetArg(0)->v_struct.members[0].v_byte << endl;
                    cout << "struct returned " << reply->GetArg(0)->v_struct.members[1].v_int32 << endl;
                    cout << "struct returned " << reply->GetArg(0)->v_struct.members[2].v_uint32 << endl;
                    cout << "struct returned " << reply->GetArg(0)->v_struct.members[3].v_double << endl;
                    cout << "struct returned " << (reply->GetArg(0)->v_struct.members[4].v_bool ? "true" : "false") << endl;
                    cout << "struct returned " << reply->GetArg(0)->v_struct.members[5].v_string.str << endl;
                    cout << "struct returned " << reply->GetArg(0)->v_struct.members[6].v_uint16 << endl;
                    cout << "struct returned " << reply->GetArg(0)->v_struct.members[7].v_int16 << endl;
                    cout << "struct returned " << reply->GetArg(0)->v_struct.members[8].v_int64 << endl;
                    cout << "struct returned " << reply->GetArg(0)->v_struct.members[9].v_uint64 << endl;
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "struct"));
                }
            }
            /* Array of struct. */
            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                struct {
                    uint32_t num;
                    const char* ord;
                } table[] = { { 1, "first" }, { 2, "second" }, { 3, "third" } };

                MsgArg arg[3];
                status = arg[0].Set("(is)", table[0].num, table[0].ord);
                status = arg[1].Set("(is)", table[1].num, table[1].ord);
                status = arg[2].Set("(is)", table[2].num, table[2].ord);
                MsgArg outer;
                status = outer.Set("a(is)", 3, arg);
                status = remoteObj->MethodCall(g_InterfaceName, "arrayofstruct", &outer, 1, reply, 50000);

                if (ER_OK == status) {
                    const MsgArg* reply_arg = reply->GetArg(0);
                    const MsgArg* reply_outer;
                    size_t reply_outerSize;
                    status = reply_arg->Get("a(is)", &reply_outerSize, &reply_outer);
                    cout << "Array of struct members " << reply_outerSize << endl;
                    for (size_t i = 0; i < reply_outerSize; ++i) {
                        cout << "element[" << i << "] members " << reply_outer[i].v_struct.numMembers << endl;
                        cout << "element[" << i << "].num " << reply_outer[i].v_struct.members[0].v_uint32 << endl;
                        cout << "element[" << i << "].ord " << reply_outer[i].v_struct.members[1].v_string.str << endl;
                    }

                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "arrayofstruct"));
                }
            }


            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                int numEntries = 1;
                MsgArg* entries = new MsgArg[numEntries];
                MsgArg dict(ALLJOYN_ARRAY);
                entries[0].typeId = ALLJOYN_DICT_ENTRY;
                entries[0].v_dictEntry.key = new MsgArg("u", 1);
                entries[0].v_dictEntry.val = new MsgArg("v", new MsgArg("u", 1234));
                entries[0].SetOwnershipFlags(MsgArg::OwnsArgs, true);
                status = dict.v_array.SetElements("{uv}", numEntries, entries);
                status = remoteObj->MethodCall(g_InterfaceName, "dictionary", &dict, 1, reply, 50000);
                if (ER_OK == status) {
                    cout << "Dictionary returned elements  " << endl;
                    const MsgArg* reply_arg = reply->GetArg(0);
                    MsgArg* reply_entries;
                    MsgArg* reply_val;
                    size_t reply_num;
                    uint32_t reply_key;
                    uint32_t reply_value;
                    status = reply_arg->Get("a{uv}", &reply_num, &reply_entries);
                    status = reply_entries[0].Get("{uv}", &reply_key, &reply_val);
                    status = reply_val->Get("u", &reply_value);
                    cout << "Dictionary returned key  " << reply_key << endl;
                    cout << "Dictionary returned value  " << reply_value << endl;
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "dictionary"));
                }
                delete [] entries;
            }

            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                uint8_t byte = 254;
                int32_t int32 = 65535;
                uint32_t uint32 = 65541;
                MsgArg nestedstruct;
                nestedstruct.Set("(y(iu))", byte, int32, uint32);
                status = remoteObj->MethodCall(g_InterfaceName, "nestedstruct", &nestedstruct, 1, reply, 50000);
                if (ER_OK == status) {
                    uint8_t byte_reply;
                    int32_t int32_reply;
                    uint32_t uint32_reply;
                    const MsgArg* reply_arg((reply->GetArg(0)));
                    reply_arg->Get("(y(iu))", &byte_reply, &int32_reply, &uint32_reply);
                    cout << "nestedstruct members  " << reply->GetArg(0)->v_struct.numMembers << endl;
                    cout << "nestedstruct returned " << (int)byte_reply << endl;
                    cout << "nestedstruct returned " << int32_reply << endl;
                    cout << "nestedstruct returned " << uint32_reply << endl;
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "nestedstruct"));
                }
            }


            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                uint8_t byteArray[] = { 255, 254, 253, 252, 251 };
                MsgArg arg;
                status = arg.Set("ay", sizeof(byteArray), byteArray);
                status = remoteObj->MethodCall(g_InterfaceName, "bytearray", &arg, 1, reply, 50000);
                if (ER_OK == status) {
                    cout << "bytearray returned elements " << (unsigned int)reply->GetArg(0)->v_scalarArray.numElements << endl;
                    for (size_t i = 0; i < reply->GetArg(0)->v_scalarArray.numElements; i++) {
                        cout << "bytearray returned " << (int)reply->GetArg(0)->v_scalarArray.v_byte[i] << endl;
                    }
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "bytearray"));
                }
            }

            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                int32_t intArray[] = { -65540, -65541, -65542, -65543, -65544 };
                MsgArg arg;
                status = arg.Set("ai", sizeof(intArray) / sizeof(int32_t), intArray);
                status = remoteObj->MethodCall(g_InterfaceName, "intarray", &arg, 1, reply, 50000);
                if (ER_OK == status) {
                    cout << "intarray returned elements " << (unsigned int)reply->GetArg(0)->v_scalarArray.numElements << endl;
                    for (size_t i = 0; i < reply->GetArg(0)->v_scalarArray.numElements; i++) {
                        cout << "intarray returned " << reply->GetArg(0)->v_scalarArray.v_int32[i] << endl;
                    }
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "intarray"));
                }
            }

            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                uint32_t unsignedintArray[] = { 65540, 65541, 65542, 65543, 65544 };
                MsgArg arg;
                status = arg.Set("au", sizeof(unsignedintArray) / sizeof(uint32_t), unsignedintArray);
                status = remoteObj->MethodCall(g_InterfaceName, "unsignedintarray", &arg, 1, reply, 50000);
                if (ER_OK == status) {
                    cout << "unsignedintarray returned elements " << (unsigned int)reply->GetArg(0)->v_scalarArray.numElements << endl;
                    for (size_t i = 0; i < reply->GetArg(0)->v_scalarArray.numElements; i++) {
                        cout << "unsignedintarray returned " << reply->GetArg(0)->v_scalarArray.v_uint32[i] << endl;
                    }
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "unsignedintarray"));
                }
            }

            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                double doubleArray[10];
                for (int i = 0; i < 10; i++) {
                    doubleArray[i] = i + (0.1 * (double)i);
                }
                MsgArg arg;
                status = arg.Set("ad", sizeof(doubleArray) / sizeof(double), doubleArray);
                status = remoteObj->MethodCall(g_InterfaceName, "doublearray", &arg, 1, reply, 100000);
                if (ER_OK == status) {
                    cout << "doublearray returned elements " << (unsigned int)reply->GetArg(0)->v_scalarArray.numElements << endl;
                    for (size_t i = 0; i < reply->GetArg(0)->v_scalarArray.numElements; i++) {
                        cout << "doublearray returned " << reply->GetArg(0)->v_scalarArray.v_double[i] << endl;
                    }
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "doublearray"));
                }
            }

            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                bool boolArray[] = { true, true, false, false, true, true };
                MsgArg arg;
                status = arg.Set("ab", sizeof(boolArray) / sizeof(bool), boolArray);
                status = remoteObj->MethodCall(g_InterfaceName, "boolarray", &arg, 1, reply, 50000);
                if (ER_OK == status) {
                    cout << "boolarray returned elements " << (unsigned int)reply->GetArg(0)->v_scalarArray.numElements << endl;
                    for (size_t i = 0; i < reply->GetArg(0)->v_scalarArray.numElements; i++) {
                        cout << "boolarray returned " << (reply->GetArg(0)->v_scalarArray.v_bool[i] ? "true" : "false") << endl;
                    }
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "boolarray"));
                }
            }

            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                uint16_t uint16Array[] = { 65535, 65534 };
                MsgArg arg;
                status = arg.Set("aq", sizeof(uint16Array) / sizeof(uint16_t), uint16Array);
                status = remoteObj->MethodCall(g_InterfaceName, "uint16array", &arg, 1, reply, 50000);
                if (ER_OK == status) {
                    cout << "uint16array returned elements " << (unsigned int)reply->GetArg(0)->v_scalarArray.numElements << endl;
                    for (size_t i = 0; i < reply->GetArg(0)->v_scalarArray.numElements; i++) {
                        cout << "uint16array returned " << reply->GetArg(0)->v_scalarArray.v_uint16[i] << endl;
                    }
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "uint16array"));
                }
            }

            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                int16_t int16Array[] = { -32768, -32767, -32766, -32765 };
                MsgArg arg;
                status = arg.Set("an", sizeof(int16Array) / sizeof(int16_t), int16Array);
                status = remoteObj->MethodCall(g_InterfaceName, "int16array", &arg, 1, reply, 50000);
                if (ER_OK == status) {
                    cout << "int16array returned elements " << (unsigned int)reply->GetArg(0)->v_scalarArray.numElements << endl;
                    for (size_t i = 0; i < reply->GetArg(0)->v_scalarArray.numElements; i++) {
                        cout << "int16array returned " << reply->GetArg(0)->v_scalarArray.v_int16[i] << endl;
                    }
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "int16array"));
                }
            }


            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
        #if _WIN32
                int64_t int64Array[] = { -5223372036854775808i64, -5223372036854775807i64, -5223372036854775806i64 };
        #else
                int64_t int64Array[] = { -5223372036854775808LL, -5223372036854775807LL, -5223372036854775806LL };
        #endif
                MsgArg arg;
                status = arg.Set("ax", sizeof(int64Array) / sizeof(int64_t), int64Array);
                status = remoteObj->MethodCall(g_InterfaceName, "int64array", &arg, 1, reply, 50000);
                if (ER_OK == status) {
                    cout << "int64array returned elements " << (unsigned int)reply->GetArg(0)->v_scalarArray.numElements << endl;
                    for (size_t i = 0; i < reply->GetArg(0)->v_scalarArray.numElements; i++) {
                        cout << "int64array returned " << reply->GetArg(0)->v_scalarArray.v_int64[i] << endl;
                    }
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "int64array"));
                }
            }


            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                uint64_t uint64Array[] = { 6223372036854775808, 6223372036854775807 };
                MsgArg arg;
                status = arg.Set("at", sizeof(uint64Array) / sizeof(uint64_t), uint64Array);
                status = remoteObj->MethodCall(g_InterfaceName, "uint64array", &arg, 1, reply, 50000);
                if (ER_OK == status) {
                    cout << "uint64array returned elements " << (unsigned int)reply->GetArg(0)->v_scalarArray.numElements << endl;
                    for (size_t i = 0; i < reply->GetArg(0)->v_scalarArray.numElements; i++) {
                        cout << "uint64array returned " << reply->GetArg(0)->v_scalarArray.v_uint64[i] << endl;
                    }
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "uint64array"));
                }
            }

            {
                cout << " ------------------------------------------------------------------------------------------------ " << endl;
                const char*string_data[3] = { "hello", "world", "dog" };
                MsgArg arg;
                status = arg.Set("as", ArraySize(string_data), string_data);
                status = remoteObj->MethodCall(g_InterfaceName, "stringarray", &arg, 1, reply, 50000);
                if (ER_OK == status) {
                    const MsgArg* reply_arg = reply->GetArg(0);
                    MsgArg* array_of_strings;
                    size_t no_of_strings;
                    status = reply_arg->Get("as", &no_of_strings, &array_of_strings);
                    cout << "stringarray returned elements " << no_of_strings << endl;
                    for (size_t i = 0; i < no_of_strings; i++) {
                        char*value;
                        array_of_strings[i].Get("s", &value);
                        cout << "string returned " << value << endl;
                    }
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "stringarray"));
                }
            }

            if (paddingTest) {

                /* Padding test1 yqut */
                {
                    cout << " ------------------------------------------------------------------------------------------------ " << endl;
                    Padding1 paddingData;
                    paddingData.byte = 254;
                    paddingData.uint16 = 65535;
                    paddingData.uint32 = 65541;

                #if _WIN32
                    paddingData.uint64 = 6223372036854775808ui64;
                #else
                    paddingData.uint64 = 6223372036854775808LLU;
                #endif

                    MsgArg structType;
                    structType.Set("(yqut)", paddingData.byte, paddingData.uint16, paddingData.uint32, paddingData.uint64);
                    status = remoteObj->MethodCall(g_PaddingInterfaceName, "paddingtest1", &structType, 1, reply, 50000);
                    if (ER_OK == status) {
                        cout << "paddingtest1 returned " << (int)reply->GetArg(0)->v_struct.members[0].v_byte << endl;
                        cout << "paddingtest1 returned " << reply->GetArg(0)->v_struct.members[1].v_uint16 << endl;
                        cout << "paddingtest1 returned " << reply->GetArg(0)->v_struct.members[2].v_uint32 << endl;
                        cout << "paddingtest1 returned " << reply->GetArg(0)->v_struct.members[3].v_uint64 << endl;
                    } else {
                        QCC_LogError(status, ("MethodCall on %s.%s failed", g_PaddingInterfaceName, "paddingtest1"));
                    }
                }

                /* Padding test2 yqtu */
                {
                    cout << " ------------------------------------------------------------------------------------------------ " << endl;
                    Padding1 paddingData;
                    paddingData.byte = 254;
                    paddingData.uint16 = 65535;
                    paddingData.uint32 = 65541;

                #if _WIN32
                    paddingData.uint64 = 6223372036854775808ui64;
                #else
                    paddingData.uint64 = 6223372036854775808LLU;
                #endif
                    MsgArg structType;
                    structType.Set("(yqtu)", paddingData.byte, paddingData.uint16, paddingData.uint64, paddingData.uint32);
                    status = remoteObj->MethodCall(g_PaddingInterfaceName, "paddingtest2", &structType, 1, reply, 50000);
                    if (ER_OK == status) {
                        cout << "paddingtest2 returned " << (int)reply->GetArg(0)->v_struct.members[0].v_byte << endl;
                        cout << "paddingtest2 returned " << reply->GetArg(0)->v_struct.members[1].v_uint16 << endl;
                        cout << "paddingtest2 returned " << reply->GetArg(0)->v_struct.members[2].v_uint64 << endl;
                        cout << "paddingtest2 returned " << reply->GetArg(0)->v_struct.members[3].v_uint32 << endl;
                    } else {
                        QCC_LogError(status, ("MethodCall on %s.%s failed", g_PaddingInterfaceName, "paddingtest2"));
                    }
                }

                /* Padding test3 yuqt */
                {
                    cout << " ------------------------------------------------------------------------------------------------ " << endl;
                    Padding1 paddingData;
                    paddingData.byte = 254;
                    paddingData.uint16 = 65535;
                    paddingData.uint32 = 65541;

                #if _WIN32
                    paddingData.uint64 = 6223372036854775808ui64;
                #else
                    paddingData.uint64 = 6223372036854775808LLU;
                #endif

                    MsgArg structType;
                    structType.Set("(yuqt)", paddingData.byte, paddingData.uint32, paddingData.uint16, paddingData.uint64);
                    status = remoteObj->MethodCall(g_PaddingInterfaceName, "paddingtest3", &structType, 1, reply, 50000);
                    if (ER_OK == status) {
                        cout << "paddingtest3 returned " << (int)reply->GetArg(0)->v_struct.members[0].v_byte << endl;
                        cout << "paddingtest3returned  " << reply->GetArg(0)->v_struct.members[1].v_uint32 << endl;
                        cout << "paddingtest3 returned " << reply->GetArg(0)->v_struct.members[2].v_uint16 << endl;
                        cout << "paddingtest3 returned " << reply->GetArg(0)->v_struct.members[3].v_uint64 << endl;
                    } else {
                        QCC_LogError(status, ("MethodCall on %s.%s failed", g_PaddingInterfaceName, "paddingtest3"));
                    }
                }

                /* Padding test4 yutq */
                {
                    cout << " ------------------------------------------------------------------------------------------------ " << endl;
                    Padding1 paddingData;
                    paddingData.byte = 254;
                    paddingData.uint16 = 65535;
                    paddingData.uint32 = 65541;

                #if _WIN32
                    paddingData.uint64 = 6223372036854775808ui64;
                #else
                    paddingData.uint64 = 6223372036854775808LLU;
                #endif

                    MsgArg structType;
                    structType.Set("(yutq)", paddingData.byte, paddingData.uint32, paddingData.uint64, paddingData.uint16);
                    status = remoteObj->MethodCall(g_PaddingInterfaceName, "paddingtest4", &structType, 1, reply, 50000);
                    if (ER_OK == status) {
                        cout << "paddingtest4 returned " << (int)reply->GetArg(0)->v_struct.members[0].v_byte << endl;
                        cout << "paddingtest4 returned " << reply->GetArg(0)->v_struct.members[1].v_uint32 << endl;
                        cout << "paddingtest4 returned " << reply->GetArg(0)->v_struct.members[2].v_uint64 << endl;
                        cout << "paddingtest4 returned " << reply->GetArg(0)->v_struct.members[3].v_uint16 << endl;

                    } else {
                        QCC_LogError(status, ("MethodCall on %s.%s failed", g_PaddingInterfaceName, "paddingtest4"));
                    }
                }

                /* Padding test5 ytqu */
                {
                    cout << " ------------------------------------------------------------------------------------------------ " << endl;
                    Padding1 paddingData;
                    paddingData.byte = 254;
                    paddingData.uint16 = 65535;
                    paddingData.uint32 = 65541;

                #if _WIN32
                    paddingData.uint64 = 6223372036854775808ui64;
                #else
                    paddingData.uint64 = 6223372036854775808LLU;
                #endif

                    MsgArg structType;
                    structType.Set("(ytqu)", paddingData.byte, paddingData.uint64, paddingData.uint16, paddingData.uint32);
                    status = remoteObj->MethodCall(g_PaddingInterfaceName, "paddingtest5", &structType, 1, reply, 50000);
                    if (ER_OK == status) {
                        cout << "paddingtest5 returned " << (int)reply->GetArg(0)->v_struct.members[0].v_byte << endl;
                        cout << "paddingtest5 returned " << reply->GetArg(0)->v_struct.members[1].v_uint64 << endl;
                        cout << "paddingtest5 returned " << reply->GetArg(0)->v_struct.members[2].v_uint16 << endl;
                        cout << "paddingtest5 returned " << reply->GetArg(0)->v_struct.members[3].v_uint32 << endl;

                    } else {
                        QCC_LogError(status, ("MethodCall on %s.%s failed", g_PaddingInterfaceName, "paddingtest5"));
                    }
                }

                /* Padding test6 ytuq */
                {
                    cout << " ------------------------------------------------------------------------------------------------ " << endl;
                    Padding1 paddingData;
                    paddingData.byte = 254;
                    paddingData.uint16 = 65535;
                    paddingData.uint32 = 65541;

                #if _WIN32
                    paddingData.uint64 = 6223372036854775808ui64;
                #else
                    paddingData.uint64 = 6223372036854775808LLU;
                #endif

                    MsgArg structType;
                    structType.Set("(ytuq)", paddingData.byte, paddingData.uint64, paddingData.uint32, paddingData.uint16);
                    status = remoteObj->MethodCall(g_PaddingInterfaceName, "paddingtest6", &structType, 1, reply, 50000);
                    if (ER_OK == status) {
                        cout << "paddingtest6 returned " << (int)reply->GetArg(0)->v_struct.members[0].v_byte << endl;
                        cout << "paddingtest6 returned " << reply->GetArg(0)->v_struct.members[1].v_uint64 << endl;
                        cout << "paddingtest6 returned " << reply->GetArg(0)->v_struct.members[2].v_uint32 << endl;
                        cout << "paddingtest6 returned " << reply->GetArg(0)->v_struct.members[3].v_uint16 << endl;

                    } else {
                        QCC_LogError(status, ("MethodCall on %s.%s failed", g_PaddingInterfaceName, "paddingtest6"));
                    }
                }

                /* Padding test7 qyut */
                {
                    cout << " ------------------------------------------------------------------------------------------------ " << endl;
                    Padding1 paddingData;
                    paddingData.byte = 254;
                    paddingData.uint16 = 65535;
                    paddingData.uint32 = 65541;

                #if _WIN32
                    paddingData.uint64 = 6223372036854775808ui64;
                #else
                    paddingData.uint64 = 6223372036854775808LLU;
                #endif

                    MsgArg structType;
                    structType.Set("(qyut)", paddingData.uint16, paddingData.byte, paddingData.uint32, paddingData.uint64);
                    status = remoteObj->MethodCall(g_PaddingInterfaceName, "paddingtest7", &structType, 1, reply, 50000);
                    if (ER_OK == status) {
                        cout << "paddingtest7 returned " << reply->GetArg(0)->v_struct.members[0].v_uint16 << endl;
                        cout << "paddingtest7 returned " << (int)reply->GetArg(0)->v_struct.members[1].v_byte << endl;
                        cout << "paddingtest7 returned " << reply->GetArg(0)->v_struct.members[2].v_uint32 << endl;
                        cout << "paddingtest7 returned " << reply->GetArg(0)->v_struct.members[3].v_uint64 << endl;
                    } else {
                        QCC_LogError(status, ("MethodCall on %s.%s failed", g_PaddingInterfaceName, "paddingtest7"));
                    }
                }


                /* Padding test8 qytu */
                {
                    cout << " ------------------------------------------------------------------------------------------------ " << endl;
                    Padding1 paddingData;
                    paddingData.byte = 254;
                    paddingData.uint16 = 65535;
                    paddingData.uint32 = 65541;

                #if _WIN32
                    paddingData.uint64 = 6223372036854775808ui64;
                #else
                    paddingData.uint64 = 6223372036854775808LLU;
                #endif

                    MsgArg structType;
                    structType.Set("(qytu)", paddingData.uint16, paddingData.byte, paddingData.uint64, paddingData.uint32);
                    status = remoteObj->MethodCall(g_PaddingInterfaceName, "paddingtest8", &structType, 1, reply, 50000);
                    if (ER_OK == status) {
                        cout << "paddingtest8 returned " << reply->GetArg(0)->v_struct.members[0].v_uint16 << endl;
                        cout << "paddingtest8 returned " << (int)reply->GetArg(0)->v_struct.members[1].v_byte << endl;
                        cout << "paddingtest8 returned " << reply->GetArg(0)->v_struct.members[2].v_uint64 << endl;
                        cout << "paddingtest8 returned " << reply->GetArg(0)->v_struct.members[3].v_uint32 << endl;

                    } else {
                        QCC_LogError(status, ("MethodCall on %s.%s failed", g_PaddingInterfaceName, "paddingtest8"));
                    }
                }

                /* Padding test9 uyqt */
                {
                    cout << " ------------------------------------------------------------------------------------------------ " << endl;
                    Padding1 paddingData;
                    paddingData.byte = 254;
                    paddingData.uint16 = 65535;
                    paddingData.uint32 = 65541;

                #if _WIN32
                    paddingData.uint64 = 6223372036854775808ui64;
                #else
                    paddingData.uint64 = 6223372036854775808LLU;
                #endif

                    MsgArg structType;
                    structType.Set("(uyqt)", paddingData.uint32,  paddingData.byte, paddingData.uint16, paddingData.uint64);
                    status = remoteObj->MethodCall(g_PaddingInterfaceName, "paddingtest9", &structType, 1, reply, 50000);
                    if (ER_OK == status) {
                        cout << "paddingtest9 returned " << reply->GetArg(0)->v_struct.members[0].v_uint32 << endl;
                        cout << "paddingtest9 returned " << (int)reply->GetArg(0)->v_struct.members[1].v_byte << endl;
                        cout << "paddingtest9 returned " << reply->GetArg(0)->v_struct.members[2].v_uint16 << endl;
                        cout << "paddingtest9 returned " << reply->GetArg(0)->v_struct.members[3].v_uint64 << endl;
                    } else {
                        QCC_LogError(status, ("MethodCall on %s.%s failed", g_PaddingInterfaceName, "paddingtest9"));
                    }
                }

                /* Padding test10 tyqu */
                {
                    cout << " ------------------------------------------------------------------------------------------------ " << endl;
                    Padding1 paddingData;
                    paddingData.byte = 254;
                    paddingData.uint16 = 65535;
                    paddingData.uint32 = 65541;

                #if _WIN32
                    paddingData.uint64 = 6223372036854775808ui64;
                #else
                    paddingData.uint64 = 6223372036854775808LLU;
                #endif

                    MsgArg structType;
                    structType.Set("(tyqu)", paddingData.uint64,  paddingData.byte, paddingData.uint16, paddingData.uint32);
                    status = remoteObj->MethodCall(g_PaddingInterfaceName, "paddingtest10", &structType, 1, reply, 50000);
                    if (ER_OK == status) {
                        cout << "paddingtest10 returned " << reply->GetArg(0)->v_struct.members[0].v_uint64 << endl;
                        cout << "paddingtest10 returned " << (int)reply->GetArg(0)->v_struct.members[1].v_byte << endl;
                        cout << "paddingtest10 returned " << reply->GetArg(0)->v_struct.members[2].v_uint16 << endl;
                        cout << "paddingtest10 returned " << reply->GetArg(0)->v_struct.members[3].v_uint32 << endl;
                    } else {
                        QCC_LogError(status, ("MethodCall on %s.%s failed", g_PaddingInterfaceName, "paddingtest10"));
                    }
                }
            }
        }
        /* Delete proxy bus object first. */
        delete remoteObj;
    }

    cout << "datatype_client exiting with status " << status << " (" << QCC_StatusText(status) << ")" << endl;
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

    /* Clean up msg bus */
    if (g_msgBus != nullptr) {
        if (g_msgBus->IsConnected()) {
            g_msgBus->Disconnect();
        }
        if (g_msgBus->Stop() == ER_OK) {
            g_msgBus->Join();
        }
        delete g_msgBus;
    }
    if (g_busListener != nullptr) {
        delete g_busListener;
    }
    if (g_discoverEvent != nullptr) {
        delete g_discoverEvent;
    }

#ifdef ROUTER
    AllJoynRouterShutdown();
#endif
    AllJoynShutdown();

    return ret;
}