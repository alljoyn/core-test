/**
 * @file
 * Alljoyn client that marshals different data types.
 */

/******************************************************************************
 * Copyright (c) AllSeen Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for any
 *    purpose with or without fee is hereby granted, provided that the above
 *    copyright notice and this permission notice appear in all copies.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 *    WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 *    MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 *    ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 *    WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 *    ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 *    OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/
#include <qcc/platform.h>
#include <qcc/Debug.h>
#include <qcc/Thread.h>
#include <signal.h>
#include <stdio.h>
#include <assert.h>
#include <vector>
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
#include <alljoyn/Status.h>

#define QCC_MODULE "DATATYPECLIENT TEST PROGRAM"

using namespace std;
using namespace qcc;
using namespace ajn;

const char* g_WellKnownName = "org.datatypes.test";
const char* g_InterfaceName = "org.datatypes.test.interface";
const char* g_PaddingInterfaceName = "org.datatypes.test.padding.interface";
const char* g_ObjectPath = "/datatypes";
SessionPort g_SessionPort = 25;

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
static BusAttachment* g_msgBus = NULL;
static Event g_discoverEvent;

/** AllJoynListener receives discovery events from AllJoyn */
class MyBusListener : public BusListener, public SessionListener {
  public:

    MyBusListener() { sessionId = 0; }

    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix)
    {
        QStatus status = ER_OK;
        QCC_SyncPrintf("FoundAdvertisedName(name=%s, transport=0x%x, prefix=%s)\n", name, transport, namePrefix);

        /* We must enable concurrent callbacks since some of the calls below are blocking */
        g_msgBus->EnableConcurrentCallbacks();

        if (0 == ::strcmp(name, g_WellKnownName)) {
            SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, transport);

            status = g_msgBus->JoinSession(name, g_SessionPort, this, sessionId, opts);
            if (ER_OK != status) {
                QCC_LogError(status, ("JoinSession(%s) failed", name));
            }

            /* Release the main thread */
            if (ER_OK == status) {
                g_discoverEvent.SetEvent();
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
    printf("Usage: datatype_client [-h] [-d] [-n <well-known name>] \n\n");
    printf("Options:\n");
    printf("   -h                        = Print this help message\n");
    printf("   -n <well-known name>      = Well-known bus name advertised by bbservice\n");
    printf("   -d                        = discover remote bus with test service\n");
    printf("   -p                        = Run additional data padding test cases\n");
    printf("\n");
}

int TestAppMain(int argc, char** argv)
{
    QStatus status = ER_OK;
    bool discoverRemote = false;
    bool paddingTest = false;

    printf("AllJoyn Library version: %s\n", ajn::GetVersion());
    printf("AllJoyn Library build info: %s\n", ajn::GetBuildInfo());

    /* Install SIGINT handler */
    signal(SIGINT, SigIntHandler);

    /* Parse command line args */
    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp("-n", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
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
        } else {
            status = ER_FAIL;
            printf("Unknown option %s\n", argv[i]);
            usage();
            exit(1);
        }
    }

    /* Create message bus */
    g_msgBus = new BusAttachment("datatype_client", true);
    /* Register a bus listener in order to get discovery indications */
    if (ER_OK == status) {
        g_busListener = new MyBusListener();
        g_msgBus->RegisterBusListener(*g_busListener);
    }

    status = g_msgBus->Start();
    if (status != ER_OK) {
        QCC_LogError(status, ("BusAttachment::Start failed"));
    }

    /* Connect to the bus */
    if (ER_OK == status) {
        status = g_msgBus->Connect();
    }

    if (discoverRemote) {
        g_discoverEvent.ResetEvent();
        status = g_msgBus->FindAdvertisedName(g_WellKnownName);
        if (status != ER_OK) {
            QCC_LogError(status, ("FindAdvertisedName failed"));
        }
    }

    bool hasOwner = false;
    status = g_msgBus->NameHasOwner(g_WellKnownName, hasOwner);
    if ((ER_OK == status) && !hasOwner) {
        QCC_SyncPrintf("Waiting for name %s to appear on the bus\n", g_WellKnownName);
        status = Event::Wait(g_discoverEvent);
        if (ER_OK != status) {
            QCC_LogError(status, ("Event::Wait failed"));
        }
    }

    /* Create the remote object that will be called */
    ProxyBusObject*remoteObj = NULL;
    if (ER_OK == status) {
        remoteObj = new ProxyBusObject(*g_msgBus, g_WellKnownName, g_ObjectPath, g_busListener->GetSessionId());
        status = remoteObj->IntrospectRemoteObject();
        if (ER_OK != status) {
            QCC_LogError(status, ("Introspection of %s (path=%s) failed",
                                  g_WellKnownName,
                                  g_ObjectPath));
        }
    }

    Message reply(*g_msgBus);

    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
        MsgArg byte;
        byte.Set("y", 255);
        status = remoteObj->MethodCall(g_InterfaceName, "byte", &byte, 1, reply, 50000);
        if (ER_OK == status) {
            QCC_SyncPrintf("byte returned %u \n", reply->GetArg(0)->v_byte);
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "byte"));
        }
    }

    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
        MsgArg integer;
        integer.Set("i", -65540);
        status = remoteObj->MethodCall(g_InterfaceName, "int", &integer, 1, reply, 50000);
        if (ER_OK == status) {
            QCC_SyncPrintf("int returned %d \n", reply->GetArg(0)->v_int32);
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "int"));
        }
    }

    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
        MsgArg unsignedInteger;
        unsignedInteger.Set("u", 65540);
        status = remoteObj->MethodCall(g_InterfaceName, "unsignedint", &unsignedInteger, 1, reply, 50000);
        if (ER_OK == status) {
            QCC_SyncPrintf("unsignedint returned %u \n", reply->GetArg(0)->v_uint32);
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "unsignedint"));
        }
    }

    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
        MsgArg doubleType;
        doubleType.Set("d", 3.1423);
        status = remoteObj->MethodCall(g_InterfaceName, "double", &doubleType, 1, reply, 50000);
        if (ER_OK == status) {
            QCC_SyncPrintf("double returned %lf \n", reply->GetArg(0)->v_double);
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "double"));
        }
    }

    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
        MsgArg boolType;
        bool temp = true;
        boolType.Set("b", temp);
        status = remoteObj->MethodCall(g_InterfaceName, "bool", &boolType, 1, reply, 50000);
        if (ER_OK == status) {
            QCC_SyncPrintf("bool returned %s \n", (reply->GetArg(0)->v_bool) ? "true" : "false");
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "bool"));
        }
    }

    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
        MsgArg stringType;
        stringType.Set("s", "Hello");
        status = remoteObj->MethodCall(g_InterfaceName, "string", &stringType, 1, reply, 50000);
        if (ER_OK == status) {
            QCC_SyncPrintf("string returned %s \n", reply->GetArg(0)->v_string.str);
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "string"));
        }
    }

    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
        MsgArg uint16Type;
        uint16Type.Set("q", 65535);
        status = remoteObj->MethodCall(g_InterfaceName, "uint16", &uint16Type, 1, reply, 50000);
        if (ER_OK == status) {
            QCC_SyncPrintf("uint16 returned %u \n", reply->GetArg(0)->v_uint16);
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "uint16"));
        }
    }


    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
        MsgArg int16Type;
        int16Type.Set("n", -32768);
        status = remoteObj->MethodCall(g_InterfaceName, "int16", &int16Type, 1, reply, 50000);
        if (ER_OK == status) {
            QCC_SyncPrintf("int16 returned %d \n", reply->GetArg(0)->v_int16);
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "int16"));
        }
    }

    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
        MsgArg int64Type;
#if _WIN32
        int64Type.Set("x", -9223372036854775808i64);
#else
        int64Type.Set("x", -9223372036854775808LLU);
#endif
        status = remoteObj->MethodCall(g_InterfaceName, "int64", &int64Type, 1, reply, 50000);
        if (ER_OK == status) {
            QCC_SyncPrintf("int64 returned %lld \n", reply->GetArg(0)->v_int64);
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "int64"));
        }
    }

    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
        MsgArg uint64Type;
#if _WIN32
        uint64Type.Set("t", 7223372036854775808ui64);
#else
        uint64Type.Set("t", 7223372036854775808LLU);
#endif
        status = remoteObj->MethodCall(g_InterfaceName, "uint64", &uint64Type, 1, reply, 50000);
        if (ER_OK == status) {
            QCC_SyncPrintf("uint64 returned %llu \n", reply->GetArg(0)->v_uint64);
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "uint64"));
        }
    }

    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
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
            QCC_SyncPrintf("struct members %d \n", reply->GetArg(0)->v_struct.numMembers);
            QCC_SyncPrintf("struct returned %u \n", reply->GetArg(0)->v_struct.members[0].v_byte);
            QCC_SyncPrintf("struct returned %d \n", reply->GetArg(0)->v_struct.members[1].v_int32);
            QCC_SyncPrintf("struct returned %u \n", reply->GetArg(0)->v_struct.members[2].v_uint32);
            QCC_SyncPrintf("struct returned %lf \n", reply->GetArg(0)->v_struct.members[3].v_double);
            QCC_SyncPrintf("struct returned %s \n", reply->GetArg(0)->v_struct.members[4].v_bool ? "true" : "false");
            QCC_SyncPrintf("struct returned %s \n", reply->GetArg(0)->v_struct.members[5].v_string.str);
            QCC_SyncPrintf("struct returned %u \n", reply->GetArg(0)->v_struct.members[6].v_uint16);
            QCC_SyncPrintf("struct returned %i \n", reply->GetArg(0)->v_struct.members[7].v_int16);
            QCC_SyncPrintf("struct returned %lld \n", reply->GetArg(0)->v_struct.members[8].v_int64);
            QCC_SyncPrintf("struct returned %llu \n", reply->GetArg(0)->v_struct.members[9].v_uint64);
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "struct"));
        }
    }
    /* Array of struct. */
    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
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
            QCC_SyncPrintf("Array of struct members %d \n", reply_outerSize);
            for (size_t i = 0; i < reply_outerSize; ++i) {
                QCC_SyncPrintf("element[%d] members %d \n", i, reply_outer[i].v_struct.numMembers);
                QCC_SyncPrintf("element[%d].num %u\n", i, reply_outer[i].v_struct.members[0].v_uint32);
                QCC_SyncPrintf("element[%d].ord %s \n", i, reply_outer[i].v_struct.members[1].v_string.str);
            }

        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "arrayofstruct"));
        }
    }


    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");

        int numEntries = 1;
        MsgArg* entries = new MsgArg[numEntries];
        MsgArg dict(ALLJOYN_ARRAY);
        entries[0].typeId = ALLJOYN_DICT_ENTRY;
        entries[0].v_dictEntry.key = new MsgArg("u", 1);
        entries[0].v_dictEntry.val = new MsgArg("v", new MsgArg("u", 1234));
        status = dict.v_array.SetElements("{uv}", numEntries, entries);
        status = remoteObj->MethodCall(g_InterfaceName, "dictionary", &dict, 1, reply, 50000);
        if (ER_OK == status) {
            QCC_SyncPrintf("Dictionary returned elements  \n");
            const MsgArg* reply_arg = reply->GetArg(0);
            MsgArg* reply_entries;
            MsgArg* reply_val;
            size_t reply_num;
            uint32_t reply_key;
            uint32_t reply_value;
            status = reply_arg->Get("a{uv}", &reply_num, &reply_entries);
            status = reply_entries[0].Get("{uv}", &reply_key, &reply_val);
            status = reply_val->Get("u", &reply_value);
            QCC_SyncPrintf("Dictionary returened key  % d \n", reply_key);
            QCC_SyncPrintf("Dictionary returened value  % d \n", reply_value);
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "dictionary"));
        }
    }

    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
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
            QCC_SyncPrintf("nestedstruct members %d \n", reply->GetArg(0)->v_struct.numMembers);
            QCC_SyncPrintf("nestedstruct returned %u \n", byte_reply);
            QCC_SyncPrintf("nestedstruct returned %u \n", int32_reply);
            QCC_SyncPrintf("nestedstruct returned %u \n", uint32_reply);
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "nestedstruct"));
        }
    }


    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
        uint8_t byteArray[] = { 255, 254, 253, 252, 251 };
        MsgArg arg;
        status = arg.Set("ay", sizeof(byteArray), byteArray);
        status = remoteObj->MethodCall(g_InterfaceName, "bytearray", &arg, 1, reply, 50000);
        if (ER_OK == status) {
            QCC_SyncPrintf("bytearray returned elements %d \n", (unsigned int)reply->GetArg(0)->v_scalarArray.numElements);
            for (size_t i = 0; i < reply->GetArg(0)->v_scalarArray.numElements; i++) {
                QCC_SyncPrintf("bytearray returned %u\n", reply->GetArg(0)->v_scalarArray.v_byte[i]);
            }
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "bytearray"));
        }
    }

    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
        int32_t intArray[] = { -65540, -65541, -65542, -65543, -65544 };
        MsgArg arg;
        status = arg.Set("ai", sizeof(intArray) / sizeof(int32_t), intArray);
        status = remoteObj->MethodCall(g_InterfaceName, "intarray", &arg, 1, reply, 50000);
        if (ER_OK == status) {
            QCC_SyncPrintf("intarray returned elements %d \n", (unsigned int)reply->GetArg(0)->v_scalarArray.numElements);
            for (size_t i = 0; i < reply->GetArg(0)->v_scalarArray.numElements; i++) {
                QCC_SyncPrintf("intarray returned %d\n", reply->GetArg(0)->v_scalarArray.v_int32[i]);
            }
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "intarray"));
        }
    }

    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
        uint32_t unsignedintArray[] = { 65540, 65541, 65542, 65543, 65544 };
        MsgArg arg;
        status = arg.Set("au", sizeof(unsignedintArray) / sizeof(uint32_t), unsignedintArray);
        status = remoteObj->MethodCall(g_InterfaceName, "unsignedintarray", &arg, 1, reply, 50000);
        if (ER_OK == status) {
            QCC_SyncPrintf("unsignedintarray returned elements %d \n", (unsigned int)reply->GetArg(0)->v_scalarArray.numElements);
            for (size_t i = 0; i < reply->GetArg(0)->v_scalarArray.numElements; i++) {
                QCC_SyncPrintf("unsignedintarray returned %u\n", reply->GetArg(0)->v_scalarArray.v_uint32[i]);
            }
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "unsignedintarray"));
        }
    }

    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
        double doubleArray[10];
        for (int i = 0; i < 10; i++) {
            doubleArray[i] = i;
        }
        MsgArg arg;
        status = arg.Set("ad", sizeof(doubleArray) / sizeof(double), doubleArray);
        status = remoteObj->MethodCall(g_InterfaceName, "doublearray", &arg, 1, reply, 100000);
        if (ER_OK == status) {
            QCC_SyncPrintf("doublearray returned elements %d \n", (unsigned int)reply->GetArg(0)->v_scalarArray.numElements);
            for (size_t i = 0; i < reply->GetArg(0)->v_scalarArray.numElements; i++) {
                QCC_SyncPrintf("doublearray returned %lf\n", reply->GetArg(0)->v_scalarArray.v_double[i]);
            }
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "doublearray"));
        }
    }

    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
        bool boolArray[] = { true, true, false, false, true, true };
        MsgArg arg;
        status = arg.Set("ab", sizeof(boolArray) / sizeof(bool), boolArray);
        status = remoteObj->MethodCall(g_InterfaceName, "boolarray", &arg, 1, reply, 50000);
        if (ER_OK == status) {
            QCC_SyncPrintf("boolarray returned elements %d \n", (unsigned int)reply->GetArg(0)->v_scalarArray.numElements);
            for (size_t i = 0; i < reply->GetArg(0)->v_scalarArray.numElements; i++) {
                QCC_SyncPrintf("doublearray returned %s\n", reply->GetArg(0)->v_scalarArray.v_bool[i] ? "true" : "false");
            }
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "boolarray"));
        }
    }

    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
        uint16_t uint16Array[] = { 65535, 65534 };
        MsgArg arg;
        status = arg.Set("aq", sizeof(uint16Array) / sizeof(uint16_t), uint16Array);
        status = remoteObj->MethodCall(g_InterfaceName, "uint16array", &arg, 1, reply, 50000);
        if (ER_OK == status) {
            QCC_SyncPrintf("uint16array returned elements %d \n", (unsigned int)reply->GetArg(0)->v_scalarArray.numElements);
            for (size_t i = 0; i < reply->GetArg(0)->v_scalarArray.numElements; i++) {
                QCC_SyncPrintf("uint16array returned %u\n", reply->GetArg(0)->v_scalarArray.v_uint16[i]);
            }
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "uint16array"));
        }
    }

    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
        int16_t int16Array[] = { -32768, -32767, -32766, -32765 };
        MsgArg arg;
        status = arg.Set("an", sizeof(int16Array) / sizeof(int16_t), int16Array);
        status = remoteObj->MethodCall(g_InterfaceName, "int16array", &arg, 1, reply, 50000);
        if (ER_OK == status) {
            QCC_SyncPrintf("int16array returned elements %d \n", (unsigned int)reply->GetArg(0)->v_scalarArray.numElements);
            for (size_t i = 0; i < reply->GetArg(0)->v_scalarArray.numElements; i++) {
                QCC_SyncPrintf("int16array returned %d\n", reply->GetArg(0)->v_scalarArray.v_int16[i]);
            }
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "int16array"));
        }
    }


    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
#if _WIN32
        int64_t int64Array[] = { -5223372036854775808i64, -5223372036854775807i64, -5223372036854775806i64 };
#else
        int64_t int64Array[] = { -5223372036854775808LL, -5223372036854775807LL, -5223372036854775806LL };
#endif
        MsgArg arg;
        status = arg.Set("ax", sizeof(int64Array) / sizeof(int64_t), int64Array);
        status = remoteObj->MethodCall(g_InterfaceName, "int64array", &arg, 1, reply, 50000);
        if (ER_OK == status) {
            QCC_SyncPrintf("int64array returned elements %d \n", (unsigned int)reply->GetArg(0)->v_scalarArray.numElements);
            for (size_t i = 0; i < reply->GetArg(0)->v_scalarArray.numElements; i++) {
                QCC_SyncPrintf("int64array returned %lld\n", reply->GetArg(0)->v_scalarArray.v_int64[i]);
            }
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "int64array"));
        }
    }


    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
        uint64_t uint64Array[] = { 6223372036854775808, 6223372036854775807 };
        MsgArg arg;
        status = arg.Set("at", sizeof(uint64Array) / sizeof(uint64_t), uint64Array);
        status = remoteObj->MethodCall(g_InterfaceName, "uint64array", &arg, 1, reply, 50000);
        if (ER_OK == status) {
            QCC_SyncPrintf("uint64array returned elements %d \n", (unsigned int)reply->GetArg(0)->v_scalarArray.numElements);
            for (size_t i = 0; i < reply->GetArg(0)->v_scalarArray.numElements; i++) {
                QCC_SyncPrintf("uint64array returned %llu\n", reply->GetArg(0)->v_scalarArray.v_uint64[i]);
            }
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "uint64array"));
        }
    }

    {
        QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
        const char*string_data[3] = { "hello", "world", "dog" };
        MsgArg arg;
        status = arg.Set("as", ArraySize(string_data), string_data);
        status = remoteObj->MethodCall(g_InterfaceName, "stringarray", &arg, 1, reply, 50000);
        if (ER_OK == status) {
            const MsgArg* reply_arg = reply->GetArg(0);
            MsgArg* array_of_strings;
            size_t no_of_strings;
            status = reply_arg->Get("as", &no_of_strings, &array_of_strings);
            QCC_SyncPrintf("stringarray returned elements %d \n", no_of_strings);
            for (size_t i = 0; i < no_of_strings; i++) {
                char*value;
                array_of_strings[i].Get("s", &value);
                QCC_SyncPrintf("string returned %s \n", value);
            }
        } else {
            QCC_LogError(status, ("MethodCall on %s.%s failed", g_InterfaceName, "stringarray"));
        }
    }

    if (paddingTest) {

        /* Padding test1 yqut */
        {
            QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");

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
                QCC_SyncPrintf("paddingtest1 returned %u \n", reply->GetArg(0)->v_struct.members[0].v_byte);
                QCC_SyncPrintf("paddingtest1 returned %u \n", reply->GetArg(0)->v_struct.members[1].v_uint16);
                QCC_SyncPrintf("paddingtest1 returned %u \n", reply->GetArg(0)->v_struct.members[2].v_uint32);
                QCC_SyncPrintf("paddingtest1 returned %llu \n", reply->GetArg(0)->v_struct.members[3].v_uint64);
            } else {
                QCC_LogError(status, ("MethodCall on %s.%s failed", g_PaddingInterfaceName, "paddingtest1"));
            }
        }

        /* Padding test2 yqtu */
        {
            QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
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
                QCC_SyncPrintf("paddingtest2 returned %u \n", reply->GetArg(0)->v_struct.members[0].v_byte);
                QCC_SyncPrintf("paddingtest2 returned %u \n", reply->GetArg(0)->v_struct.members[1].v_uint16);
                QCC_SyncPrintf("paddingtest2 returned %llu \n", reply->GetArg(0)->v_struct.members[2].v_uint64);
                QCC_SyncPrintf("paddingtest2 returned %u \n", reply->GetArg(0)->v_struct.members[3].v_uint32);
            } else {
                QCC_LogError(status, ("MethodCall on %s.%s failed", g_PaddingInterfaceName, "paddingtest2"));
            }
        }

        /* Padding test3 yuqt */
        {
            QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
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
                QCC_SyncPrintf("paddingtest3 returned %u \n", reply->GetArg(0)->v_struct.members[0].v_byte);
                QCC_SyncPrintf("paddingtest3returned %u \n", reply->GetArg(0)->v_struct.members[1].v_uint32);
                QCC_SyncPrintf("paddingtest3 returned %u \n", reply->GetArg(0)->v_struct.members[2].v_uint16);
                QCC_SyncPrintf("paddingtest3 returned %llu \n", reply->GetArg(0)->v_struct.members[3].v_uint64);
            } else {
                QCC_LogError(status, ("MethodCall on %s.%s failed", g_PaddingInterfaceName, "paddingtest3"));
            }
        }

        /* Padding test4 yutq */
        {
            QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
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
                QCC_SyncPrintf("paddingtest4 returned %u \n", reply->GetArg(0)->v_struct.members[0].v_byte);
                QCC_SyncPrintf("paddingtest4 returned %u \n", reply->GetArg(0)->v_struct.members[1].v_uint32);
                QCC_SyncPrintf("paddingtest4 returned %llu \n", reply->GetArg(0)->v_struct.members[2].v_uint64);
                QCC_SyncPrintf("paddingtest4 returned %u \n", reply->GetArg(0)->v_struct.members[3].v_uint16);

            } else {
                QCC_LogError(status, ("MethodCall on %s.%s failed", g_PaddingInterfaceName, "paddingtest4"));
            }
        }

        /* Padding test5 ytqu */
        {
            QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
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
                QCC_SyncPrintf("paddingtest5 returned %u \n", reply->GetArg(0)->v_struct.members[0].v_byte);
                QCC_SyncPrintf("paddingtest5 returned %llu \n", reply->GetArg(0)->v_struct.members[1].v_uint64);
                QCC_SyncPrintf("paddingtest5 returned %u \n", reply->GetArg(0)->v_struct.members[2].v_uint16);
                QCC_SyncPrintf("paddingtest5 returned %u \n", reply->GetArg(0)->v_struct.members[3].v_uint32);

            } else {
                QCC_LogError(status, ("MethodCall on %s.%s failed", g_PaddingInterfaceName, "paddingtest5"));
            }
        }

        /* Padding test6 ytuq */
        {
            QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
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
                QCC_SyncPrintf("paddingtest6 returned %u \n", reply->GetArg(0)->v_struct.members[0].v_byte);
                QCC_SyncPrintf("paddingtest6 returned %llu \n", reply->GetArg(0)->v_struct.members[1].v_uint64);
                QCC_SyncPrintf("paddingtest6 returned %u \n", reply->GetArg(0)->v_struct.members[2].v_uint32);
                QCC_SyncPrintf("paddingtest6 returned %u \n", reply->GetArg(0)->v_struct.members[3].v_uint16);

            } else {
                QCC_LogError(status, ("MethodCall on %s.%s failed", g_PaddingInterfaceName, "paddingtest6"));
            }
        }

        /* Padding test7 qyut */
        {
            QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
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
                QCC_SyncPrintf("paddingtest7 returned %u \n", reply->GetArg(0)->v_struct.members[0].v_uint16);
                QCC_SyncPrintf("paddingtest7 returned %u \n", reply->GetArg(0)->v_struct.members[1].v_byte);
                QCC_SyncPrintf("paddingtest7 returned %u \n", reply->GetArg(0)->v_struct.members[2].v_uint32);
                QCC_SyncPrintf("paddingtest7 returned %llu \n", reply->GetArg(0)->v_struct.members[3].v_uint64);
            } else {
                QCC_LogError(status, ("MethodCall on %s.%s failed", g_PaddingInterfaceName, "paddingtest7"));
            }
        }


        /* Padding test8 qytu */
        {
            QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
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
                QCC_SyncPrintf("paddingtest8 returned %u \n", reply->GetArg(0)->v_struct.members[0].v_uint16);
                QCC_SyncPrintf("paddingtest8 returned %u \n", reply->GetArg(0)->v_struct.members[1].v_byte);
                QCC_SyncPrintf("paddingtest8 returned %llu \n", reply->GetArg(0)->v_struct.members[2].v_uint64);
                QCC_SyncPrintf("paddingtest8 returned %u \n", reply->GetArg(0)->v_struct.members[3].v_uint32);

            } else {
                QCC_LogError(status, ("MethodCall on %s.%s failed", g_PaddingInterfaceName, "paddingtest8"));
            }
        }

        /* Padding test9 uyqt */
        {
            QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
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
                QCC_SyncPrintf("paddingtest9 returned %u \n", reply->GetArg(0)->v_struct.members[0].v_uint32);
                QCC_SyncPrintf("paddingtest9 returned %u \n", reply->GetArg(0)->v_struct.members[1].v_byte);
                QCC_SyncPrintf("paddingtest9 returned %u \n", reply->GetArg(0)->v_struct.members[2].v_uint16);
                QCC_SyncPrintf("paddingtest9 returned %llu \n", reply->GetArg(0)->v_struct.members[3].v_uint64);
            } else {
                QCC_LogError(status, ("MethodCall on %s.%s failed", g_PaddingInterfaceName, "paddingtest9"));
            }
        }

        /* Padding test10 tyqu */
        {
            QCC_SyncPrintf(" ------------------------------------------------------------------------------------------------ \n");
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
                QCC_SyncPrintf("paddingtest10 returned %llu \n", reply->GetArg(0)->v_struct.members[0].v_uint64);
                QCC_SyncPrintf("paddingtest10 returned %u \n", reply->GetArg(0)->v_struct.members[1].v_byte);
                QCC_SyncPrintf("paddingtest10 returned %u \n", reply->GetArg(0)->v_struct.members[2].v_uint16);
                QCC_SyncPrintf("paddingtest10 returned %u \n", reply->GetArg(0)->v_struct.members[3].v_uint32);
            } else {
                QCC_LogError(status, ("MethodCall on %s.%s failed", g_PaddingInterfaceName, "paddingtest10"));
            }
        }
    }
    /* Delete proxy bus object first. */
    delete remoteObj;
/* Deallocate bus */
    delete g_msgBus;
    delete g_busListener;
    g_busListener = NULL;
    printf("datatype_lient exiting with status %d (%s)\n", status, QCC_StatusText(status));
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
