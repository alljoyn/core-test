/**
 * @file
 * AllJoyn service that marshals different data types.
 */

/******************************************************************************
 * Copyright AllSeen Alliance. All rights reserved.
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

#include <assert.h>
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
#include <alljoyn/BusAttachment.h>
#include <alljoyn/BusObject.h>
#include <alljoyn/DBusStd.h>
#include <alljoyn/AllJoynStd.h>
#include <alljoyn/MsgArg.h>
#include <alljoyn/version.h>
#include <alljoyn/Status.h>

#define QCC_MODULE "ALLJOYN"

using namespace std;
using namespace qcc;
using namespace ajn;


const char* g_WellKnownName = "org.datatypes.test";
const char* g_InterfaceName = "org.datatypes.test.interface";
const char* g_PaddingInterfaceName = "org.datatypes.test.padding.interface";
const char* g_ObjectPath = "/datatypes";
SessionPort g_SessionPort = 25;

/* Forward declaration */
class MySessionPortListener;

/* Static top level globals */
static BusAttachment* g_msgBus = NULL;
static MySessionPortListener*g_SessionPortListener = NULL;

static volatile sig_atomic_t g_interrupt = false;

static void SigIntHandler(int sig)
{
    g_interrupt = true;
}

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
}Padding;


typedef struct {
    uint32_t num;
    char* ord;
}StructTest;

class MySessionPortListener : public SessionPortListener {

  public:
    MySessionPortListener() { }

    bool AcceptSessionJoiner(SessionPort sessionPort, const char* joiner, const SessionOpts& opts)
    {
        return true;
    }

};

class LocalTestObject : public BusObject {

  public:

    LocalTestObject(BusAttachment& bus, const char* path) : BusObject(path)
    {
        QStatus status = ER_OK;

        /* Add the test interface to this object */
        const InterfaceDescription* regTestIntf = bus.GetInterface(g_InterfaceName);
        assert(regTestIntf);
        AddInterface(*regTestIntf);


        /* Register the method handlers with the object */
        const MethodEntry methodEntries[] = {
            { regTestIntf->GetMember("byte"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Byte) },
            { regTestIntf->GetMember("int"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Int) },
            { regTestIntf->GetMember("unsignedint"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::UnsignedInt) },
            { regTestIntf->GetMember("double"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Double) },
            { regTestIntf->GetMember("bool"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Bool) },
            { regTestIntf->GetMember("string"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::String) },
            { regTestIntf->GetMember("uint16"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::UInt16) },
            { regTestIntf->GetMember("int16"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Int16) },
            { regTestIntf->GetMember("int64"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Int64) },
            { regTestIntf->GetMember("uint64"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::UInt64) },
            { regTestIntf->GetMember("struct"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Struct) },
            { regTestIntf->GetMember("bytearray"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::ByteArray) },
            { regTestIntf->GetMember("intarray"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::IntArray) },
            { regTestIntf->GetMember("unsignedintarray"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::UnsignedIntArray) },
            { regTestIntf->GetMember("doublearray"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::DoubleArray) },
            { regTestIntf->GetMember("boolarray"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::BoolArray) },
            { regTestIntf->GetMember("stringarray"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::StringArray) },
            { regTestIntf->GetMember("uint16array"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::UInt16Array) },
            { regTestIntf->GetMember("int16array"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Int16Array) },
            { regTestIntf->GetMember("int64array"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Int64Array) },
            { regTestIntf->GetMember("uint64array"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::UInt64Array) },
            { regTestIntf->GetMember("arrayofstruct"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::ArrayofStruct) },
            { regTestIntf->GetMember("dictionary"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Dictionary) },
            { regTestIntf->GetMember("nestedstruct"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::NestedStruct) }
        };

        status = AddMethodHandlers(methodEntries, ArraySize(methodEntries));
        if (ER_OK != status) {
            QCC_LogError(status, ("Failed to register method handlers for LocalTestObject"));
        }

        /* Add the padding test interface to this object */
        const InterfaceDescription* regPaddingTestIntf = bus.GetInterface(g_PaddingInterfaceName);
        assert(regPaddingTestIntf);
        AddInterface(*regPaddingTestIntf);
        /* Register the method handlers with the object */
        const MethodEntry paddingmethodEntries[] = {
            { regPaddingTestIntf->GetMember("paddingtest1"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Paddingtest1) },
            { regPaddingTestIntf->GetMember("paddingtest2"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Paddingtest2) },
            { regPaddingTestIntf->GetMember("paddingtest3"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Paddingtest3) },
            { regPaddingTestIntf->GetMember("paddingtest4"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Paddingtest4) },
            { regPaddingTestIntf->GetMember("paddingtest5"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Paddingtest5) },
            { regPaddingTestIntf->GetMember("paddingtest6"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Paddingtest6) },
            { regPaddingTestIntf->GetMember("paddingtest7"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Paddingtest7) },
            { regPaddingTestIntf->GetMember("paddingtest8"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Paddingtest8) },
            { regPaddingTestIntf->GetMember("paddingtest9"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Paddingtest9) },
            { regPaddingTestIntf->GetMember("paddingtest10"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::Paddingtest10) },
        };

        status = AddMethodHandlers(paddingmethodEntries, ArraySize(paddingmethodEntries));
        if (ER_OK != status) {
            QCC_LogError(status, ("Failed to register padding method handlers for LocalTestObject"));
        }
    }

    void Byte(const InterfaceDescription::Member* member, Message& msg)
    {
        uint8_t value = 0;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("y", &value);
        printf("Pinged with: %u\n", value);
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Byte: Error sending reply"));
        }
    }

    void Int(const InterfaceDescription::Member* member, Message& msg)
    {
        int value = 0;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("i", &value);
        printf("Pinged with: %d\n", value);
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Int: Error sending reply"));
        }
    }

    void UnsignedInt(const InterfaceDescription::Member* member, Message& msg)
    {
        uint32_t value = 0;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("u", &value);
        printf("Pinged with: %u\n", value);
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("UnsignedInt: Error sending reply"));
        }
    }

    void Double(const InterfaceDescription::Member* member, Message& msg)
    {
        double value = 0;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("d", &value);
        printf("Pinged with: %lf\n", value);
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Double: Error sending reply"));
        }
    }

    void Bool(const InterfaceDescription::Member* member, Message& msg)
    {
        bool value = false;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("b", &value);
        printf("Pinged with: %s \n", (value ? "true" : "false"));
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Bool: Error sending reply"));
        }
    }

    void String(const InterfaceDescription::Member* member, Message& msg)
    {
        char*value;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("s", &value);
        printf("Pinged with: %s\n", value);
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("String: Error sending reply"));
        }
    }

    void UInt16(const InterfaceDescription::Member* member, Message& msg)
    {
        uint16_t value = 0;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("q", &value);
        printf("Pinged with: %u\n", value);
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("UInt16: Error sending reply"));
        }
    }

    void Int16(const InterfaceDescription::Member* member, Message& msg)
    {
        int16_t value = 0;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("n", &value);
        printf("Pinged with: %d\n", value);
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Int16: Error sending reply"));
        }
    }

    void Int64(const InterfaceDescription::Member* member, Message& msg)
    {
        int64_t value = 0;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("x", &value);
        printf("Pinged with: %lld\n", value);
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Int64: Error sending reply"));
        }
    }

    void UInt64(const InterfaceDescription::Member* member, Message& msg)
    {
        const MsgArg* arg((msg->GetArg(0)));
        /* Reply with same string that was sent to us */
        printf("Pinged with: %llu\n", arg->v_uint64);
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("UInt64: Error sending reply"));
        }
    }

    void Struct(const InterfaceDescription::Member* member, Message& msg)
    {
        Structure structData;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(yiudbsqnxt)", &structData.byte, &structData.int32, &structData.uint32, &structData.doubleValue, &structData.boolValue, &structData.stringValue, &structData.uint16, &structData.int16, &structData.int64, &structData.uint64);
        printf("Pinged with Structure:  \n");
        printf("	Pinged with Structure.byte: %u\n", structData.byte);
        printf("	Pinged with Structure.int32: %d\n", structData.int32);
        printf("	Pinged with Structure.uint32: %u\n", structData.uint32);
        printf("	Pinged with Structure.double: %lf\n", structData.doubleValue);
        printf("	Pinged with Structure.bool: %s\n", structData.boolValue ? "true" : "false");
        printf("	Pinged with Structure.string: %s \n", structData.stringValue);
        printf("	Pinged with Structure.uint16: %u\n", structData.uint16);
        printf("	Pinged with Structure.int16: %d\n", structData.int16);
        printf("	Pinged with Structure.int64: %lld\n", structData.int64);
        printf("	Pinged with Structure.uint64: %llu\n", structData.uint64);
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Struct: Error sending reply"));
        }
    }

    /* Padding test1 - yqut  */
    void Paddingtest1(const InterfaceDescription::Member* member, Message& msg)
    {
        Padding paddingData;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(yqut)", &paddingData.byte, &paddingData.uint16, &paddingData.uint32, &paddingData.uint64);
        printf("Pinged with yqut:  \n");
        printf("        Pinged with yqut.byte: %u\n", paddingData.byte);
        printf("        Pinged with yqut.uint16: %u\n", paddingData.uint16);
        printf("        Pinged with yqut.uint32: %u\n", paddingData.uint32);
        printf("        Pinged with yqut.uint64: %llu\n", paddingData.uint64);
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Paddingtest1: Error sending reply"));
        }
    }

    /* Padding test2 - yqtu */
    void Paddingtest2(const InterfaceDescription::Member* member, Message& msg)
    {
        Padding paddingData;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(yqtu)", &paddingData.byte, &paddingData.uint16, &paddingData.uint64, &paddingData.uint32);
        printf("Pinged with yqtu:  \n");
        printf("        Pinged with yqtu.byte: %u\n", paddingData.byte);
        printf("        Pinged with yqtu.uint16: %u\n", paddingData.uint16);
        printf("        Pinged with yqtu.uint64: %llu\n", paddingData.uint64);
        printf("        Pinged with yqtu.uint32: %u\n", paddingData.uint32);
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Paddingtest2: Error sending reply"));
        }
    }

    /* Padding test3 - yuqt */
    void Paddingtest3(const InterfaceDescription::Member* member, Message& msg)
    {
        Padding paddingData;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(yuqt)", &paddingData.byte, &paddingData.uint32, &paddingData.uint16, &paddingData.uint64);
        printf("Pinged with yuqt:  \n");
        printf("        Pinged with yuqt.byte: %u\n", paddingData.byte);
        printf("        Pinged with yuqt.uint32: %u\n", paddingData.uint32);
        printf("        Pinged with yuqt.uint16: %u\n", paddingData.uint16);
        printf("        Pinged with yuqt.uint64: %llu\n", paddingData.uint64);
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Paddingtest3: Error sending reply"));
        }
    }

    /* Padding test4 - yutq*/
    void Paddingtest4(const InterfaceDescription::Member* member, Message& msg)
    {
        Padding paddingData;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(yutq)", &paddingData.byte, &paddingData.uint32, &paddingData.uint64, &paddingData.uint16);
        printf("Pinged with yutq:  \n");
        printf("        Pinged with yutq.byte: %u\n", paddingData.byte);
        printf("        Pinged with yutq.uint32: %u\n", paddingData.uint32);
        printf("        Pinged with yutq.uint64: %llu\n", paddingData.uint64);
        printf("        Pinged with yutq.uint16: %u\n", paddingData.uint16);
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Paddingtest4: Error sending reply"));
        }
    }

    /* Padding test5 - ytqu*/
    void Paddingtest5(const InterfaceDescription::Member* member, Message& msg)
    {
        Padding paddingData;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(ytqu)", &paddingData.byte, &paddingData.uint64, &paddingData.uint16, &paddingData.uint32);
        printf("Pinged with yutq:  \n");
        printf("        Pinged with ytqu.byte: %u\n", paddingData.byte);
        printf("        Pinged with ytqu.uint64: %llu\n", paddingData.uint64);
        printf("        Pinged with ytqu.uint16: %u\n", paddingData.uint16);
        printf("        Pinged with ytqu.uint32: %u\n", paddingData.uint32);
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Paddingtest5: Error sending reply"));
        }
    }

    /* Padding test6 - ytuq */
    void Paddingtest6(const InterfaceDescription::Member* member, Message& msg)
    {
        Padding paddingData;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(ytuq)", &paddingData.byte, &paddingData.uint64, &paddingData.uint32, &paddingData.uint16);
        printf("Pinged with ytuq:  \n");
        printf("        Pinged with ytuq.byte: %u\n", paddingData.byte);
        printf("        Pinged with ytuq.uint64: %llu\n", paddingData.uint64);
        printf("        Pinged with ytuq.uint32: %u\n", paddingData.uint32);
        printf("        Pinged with ytuq.uint16: %u\n", paddingData.uint16);
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Paddingtest6: Error sending reply"));
        }
    }

    /* Padding test7 - ytuq */
    void Paddingtest7(const InterfaceDescription::Member* member, Message& msg)
    {
        Padding paddingData;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(qyut)", &paddingData.uint16, &paddingData.byte, &paddingData.uint32, &paddingData.uint64);
        printf("Pinged with qyut:  \n");
        printf("        Pinged with qyut.uint16: %u\n", paddingData.uint16);
        printf("        Pinged with qyut.byte: %u\n", paddingData.byte);
        printf("        Pinged with qyut.uint32: %u\n", paddingData.uint32);
        printf("        Pinged with qyut.uint64: %llu\n", paddingData.uint64);
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Paddingtest7: Error sending reply"));
        }
    }

    /* Padding test8 - qytu */
    void Paddingtest8(const InterfaceDescription::Member* member, Message& msg)
    {
        Padding paddingData;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(qytu)", &paddingData.uint16, &paddingData.byte, &paddingData.uint64, &paddingData.uint32);
        printf("Pinged with qytu:  \n");
        printf("        Pinged with qytu.uint16: %u\n", paddingData.uint16);
        printf("        Pinged with qytu.byte: %u\n", paddingData.byte);
        printf("        Pinged with qytu.uint64: %llu\n", paddingData.uint64);
        printf("        Pinged with qytu.uint32: %u\n", paddingData.uint32);
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Paddingtest8: Error sending reply"));
        }
    }

    /* Padding test9 - uyqt */
    void Paddingtest9(const InterfaceDescription::Member* member, Message& msg)
    {
        Padding paddingData;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(uyqt)", &paddingData.uint32, &paddingData.byte, &paddingData.uint16, &paddingData.uint64);
        printf("Pinged with uyqt:  \n");
        printf("        Pinged with uyqt.uint32: %u\n", paddingData.uint32);
        printf("        Pinged with uyqt.byte: %u\n", paddingData.byte);
        printf("        Pinged with uyqt.uint16: %u\n", paddingData.uint16);
        printf("        Pinged with uyqt.uint64: %llu\n", paddingData.uint64);
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Paddingtest9: Error sending reply"));
        }
    }

    /* Padding test10 - tyqu */
    void Paddingtest10(const InterfaceDescription::Member* member, Message& msg)
    {
        Padding paddingData;
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(tyqu)", &paddingData.uint64, &paddingData.byte, &paddingData.uint16, &paddingData.uint32);
        printf("Pinged with tyqu:  \n");
        printf("        Pinged with tyqu.uint64: %llu\n", paddingData.uint64);
        printf("        Pinged with tyqu.byte: %u\n", paddingData.byte);
        printf("        Pinged with tyqu.uint16: %u\n", paddingData.uint16);
        printf("        Pinged with tyqu.uint32: %u\n", paddingData.uint32);
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Paddingtest10: Error sending reply"));
        }
    }

    void ArrayofStruct(const InterfaceDescription::Member* member, Message& msg)
    {
        const MsgArg* arg((msg->GetArg(0)));
        /* Reply with same string that was sent to us */
        printf("Pinged with Array of Structures: \n");
        MsgArg* outer;
        size_t outerSize;
        QStatus status = arg->Get("a(is)", &outerSize, &outer);

        for (size_t i = 0; i < outerSize; ++i) {
            StructTest tmp;
            status = outer[i].Get("(is)", &tmp.num, &tmp.ord);
            printf("	element[%d].num %u \n", i, tmp.num);
            printf("	element[%d].ord %s \n", i, tmp.ord);
        }
        status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("ArrayofStruct: Error sending reply"));
        }
    }

    void Dictionary(const InterfaceDescription::Member* member, Message& msg)
    {
        const MsgArg* arg((msg->GetArg(0)));
        /* Reply with same string that was sent to us */
        MsgArg* entries;
        MsgArg* val;
        size_t num;
        uint32_t key;
        uint32_t value;
        QStatus status = arg->Get("a{uv}", &num, &entries);
        status = entries[0].Get("{uv}", &key, &val);
        status = val->Get("u", &value);
        printf("Pinged with Dictionary: \n");
        printf("      Pinged with key: %u\n", key);
        printf("      Pinged with Value: %u\n", value);
        status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Dictionary: Error sending reply"));
        }

    }

    void NestedStruct(const InterfaceDescription::Member* member, Message& msg)
    {
        uint8_t byte;
        int32_t int32;
        uint32_t uint32;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(y(iu))", &byte, &int32, &uint32);
        printf("Pinged with y(iu) :  \n");
        printf("        Pinged with y(iu)  y  %u\n", byte);
        printf("        Pinged with y(iu) i %d\n", int32);
        printf("        Pinged with y(iu) u %u\n", uint32);
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Struct: Error sending reply"));
        }
    }


    void ByteArray(const InterfaceDescription::Member* member, Message& msg)
    {
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        printf("Pinged with ByteArray: \n");
        for (int i = 0; i < (int)arg->v_scalarArray.numElements; i++) {
            printf("	Pinged with ByteArray: %u\n", arg->v_scalarArray.v_byte[i]);
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("ByteArray: Error sending reply"));
        }

    }

    void IntArray(const InterfaceDescription::Member* member, Message& msg)
    {
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        printf("Pinged with IntArray: \n");
        for (int i = 0; i < (int)arg->v_scalarArray.numElements; i++) {
            printf("      Pinged with IntArray: %d\n", arg->v_scalarArray.v_int32[i]);
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("IntArray: Error sending reply"));
        }

    }


    void UnsignedIntArray(const InterfaceDescription::Member* member, Message& msg)
    {
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        printf("Pinged with UnsignedIntArray: \n");
        for (int i = 0; i < (int)arg->v_scalarArray.numElements; i++) {
            printf("      Pinged with UInt32Array: %u\n", arg->v_scalarArray.v_uint32[i]);
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("UInt32Array: Error sending reply"));
        }

    }


    void DoubleArray(const InterfaceDescription::Member* member, Message& msg)
    {
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        printf("Pinged with DoubleArray: \n");
        for (int i = 0; i < (int)arg->v_scalarArray.numElements; i++) {
            printf("      Pinged with DoubleArray: %lf\n", arg->v_scalarArray.v_double[i]);
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("DoubleArray: Error sending reply"));
        }
    }


    void BoolArray(const InterfaceDescription::Member* member, Message& msg)
    {
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        printf("Pinged with BoolArray: \n");
        for (int i = 0; i < (int)arg->v_scalarArray.numElements; i++) {
            printf("      Pinged with BoolArray: %s\n", arg->v_scalarArray.v_bool[i] ? "true" : "false");
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("BoolArray: Error sending reply"));
        }

    }

    void StringArray(const InterfaceDescription::Member* member, Message& msg)
    {
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        printf("Pinged with StringArray: \n");
        MsgArg* outer;
        size_t outerSize;
        QStatus status = arg->Get("as", &outerSize, &outer);

        for (size_t i = 0; i < outerSize; ++i) {
            char*value;
            status = outer[i].Get("s", &value);
            printf("      Pinged with StringArray: %s \n", value);
        }
        status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("StringArray: Error sending reply"));
        }
    }


    void UInt16Array(const InterfaceDescription::Member* member, Message& msg)
    {
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        printf("Pinged with UInt16Array: \n");
        for (int i = 0; i < (int)arg->v_scalarArray.numElements; i++) {
            printf("      Pinged with UInt16Array: %u\n", arg->v_scalarArray.v_uint16[i]);
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("UInt16Array: Error sending reply"));
        }

    }


    void Int16Array(const InterfaceDescription::Member* member, Message& msg)
    {
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        printf("Pinged with Int16Array: \n");
        for (int i = 0; i < (int)arg->v_scalarArray.numElements; i++) {
            printf("      Pinged with Int16Array: %d\n", arg->v_scalarArray.v_int16[i]);
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Int16Array: Error sending reply"));
        }
    }


    void Int64Array(const InterfaceDescription::Member* member, Message& msg)
    {
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        printf("Pinged with Int64Array: \n");
        for (int i = 0; i < (int)arg->v_scalarArray.numElements; i++) {
            printf("      Pinged with Int64Array: %lld\n", arg->v_scalarArray.v_int64[i]);

        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Int64Array: Error sending reply"));
        }

    }

    void UInt64Array(const InterfaceDescription::Member* member, Message& msg)
    {
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        printf("Pinged with UInt64Array: \n");
        for (int i = 0; i < (int)arg->v_scalarArray.numElements; i++) {
            printf("      Pinged with UInt64Array: %llu\n", arg->v_scalarArray.v_uint64[i]);
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("UInt64Array: Error sending reply"));
        }
    }
};

static void usage(void)
{
    printf("Usage: datatype_service [-h] [-n <name>] \n\n");
    printf("Options:\n");
    printf("   -h                    = Print this help message\n");
    printf("   -n <well-known name>  = Well-known name to advertise\n");
    printf("   -p                    = Run additional data padding test cases\n");
}


/** Main entry point */
int main(int argc, char** argv)
{
    QStatus status = ER_OK;
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
        } else if (0 == strcmp("-n", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_WellKnownName = argv[i];
            }
        }  else {
            status = ER_FAIL;
            printf("Unknown option %s\n", argv[i]);
            usage();
            exit(1);
        }
    }

    /* Create message bus */
    g_msgBus = new BusAttachment("datatype_service", true);

    InterfaceDescription* testIntf = NULL;
    status = g_msgBus->CreateInterface(g_InterfaceName, testIntf);
    if (ER_OK == status) {
        testIntf->AddMethod("byte", "y", "y", "inStr,outStr", 0);
        testIntf->AddMethod("int", "i", "i", "inStr,outStr", 0);
        testIntf->AddMethod("unsignedint", "u", "u", "inStr,outStr", 0);
        testIntf->AddMethod("double", "d", "d", "inStr,outStr", 0);
        testIntf->AddMethod("bool", "b", "b", "inStr,outStr", 0);
        testIntf->AddMethod("string", "s", "s", "inStr,outStr", 0);
        testIntf->AddMethod("uint16", "q", "q", "inStr,outStr", 0);
        testIntf->AddMethod("int16", "n", "n", "inStr,outStr", 0);
        testIntf->AddMethod("int64", "x", "x", "inStr,outStr", 0);
        testIntf->AddMethod("uint64", "t", "t", "inStr,outStr", 0);
        testIntf->AddMethod("struct", "(yiudbsqnxt)", "(yiudbsqnxt)", "inStr,outStr", 0);
        testIntf->AddMethod("bytearray", "ay", "ay", "inStr,outStr", 0);
        testIntf->AddMethod("intarray", "ai", "ai", "inStr,outStr", 0);
        testIntf->AddMethod("unsignedintarray", "au", "au", "inStr,outStr", 0);
        testIntf->AddMethod("doublearray", "ad", "ad", "inStr,outStr", 0);
        testIntf->AddMethod("boolarray", "ab", "ab", "inStr,outStr", 0);
        testIntf->AddMethod("stringarray", "as", "as", "inStr,outStr", 0);
        testIntf->AddMethod("uint16array", "aq", "aq", "inStr,outStr", 0);
        testIntf->AddMethod("int16array", "an", "an", "inStr,outStr", 0);
        testIntf->AddMethod("int64array", "ax", "ax", "inStr,outStr", 0);
        testIntf->AddMethod("uint64array", "at", "at", "inStr,outStr", 0);
        testIntf->AddMethod("arrayofstruct", "a(is)", "a(is)", "inStr,outStr", 0);
        testIntf->AddMethod("dictionary", "a{uv}", "a{uv}", "inStr,outStr", 0);
        testIntf->AddMethod("nestedstruct", "(y(iu))", "(y(iu))", "inStr,outStr", 0);
        testIntf->Activate();
    } else {
        QCC_LogError(status, ("Failed to create interface %s", g_InterfaceName));
    }
    InterfaceDescription* paddingtestIntf = NULL;
    status = g_msgBus->CreateInterface(g_PaddingInterfaceName, paddingtestIntf);
    printf("Status of create interface ------------------------  %d \n", status);
    if (ER_OK == status) {
        paddingtestIntf->AddMethod("paddingtest1", "(yqut)", "(yqut)", "inStr,outStr", 0);
        paddingtestIntf->AddMethod("paddingtest2", "(yqtu)", "(yqtu)", "inStr,outStr", 0);
        paddingtestIntf->AddMethod("paddingtest3", "(yuqt)", "(yuqt)", "inStr,outStr", 0);
        paddingtestIntf->AddMethod("paddingtest4", "(yutq)", "(yutq)", "inStr,outStr", 0);
        paddingtestIntf->AddMethod("paddingtest5", "(ytqu)", "(ytqu)", "inStr,outStr", 0);
        paddingtestIntf->AddMethod("paddingtest6", "(ytuq)", "(ytuq)", "inStr,outStr", 0);
        paddingtestIntf->AddMethod("paddingtest7", "(qyut)", "(qyut)", "inStr,outStr", 0);
        paddingtestIntf->AddMethod("paddingtest8", "(qytu)", "(qytu)", "inStr,outStr", 0);
        paddingtestIntf->AddMethod("paddingtest9", "(uyqt)", "(uyqt)", "inStr,outStr", 0);
        paddingtestIntf->AddMethod("paddingtest10", "(tyqu)", "(tyqu)", "inStr,outStr", 0);
        paddingtestIntf->Activate();
    } else {
        QCC_LogError(status, ("Failed to create interface %s", g_PaddingInterfaceName));
    }

    /* Start the msg bus */
    if (ER_OK == status) {
        status = g_msgBus->Start();
    } else {
        QCC_LogError(status, ("BusAttachment::Start failed"));
        exit(1);
    }

    /* Create a bus listener to be used to accept incoming session requests */
    g_SessionPortListener = new MySessionPortListener();

    /* Register local objects and connect to the daemon */
    LocalTestObject testObj(*g_msgBus, g_ObjectPath);
    g_msgBus->RegisterBusObject(testObj);



    status = g_msgBus->Connect();
    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to connect to bus"));
    }

    status = g_msgBus->BindSessionPort(g_SessionPort, opts, *g_SessionPortListener);
    if (status != ER_OK) {
        QCC_LogError(status, ("BindSessionPort failed"));
    }

    /* Request a well-known name */
    status = g_msgBus->RequestName(g_WellKnownName, DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE);
    if (status != ER_OK) {
        QCC_LogError(status, ("RequestName(%s) failed.", g_WellKnownName));
    }

    /* Begin Advertising the well-known name */
    status = g_msgBus->AdvertiseName(g_WellKnownName, opts.transports);
    if (ER_OK != status) {
        QCC_LogError(status, ("AdvertiseName(%s) failed.", g_WellKnownName));
    }

    if (ER_OK == status) {
        while (g_interrupt == false) {
            qcc::Sleep(100);
        }
    }

    g_msgBus->UnregisterBusObject(testObj);

    /* Clean up msg bus */
    delete g_msgBus;
    delete g_SessionPortListener;

    printf("%s exiting with status %d (%s)\n", argv[0], status, QCC_StatusText(status));

    return (int) status;
}
