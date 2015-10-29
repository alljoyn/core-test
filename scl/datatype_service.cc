/**
 * @file
 * AllJoyn service that marshals different data types.
 */

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
 ******************************************************************************/
#include <signal.h>
#include <qcc/Thread.h>
#include <qcc/Util.h>
#include <alljoyn/BusAttachment.h>
#include <alljoyn/Init.h>
#include <alljoyn/version.h>

#define QCC_MODULE "DATATYPESERVICE TEST PROGRAM"

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

static void CDECL_CALL SigIntHandler(int sig)
{
    QCC_UNUSED(sig);
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
        QCC_UNUSED(sessionPort);
        QCC_UNUSED(joiner);
        QCC_UNUSED(opts);
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
        QCC_UNUSED(member);
        uint8_t value = 0;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("y", &value);
        cout << "Pinged with: " << (int)value << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Byte: Error sending reply"));
        }
    }

    void Int(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        int value = 0;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("i", &value);
        cout << "Pinged with: " << value << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Int: Error sending reply"));
        }
    }

    void UnsignedInt(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        uint32_t value = 0;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("u", &value);
        cout << "Pinged with: " << value << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("UnsignedInt: Error sending reply"));
        }
    }

    void Double(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        double value = 0;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("d", &value);
        cout << "Pinged with: " << value << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Double: Error sending reply"));
        }
    }

    void Bool(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        bool value = false;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("b", &value);
        cout << "Pinged with: " << (value ? "true" : "false") << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Bool: Error sending reply"));
        }
    }

    void String(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        char*value;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("s", &value);
        cout << "Pinged with: " << value << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("String: Error sending reply"));
        }
    }

    void UInt16(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        uint16_t value = 0;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("q", &value);
        cout << "Pinged with: " << value << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("UInt16: Error sending reply"));
        }
    }

    void Int16(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        int16_t value = 0;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("n", &value);
        cout << "Pinged with: " << value << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Int16: Error sending reply"));
        }
    }

    void Int64(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        int64_t value = 0;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("x", &value);
        cout << "Pinged with: " << value << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Int64: Error sending reply"));
        }
    }

    void UInt64(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        const MsgArg* arg((msg->GetArg(0)));
        /* Reply with same string that was sent to us */
        cout << "Pinged with: " << arg->v_uint64 << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("UInt64: Error sending reply"));
        }
    }

    void Struct(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        Structure structData;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(yiudbsqnxt)", &structData.byte, &structData.int32, &structData.uint32, &structData.doubleValue, &structData.boolValue, &structData.stringValue, &structData.uint16, &structData.int16, &structData.int64, &structData.uint64);
        cout << "Pinged with Structure:  " << endl;
        cout << "   Pinged with Structure.byte: " << (int)structData.byte << endl;
        cout << "   Pinged with Structure.int32: " << structData.int32 << endl;
        cout << "   Pinged with Structure.uint32: " << structData.uint32 << endl;
        cout << "   Pinged with Structure.double: " << structData.doubleValue << endl;
        cout << "   Pinged with Structure.bool: " << (structData.boolValue ? "true" : "false") << endl;
        cout << "   Pinged with Structure.string: " << structData.stringValue << endl;
        cout << "   Pinged with Structure.uint16: " << structData.uint16 << endl;
        cout << "   Pinged with Structure.int16: " << structData.int16 << endl;
        cout << "   Pinged with Structure.int64: " << structData.int64 << endl;
        cout << "   Pinged with Structure.uint64: " << structData.uint64 << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Struct: Error sending reply"));
        }
    }

    /* Padding test1 - yqut  */
    void Paddingtest1(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        Padding paddingData;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(yqut)", &paddingData.byte, &paddingData.uint16, &paddingData.uint32, &paddingData.uint64);
        cout << "Pinged with yqut:  " << endl;
        cout << "   Pinged with yqut.byte: " << (int)paddingData.byte << endl;
        cout << "   Pinged with yqut.uint16: " << paddingData.uint16 << endl;
        cout << "   Pinged with yqut.uint32: " << paddingData.uint32 << endl;
        cout << "   Pinged with yqut.uint64: " << paddingData.uint64 << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Paddingtest1: Error sending reply"));
        }
    }

    /* Padding test2 - yqtu */
    void Paddingtest2(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        Padding paddingData;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(yqtu)", &paddingData.byte, &paddingData.uint16, &paddingData.uint64, &paddingData.uint32);
        cout << "Pinged with yqtu:  " << endl;
        cout << "   Pinged with yqtu.byte: " << (int)paddingData.byte << endl;
        cout << "   Pinged with yqtu.uint16: " << paddingData.uint16 << endl;
        cout << "   Pinged with yqtu.uint64: " << paddingData.uint64 << endl;
        cout << "   Pinged with yqtu.uint32: " << paddingData.uint32 << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Paddingtest2: Error sending reply"));
        }
    }

    /* Padding test3 - yuqt */
    void Paddingtest3(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        Padding paddingData;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(yuqt)", &paddingData.byte, &paddingData.uint32, &paddingData.uint16, &paddingData.uint64);
        cout << "Pinged with yuqt:  " << endl;
        cout << "   Pinged with yuqt.byte: " << (int)paddingData.byte << endl;
        cout << "   Pinged with yuqt.uint32: " << paddingData.uint32 << endl;
        cout << "   Pinged with yuqt.uint16: " << paddingData.uint16 << endl;
        cout << "   Pinged with yuqt.uint64: " << paddingData.uint64 << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Paddingtest3: Error sending reply"));
        }
    }

    /* Padding test4 - yutq*/
    void Paddingtest4(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        Padding paddingData;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(yutq)", &paddingData.byte, &paddingData.uint32, &paddingData.uint64, &paddingData.uint16);
        cout << "Pinged with yutq:  " << endl;
        cout << "   Pinged with yutq.byte: " << (int)paddingData.byte << endl;
        cout << "   Pinged with yutq.uint32: " << paddingData.uint32 << endl;
        cout << "   Pinged with yutq.uint64: " << paddingData.uint64 << endl;
        cout << "   Pinged with yutq.uint16: " << paddingData.uint16 << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Paddingtest4: Error sending reply"));
        }
    }

    /* Padding test5 - ytqu*/
    void Paddingtest5(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        Padding paddingData;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(ytqu)", &paddingData.byte, &paddingData.uint64, &paddingData.uint16, &paddingData.uint32);
        cout << "Pinged with yutq:  " << endl;
        cout << "   Pinged with ytqu.byte: " << (int)paddingData.byte << endl;
        cout << "   Pinged with ytqu.uint64: " << paddingData.uint64 << endl;
        cout << "   Pinged with ytqu.uint16: " << paddingData.uint16 << endl;
        cout << "   Pinged with ytqu.uint32: " << paddingData.uint32 << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Paddingtest5: Error sending reply"));
        }
    }

    /* Padding test6 - ytuq */
    void Paddingtest6(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        Padding paddingData;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(ytuq)", &paddingData.byte, &paddingData.uint64, &paddingData.uint32, &paddingData.uint16);
        cout << "Pinged with ytuq:  " << endl;
        cout << "   Pinged with ytuq.byte: " << (int)paddingData.byte << endl;
        cout << "   Pinged with ytuq.uint64: " << paddingData.uint64 << endl;
        cout << "   Pinged with ytuq.uint32: " << paddingData.uint32 << endl;
        cout << "   Pinged with ytuq.uint16: " << paddingData.uint16 << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Paddingtest6: Error sending reply"));
        }
    }

    /* Padding test7 - ytuq */
    void Paddingtest7(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        Padding paddingData;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(qyut)", &paddingData.uint16, &paddingData.byte, &paddingData.uint32, &paddingData.uint64);
        cout << "Pinged with qyut:  " << endl;
        cout << "   Pinged with qyut.uint16: " << paddingData.uint16 << endl;
        cout << "   Pinged with qyut.byte: " << (int)paddingData.byte << endl;
        cout << "   Pinged with qyut.uint32: " << paddingData.uint32 << endl;
        cout << "   Pinged with qyut.uint64: " << paddingData.uint64 << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Paddingtest7: Error sending reply"));
        }
    }

    /* Padding test8 - qytu */
    void Paddingtest8(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        Padding paddingData;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(qytu)", &paddingData.uint16, &paddingData.byte, &paddingData.uint64, &paddingData.uint32);
        cout << "Pinged with qytu:  " << endl;
        cout << "   Pinged with qytu.uint16: " << paddingData.uint16 << endl;
        cout << "   Pinged with qytu.byte: " << (int)paddingData.byte << endl;
        cout << "   Pinged with qytu.uint64: " << paddingData.uint64 << endl;
        cout << "   Pinged with qytu.uint32: " << paddingData.uint32 << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Paddingtest8: Error sending reply"));
        }
    }

    /* Padding test9 - uyqt */
    void Paddingtest9(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        Padding paddingData;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(uyqt)", &paddingData.uint32, &paddingData.byte, &paddingData.uint16, &paddingData.uint64);
        cout << "Pinged with uyqt:  " << endl;
        cout << "   Pinged with uyqt.uint32: " << paddingData.uint32 << endl;
        cout << "   Pinged with uyqt.byte: " << (int)paddingData.byte << endl;
        cout << "   Pinged with uyqt.uint16: " << paddingData.uint16 << endl;
        cout << "   Pinged with uyqt.uint64: " << paddingData.uint64 << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Paddingtest9: Error sending reply"));
        }
    }

    /* Padding test10 - tyqu */
    void Paddingtest10(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        Padding paddingData;
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(tyqu)", &paddingData.uint64, &paddingData.byte, &paddingData.uint16, &paddingData.uint32);
        cout << "Pinged with tyqu:  " << endl;
        cout << "   Pinged with tyqu.uint64: " << paddingData.uint64 << endl;
        cout << "   Pinged with tyqu.byte: " << (int)paddingData.byte << endl;
        cout << "   Pinged with tyqu.uint16: " << paddingData.uint16 << endl;
        cout << "   Pinged with tyqu.uint32: " << paddingData.uint32 << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Paddingtest10: Error sending reply"));
        }
    }

    void ArrayofStruct(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        const MsgArg* arg((msg->GetArg(0)));
        /* Reply with same string that was sent to us */
        cout << "Pinged with Array of Structures: " << endl;
        MsgArg* outer;
        size_t outerSize;
        QStatus status = arg->Get("a(is)", &outerSize, &outer);

        for (size_t i = 0; i < outerSize; ++i) {
            StructTest tmp;
            status = outer[i].Get("(is)", &tmp.num, &tmp.ord);
            cout << "   element[" << i << "].num " << tmp.num << endl;
            cout << "   element[" << i << "].ord " << tmp.ord << endl;
        }
        status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("ArrayofStruct: Error sending reply"));
        }
    }

    void Dictionary(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
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
        cout << "Pinged with Dictionary: " << endl;
        cout << "   Pinged with key: " << key << endl;
        cout << "   Pinged with Value: " << value << endl;
        status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Dictionary: Error sending reply"));
        }

    }

    void NestedStruct(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        uint8_t byte;
        int32_t int32;
        uint32_t uint32;
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        arg->Get("(y(iu))", &byte, &int32, &uint32);
        cout << "Pinged with y(iu) :  " << endl;
        cout << "   Pinged with y(iu) y  " << (int)byte << endl;
        cout << "   Pinged with y(iu) i " << int32 << endl;
        cout << "   Pinged with y(iu) u " << uint32 << endl;
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Struct: Error sending reply"));
        }
    }

    void ByteArray(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        cout << "Pinged with ByteArray: " << endl;
        for (int i = 0; i < (int)arg->v_scalarArray.numElements; i++) {
            cout << "   Pinged with ByteArray: " << (int)arg->v_scalarArray.v_byte[i] << endl;
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("ByteArray: Error sending reply"));
        }

    }

    void IntArray(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        cout << "Pinged with IntArray: " << endl;
        for (int i = 0; i < (int)arg->v_scalarArray.numElements; i++) {
            cout << "   Pinged with IntArray: " << arg->v_scalarArray.v_int32[i] << endl;
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("IntArray: Error sending reply"));
        }

    }


    void UnsignedIntArray(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        cout << "Pinged with UnsignedIntArray: " << endl;
        for (int i = 0; i < (int)arg->v_scalarArray.numElements; i++) {
            cout << "   Pinged with UInt32Array: " << arg->v_scalarArray.v_uint32[i] << endl;
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("UInt32Array: Error sending reply"));
        }

    }


    void DoubleArray(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        cout << "Pinged with DoubleArray: " << endl;
        for (int i = 0; i < (int)arg->v_scalarArray.numElements; i++) {
            cout << "   Pinged with DoubleArray: " << arg->v_scalarArray.v_double[i] << endl;
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("DoubleArray: Error sending reply"));
        }
    }


    void BoolArray(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        cout << "Pinged with BoolArray: " << endl;
        for (int i = 0; i < (int)arg->v_scalarArray.numElements; i++) {
            cout << "   Pinged with BoolArray: " << (arg->v_scalarArray.v_bool[i] ? "true" : "false") << endl;
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("BoolArray: Error sending reply"));
        }

    }

    void StringArray(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        cout << "Pinged with StringArray: " << endl;
        MsgArg* outer;
        size_t outerSize;
        QStatus status = arg->Get("as", &outerSize, &outer);

        for (size_t i = 0; i < outerSize; ++i) {
            char*value;
            status = outer[i].Get("s", &value);
            cout << "   Pinged with StringArray: " << value << endl;
        }
        status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("StringArray: Error sending reply"));
        }
    }


    void UInt16Array(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        cout << "Pinged with UInt16Array: " << endl;
        for (int i = 0; i < (int)arg->v_scalarArray.numElements; i++) {
            cout << "   Pinged with UInt16Array: " << arg->v_scalarArray.v_uint16[i] << endl;
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("UInt16Array: Error sending reply"));
        }

    }


    void Int16Array(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        cout << "Pinged with Int16Array: " << endl;
        for (int i = 0; i < (int)arg->v_scalarArray.numElements; i++) {
            cout << "   Pinged with Int16Array: " << arg->v_scalarArray.v_int16[i] << endl;
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Int16Array: Error sending reply"));
        }
    }


    void Int64Array(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        cout << "Pinged with Int64Array: " << endl;
        for (int i = 0; i < (int)arg->v_scalarArray.numElements; i++) {
            cout << "   Pinged with Int64Array: " << arg->v_scalarArray.v_int64[i] << endl;
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Int64Array: Error sending reply"));
        }

    }

    void UInt64Array(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        /* Reply with same string that was sent to us */
        const MsgArg* arg((msg->GetArg(0)));
        cout << "Pinged with UInt64Array: " << endl;
        for (int i = 0; i < (int)arg->v_scalarArray.numElements; i++) {
            cout << "    Pinged with UInt64Array: " << arg->v_scalarArray.v_uint64[i] << endl;
        }
        QStatus status = MethodReply(msg, arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("UInt64Array: Error sending reply"));
        }
    }
};

static void usage(void)
{
    cout << "Usage: datatype_service [-h] [-n <name>] " << endl << endl;
    cout << "Options:" << endl;
    cout << "   -h                    = Print this help message" << endl;
    cout << "   -n <well-known name>  = Well-known name to advertise" << endl;
}


int TestAppMain(int argc, char** argv)
{
    QStatus status = ER_OK;
    SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
    cout << "AllJoyn Library version: " << ajn::GetVersion() << endl;
    cout << "AllJoyn Library build info: " << ajn::GetBuildInfo() << endl;

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
                cout << "option " << argv[i - 1] << " requires a parameter" << endl;
                usage();
                exit(1);
            } else {
                g_WellKnownName = argv[i];
            }
        }  else {
            status = ER_FAIL;
            cout << "Unknown option " << argv[i] << endl;
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

    cout << argv[0] << " exiting with status " << status << " (" << QCC_StatusText(status) << ")" << endl;

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