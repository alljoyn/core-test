/**
 * @file
 * Sample implementation of an AllJoyn client.
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

#include <alljoyn/AllJoynStd.h>
#include <alljoyn/BusAttachment.h>
#include <alljoyn/DBusStd.h>
#include <alljoyn/Init.h>
#include <alljoyn/version.h>

#include <alljoyn/Status.h>

#define QCC_MODULE "ALLJOYN"

#define METHODCALL_TIMEOUT 30000

using namespace std;
using namespace qcc;
using namespace ajn;

/* setup for first test object */
namespace abcd {
const char* WellKnownName = "abcd.org";
const char* ObjectPath = "/abcd/org";
const char* InterfaceName1 = "ab.org";
const char* InterfaceName2 = "cd.org";

const char* MethodName1 = "aMethod";
const char* MethodName2 = "bMethod";
const char* MethodName3 = "cMethod";
const char* MethodName4 = "dMethod";

const char* ErrorMethod1 = "aError";
const char* ErrorMethod2 = "bError";
const char* ErrorMethod3 = "cError";
const char* ErrorMethod4 = "dError";

const char* SignalName1 = "a_signal";
const char* SignalName2 = "b_signal";
const char* SignalName3 = "c_signal";
const char* SignalName4 = "d_signal";
}

/* setup for 2nd test object */
namespace efgh {
const char* WellKnownName = "efgh.gov";
const char* ObjectPath = "/efgh/gov";
const char* InterfaceName1 = "ef.gov";
const char* InterfaceName2 = "gh.gov";

const char* MethodName1 = "eMethod";
const char* MethodName2 = "fMethod";
const char* MethodName3 = "gMethod";
const char* MethodName4 = "hMethod";

const char* ErrorMethod1 = "eError";
const char* ErrorMethod2 = "fError";
const char* ErrorMethod3 = "gError";
const char* ErrorMethod4 = "hError";

const char* SignalName1 = "e_signal";
const char* SignalName2 = "f_signal";
const char* SignalName3 = "g_signal";
const char* SignalName4 = "h_signal";

}

static const SessionPort mySessionPort = 30;    /**< Well-knwon session port value for policyClient/policyService */
static String g_wellKnownName1 = ::abcd::WellKnownName;
static String g_wellKnownName2 = ::efgh::WellKnownName;

static String g_wellKnownName = ::abcd::WellKnownName;
static String g_objectPath = ::abcd::ObjectPath;
static String g_interfaceName = ::abcd::InterfaceName1;
static String g_methodName = ::abcd::MethodName1;

static String g_signalName = ::abcd::SignalName1;

/** Static data */
static BusAttachment* g_msgBus = NULL;
static Event g_discoverEvent;

static TransportMask allowedTransports = TRANSPORT_ANY;
static uint32_t findStartTime = 0;
static uint32_t findEndTime = 0;
static uint32_t joinStartTime = 0;
static uint32_t joinEndTime = 0;
static uint32_t keyExpiration = 0xFFFFFFFF;




/** AllJoynListener receives discovery events from AllJoyn */
class MyBusListener : public BusListener, public SessionListener {
  public:

    MyBusListener(bool stopDiscover) : BusListener(), sessionId(0), stopDiscover(stopDiscover) { }

    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix)
    {
        findEndTime = GetTimestamp();
        QCC_SyncPrintf("FindAdvertisedName 0x%x takes %d ms \n", transport, (findEndTime - findStartTime));
        QCC_SyncPrintf("FoundAdvertisedName(name=%s, transport=0x%x, prefix=%s)\n", name, transport, namePrefix);

        if (0 == (transport & allowedTransports)) {
            QCC_SyncPrintf("Ignoring FoundAdvertised name from transport 0x%x\n", transport);
            return;
        }

        /* We must enable concurrent callbacks since some of the calls below are blocking */
        g_msgBus->EnableConcurrentCallbacks();

        if (0 == ::strcmp(name, g_wellKnownName.c_str())) {
            /* We found a remote bus that is advertising bbservice's well-known name so connect to it */
            SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, transport);
            QStatus status;

            if (stopDiscover) {
                status = g_msgBus->CancelFindAdvertisedName(g_wellKnownName.c_str());
                if (ER_OK != status) {
                    QCC_LogError(status, ("CancelFindAdvertisedName(%s) failed", name));
                }
            }

            joinStartTime = GetTimestamp();

            status = g_msgBus->JoinSession(name, mySessionPort, this, sessionId, opts);
            if (ER_OK != status) {
                QCC_LogError(status, ("JoinSession(%s) failed", name));
            }

            /* Release the main thread */
            if (ER_OK == status) {
                joinEndTime = GetTimestamp();
                QCC_SyncPrintf("JoinSession 0x%x takes %d ms \n", transport, (joinEndTime - joinStartTime));

                g_discoverEvent.SetEvent();
            }
        }
    }

    void LostAdvertisedName(const char* name, TransportMask transport, const char* prefix)
    {
        QCC_SyncPrintf("LostAdvertisedName(name=%s, transport=0x%x, prefix=%s)\n", name, transport, prefix);
    }

    void NameOwnerChanged(const char* name, const char* previousOwner, const char* newOwner)
    {
        QCC_SyncPrintf("NameOwnerChanged(%s, %s, %s)\n",
                       name,
                       previousOwner ? previousOwner : "null",
                       newOwner ? newOwner : "null");
    }

    void SessionLost(SessionId sessionId, SessionLostReason reason) {
        QCC_SyncPrintf("SessionLost(%08x) was called. Reason=%u.\n", sessionId, reason);
        _exit(1);
    }

    SessionId GetSessionId() const { return sessionId; }

  private:
    SessionId sessionId;
    bool stopDiscover;
};

/** Static bus listener */
static MyBusListener* g_busListener;

static unsigned long timeToLive = 0;

class LocalTestObject1 : public BusObject {

  public:

    LocalTestObject1(BusAttachment& bus, const char* path, unsigned long signalDelay, unsigned long disconnectDelay,
                     unsigned long reportInterval, unsigned long maxSignals, const InterfaceDescription* testIfc1,
                     const InterfaceDescription* testIfc2) :
        BusObject(path),
        signalDelay(signalDelay),
        disconnectDelay(disconnectDelay),
        reportInterval(reportInterval),
        maxSignals(maxSignals),
        ifc1(testIfc1),
        ifc2(testIfc2)
    {

        assert(ifc1);
        assert(ifc2);

        a_signal_member = ifc1->GetMember("a_signal");
        b_signal_member = ifc1->GetMember("b_signal");
        c_signal_member = ifc2->GetMember("c_signal");
        d_signal_member = ifc2->GetMember("d_signal");

        assert(a_signal_member);
        assert(b_signal_member);
        assert(c_signal_member);
        assert(d_signal_member);
    }

    QStatus SendSignalA() {
        uint8_t flags = ALLJOYN_FLAG_GLOBAL_BROADCAST;

        MsgArg arg("a{ys}", 0, NULL);

        QCC_SyncPrintf("A Send signal\n");
        return Signal(NULL, g_busListener->GetSessionId(), *a_signal_member, &arg, 1, timeToLive, flags);
    }

    QStatus SendSignalB() {
        uint8_t flags = ALLJOYN_FLAG_GLOBAL_BROADCAST;

        MsgArg arg("a{ys}", 0, NULL);

        QCC_SyncPrintf("B Send signal\n");
        return Signal(NULL, g_busListener->GetSessionId(), *b_signal_member, &arg, 1, timeToLive, flags);
    }
    QStatus SendSignalC() {
        uint8_t flags = ALLJOYN_FLAG_GLOBAL_BROADCAST;

        MsgArg arg("a{ys}", 0, NULL);

        QCC_SyncPrintf("C Send signal\n");
        return Signal(NULL, g_busListener->GetSessionId(), *c_signal_member, &arg, 1, timeToLive, flags);
    }

    QStatus SendSignalD() {
        uint8_t flags = ALLJOYN_FLAG_GLOBAL_BROADCAST;

        MsgArg arg("a{ys}", 0, NULL);

        QCC_SyncPrintf("D Send signal\n");
        return Signal(NULL, g_busListener->GetSessionId(), *d_signal_member, &arg, 1, timeToLive, flags);
    }
    void ObjectRegistered(void)
    {

    }

    void NameAcquiredCB(Message& msg, void* context)
    {

    }

    void AdvertiseRequestCB(Message& msg, void* context)
    {

    }


    map<qcc::String, size_t> rxCounts;

    unsigned long signalDelay;
    unsigned long disconnectDelay;
    unsigned long reportInterval;
    unsigned long maxSignals;
    const InterfaceDescription* ifc1;
    const InterfaceDescription* ifc2;
    const InterfaceDescription::Member* a_signal_member;
    const InterfaceDescription::Member* b_signal_member;
    const InterfaceDescription::Member* c_signal_member;
    const InterfaceDescription::Member* d_signal_member;
};

class LocalTestObject2 : public BusObject {

  public:

    LocalTestObject2(BusAttachment& bus, const char* path, unsigned long signalDelay, unsigned long disconnectDelay,
                     unsigned long reportInterval, unsigned long maxSignals, const InterfaceDescription* testIfc1,
                     const InterfaceDescription* testIfc2) :
        BusObject(path),
        signalDelay(signalDelay),
        disconnectDelay(disconnectDelay),
        reportInterval(reportInterval),
        maxSignals(maxSignals),
        ifc1(testIfc1),
        ifc2(testIfc2)
    {

        assert(ifc1);
        assert(ifc2);

        e_signal_member = ifc1->GetMember("e_signal");
        f_signal_member = ifc1->GetMember("f_signal");
        g_signal_member = ifc2->GetMember("g_signal");
        h_signal_member = ifc2->GetMember("h_signal");

        assert(e_signal_member);
        assert(f_signal_member);
        assert(g_signal_member);
        assert(h_signal_member);
    }

    QStatus SendSignalE() {
        uint8_t flags = ALLJOYN_FLAG_GLOBAL_BROADCAST;

        MsgArg arg("a{ys}", 0, NULL);

        QCC_SyncPrintf("E Send signal\n");
        return Signal(NULL, g_busListener->GetSessionId(), *e_signal_member, &arg, 1, timeToLive, flags);
    }

    QStatus SendSignalF() {
        uint8_t flags = ALLJOYN_FLAG_GLOBAL_BROADCAST;

        MsgArg arg("a{ys}", 0, NULL);

        QCC_SyncPrintf("F Send signal\n");
        return Signal(NULL, g_busListener->GetSessionId(), *f_signal_member, &arg, 1, timeToLive, flags);
    }
    QStatus SendSignalG() {
        uint8_t flags = ALLJOYN_FLAG_GLOBAL_BROADCAST;

        MsgArg arg("a{ys}", 0, NULL);

        QCC_SyncPrintf("G Send signal\n");
        return Signal(NULL, g_busListener->GetSessionId(), *g_signal_member, &arg, 1, timeToLive, flags);
    }

    QStatus SendSignalH() {
        uint8_t flags = ALLJOYN_FLAG_GLOBAL_BROADCAST;

        MsgArg arg("a{ys}", 0, NULL);

        QCC_SyncPrintf("H Send signal\n");
        return Signal(NULL, g_busListener->GetSessionId(), *h_signal_member, &arg, 1, timeToLive, flags);
    }
    void ObjectRegistered(void)
    {

    }

    void NameAcquiredCB(Message& msg, void* context)
    {

    }

    void AdvertiseRequestCB(Message& msg, void* context)
    {

    }


    map<qcc::String, size_t> rxCounts;

    unsigned long signalDelay;
    unsigned long disconnectDelay;
    unsigned long reportInterval;
    unsigned long maxSignals;
    const InterfaceDescription* ifc1;
    const InterfaceDescription* ifc2;
    const InterfaceDescription::Member* e_signal_member;
    const InterfaceDescription::Member* f_signal_member;
    const InterfaceDescription::Member* g_signal_member;
    const InterfaceDescription::Member* h_signal_member;
};

static volatile sig_atomic_t g_interrupt = false;

static void SigIntHandler(int sig)
{
    g_interrupt = true;
}

static void usage(void)
{
    printf("Usage: policyClient [-h] [-n <1|2>] [-i <1|2>] [-m <1|2>] [-e <1|2>] [-d] \n\n");
    printf("Options:\n");
    printf("   -h                        = Print this help message\n");
    printf("   -n <1|2>                  = Well-known name 1 or 2 advertised by policyService\n");
    printf("   -i <1|2>                  = interface 1 or interface 2\n");
    printf("   -m <1|2>                  = method 1 or 2 \n");
    printf("   -e <1|2>                  = error 1 or 2 \n");
    printf("   -d                        = discover remote bus with test service\n");
    printf("\n");
}


static const char x509cert[] = {
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBszCCARwCCQDuCh+BWVBk2DANBgkqhkiG9w0BAQUFADAeMQ0wCwYDVQQKDARN\n"
    "QnVzMQ0wCwYDVQQDDARHcmVnMB4XDTEwMDUxNzE1MTg1N1oXDTExMDUxNzE1MTg1\n"
    "N1owHjENMAsGA1UECgwETUJ1czENMAsGA1UEAwwER3JlZzCBnzANBgkqhkiG9w0B\n"
    "AQEFAAOBjQAwgYkCgYEArSd4r62mdaIRG9xZPDAXfImt8e7GTIyXeM8z49Ie1mrQ\n"
    "h7roHbn931Znzn20QQwFD6pPC7WxStXJVH0iAoYgzzPsXV8kZdbkLGUMPl2GoZY3\n"
    "xDSD+DA3m6krcXcN7dpHv9OlN0D9Trc288GYuFEENpikZvQhMKPDUAEkucQ95Z8C\n"
    "AwEAATANBgkqhkiG9w0BAQUFAAOBgQBkYY6zzf92LRfMtjkKs2am9qvjbqXyDJLS\n"
    "viKmYe1tGmNBUzucDC5w6qpPCTSe23H2qup27///fhUUuJ/ssUnJ+Y77jM/u1O9q\n"
    "PIn+u89hRmqY5GKHnUSZZkbLB/yrcFEchHli3vLo4FOhVVHwpnwLtWSpfBF9fWcA\n"
    "7THIAV79Lg==\n"
    "-----END CERTIFICATE-----"
};

static const char privKey[] = {
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "Proc-Type: 4,ENCRYPTED\n"
    "DEK-Info: AES-128-CBC,0AE4BAB94CEAA7829273DD861B067DBA\n"
    "\n"
    "LSJOp+hEzNDDpIrh2UJ+3CauxWRKvmAoGB3r2hZfGJDrCeawJFqH0iSYEX0n0QEX\n"
    "jfQlV4LHSCoGMiw6uItTof5kHKlbp5aXv4XgQb74nw+2LkftLaTchNs0bW0TiGfQ\n"
    "XIuDNsmnZ5+CiAVYIKzsPeXPT4ZZSAwHsjM7LFmosStnyg4Ep8vko+Qh9TpCdFX8\n"
    "w3tH7qRhfHtpo9yOmp4hV9Mlvx8bf99lXSsFJeD99C5GQV2lAMvpfmM8Vqiq9CQN\n"
    "9OY6VNevKbAgLG4Z43l0SnbXhS+mSzOYLxl8G728C6HYpnn+qICLe9xOIfn2zLjm\n"
    "YaPlQR4MSjHEouObXj1F4MQUS5irZCKgp4oM3G5Ovzt82pqzIW0ZHKvi1sqz/KjB\n"
    "wYAjnEGaJnD9B8lRsgM2iLXkqDmndYuQkQB8fhr+zzcFmqKZ1gLRnGQVXNcSPgjU\n"
    "Y0fmpokQPHH/52u+IgdiKiNYuSYkCfHX1Y3nftHGvWR3OWmw0k7c6+DfDU2fDthv\n"
    "3MUSm4f2quuiWpf+XJuMB11px1TDkTfY85m1aEb5j4clPGELeV+196OECcMm4qOw\n"
    "AYxO0J/1siXcA5o6yAqPwPFYcs/14O16FeXu+yG0RPeeZizrdlv49j6yQR3JLa2E\n"
    "pWiGR6hmnkixzOj43IPJOYXySuFSi7lTMYud4ZH2+KYeK23C2sfQSsKcLZAFATbq\n"
    "DY0TZHA5lbUiOSUF5kgd12maHAMidq9nIrUpJDzafgK9JrnvZr+dVYM6CiPhiuqJ\n"
    "bXvt08wtKt68Ymfcx+l64mwzNLS+OFznEeIjLoaHU4c=\n"
    "-----END RSA PRIVATE KEY-----"
};

class MyAuthListener : public AuthListener {
  public:

    MyAuthListener(const qcc::String& userName, unsigned long maxAuth) : AuthListener(), userName(userName), maxAuth(maxAuth) { }

  private:

    bool RequestCredentials(const char* authMechanism, const char* authPeer, uint16_t authCount, const char* userId, uint16_t credMask, Credentials& creds) {

        if (authCount > maxAuth) {
            return false;
        }

        printf("RequestCredentials for authenticating %s using mechanism %s\n", authPeer, authMechanism);

        if (keyExpiration != 0xFFFFFFFF) {
            creds.SetExpiration(keyExpiration);
        }

        if (strcmp(authMechanism, "ALLJOYN_PIN_KEYX") == 0) {
            if (credMask & AuthListener::CRED_PASSWORD) {
                creds.SetPassword("ABCDEFGH");
            }
            return authCount == 1;
        }

        if (strcmp(authMechanism, "ALLJOYN_SRP_KEYX") == 0) {
            if (credMask & AuthListener::CRED_PASSWORD) {
                if (authCount == 3) {
                    creds.SetPassword("123456");
                } else {
                    creds.SetPassword("xxxxxx");
                }
                printf("AuthListener returning fixed pin \"%s\" for %s\n", creds.GetPassword().c_str(), authMechanism);
            }
            return true;
        }

        if (strcmp(authMechanism, "ALLJOYN_RSA_KEYX") == 0) {
            if (credMask & AuthListener::CRED_CERT_CHAIN) {
                creds.SetCertChain(x509cert);
            }
            if (credMask & AuthListener::CRED_PRIVATE_KEY) {
                creds.SetPrivateKey(privKey);
            }
            if (credMask & AuthListener::CRED_PASSWORD) {
                creds.SetPassword("123456");
            }
            return true;
        }

        if (strcmp(authMechanism, "ALLJOYN_SRP_LOGON") == 0) {
            if (credMask & AuthListener::CRED_USER_NAME) {
                if (authCount == 1) {
                    creds.SetUserName("Mr Bogus");
                } else {
                    creds.SetUserName(userName);
                }
            }
            if (credMask & AuthListener::CRED_PASSWORD) {
                creds.SetPassword("123456");
            }
            return true;
        }

        return false;
    }

    bool VerifyCredentials(const char* authMechanism, const char* authPeer, const Credentials& creds) {
        if (strcmp(authMechanism, "ALLJOYN_RSA_KEYX") == 0) {
            if (creds.IsSet(AuthListener::CRED_CERT_CHAIN)) {
                printf("Verify\n%s\n", creds.GetCertChain().c_str());
                return true;
            }
        }
        return false;
    }

    void AuthenticationComplete(const char* authMechanism, const char* authPeer, bool success) {
        printf("Authentication %s %s\n", authMechanism, success ? "succesful" : "failed");
    }

    void SecurityViolation(QStatus status, const Message& msg) {
        printf("Security violation %s\n", QCC_StatusText(status));
    }

    qcc::String userName;
    unsigned long maxAuth;
};


class MyMessageReceiver : public MessageReceiver {
  public:
    void PingResponseHandler(Message& message, void* context)
    {
        const InterfaceDescription::Member* pingMethod = static_cast<const InterfaceDescription::Member*>(context);
        if (message->GetType() == MESSAGE_METHOD_RET) {
            QCC_SyncPrintf("%s.%s returned \"%s\"\n",
                           g_wellKnownName.c_str(),
                           pingMethod->name.c_str(),
                           message->GetArg(0)->v_string.str);

        } else {
            // must be an error
            qcc::String errMsg;
            const char* errName = message->GetErrorName(&errMsg);
            QCC_SyncPrintf("%s.%s returned error %s: %s\n",
                           g_wellKnownName.c_str(),
                           pingMethod->name.c_str(),
                           errName,
                           errMsg.c_str());
        }
    }
};

/* Calculate well known name and object path from passed-in parameters */
static void getWkNameAndObjPath(uint8_t wkNameIndex)
{
    printf("Client want name from index %d \n", wkNameIndex);

    if (1 == wkNameIndex) {
        g_wellKnownName = ::abcd::WellKnownName;
        g_objectPath = ::abcd::ObjectPath;
    } else if (2 == wkNameIndex) {
        g_wellKnownName = ::efgh::WellKnownName;
        g_objectPath = ::efgh::ObjectPath;
    } else {
        printf("Invalid name index %d !\n", wkNameIndex);
    }
}
/* Calculate interface name from passed-in parameters */
static void getInterfaceName(uint8_t wkNameIndex, uint8_t ifcIndex)
{
    printf("Client want interface from %d %d \n", wkNameIndex, ifcIndex);

    if (1 == wkNameIndex) {
        if (1 == ifcIndex) {
            g_interfaceName = ::abcd::InterfaceName1;
        } else {
            g_interfaceName = ::abcd::InterfaceName2;
        }
    } else if (2 == wkNameIndex) {
        if (1 == ifcIndex) {
            g_interfaceName = ::efgh::InterfaceName1;
        } else {
            g_interfaceName = ::efgh::InterfaceName2;
        }
    }

}
/* Calculate method name from passed-in parameters */
static void getMethodName(uint8_t wkNameIndex, uint8_t ifcIndex, uint8_t methodIndex)
{
    printf("Client want method from %d %d \n", wkNameIndex, ifcIndex);

    if (1 == wkNameIndex) {
        if (1 == ifcIndex) {
            if (1 == methodIndex) {
                g_methodName = ::abcd::MethodName1;
            } else {
                g_methodName = ::abcd::MethodName2;
            }
        } else {
            if (1 == methodIndex) {
                g_methodName = ::abcd::MethodName3;
            } else {
                g_methodName = ::abcd::MethodName4;
            }
        }
    } else if (2 == wkNameIndex) {
        if (1 == ifcIndex) {
            if (1 == methodIndex) {
                g_methodName = ::efgh::MethodName1;
            } else {
                g_methodName = ::efgh::MethodName2;
            }
        } else {
            if (1 == methodIndex) {
                g_methodName = ::efgh::MethodName3;
            } else {
                g_methodName = ::efgh::MethodName4;
            }
        }
    }

}
/* Calculate error name from passed-in parameters */
static void getErrorMethod(uint8_t wkNameIndex, uint8_t ifcIndex, uint8_t errorIndex)
{
    printf("Client want error from name/interface %d %d \n", wkNameIndex, ifcIndex);

    if (1 == wkNameIndex) {
        if (1 == ifcIndex) {
            if (1 == errorIndex) {
                g_methodName = ::abcd::ErrorMethod1;
            } else {
                g_methodName = ::abcd::ErrorMethod2;
            }
        } else {
            if (1 == errorIndex) {
                g_methodName = ::abcd::ErrorMethod3;
            } else {
                g_methodName = ::abcd::ErrorMethod4;
            }
        }
    } else if (2 == wkNameIndex) {
        if (1 == ifcIndex) {
            if (1 == errorIndex) {
                g_methodName = ::efgh::ErrorMethod1;
            } else {
                g_methodName = ::efgh::ErrorMethod2;
            }
        } else {
            if (1 == errorIndex) {
                g_methodName = ::efgh::ErrorMethod3;
            } else {
                g_methodName = ::efgh::ErrorMethod4;
            }
        }
    }

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

    QStatus status = ER_OK;
    bool useIntrospection = false;
    InterfaceSecurityPolicy secPolicy = AJ_IFC_SECURITY_INHERIT;
    bool clearKeys = false;
    qcc::String authMechs;
    qcc::String pbusConnect;
    qcc::String userId;
    const char* keyStore = NULL;
    unsigned long repCount = 1;
    unsigned long authCount = 1000;
    Environ* env;

    bool discoverRemote = false;
    bool stopDiscover = false;
    bool waitForService = true;
    uint32_t pingDelay = 0;
    uint32_t pingInterval = 0;
    bool waitForSigint = false;
    bool objSecure = false;

    uint8_t nameIndex = 1;
    uint8_t interfaceIndex = 1;
    uint8_t methodIndex = 0;
    uint8_t errorIndex = 0;

    bool fSendSignal = false;
    bool fMethodCall = false;
    uint8_t signalIndex = 0;

    unsigned long signalDelay = 0;
    unsigned long disconnectDelay = 0;
    unsigned long reportInterval = 1000;
    unsigned long maxSignals = 1;

    InterfaceDescription* testIntf1 = NULL;
    InterfaceDescription* testIntf2 = NULL;
    InterfaceDescription* testIntf3 = NULL;
    InterfaceDescription* testIntf4 = NULL;

    printf("AllJoyn Library version: %s\n", ajn::GetVersion());
    printf("AllJoyn Library build info: %s\n", ajn::GetBuildInfo());

    /* Install SIGINT handler */
    signal(SIGINT, SigIntHandler);

    /* Parse command line args */
    for (int i = 1; i < argc; ++i) {
        if (0 == ::strcmp("-n", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                nameIndex = strtoul(argv[i], NULL, 10);
                printf("Well known name number is %d\n", nameIndex);

                if (nameIndex > 2 || nameIndex < 1) {
                    printf("name index is NOT 1 or 2\n");
                    usage();
                    exit(1);
                }
            }
        } else if (0 == strcmp("-i", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                interfaceIndex = strtoul(argv[i], NULL, 10);
                printf("Interface number is %d\n", interfaceIndex);

                if (interfaceIndex > 2 || interfaceIndex < 1) {
                    printf("interface index is NOT 1 or 2 \n");
                    usage();
                    exit(1);
                }
            }
        } else if (0 == ::strcmp("-m", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                methodIndex = strtoul(argv[i], NULL, 10);
                printf("Method number is %d\n", methodIndex);

                if (methodIndex > 2 || methodIndex < 1) {
                    printf("method index is NOT 1 or 2\n");
                    usage();
                    exit(1);
                }
                fMethodCall = true;
            }
        } else if (0 == ::strcmp("-e", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                errorIndex = strtoul(argv[i], NULL, 10);
                printf("Error number is %d\n", errorIndex);

                if (errorIndex > 2 || errorIndex < 1) {
                    printf("error index is NOT 1 or 2\n");
                    usage();
                    exit(1);
                }
                fMethodCall = true;
            }
        } else if (0 == ::strcmp("-s", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                signalIndex = strtoul(argv[i], NULL, 10);
                printf("Signal number is %d\n", signalIndex);

                if (signalIndex > 2 || signalIndex < 1) {
                    printf("Signal index is NOT 1 or 2\n");
                    usage();
                    exit(1);
                }
                fSendSignal = true;
            }
        } else if (0 == strcmp("-d", argv[i])) {
            discoverRemote = true;
        } else {
            status = ER_FAIL;
            printf("Unknown option %s\n", argv[i]);
            usage();
            exit(1);
        }
    }


    /* Get well known name and object path */
    getWkNameAndObjPath(nameIndex);

    /* Get env vars */
    env = Environ::GetAppEnviron();
    qcc::String connectArgs = env->Find("BUS_ADDRESS");

    for (unsigned long i = 0; i < repCount && !g_interrupt; i++) {

        /* Create message bus */
        g_msgBus = new BusAttachment("policyClient", true);

        if (!useIntrospection) {
            /* Add abcd interface */

            status = g_msgBus->CreateInterface(::abcd::InterfaceName1, testIntf1, secPolicy);
            if (ER_OK == status) {
                testIntf1->AddSignal("a_signal", "a{ys}", NULL, 0);
                testIntf1->AddSignal("b_signal", "a{ys}", NULL, 0);
                testIntf1->AddMethod("aMethod", "s", "s", "inStr,outStr", 0);
                testIntf1->AddMethod("bMethod", "s", "s", "inStr,outStr", 0);
                testIntf1->AddMethod("aError", "s", "s", "inStr,outStr", 0);
                testIntf1->AddMethod("bError", "s", "s", "inStr,outStr", 0);
                testIntf1->Activate();
            } else {
                QCC_LogError(status, ("Failed to create interface %s", ::abcd::InterfaceName1));
            }


            status = g_msgBus->CreateInterface(::abcd::InterfaceName2, testIntf2, secPolicy);
            if (ER_OK == status) {
                testIntf2->AddSignal("c_signal", "a{ys}", NULL, 0);
                testIntf2->AddSignal("d_signal", "a{ys}", NULL, 0);
                testIntf2->AddMethod("cMethod", "s", "s", "inStr,outStr", 0);
                testIntf2->AddMethod("dMethod", "s", "s", "inStr,outStr", 0);
                testIntf2->AddMethod("cError", "s", "s", "inStr,outStr", 0);
                testIntf2->AddMethod("dError", "s", "s", "inStr,outStr", 0);
                testIntf2->Activate();
            } else {
                QCC_LogError(status, ("Failed to create interface %s", ::abcd::InterfaceName2));
            }

            /* Add efgh interface */
            status = g_msgBus->CreateInterface(::efgh::InterfaceName1, testIntf3, secPolicy);
            if (ER_OK == status) {
                testIntf3->AddSignal("e_signal", "a{ys}", NULL, 0);
                testIntf3->AddSignal("f_signal", "a{ys}", NULL, 0);
                testIntf3->AddMethod("eMethod", "s", "s", "inStr,outStr", 0);
                testIntf3->AddMethod("fMethod", "s", "s", "inStr,outStr", 0);
                testIntf3->AddMethod("eError", "s", "s", "inStr,outStr", 0);
                testIntf3->AddMethod("fError", "s", "s", "inStr,outStr", 0);
                testIntf3->Activate();
            } else {
                QCC_LogError(status, ("Failed to create interface %s", ::efgh::InterfaceName1));
            }

            status = g_msgBus->CreateInterface(::efgh::InterfaceName2, testIntf4, secPolicy);
            if (ER_OK == status) {
                testIntf4->AddSignal("g_signal", "a{ys}", NULL, 0);
                testIntf4->AddSignal("h_signal", "a{ys}", NULL, 0);
                testIntf4->AddMethod("gMethod", "s", "s", "inStr,outStr", 0);
                testIntf4->AddMethod("hMethod", "s", "s", "inStr,outStr", 0);
                testIntf4->AddMethod("gError", "s", "s", "inStr,outStr", 0);
                testIntf4->AddMethod("hError", "s", "s", "inStr,outStr", 0);
                testIntf4->Activate();
            } else {
                QCC_LogError(status, ("Failed to create interface %s", ::efgh::InterfaceName2));
            }

        }

        /* Register a bus listener in order to get discovery indications */
        if (ER_OK == status) {
            g_busListener = new MyBusListener(stopDiscover);
            g_msgBus->RegisterBusListener(*g_busListener);
        }

        /* Start the msg bus */
        if (ER_OK == status) {
            status = g_msgBus->Start();
            if (ER_OK == status) {
                if (secPolicy != AJ_IFC_SECURITY_INHERIT) {
                    g_msgBus->EnablePeerSecurity(authMechs.c_str(), new MyAuthListener(userId, authCount), keyStore, keyStore != NULL);
                    if (clearKeys) {
                        g_msgBus->ClearKeyStore();
                    }
                }
            } else {
                QCC_LogError(status, ("BusAttachment::Start failed"));
            }
        }
        LocalTestObject1* testObj1 = NULL;
        LocalTestObject2* testObj2 = NULL;

        /* Register object for sending signal and start the bus */
        if (1 == nameIndex) {
            testObj1 = new LocalTestObject1(*g_msgBus, ::abcd::ObjectPath, signalDelay, disconnectDelay, reportInterval, maxSignals, testIntf1, testIntf2);
            g_msgBus->RegisterBusObject(*testObj1);
        } else {
            testObj2 = new LocalTestObject2(*g_msgBus, ::efgh::ObjectPath, signalDelay, disconnectDelay, reportInterval, maxSignals, testIntf3, testIntf4);
            g_msgBus->RegisterBusObject(*testObj2);
        }

        /* Connect to the bus */
        if (ER_OK == status) {
            if (connectArgs.empty()) {
                status = g_msgBus->Connect();
            } else {
                status = g_msgBus->Connect(connectArgs.c_str());
            }
            if (ER_OK != status) {
                QCC_LogError(status, ("BusAttachment::Connect(\"%s\") failed", connectArgs.c_str()));
            }
        }

        if (ER_OK == status) {
            if (discoverRemote) {
                /* Begin discovery on the well-known name of the service to be called */
                findStartTime = GetTimestamp();
                /*
                 * Make sure the g_discoverEvent flag has been set to the
                 * name-not-found state before trying to find the well-known name.
                 */
                g_discoverEvent.ResetEvent();
                status = g_msgBus->FindAdvertisedName(g_wellKnownName.c_str());
                if (status != ER_OK) {
                    QCC_LogError(status, ("FindAdvertisedName failed"));
                }
            }
        }

        /*
         * If discovering, wait for the "FoundAdvertisedName" signal that tells us that we are connected to a
         * remote bus that is advertising bbservice's well-known name.
         */
        if (discoverRemote && (ER_OK == status)) {
            for (bool discovered = false; !discovered;) {
                /*
                 * We want to wait for the discover event, but we also want to
                 * be able to interrupt discovery with a control-C.  The AllJoyn
                 * idiom for waiting for more than one thing this is to create a
                 * vector of things to wait on.  To provide quick response we
                 * poll the g_interrupt bit every 100 ms using a 100 ms timer
                 * event.
                 */
                qcc::Event timerEvent(100, 100);
                vector<qcc::Event*> checkEvents, signaledEvents;
                checkEvents.push_back(&g_discoverEvent);
                checkEvents.push_back(&timerEvent);
                status = qcc::Event::Wait(checkEvents, signaledEvents);
                if (status != ER_OK && status != ER_TIMEOUT) {
                    break;
                }

                /*
                 * If it was the discover event that popped, we're done.
                 */
                for (vector<qcc::Event*>::iterator i = signaledEvents.begin(); i != signaledEvents.end(); ++i) {
                    if (*i == &g_discoverEvent) {
                        discovered = true;
                        break;
                    }
                }
                /*
                 * If we see the g_interrupt bit, we're also done.  Set an error
                 * condition so we don't do anything else.
                 */
                if (g_interrupt) {
                    status = ER_FAIL;
                    break;
                }
            }
        } else if (waitForService && (ER_OK == status)) {
            /* If policyService's well-known name is not currently on the bus yet, then wait for it to appear */
            bool hasOwner = false;
            g_discoverEvent.ResetEvent();
            status = g_msgBus->NameHasOwner(g_wellKnownName.c_str(), hasOwner);
            if ((ER_OK == status) && !hasOwner) {
                QCC_SyncPrintf("Waiting for name %s to appear on the bus\n", g_wellKnownName.c_str());
                status = Event::Wait(g_discoverEvent);
                if (ER_OK != status) {
                    QCC_LogError(status, ("Event::Wait failed"));
                }
            }
        }

        if ((ER_OK == status) && fMethodCall) {
            QCC_SyncPrintf("Method call...\n");

            /* Create the remote object that will be called */
            ProxyBusObject remoteObj;
            if (ER_OK == status) {
                remoteObj = ProxyBusObject(*g_msgBus, g_wellKnownName.c_str(), g_objectPath.c_str(), g_busListener->GetSessionId(), objSecure);

                /* Get desired interface name */
                getInterfaceName(nameIndex, interfaceIndex);

                const InterfaceDescription* alljoynTestIntf = g_msgBus->GetInterface(g_interfaceName.c_str());

                assert(alljoynTestIntf);
                remoteObj.AddInterface(*alljoynTestIntf);


                /* Enable security if it is needed */
                if ((remoteObj.IsSecure() || (secPolicy == AJ_IFC_SECURITY_REQUIRED)) && !g_msgBus->IsPeerSecurityEnabled()) {
                    QCC_SyncPrintf("Enabling peer security\n");
                    g_msgBus->EnablePeerSecurity("ALLJOYN_SRP_KEYX ALLJOYN_PIN_KEYX ALLJOYN_RSA_KEYX ALLJOYN_SRP_LOGON",
                                                 new MyAuthListener(userId, authCount),
                                                 keyStore,
                                                 keyStore != NULL);
                }
            }

            MyMessageReceiver msgReceiver;
            size_t cnt = 0;

            /* Call the remote method */
            if ((ER_OK == status)) {
                Message reply(*g_msgBus);
                MsgArg pingArgs[2];
                const InterfaceDescription::Member* pingMethod;

                const InterfaceDescription* ifc = remoteObj.GetInterface(g_interfaceName.c_str());
                if (ifc == NULL) {
                    status = ER_BUS_NO_SUCH_INTERFACE;
                    QCC_SyncPrintf("Unable to Get InterfaceDecription for the %s interface\n",
                                   g_interfaceName.c_str());
                    break;
                }
                char buf[80];

                /* Get desired method name */
                if (methodIndex > 0) {
                    getMethodName(nameIndex, interfaceIndex, methodIndex);
                    /* Get desired error name */
                } else {
                    getErrorMethod(nameIndex, interfaceIndex, errorIndex);
                }

                snprintf(buf, 80, "Ping String %u", static_cast<unsigned int>(++cnt));
                pingArgs[0].Set("s", buf);


                pingMethod = ifc->GetMember(g_methodName.c_str());


                QCC_SyncPrintf("Sending \"%s\" to %s.%s synchronously\n",
                               buf, g_interfaceName.c_str(), pingMethod->name.c_str());

                status = remoteObj.MethodCall(*pingMethod, pingArgs, (pingDelay > 0) ? 2 : 1, reply, pingDelay + 50000);

                if (ER_OK == status) {
                    QCC_SyncPrintf("%s:%s:%s ( path=%s ) returned \"%s\"\n",
                                   g_wellKnownName.c_str(),
                                   g_interfaceName.c_str(),
                                   pingMethod->name.c_str(),
                                   g_objectPath.c_str(),
                                   reply->GetArg(0)->v_string.str);

                } else if (status == ER_BUS_REPLY_IS_ERROR_MESSAGE) {
                    qcc::String errDescription;
                    const char* errName = reply->GetErrorName(&errDescription);
                    QCC_SyncPrintf("MethodCall on %s.%s reply was error %s %s\n", g_interfaceName.c_str(), pingMethod->name.c_str(), errName, errDescription.c_str());
                    status = ER_OK;
                } else {
                    QCC_LogError(status, ("MethodCall on %s.%s failed", g_interfaceName.c_str(), pingMethod->name.c_str()));
                }

                if (pingInterval > 0) {
                    qcc::Sleep(pingInterval);
                }
            }

        }


        /* Start sending signals */
        if (ER_OK == status && fSendSignal) {
            QCC_SyncPrintf("Sending signal...\n");
            QStatus status = ER_OK;

            if (1 == nameIndex) {
                if (1 == interfaceIndex) {
                    if (1 == signalIndex) {
                        status = testObj1->SendSignalA();
                    } else {
                        status = testObj1->SendSignalB();
                    }
                } else {
                    if (1 == signalIndex) {
                        status = testObj1->SendSignalC();
                    } else {
                        status = testObj1->SendSignalD();
                    }
                }
            } else {
                if (1 == interfaceIndex) {
                    if (1 == signalIndex) {
                        status = testObj2->SendSignalE();
                    } else {
                        status = testObj2->SendSignalF();
                    }
                } else {
                    if (1 == signalIndex) {
                        status = testObj2->SendSignalG();
                    } else {
                        status = testObj2->SendSignalH();
                    }
                }
            }


            if (status != ER_OK) {
                QCC_LogError(status, ("Failed to send signal"));
                break;
            }


            if (g_interrupt) {
                break;
            }

        }

        if (status == ER_OK && waitForSigint) {
            while (g_interrupt == false) {
                qcc::Sleep(100);
            }
        }

        /* Deallocate bus */
        delete g_msgBus;
        g_msgBus = NULL;

        delete g_busListener;
        g_busListener = NULL;

        if (status != ER_OK) {
            break;
        }
    }

#ifdef ROUTER
    AllJoynRouterShutdown();
#endif
    AllJoynShutdown();

    printf("policyClient exiting with status %d (%s)\n", status, QCC_StatusText(status));

    return (int) status;
}
