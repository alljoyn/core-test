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
#include "ajtcscTestCommon.h"
#include <alljoyn/ApplicationStateListener.h>
#include <alljoyn/SecurityApplicationProxy.h>

#include <queue>

#include "InMemoryKeyStore.h"
#include "PermissionMgmtObj.h"
#include "PermissionMgmtTest.h"

using namespace ajn;
using namespace qcc;
using namespace std;
/*
 * The unit test use many busy wait loops.  The busy wait loops were chosen
 * over thread sleeps because of the ease of understanding the busy wait loops.
 * Also busy wait loops do not require any platform specific threading code.
 */
#define WAIT_MSECS 5

static const char* const testInterface[] = {
    "org.allseen.test.SecurityApplication.rules",
    "?Echo <s >s",
    "!Chirp >s",
    "@Prop1=i",
    "@Prop2=i",
    NULL
};

#define APP_GET_PROP        AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_GET)
#define APP_SET_PROP        AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_SET)
#define APP_ECHO            AJ_APP_MESSAGE_ID(0, 1, 0)
#define APP_CHIRP           AJ_APP_MESSAGE_ID(0, 1, 1)
#define APP_PROP1           AJ_APP_PROPERTY_ID(0, 1, 2)
#define APP_PROP2           AJ_APP_PROPERTY_ID(0, 1, 3)

#define PRX_GET_PROP        AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_GET)
#define PRX_SET_PROP        AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_SET)
#define PRX_ECHO            AJ_PRX_MESSAGE_ID(0, 1, 0)
#define PRX_CHIRP           AJ_PRX_MESSAGE_ID(0, 1, 1)
#define PRX_PROP1           AJ_PRX_PROPERTY_ID(0, 1, 2)
#define PRX_PROP2           AJ_PRX_PROPERTY_ID(0, 1, 3)

static const AJ_InterfaceDescription testInterfaces[] = {
    AJ_PropertiesIface,
    testInterface,
    NULL
};

static AJ_Object AppObjects[] = {
    { "/test", testInterfaces, 0 },
    { NULL }
};

static int32_t prop1;
static int32_t prop2;

static AJ_Status PropGetHandler(AJ_Message* msg, uint32_t id, void* context)
{
    QCC_UNUSED(context);
    switch (id) {
    case APP_PROP1:
        AJ_MarshalArgs(msg, "i", prop1);
        printf("Get Prop1: %d\n", prop1);
        return AJ_OK;

    case APP_PROP2:
        AJ_MarshalArgs(msg, "i", prop2);
        printf("Get Prop2: %d\n", prop2);
        return AJ_OK;

    default:
        return AJ_ERR_UNEXPECTED;
    }
}

static AJ_Status PropSetHandler(AJ_Message* msg, uint32_t id, void* context)
{
    QCC_UNUSED(context);
    switch (id) {
    case APP_PROP1:
        AJ_UnmarshalArgs(msg, "i", &prop1);
        printf("Set Prop1: %d\n", prop1);
        return AJ_OK;

    case APP_PROP2:
        AJ_UnmarshalArgs(msg, "i", &prop2);
        printf("Set Prop2: %d\n", prop2);
        return AJ_OK;

    default:
        return AJ_ERR_UNEXPECTED;
    }
}

static AJ_Status AuthListenerCallback(uint32_t authmechanism, uint32_t command, AJ_Credential* cred)
{
    AJ_Status status = AJ_ERR_INVALID;

    AJ_AlwaysPrintf(("AuthListenerCallback authmechanism %d command %d\n", authmechanism, command));

    switch (authmechanism) {
    case AUTH_SUITE_ECDHE_NULL:
        cred->expiration = 1;
        status = AJ_OK;
        break;

    default:
        break;
    }
    return status;
}

static void AuthCallback(const void* context, AJ_Status status)
{
    *((AJ_Status*)context) = status;
}

#define UNMARSHAL_TIMEOUT  (1000 * 5)
class TCThread : public Thread {

  public:
    qcc::ThreadReturn STDCALL Run(void* arg){
        QCC_UNUSED(arg);
        AJ_Message msg;
        while (running) {
            TCStatus = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);
            //printf("TC unmarshal ... %s\n", AJ_StatusText(TCStatus));
            if (AJ_ERR_TIMEOUT == TCStatus && AJ_ERR_LINK_TIMEOUT == AJ_BusLinkStateProc(&bus)) {
                TCStatus = AJ_ERR_READ;
            }
            if (AJ_ERR_READ == TCStatus) {
                running = FALSE;
                break;
            } else if (AJ_OK == TCStatus) {
                uint16_t port;
                uint32_t sessionId;
                const char* str;
                switch (msg.msgId) {
                case AJ_REPLY_ID(AJ_METHOD_BIND_SESSION_PORT):
                    uint32_t disposition;
                    if (msg.hdr->msgType == AJ_MSG_ERROR) {
                        printf("BindSessionPort(bus=%p): AJ_METHOD_BIND_SESSION_PORT: %s\n", &bus, msg.error);
                    } else {
                        AJ_UnmarshalArgs(&msg, "uq", &disposition, &port);
                        if (port == sessionPort) {
                            printf("BindSessionPort(bus=%p): AJ_METHOD_BIND_SESSION_PORT %d OK\n", &bus, port);
                            bound = TRUE;
                        } else {
                            printf("BindSessionPort(bus=%p): AJ_METHOD_BIND_SESSION_PORT %d BUS\n", &bus, port);
                            AJ_ResetArgs(&msg);
                            AJ_BusHandleBusMessage(&msg);
                        }
                    }
                    break;

                case AJ_REPLY_ID(AJ_METHOD_JOIN_SESSION):
                    uint32_t replyCode;
                    if (AJ_MSG_ERROR != msg.hdr->msgType) {
                        AJ_UnmarshalArgs(&msg, "uu", &replyCode, &sessionId);
                        if (replyCode == AJ_JOINSESSION_REPLY_SUCCESS) {
                            printf("Joined session session_id=%u\n", sessionId);
                            session = sessionId;
                        } else {
                            printf("Joined session failed\n");
                        }
                    }
                    break;

                case AJ_METHOD_ACCEPT_SESSION:
                    AJ_UnmarshalArgs(&msg, "qus", &port, &sessionId, &str);
                    if (port == sessionPort) {
                        session = sessionId;
                        AJ_BusReplyAcceptSession(&msg, TRUE);
                        printf("Accepted session session_id=%u joiner=%s\n", sessionId, str);
                    } else {
                        AJ_ResetArgs(&msg);
                        AJ_BusHandleBusMessage(&msg);
                    }
                    break;

                case APP_ECHO:
                    AJ_Message reply;
                    AJ_UnmarshalArgs(&msg, "s", &str);
                    printf("Echo: %s\n", str);
                    AJ_MarshalReplyMsg(&msg, &reply);
                    AJ_MarshalArgs(&reply, "s", str);
                    AJ_DeliverMsg(&reply);
                    break;

                case APP_CHIRP:
                    AJ_UnmarshalArgs(&msg, "s", &str);
                    printf("Chirp: %s\n", str);
                    signalReceivedFlag = TRUE;
                    break;

                case APP_GET_PROP:
                    AJ_BusPropGet(&msg, PropGetHandler, NULL);
                    break;

                case APP_SET_PROP:
                    AJ_BusPropSet(&msg, PropSetHandler, NULL);
                    break;

                case AJ_REPLY_ID(PRX_ECHO):
                    if (AJ_MSG_ERROR == msg.hdr->msgType) {
                        strncpy(response, msg.error, sizeof (response));
                        SCStatus = ER_BUS_REPLY_IS_ERROR_MESSAGE;
                    } else {
                        const char* resp;
                        AJ_UnmarshalArgs(&msg, "s", &resp);
                        strncpy(response, resp, sizeof (response));
                        SCStatus = ER_OK;
                    }
                    printf("Echo Reply: %s\n", response);
                    break;

                case AJ_REPLY_ID(PRX_GET_PROP):
                    if (AJ_MSG_ERROR == msg.hdr->msgType) {
                        strncpy(response, msg.error, sizeof (response));
                        SCStatus = ER_BUS_REPLY_IS_ERROR_MESSAGE;
                    } else {
                        const char* sig;
                        AJ_UnmarshalVariant(&msg, &sig);
                        AJ_UnmarshalArgs(&msg, sig, &propval);
                        SCStatus = ER_OK;
                    }
                    break;

                case AJ_REPLY_ID(PRX_SET_PROP):
                case AJ_REPLY_ID(AJ_METHOD_MANAGED_RESET):
                    if (AJ_MSG_ERROR == msg.hdr->msgType) {
                        strncpy(response, msg.error, sizeof (response));
                        SCStatus = ER_BUS_REPLY_IS_ERROR_MESSAGE;
                    } else {
                        SCStatus = ER_OK;
                    }
                    break;

                default:
                    /*
                     * Pass to the built-in bus message handlers
                     */
                    AJ_BusHandleBusMessage(&msg);
                    break;
                }
            }
            AJ_CloseMsg(&msg);
        }

        AJ_Disconnect(&bus);
        return this;
    }
    void SetUp(const char* router) {
        AJ_AlwaysPrintf(("TC SetUp %s\n", router));
        AJ_Initialize();
        // Ensure that a routing node is found as quickly as possible
        //AJ_SetSelectionTimeout(10);
        AJ_FindBusAndConnect(&bus, router, TC_LEAFNODE_CONNECT_TIMEOUT);
        //This resets the keystore
        AJ_ClearCredentials(0);
        AJ_BusSetAuthListenerCallback(&bus, AuthListenerCallback);
        PrintXML(AppObjects);
        running = TRUE;
        sessionPort = 0;
        prop1 = 42;
        prop2 = 17;
        signalReceivedFlag = FALSE;
    }
    QStatus Stop() {
        running = FALSE;
        AJ_Net_Interrupt();
        return Thread::Stop();
    }
    qcc::String GetUniqueName() {
        return qcc::String(bus.uniqueName);
    }
    QStatus EnablePeerSecurity(const char* mechanisms, AuthListener* listener, const char* keystore = NULL, bool shared = FALSE) {
        QCC_UNUSED(listener);
        QCC_UNUSED(keystore);
        QCC_UNUSED(shared);
        qcc::String str(mechanisms);
        uint32_t suites[AJ_AUTH_SUITES_NUM] = { 0 };
        size_t numsuites = 0;
        if (qcc::String::npos != str.find("ALLJOYN_ECDHE_NULL")) {
            suites[numsuites++] = AUTH_SUITE_ECDHE_NULL;
        }
        if (qcc::String::npos != str.find("ALLJOYN_ECDHE_PSK")) {
            suites[numsuites++] = AUTH_SUITE_ECDHE_PSK;
        }
        if (qcc::String::npos != str.find("ALLJOYN_ECDHE_ECDSA")) {
            suites[numsuites++] = AUTH_SUITE_ECDHE_ECDSA;
        }
        AJ_BusEnableSecurity(&bus, suites, numsuites);
        return ER_OK;
    }
    void SetApplicationState(uint16_t state) {
        AJ_SecuritySetClaimConfig(&bus, state, CLAIM_CAPABILITY_ECDHE_PSK | CLAIM_CAPABILITY_ECDHE_NULL, 0);
    }
    void SetPermissionManifest(AJ_Manifest* manifest) {
        AJ_ManifestTemplateSet(manifest);
    }
    void PrintXML(const AJ_Object* objs) {
        AJ_PrintXML(objs);
    }
    void RegisterObjects(AJ_Object* objs, AJ_Object* prxs, uint8_t secure) {
        uint8_t n;
        AJ_Object* tmp;
        tmp = objs;
        n = 0;
        while (tmp[n].path) {
            if (secure) {
                tmp[n].flags |= AJ_OBJ_FLAG_SECURE;
            } else {
                tmp[n].flags &= ~AJ_OBJ_FLAG_SECURE;
            }
            n++;
        }
        tmp = prxs;
        n = 0;
        while (tmp[n].path) {
            if (secure) {
                tmp[n].flags |= AJ_OBJ_FLAG_SECURE;
            } else {
                tmp[n].flags &= ~AJ_OBJ_FLAG_SECURE;
            }
            n++;
        }
        AJ_RegisterObjects(objs, prxs);
    }
    QStatus BindSessionPort(uint16_t port) {
        bound = FALSE;
        sessionPort = port;
        AJ_BusBindSessionPort(&bus, port, NULL, 0);
        for (int msec = 0; msec < 10000; msec += WAIT_MSECS) {
            if (bound) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }
        return bound ? ER_OK : ER_FAIL;
    }
    QStatus JoinSession(const char* host, uint16_t port, SessionListener* listener, uint32_t& id, SessionOpts& opts) {
        QCC_UNUSED(listener);
        QCC_UNUSED(opts);
        session = 0;
        sessionPort = port;
        AJ_BusJoinSession(&bus, host, port, NULL);
        for (int msec = 0; msec < 10000; msec += WAIT_MSECS) {
            if (session) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }
        if (!session) {
            return ER_FAIL;
        }
        id = session;
        if (session) {
            return AuthenticatePeer(host);
        }
        return ER_FAIL;
    }
    QStatus AuthenticatePeer(const char* host) {
        AJ_Status authStatus = AJ_ERR_NULL;
        AJ_BusAuthenticatePeer(&bus, host, AuthCallback, &authStatus);
        /* Wait for authentication to pass */
        for (int msec = 0; msec < 10000; msec += WAIT_MSECS) {
            if (AJ_ERR_NULL != authStatus) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }
        return (AJ_OK == authStatus) ? ER_OK : ER_FAIL;
    }
    uint32_t ReadProp1() {
        return prop1;
    }
    uint32_t ReadProp2() {
        return prop2;
    }
    QStatus GetProperty(const char* peer, uint32_t id) {
        AJ_Status status;
        AJ_Message msg;
        AJ_MarshalMethodCall(&bus, &msg, PRX_GET_PROP, peer, session, 0, 25000);
        SCStatus = ER_FAIL;
        response[0] = '\0';
        propid = id;
        status = AJ_MarshalPropertyArgs(&msg, propid);
        if (AJ_OK != status) {
            if (AJ_ERR_ACCESS == status) {
                return ER_PERMISSION_DENIED;
            }
            return ER_FAIL;
        }
        AJ_DeliverMsg(&msg);
        return ER_OK;
    }
    QStatus GetPropertyReply(int32_t& i) {
        for (int msec = 0; msec < 10000; msec += WAIT_MSECS) {
            if (ER_FAIL != SCStatus) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }
        if (ER_OK == SCStatus) {
            i = propval;
        }
        return SCStatus;
    }
    QStatus SetProperty(const char* peer, uint32_t id, int32_t i) {
        AJ_Status status;
        AJ_Message msg;
        AJ_MarshalMethodCall(&bus, &msg, PRX_SET_PROP, peer, session, 0, 25000);
        SCStatus = ER_FAIL;
        response[0] = '\0';
        propid = id;
        status = AJ_MarshalPropertyArgs(&msg, propid);
        if (AJ_OK != status) {
            if (AJ_ERR_ACCESS == status) {
                return ER_PERMISSION_DENIED;
            }
            return ER_FAIL;
        }
        AJ_MarshalArgs(&msg, "i", i);
        AJ_DeliverMsg(&msg);
        return ER_OK;
    }
    QStatus SetPropertyReply() {
        for (int msec = 0; msec < 10000; msec += WAIT_MSECS) {
            if (ER_FAIL != SCStatus) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }
        return SCStatus;
    }
    QStatus MethodCall(const char* peer, uint32_t id, const char* str) {
        AJ_Status status;
        AJ_Message msg;
        SCStatus = ER_FAIL;
        response[0] = '\0';
        status = AJ_MarshalMethodCall(&bus, &msg, id, peer, session, 0, 25000);
        if (AJ_OK != status) {
            if (AJ_ERR_ACCESS == status) {
                return ER_PERMISSION_DENIED;
            }
            return ER_FAIL;
        }
        if (NULL != str) {
            AJ_MarshalArgs(&msg, "s", str);
        }
        AJ_DeliverMsg(&msg);
        return ER_OK;
    }
    QStatus MethodCallReply() {
        for (int msec = 0; msec < 10000; msec += WAIT_MSECS) {
            if (ER_FAIL != SCStatus) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }
        return SCStatus;
    }
    QStatus Signal(const char* peer, const char* mbr, const char* str) {
        AJ_Status status;
        AJ_Message msg;
        SCStatus = ER_FAIL;
        if (0 == strncmp(mbr, "Chirp", 5)) {
            status = AJ_MarshalSignal(&bus, &msg, PRX_CHIRP, peer, session, 0, 0);
            if (AJ_OK != status) {
                if (AJ_ERR_ACCESS == status) {
                    return ER_PERMISSION_DENIED;
                }
                return ER_FAIL;
            }
            AJ_MarshalArgs(&msg, "s", str);
            AJ_DeliverMsg(&msg);
            return ER_OK;
        }
        return SCStatus;
    }
    const char* GetErrorName() {
        return response;
    }
    const char* GetResponse() {
        return response;
    }

    bool running;
    bool bound;
    AJ_Status TCStatus;
    AJ_BusAttachment bus;
    uint16_t sessionPort;
    uint32_t session;
    bool signalReceivedFlag;
    QStatus SCStatus;
    char response[1024];
    uint32_t propid;
    int32_t propval;
};

class DefaultPolicy_ApplicationStateListener : public ApplicationStateListener {
  public:
    DefaultPolicy_ApplicationStateListener() : stateMap() { }

    virtual void State(const char* busName, const qcc::KeyInfoNISTP256& publicKeyInfo, PermissionConfigurator::ApplicationState state) {
        QCC_UNUSED(publicKeyInfo);
        stateMap[busName] = state;
    }

    bool isClaimed(const String& busName) {
        if (stateMap.count(busName) > 0) {
            if (stateMap.find(busName)->second == PermissionConfigurator::ApplicationState::CLAIMED) {
                return true;
            }
        }
        return false;
    }
    map<String, PermissionConfigurator::ApplicationState> stateMap;
};

class DefaultPolicyTestSessionPortListener : public SessionPortListener {
  public:
    virtual bool AcceptSessionJoiner(SessionPort sessionPort, const char* joiner, const SessionOpts& opts) {
        QCC_UNUSED(sessionPort);
        QCC_UNUSED(joiner);
        QCC_UNUSED(opts);
        return true;
    }
};

class DefaultRulesTestBusObject : public BusObject {
  public:
    DefaultRulesTestBusObject(BusAttachment& bus, const char* path, const char* interfaceName, bool announce = true)
        : BusObject(path), isAnnounced(announce), prop1(42), prop2(17) {
        const InterfaceDescription* iface = bus.GetInterface(interfaceName);
        EXPECT_TRUE(iface != NULL) << "NULL InterfaceDescription* for " << interfaceName;
        if (iface == NULL) {
            printf("The interfaceDescription pointer for %s was NULL when it should not have been.\n", interfaceName);
            return;
        }

        if (isAnnounced) {
            AddInterface(*iface, ANNOUNCED);
        } else {
            AddInterface(*iface, UNANNOUNCED);
        }

        /* Register the method handlers with the object */
        const MethodEntry methodEntries[] = {
            { iface->GetMember("Echo"), static_cast<MessageReceiver::MethodHandler>(&DefaultRulesTestBusObject::Echo) }
        };
        EXPECT_EQ(ER_OK, AddMethodHandlers(methodEntries, sizeof(methodEntries) / sizeof(methodEntries[0])));
    }

    void Echo(const InterfaceDescription::Member* member, Message& msg) {
        QCC_UNUSED(member);
        const MsgArg* arg((msg->GetArg(0)));
        QStatus status = MethodReply(msg, arg, 1);
        EXPECT_EQ(ER_OK, status) << "Echo: Error sending reply";
    }

    QStatus Get(const char* ifcName, const char* propName, MsgArg& val)
    {
        QCC_UNUSED(ifcName);
        QStatus status = ER_OK;
        if (0 == strcmp("Prop1", propName)) {
            val.Set("i", prop1);
        } else if (0 == strcmp("Prop2", propName)) {
            val.Set("i", prop2);
        } else {
            status = ER_BUS_NO_SUCH_PROPERTY;
        }
        return status;

    }

    QStatus Set(const char* ifcName, const char* propName, MsgArg& val)
    {
        QCC_UNUSED(ifcName);
        QStatus status = ER_OK;
        if ((0 == strcmp("Prop1", propName)) && (val.typeId == ALLJOYN_INT32)) {
            val.Get("i", &prop1);
        } else if ((0 == strcmp("Prop2", propName)) && (val.typeId == ALLJOYN_INT32)) {
            val.Get("i", &prop2);
        } else {
            status = ER_BUS_NO_SUCH_PROPERTY;
        }
        return status;
    }
    int32_t ReadProp1() {
        return prop1;
    }
  private:
    bool isAnnounced;
    int32_t prop1;
    int32_t prop2;
};

class ChirpSignalReceiver : public MessageReceiver {
  public:
    ChirpSignalReceiver() : signalReceivedFlag(false) { }
    void ChirpSignalHandler(const InterfaceDescription::Member* member,
                            const char* sourcePath, Message& msg) {
        QCC_UNUSED(member);
        QCC_UNUSED(sourcePath);
        QCC_UNUSED(msg);
        signalReceivedFlag = true;
    }
    bool signalReceivedFlag;
};

class SecurityDefaultPolicyTest : public testing::Test {
  public:
    SecurityDefaultPolicyTest() :
        managerBus("SecurityPolicyRulesManager"),
        SCBus("SecurityPolicyRulesSC"),
        managerSessionPort(42),
        SCSessionPort(42),
        TCSessionPort(42),
        managerToManagerSessionId(0),
        managerToSCSessionId(0),
        managerToTCSessionId(0),
        interfaceName("org.allseen.test.SecurityApplication.rules"),
        managerAuthListener(NULL),
        SCAuthListener(NULL),
        appStateListener()
    {
    }

    virtual void SetUp() {
        EXPECT_EQ(ER_OK, managerBus.Start());
        EXPECT_EQ(ER_OK, managerBus.Connect());
        EXPECT_EQ(ER_OK, SCBus.Start());
        EXPECT_EQ(ER_OK, SCBus.Connect());

        // Register in memory keystore listeners
        EXPECT_EQ(ER_OK, managerBus.RegisterKeyStoreListener(managerKeyStoreListener));
        EXPECT_EQ(ER_OK, SCBus.RegisterKeyStoreListener(SCKeyStoreListener));

        managerAuthListener = new DefaultECDHEAuthListener();
        SCAuthListener = new DefaultECDHEAuthListener();

        // To avoid cross-talk, i.e. thin leaf node connect to unintended
        // routing nodes, generate and advertise a random routing node prefix.
        qcc::String routingNodePrefix = "test.rnPrefix.randhex" +
                                        qcc::RandHexString(64);
        qcc::String advertisingPrefix = "quiet@" + routingNodePrefix;
        ASSERT_EQ(ER_OK, managerBus.AdvertiseName(advertisingPrefix.c_str(), ajn::TRANSPORT_ANY));

        TCBus.SetUp(routingNodePrefix.c_str());
        TCBus.Start();

        EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", managerAuthListener));
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", NULL));

        // We are not marking the interface as a secure interface. Some of the
        // tests don't use security. So we use Object based security for any
        // test that security is required.
        interface = "<node>"
                    "<interface name='" + String(interfaceName) + "'>"
                    "  <method name='Echo'>"
                    "    <arg name='shout' type='s' direction='in'/>"
                    "    <arg name='reply' type='s' direction='out'/>"
                    "  </method>"
                    "  <signal name='Chirp'>"
                    "    <arg name='tweet' type='s'/>"
                    "  </signal>"
                    "  <property name='Prop1' type='i' access='readwrite'/>"
                    "  <property name='Prop2' type='i' access='readwrite'/>"
                    "</interface>"
                    "</node>";

        EXPECT_EQ(ER_OK, managerBus.CreateInterfacesFromXml(interface.c_str()));
        EXPECT_EQ(ER_OK, SCBus.CreateInterfacesFromXml(interface.c_str()));

        SessionOpts opts1;
        EXPECT_EQ(ER_OK, managerBus.BindSessionPort(managerSessionPort, opts1, managerSessionPortListener));

        SessionOpts opts2;
        EXPECT_EQ(ER_OK, SCBus.BindSessionPort(SCSessionPort, opts2, SCSessionPortListener));

        SessionOpts opts3;
        EXPECT_EQ(ER_OK, TCBus.BindSessionPort(TCSessionPort));

        EXPECT_EQ(ER_OK, managerBus.JoinSession(managerBus.GetUniqueName().c_str(), managerSessionPort, NULL, managerToManagerSessionId, opts1));
        EXPECT_EQ(ER_OK, managerBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, NULL, managerToSCSessionId, opts2));
        EXPECT_EQ(ER_OK, managerBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, managerToTCSessionId, opts3));

        SecurityApplicationProxy sapWithManager(managerBus, managerBus.GetUniqueName().c_str(), managerToManagerSessionId);
        PermissionConfigurator::ApplicationState applicationStateManager;
        EXPECT_EQ(ER_OK, sapWithManager.GetApplicationState(applicationStateManager));
        EXPECT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateManager);

        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
        PermissionConfigurator::ApplicationState applicationStateSC;
        EXPECT_EQ(ER_OK, sapWithSC.GetApplicationState(applicationStateSC));
        EXPECT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateSC);

        SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
        PermissionConfigurator::ApplicationState applicationStateTC;
        EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
        EXPECT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateTC);

        managerBus.RegisterApplicationStateListener(appStateListener);
        managerBus.AddApplicationStateRule();

        // All Inclusive manifest
        const size_t manifestSize = 1;
        PermissionPolicy::Rule manifest[manifestSize];
        manifest[0].SetObjPath("*");
        manifest[0].SetInterfaceName("*");
        {
            PermissionPolicy::Rule::Member members[1];
            members[0].Set("*",
                           PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                           PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                           PermissionPolicy::Rule::Member::ACTION_MODIFY |
                           PermissionPolicy::Rule::Member::ACTION_OBSERVE);
            manifest[0].SetMembers(1, members);
        }
        //Get manager key
        KeyInfoNISTP256 managerKey;
        PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(managerKey));

        //Create SC key
        KeyInfoNISTP256 SCKey;
        PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

        //Create TC key
        ECCPublicKey TCPublicKey;
        EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));

        uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
        EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(managerBus,
                                                                   manifest, manifestSize,
                                                                   digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

        //Create identityCert
        const size_t certChainSize = 1;
        IdentityCertificate identityCertChainMaster[certChainSize];

        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(managerBus,
                                                                      "0",
                                                                      managerGuid.ToString(),
                                                                      managerKey.GetPublicKey(),
                                                                      "ManagerAlias",
                                                                      3600,
                                                                      identityCertChainMaster[0],
                                                                      digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

        SecurityApplicationProxy sapWithManagerBus(managerBus, managerBus.GetUniqueName().c_str());
        EXPECT_EQ(ER_OK, sapWithManagerBus.Claim(managerKey,
                                                 managerGuid,
                                                 managerKey,
                                                 identityCertChainMaster, certChainSize,
                                                 manifest, manifestSize));

        for (int msec = 0; msec < 10000; msec += WAIT_MSECS) {
            if (appStateListener.isClaimed(managerBus.GetUniqueName())) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }

        ECCPublicKey managerPublicKey;
        sapWithManager.GetEccPublicKey(managerPublicKey);
        ASSERT_EQ(*managerKey.GetPublicKey(), managerPublicKey);

        ASSERT_EQ(PermissionConfigurator::ApplicationState::CLAIMED, appStateListener.stateMap[managerBus.GetUniqueName()]);

        //Create SC identityCert
        IdentityCertificate identityCertChainSC[certChainSize];


        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(managerBus,
                                                                      "0",
                                                                      managerGuid.ToString(),
                                                                      SCKey.GetPublicKey(),
                                                                      "SCAlias",
                                                                      3600,
                                                                      identityCertChainSC[0],
                                                                      digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

        //Manager claims Peers
        EXPECT_EQ(ER_OK, sapWithSC.Claim(managerKey,
                                            managerGuid,
                                            managerKey,
                                            identityCertChainSC, certChainSize,
                                            manifest, manifestSize));

        for (int msec = 0; msec < 10000; msec += WAIT_MSECS) {
            if (appStateListener.isClaimed(SCBus.GetUniqueName())) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }

        ASSERT_EQ(PermissionConfigurator::ApplicationState::CLAIMED, appStateListener.stateMap[SCBus.GetUniqueName()]);

        //Create TC identityCert
        IdentityCertificate identityCertChainTC[certChainSize];


        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(managerBus,
                                                                      "0",
                                                                      managerGuid.ToString(),
                                                                      &TCPublicKey,
                                                                      "TCAlias",
                                                                      3600,
                                                                      identityCertChainTC[0],
                                                                      digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";
        EXPECT_EQ(ER_OK, sapWithTC.Claim(managerKey,
                                            managerGuid,
                                            managerKey,
                                            identityCertChainTC, certChainSize,
                                            manifest, manifestSize));

        for (int msec = 0; msec < 10000; msec += WAIT_MSECS) {
            if (appStateListener.isClaimed(SCBus.GetUniqueName())) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }

        ASSERT_EQ(PermissionConfigurator::ApplicationState::CLAIMED, appStateListener.stateMap[SCBus.GetUniqueName()]);

        EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", managerAuthListener));
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", managerAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", NULL));
    }

    virtual void TearDown() {
        managerBus.Stop();
        managerBus.Join();
        SCBus.Stop();
        SCBus.Join();
        TCBus.Stop();
        TCBus.Join();
        delete managerAuthListener;
        delete SCAuthListener;
    }

    void InstallMemberShipOnManager() {
        //Get manager key
        KeyInfoNISTP256 managerKey;
        PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(managerKey));

        String membershipSerial = "1";
        qcc::MembershipCertificate managerMembershipCertificate[1];
        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert(membershipSerial,
                                                                        managerBus,
                                                                        managerBus.GetUniqueName(),
                                                                        managerKey.GetPublicKey(),
                                                                        managerGuid,
                                                                        false,
                                                                        3600,
                                                                        managerMembershipCertificate[0]
                                                                        ));
        SecurityApplicationProxy sapWithManagerBus(managerBus, managerBus.GetUniqueName().c_str());
        EXPECT_EQ(ER_OK, sapWithManagerBus.InstallMembership(managerMembershipCertificate, 1));
    }

    void InstallMemberShipOnSC() {
        //Create SC key
        KeyInfoNISTP256 SCKey;
        PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

        String membershipSerial = "1";
        qcc::MembershipCertificate SCMembershipCertificate[1];
        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert(membershipSerial,
                                                                        managerBus,
                                                                        SCBus.GetUniqueName(),
                                                                        SCKey.GetPublicKey(),
                                                                        managerGuid,
                                                                        false,
                                                                        3600,
                                                                        SCMembershipCertificate[0]
                                                                        ));
        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
        EXPECT_EQ(ER_OK, sapWithSC.InstallMembership(SCMembershipCertificate, 1));
    }

    void InstallMemberShipOnTC() {
        SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
        //Create TC key
        ECCPublicKey TCPublicKey;
        EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));

        String membershipSerial = "1";
        qcc::MembershipCertificate TCMembershipCertificate[1];
        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert(membershipSerial,
                                                                        managerBus,
                                                                        TCBus.GetUniqueName(),
                                                                        &TCPublicKey,
                                                                        managerGuid,
                                                                        false,
                                                                        3600,
                                                                        TCMembershipCertificate[0]
                                                                        ));
        EXPECT_EQ(ER_OK, sapWithTC.InstallMembership(TCMembershipCertificate, 1));
    }

    /*
     * Creates a PermissionPolicy that allows everything.
     * @policy[out] the policy to set
     * @version[in] the version number for the policy
     */
    void GeneratePermissivePolicy(PermissionPolicy& policy, uint32_t version) {
        policy.SetVersion(version);
        {
            PermissionPolicy::Acl acls[1];
            {
                PermissionPolicy::Peer peers[1];
                peers[0].SetType(PermissionPolicy::Peer::PEER_ALL);
                acls[0].SetPeers(1, peers);
            }
            {
                PermissionPolicy::Rule rules[1];
                rules[0].SetObjPath("*");
                rules[0].SetInterfaceName("*");
                {
                    PermissionPolicy::Rule::Member members[1];
                    members[0].Set("*",
                                   PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                                   PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                                   PermissionPolicy::Rule::Member::ACTION_MODIFY |
                                   PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                    rules[0].SetMembers(1, members);
                }
                acls[0].SetRules(1, rules);
            }
            policy.SetAcls(1, acls);
        }
    }

    QStatus UpdatePolicyWithValuesFromDefaultPolicy(const PermissionPolicy& defaultPolicy,
                                                    PermissionPolicy& policy,
                                                    bool keepCAentry = true,
                                                    bool keepAdminGroupEntry = false,
                                                    bool keepInstallMembershipEntry = false) {
        size_t count = policy.GetAclsSize();
        if (keepCAentry) {
            ++count;
        }
        if (keepAdminGroupEntry) {
            ++count;
        }
        if (keepInstallMembershipEntry) {
            ++count;
        }

        PermissionPolicy::Acl* acls = new PermissionPolicy::Acl[count];
        size_t idx = 0;
        for (size_t cnt = 0; cnt < defaultPolicy.GetAclsSize(); ++cnt) {
            if (defaultPolicy.GetAcls()[cnt].GetPeersSize() > 0) {
                if (defaultPolicy.GetAcls()[cnt].GetPeers()[0].GetType() == PermissionPolicy::Peer::PEER_FROM_CERTIFICATE_AUTHORITY) {
                    if (keepCAentry) {
                        acls[idx++] = defaultPolicy.GetAcls()[cnt];
                    }
                } else if (defaultPolicy.GetAcls()[cnt].GetPeers()[0].GetType() == PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP) {
                    if (keepAdminGroupEntry) {
                        acls[idx++] = defaultPolicy.GetAcls()[cnt];
                    }
                } else if (defaultPolicy.GetAcls()[cnt].GetPeers()[0].GetType() == PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY) {
                    if (keepInstallMembershipEntry) {
                        acls[idx++] = defaultPolicy.GetAcls()[cnt];
                    }
                }
            }

        }
        for (size_t cnt = 0; cnt < policy.GetAclsSize(); ++cnt) {
            assert(idx <= count);
            acls[idx++] = policy.GetAcls()[cnt];
        }
        policy.SetAcls(count, acls);
        delete [] acls;
        return ER_OK;
    }
    BusAttachment managerBus;
    BusAttachment SCBus;
    TCThread TCBus;

    SessionPort managerSessionPort;
    SessionPort SCSessionPort;
    SessionPort TCSessionPort;

    DefaultPolicyTestSessionPortListener managerSessionPortListener;
    DefaultPolicyTestSessionPortListener SCSessionPortListener;

    SessionId managerToManagerSessionId;
    SessionId managerToSCSessionId;
    SessionId managerToTCSessionId;

    InMemoryKeyStoreListener managerKeyStoreListener;
    InMemoryKeyStoreListener SCKeyStoreListener;

    String interface;
    const char* interfaceName;
    DefaultECDHEAuthListener* managerAuthListener;
    DefaultECDHEAuthListener* SCAuthListener;

    DefaultPolicy_ApplicationStateListener appStateListener;

    //Random GUID used for the SecurityManager
    GUID128 managerGuid;
};

/*
 * Purpose:
 * On the app's default policy, ASG member can send and receive messages
 * securely with the claimed app.
 *
 * app bus  implements the following message types: method call, signal,
 * property 1, property 2.
 * ASG bus implements the following message types: method call, signal, property
 * 1, property 2.
 *
 * app. bus is claimed by the ASGA.
 * ASG bus has a MC signed by ASGA.
 * app. bus has default policy.
 * ASG bus has a policy that allow everything.
 *
 * ASG bus and app. bus have enabled ECDHE_ECDSA auth. mechanism.
 * Both peers have a default manifest that allows everything.
 *
 * 1. App. bus makes a method call, get property call, set property call, getall
 *    properties call on the ASG bus.
 * 2. App. bus sends a signal to to the ASG bus.
 * 3. ASG bus makes a method call, get property call, set property call, getall
 *    properties call on the app. bus.
 * 4. ASG bus sends a signal to the app. bus.
 * 5. ASG bus calls Reset on the app. bus.
 *
 * Verification:
 * 1. Method call, get property, set property, getall properties are successful.
 * 2. The signal is received by the ASG bus.
 * 3. Method call, get property, set property, getall properties are successful.
 * 4. The signal is received by the app. bus.
 * 5. Verify that Reset method call was successful.
 *
 * In this test managerBus == ASGA
 *              peer1Bus == ASA bus
 *              peer2Bus == app. bus
 */
TEST_F(SecurityDefaultPolicyTest, DefaultPolicy_ECDSA_everything_passes)
{
    InstallMemberShipOnManager();
    InstallMemberShipOnSC();

    DefaultRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject, true));
    TCBus.RegisterObjects(AppObjects, AppObjects, true);

    /* install all permissive permission policy for SC*/
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    GeneratePermissivePolicy(SCPolicy, 1);

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));

    ProxyBusObject proxy;
    proxy = ProxyBusObject(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    
    // SC to TC
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    // Verify Method call
    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    QStatus status = proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg);
    EXPECT_EQ(ER_OK, status) << "SC failed make MethodCall call " << replyMsg->GetErrorDescription().c_str();

    if (status == ER_OK) {
        char* echoReply;
        replyMsg->GetArg(0)->Get("s", &echoReply);
        EXPECT_STREQ("String that should be Echoed back.", echoReply);
    }

    // Verify Set/Get Property and GetAll Properties
    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_OK, proxy.SetProperty(interfaceName, "Prop1", prop1Arg)) << "SC failed SetProperty call";
    EXPECT_EQ(513, TCBus.ReadProp1());

    MsgArg prop1ArgOut;
    EXPECT_EQ(ER_OK, proxy.GetProperty(interfaceName, "Prop1", prop1Arg)) << "SC failed GetProperty call";;
    int32_t prop1;
    prop1Arg.Get("i", &prop1);
    EXPECT_EQ(513, prop1);

    #ifdef NOT_DEFINED
    MsgArg props;
    EXPECT_EQ(ER_OK, proxy.GetAllProperties(interfaceName, props)) << "SC failed GetAllProperties call";;
    MsgArg* propArg;
    int32_t prop2;
    EXPECT_EQ(ER_OK, props.GetElement("{sv}", "Prop1", &propArg)) << props.ToString().c_str();
    EXPECT_EQ(ER_OK, propArg->Get("i", &prop1)) << propArg->ToString().c_str();
    EXPECT_EQ(513, prop1);

    EXPECT_EQ(ER_OK, props.GetElement("{sv}", "Prop2", &propArg)) << props.ToString().c_str();
    EXPECT_EQ(ER_OK, propArg->Get("i", &prop2)) << propArg->ToString().c_str();
    EXPECT_EQ(17, prop2);
    #endif

    // TC to SC
    // Verify Method call
    const char* s = "String that should be Echoed back.";
    EXPECT_EQ(ER_OK, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));
    EXPECT_EQ(ER_OK, TCBus.MethodCallReply());
    EXPECT_STREQ(s, TCBus.GetResponse());

    // Verify Set/Get Property and GetAll Properties
    int32_t prop = 513;
    EXPECT_EQ(ER_OK, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop));
    EXPECT_EQ(ER_OK, TCBus.SetPropertyReply());
    EXPECT_EQ(513, SCBusObject.ReadProp1());

    prop = 0;
    EXPECT_EQ(ER_OK, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1));
    EXPECT_EQ(ER_OK, TCBus.GetPropertyReply(prop));
    EXPECT_EQ(513, prop);

    #ifdef NOT_DEFINED
    MsgArg props;
    EXPECT_EQ(ER_OK, proxy.GetAllProperties(interfaceName, props)) << "Peer" << i + 1 << " failed GetAllProperties call";;
    MsgArg* propArg;
    int32_t prop2;
    EXPECT_EQ(ER_OK, props.GetElement("{sv}", "Prop1", &propArg)) << props.ToString().c_str();
    EXPECT_EQ(ER_OK, propArg->Get("i", &prop1)) << propArg->ToString().c_str();
    EXPECT_EQ(513, prop1);

    EXPECT_EQ(ER_OK, props.GetElement("{sv}", "Prop2", &propArg)) << props.ToString().c_str();
    EXPECT_EQ(ER_OK, propArg->Get("i", &prop2)) << propArg->ToString().c_str();
    EXPECT_EQ(17, prop2);
    #endif

    // SC can Send Signal
    arg.Set("s", "Chirp this String out in the signal.");
    // Signals are send and forget.  They will always return ER_OK.
    EXPECT_EQ(ER_OK, SCBusObject.Signal(TCBus.GetUniqueName().c_str(), SCToTCSessionId, *SCBus.GetInterface(interfaceName)->GetMember("Chirp"), &arg, 1, 0, 0));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < 2000; msec += WAIT_MSECS) {
        if (TCBus.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(TCBus.signalReceivedFlag) << "TC failed to receive the Signal from SC";

    // TC can Send Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver, static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler), SCBus.GetInterface(interfaceName)->GetMember("Chirp"), NULL));

    // Signals are send and forget.  They will always return ER_OK.
    EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), "Chirp", "Chirp this String out in the signal."));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < 2000; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag) << "SC failed to receive the Signal from TC";
    SCBus.UnregisterSignalHandler(&chirpSignalReceiver, static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler), SCBus.GetInterface(interfaceName)->GetMember("Chirp"), NULL);

    SecurityApplicationProxy sapSCtoTC(SCBus, TCBus.GetUniqueName().c_str(), SCToTCSessionId);
    EXPECT_EQ(ER_OK, sapSCtoTC.Reset());

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Purpose:
 * Only Trusted peers are allowed to interact with the application under default
 * policy.
 *
 * app bus  implements the following message types: method call, signal,
 * property 1, property 2.
 * ASG bus implements the following message types: method call, signal,
 * property 1, property 2.
 *
 * app. bus is claimed by the ASGA.
 * ASG bus has a MC signed by ASGA.
 * app. bus has default policy.
 * ASG bus has a policy that allows everything.
 *
 * ASG bus and app. bus have enabled ECDHE_NULL auth. mechanism.
 * Both peers have a default manifest that allows everything.
 *
 * 1. App. bus makes a method call, get property call, set property call, getall
 *    properties call on the ASG bus.
 * 2. App. bus sends a signal to to the ASG bus.
 * 3. ASG bus makes a method call, get property call, set property call, getall
 *    properties call on the app. bus.
 * 4. ASG bus sends a signal to the app. bus.
 * 5. ASG bus calls Reset on the app. bus.
 *
 * Verification:
 * The messages cannot be sent or received successfully by the app. bus.
 *
 * In this test managerBus == ASGA
 *              peer1Bus == ASA bus
 *              peer2Bus == app. bus
 */
TEST_F(SecurityDefaultPolicyTest, DefaultPolicy_ECDHE_NULL_everything_fails)
{
    InstallMemberShipOnManager();
    InstallMemberShipOnSC();

    DefaultRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject, true));
    TCBus.RegisterObjects(AppObjects, AppObjects, true);

    /* install all permissive permission policy for SC*/
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    GeneratePermissivePolicy(SCPolicy, 1);

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));

    // Stitch the auth mechanism to ECDHE_NULL
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", SCAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", NULL));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));

    //1 . App. bus makes a method call, get property call, set property call,
    //    getall properties call on the ASG bus.
    // verify: The messages cannot be sent or received successfully by the app. bus.
    {
        // TC to SC
        EXPECT_EQ(ER_OK, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));
        // Verify Method call
        const char* s = "String that should be Echoed back.";
        EXPECT_EQ(ER_PERMISSION_DENIED, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));

        // Verify Set/Get Property and GetAll Properties
        int32_t prop = 513;
        EXPECT_EQ(ER_PERMISSION_DENIED, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop));
        EXPECT_EQ(42, SCBusObject.ReadProp1());

        prop = 0;
        EXPECT_EQ(ER_PERMISSION_DENIED, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1));

        #ifdef NOT_DEFINED
        MsgArg props;
        EXPECT_EQ(ER_PERMISSION_DENIED, proxy.GetAllProperties(interfaceName, props)) << "TC failed GetAllProperties call";;
        EXPECT_EQ((size_t)0, props.v_array.GetNumElements());
        #endif
    }
    //2. App. bus sends a signal to to the ASG bus.
    // verify: The signal cannot be received successfully by the ASG bus.
    {
        // TC Send Signal
        EXPECT_EQ(ER_PERMISSION_DENIED, TCBus.Signal(SCBus.GetUniqueName().c_str(), "Chirp", "Chirp this String out in the signal."));
    }

    //3. ASG bus makes a method call, get property call, set property call, getall
    //   properties call on the app. bus.
    // verify: The messages cannot be sent or received successfully by the app. bus.
    {
        ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
        EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
        EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

        // Verify Method call
        MsgArg arg("s", "String that should be Echoed back.");
        Message replyMsg(SCBus);
        EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
        EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", replyMsg->GetErrorName());

        // Verify Set/Get Property and GetAll Properties
        MsgArg prop1Arg;
        EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
        EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, proxy.SetProperty(interfaceName, "Prop1", prop1Arg));
        EXPECT_EQ(42, TCBus.ReadProp1());

        MsgArg prop1ArgOut;
        EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, proxy.GetProperty(interfaceName, "Prop1", prop1Arg));

        #ifdef NOT_DEFINED
        MsgArg props;
        EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, proxy.GetAllProperties(interfaceName, props)) << "TC failed GetAllProperties call";;
        EXPECT_EQ((size_t)0, props.v_array.GetNumElements());
        #endif
    }
    // 4. ASG bus sends a signal to the app. bus.
    // verify: The signal cannot be received successfully by the app. bus.
    {
        // SC Send Signal
        MsgArg arg("s", "Chirp this String out in the signal.");
        // Signals are send and forget.  They will always return ER_OK.
        EXPECT_EQ(ER_OK, SCBusObject.Signal(TCBus.GetUniqueName().c_str(),
                                               SCToTCSessionId,
                                               *SCBus.GetInterface(interfaceName)->GetMember("Chirp"),
                                               &arg, 1, 0, 0));

        //Wait for a maximum of 2 sec for the Chirp Signal.
        for (int msec = 0; msec < 2000; msec += WAIT_MSECS) {
            if (TCBus.signalReceivedFlag) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }
        EXPECT_FALSE(TCBus.signalReceivedFlag) << "TC failed to receive the Signal from SC";
    }
    // 5. ASG bus calls Reset on the app. bus.
    // verify: The Reset cannot be sent or received successfully on the app. bus.
    {
        SecurityApplicationProxy sapSCtoTC(SCBus, TCBus.GetUniqueName().c_str(), SCToTCSessionId);
        EXPECT_EQ(ER_PERMISSION_DENIED, sapSCtoTC.Reset());
    }

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Purpose:
 * On the app's default policy, a non ASG member can only receive messages sent
 * by the app. bus. The non ASG member cannot send messages to the app. bus.
 *
 * app. bus  implements the following message types: method call, signal,
 * property 1, property 2.
 * Peer A implements the following message types: method call, signal,
 * property 1, property 2.
 *
 * app. bus is claimed by the ASGA.
 * Peer A does not belong to ASG i.e it does not have a MC from ASG.
 * Peer A has a policy that enables method calls, signals, and properties.
 * app. bus has default policy.
 *
 * Peer A bus and app. bus have enabled ECDHE_ECDSA auth. mechanism.
 *
 * 1. App. bus makes a method call, get property call, set property call,
 *    getall properties call on Peer A.
 * 2. App. bus sends a signal to to Peer A.
 * 3. Peer A makes a method call, get property call, set property call, getall
 *    properties call on the app. bus.
 * 4. Peer A sends a signal to the app. bus.
 * 5. Peer A calls Reset on the app. bus
 *
 * Verification:
 * 1. Method call, get property, set property, getall properties are successful.
 * 2. The signal received by the ASG bus.
 * 3. Method call, get property, set property, getall properties are not
 *    received by the app. bus.
 * 4. The signal is not received by the app. bus.
 * 5. Reset method call should fail.
 *
 * In this test managerBus == ASGA
 *              peer1Bus == Peer A
 *              peer2Bus == app. bus
 */
TEST_F(SecurityDefaultPolicyTest, DefaultPolicy_MemberShipCertificate_not_installed)
{
    InstallMemberShipOnManager();

    /*
     * SC is not expected to be a member of the security manager security
     * group. We need it to be a member of the security group to install the
     * permission policy that is expected to be installed so we install the
     * membership on SC then we Remove the membership.
     */
    DefaultRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject, true));
    TCBus.RegisterObjects(AppObjects, AppObjects, true);

    /* install all permissive permission policy for SC*/
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    GeneratePermissivePolicy(SCPolicy, 1);

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    /* After having a new policy installed, the target bus
       clears out all of its peer's secret and session keys, so the
       next call will get security violation.  So just make the call and ignore
       the outcome.
     */
    PermissionPolicy retPolicy;
    sapWithSC.GetPolicy(retPolicy);

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));

    // 1. App. bus (TC) makes a method call, get property call, set property call,
    //   getall properties call on Peer A (SC).
    // verify: Method call, get property, set property, getall properties are successful.
    {
        // TC to SC
        EXPECT_EQ(ER_OK, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));
        // Verify Method call
        const char* s = "String that should be Echoed back.";
        EXPECT_EQ(ER_OK, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));
        EXPECT_EQ(ER_OK, TCBus.MethodCallReply());
        EXPECT_STREQ(s, TCBus.GetResponse());

        // Verify Set/Get Property and GetAll Properties
        int32_t prop = 513;
        EXPECT_EQ(ER_OK, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop));
        EXPECT_EQ(ER_OK, TCBus.SetPropertyReply());
        EXPECT_EQ(513, SCBusObject.ReadProp1());

        prop = 0;
        EXPECT_EQ(ER_OK, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1));
        EXPECT_EQ(ER_OK, TCBus.GetPropertyReply(prop));
        EXPECT_EQ(513, prop);

        #ifdef NOT_DEFINED
        MsgArg props;
        EXPECT_EQ(ER_OK, proxy.GetAllProperties(interfaceName, props)) << "TC failed GetAllProperties call";;
        MsgArg* propArg;
        int32_t prop2;
        EXPECT_EQ(ER_OK, props.GetElement("{sv}", "Prop1", &propArg)) << props.ToString().c_str();
        ASSERT_EQ(ER_OK, propArg->Get("i", &prop1)) << propArg->ToString().c_str();
        EXPECT_EQ(513, prop1);

        EXPECT_EQ(ER_OK, props.GetElement("{sv}", "Prop2", &propArg)) << props.ToString().c_str();
        EXPECT_EQ(ER_OK, propArg->Get("i", &prop2)) << propArg->ToString().c_str();
        EXPECT_EQ(17, prop2);
        #endif
    }
    //2. App. bus (TC) sends a signal to to Peer A.
    // verify: The signal received by the ASG bus. (SC)
    {
        // TC can Send Signal
        ChirpSignalReceiver chirpSignalReceiver;

        EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver,
                                                        static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler),
                                                        SCBus.GetInterface(interfaceName)->GetMember("Chirp"),
                                                        NULL));

        EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), "Chirp", "Chirp this String out in the signal."));

        //Wait for a maximum of 2 sec for the Chirp Signal.
        for (int msec = 0; msec < 2000; msec += WAIT_MSECS) {
            if (chirpSignalReceiver.signalReceivedFlag) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }
        EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag) << "SC failed to receive the Signal from TC";
        SCBus.UnregisterSignalHandler(&chirpSignalReceiver,
                                         static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler),
                                         SCBus.GetInterface(interfaceName)->GetMember("Chirp"),
                                         NULL);
    }

    //3. Peer A (SC) makes a method call, get property call, set property call, getall
    //  properties call on the app. bus. (TC)
    // verify: Method call, get property, set property, getall properties are not
    //         received by the app. bus. (TC)
    {
        ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
        EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
        EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

        // Verify Method call
        MsgArg arg("s", "String that should be Echoed back.");
        Message replyMsg(SCBus);
        EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
        EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", replyMsg->GetErrorName());

        // Verify Set/Get Property and GetAll Properties
        MsgArg prop1Arg;
        EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
        EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, proxy.SetProperty(interfaceName, "Prop1", prop1Arg));
        EXPECT_EQ(42, TCBus.ReadProp1());

        MsgArg prop1ArgOut;
        EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, proxy.GetProperty(interfaceName, "Prop1", prop1Arg));

        #ifdef NOT_DEFINED
        MsgArg props;
        EXPECT_EQ(ER_OK, proxy.GetAllProperties(interfaceName, props)) << "TC failed GetAllProperties call";;
        EXPECT_EQ((size_t)0, props.v_array.GetNumElements());
        #endif
    }
    // 4. Peer A (SC) sends a signal to the app. bus (TC).
    // verify: The signal is not received by the app. bus (TC).
    {
        // SC can Send Signal
        TCBus.signalReceivedFlag = FALSE;
        MsgArg arg("s", "Chirp this String out in the signal.");
        // Signals are send and forget.  They will always return ER_OK.
        EXPECT_EQ(ER_OK, SCBusObject.Signal(TCBus.GetUniqueName().c_str(),
                                               SCToTCSessionId,
                                               *SCBus.GetInterface(interfaceName)->GetMember("Chirp"),
                                               &arg, 1, 0, 0));

        //Wait for a maximum of 2 sec for the Chirp Signal.
        for (int msec = 0; msec < 2000; msec += WAIT_MSECS) {
            if (TCBus.signalReceivedFlag) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }
        //EXPECT_FALSE(TCBus.signalReceivedFlag) << "TC failed to receive the Signal from SC";
        EXPECT_TRUE(TCBus.signalReceivedFlag);
    }
    // 5. Peer A (SC) calls Reset on the app. bus (TC)
    // verify: Reset method call should fail.
    {
        SecurityApplicationProxy sapSCtoTC(SCBus, TCBus.GetUniqueName().c_str(), SCToTCSessionId);
        EXPECT_EQ(ER_PERMISSION_DENIED, sapSCtoTC.Reset());
    }

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Purpose:
 * Any application can send and receive messages unsecurely.
 *
 * app. bus  implements the following message types: method call, signal,
 * property 1, property 2.
 * Peer A implements the following message types: method call, signal,
 * property 1, property 2.
 *
 * app. bus is claimed by the ASGA.
 * Peer A does not belong to ASG i.e it does not have a MC from ASG.
 * app. bus has default policy.
 *
 * Peer A bus and app. bus have enabled ECDHE_ECDSA auth. mechanism.
 *
 * 1. App. bus makes an unsecure method call, get property call, set property call,
 *    getall properties call on Peer A.
 * 2. App. bus sends an unsecure signal to to Peer A.
 * 3. Peer A makes an unsecure method call, get property call, set property call, getall
 *    properties call on the app. bus.
 * 4. Peer A sends an unsecure signal to the app. bus.
 *
 * Verification:
 * 1. Method call, get property, set property, getall properties are successful.
 * 2. The signal received by the ASG bus.
 * 3. Method call, get property, set property, getall properties are successful.
 * 4. The signal is received by the app. bus.
 *
 * In this test managerBus == ASGA
 *              peer1Bus == Peer A
 *              peer2Bus == app. bus
 */
TEST_F(SecurityDefaultPolicyTest, DefaultPolicy_unsecure_method_signal_properties_succeed)
{
    InstallMemberShipOnManager();

    // Both SC and TC have unsecure BusObjects that should succeed even
    // when using Security2.0
    DefaultRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject, false));
    TCBus.RegisterObjects(AppObjects, AppObjects, false);

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));

    // 1. App. bus (TC) makes a method call, get property call, set property call,
    //   getall properties call on Peer A (SC).
    // verify:  Method call, get property, set property, getall properties are successful.
    {
        // Verify Method call
        const char* s = "String that should be Echoed back.";
        EXPECT_EQ(ER_OK, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));
        EXPECT_EQ(ER_OK, TCBus.MethodCallReply());
        EXPECT_STREQ(s, TCBus.GetResponse());

        // Verify Set/Get Property and GetAll Properties
        int32_t prop = 513;
        EXPECT_EQ(ER_OK, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop));
        EXPECT_EQ(ER_OK, TCBus.SetPropertyReply());
        EXPECT_EQ(513, SCBusObject.ReadProp1());

        prop = 0;
        EXPECT_EQ(ER_OK, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1));
        EXPECT_EQ(ER_OK, TCBus.GetPropertyReply(prop));
        EXPECT_EQ(513, prop);

        #ifdef NOT_DEFINED
        MsgArg props;
        EXPECT_EQ(ER_OK, proxy.GetAllProperties(interfaceName, props)) << "TC failed GetAllProperties call";;
        MsgArg* propArg;
        int32_t prop2;
        EXPECT_EQ(ER_OK, props.GetElement("{sv}", "Prop1", &propArg)) << props.ToString().c_str();
        ASSERT_EQ(ER_OK, propArg->Get("i", &prop1)) << propArg->ToString().c_str();
        EXPECT_EQ(513, prop1);

        EXPECT_EQ(ER_OK, props.GetElement("{sv}", "Prop2", &propArg)) << props.ToString().c_str();
        EXPECT_EQ(ER_OK, propArg->Get("i", &prop2)) << propArg->ToString().c_str();
        EXPECT_EQ(17, prop2);
        #endif
    }
    //2. App. bus (TC) sends a signal to to Peer A.
    // verify: The signal received by the ASG bus. (SC)
    {
        // TC can Send Signal
        ChirpSignalReceiver chirpSignalReceiver;

        MsgArg arg("s", "Chirp this String out in the signal.");
        EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver,
                                                        static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler),
                                                        SCBus.GetInterface(interfaceName)->GetMember("Chirp"),
                                                        NULL));

        // Signals are send and forget.  They will always return ER_OK.
        EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), "Chirp", "Chirp this String out in the signal."));

        //Wait for a maximum of 2 sec for the Chirp Signal.
        for (int msec = 0; msec < 2000; msec += WAIT_MSECS) {
            if (chirpSignalReceiver.signalReceivedFlag) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }
        EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag) << "SC failed to receive the Signal from TC";
        SCBus.UnregisterSignalHandler(&chirpSignalReceiver,
                                         static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler),
                                         SCBus.GetInterface(interfaceName)->GetMember("Chirp"),
                                         NULL);
    }

    // 3. Peer A (SC) makes an unsecure method call, get property call, set property call, getall
    //    properties call on the app. bus (TC).
    // verify:  Method call, get property, set property, getall properties are successful.
    {
        ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, false);
        EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
        EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

        // Verify Method call
        MsgArg arg("s", "String that should be Echoed back.");
        Message replyMsg(SCBus);
        QStatus status = proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg);
        EXPECT_EQ(ER_OK, status) << "TC failed make MethodCall call " << replyMsg->GetErrorDescription().c_str();

        if (status == ER_OK) {
            char* echoReply;
            replyMsg->GetArg(0)->Get("s", &echoReply);
            EXPECT_STREQ("String that should be Echoed back.", echoReply);
        }

        // Verify Set/Get Property and GetAll Properties
        MsgArg prop1Arg;
        EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
        EXPECT_EQ(ER_OK, proxy.SetProperty(interfaceName, "Prop1", prop1Arg)) << "TC failed SetProperty call";
        EXPECT_EQ(513, SCBusObject.ReadProp1());

        MsgArg prop1ArgOut;
        EXPECT_EQ(ER_OK, proxy.GetProperty(interfaceName, "Prop1", prop1Arg)) << "TC failed GetProperty call";;
        int32_t prop1;
        ASSERT_EQ(ER_OK, prop1Arg.Get("i", &prop1));
        EXPECT_EQ(513, prop1);

        #ifdef NOT_DEFINED
        MsgArg props;
        EXPECT_EQ(ER_OK, proxy.GetAllProperties(interfaceName, props)) << "TC failed GetAllProperties call";;
        MsgArg* propArg;
        int32_t prop2;
        EXPECT_EQ(ER_OK, props.GetElement("{sv}", "Prop1", &propArg)) << props.ToString().c_str();
        ASSERT_EQ(ER_OK, propArg->Get("i", &prop1)) << propArg->ToString().c_str();
        EXPECT_EQ(513, prop1);

        EXPECT_EQ(ER_OK, props.GetElement("{sv}", "Prop2", &propArg)) << props.ToString().c_str();
        EXPECT_EQ(ER_OK, propArg->Get("i", &prop2)) << propArg->ToString().c_str();
        EXPECT_EQ(17, prop2);
        #endif
    }
    // 4. Peer A (SC )sends an unsecure signal to the app. bus.
    // verify: The signal is received by the app. bus. (TC)
    {
        // SC can Send Signal
        ChirpSignalReceiver chirpSignalReceiver;

        MsgArg arg("s", "Chirp this String out in the signal.");
        // Signals are send and forget.  They will always return ER_OK.
        EXPECT_EQ(ER_OK, SCBusObject.Signal(TCBus.GetUniqueName().c_str(),
                                               SCToTCSessionId,
                                               *SCBus.GetInterface(interfaceName)->GetMember("Chirp"),
                                               &arg, 1, 0, 0));

        //Wait for a maximum of 2 sec for the Chirp Signal.
        for (int msec = 0; msec < 2000; msec += WAIT_MSECS) {
            if (TCBus.signalReceivedFlag) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }
        EXPECT_TRUE(TCBus.signalReceivedFlag) << "SC failed to receive the Signal from TC";
    }

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Purpose:
 * The default policies are overridden when a new policy is installed.
 *
 * Setup:
 * app. bus is claimed by the ASGA.
 * ASG bus has a MC signed by ASGA.
 * app. bus has default policy.
 *
 * ASG bus installs the following policy on the app. bus:
 * ACL: Peer type: ANY_TRUSTED; Rule: Allow method call "Ping"
 *
 * ASG bus and app. bus have enabled ECDHE_ECDSA auth. mechanism.
 * Both peers have a default manifest that allows everything.
 *
 * 1. ASG bus calls Reset on the app. bus
 *
 * Verification:
 * Verify that Reset method call fails. (There is no rule that explicitly allows Reset.)
 *      ASGA =     managerBus
 *      app. bus = Peer1
 */
TEST_F(SecurityDefaultPolicyTest, default_policy_overridden_when_a_new_policy_installed)
{
    InstallMemberShipOnManager();

    PermissionPolicy policy;
    policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Ping",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        policy.SetAcls(1, acls);
    }
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);

    PermissionPolicy defaultPolicy;
    EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(defaultPolicy));
    EXPECT_EQ(ER_OK, UpdatePolicyWithValuesFromDefaultPolicy(defaultPolicy, policy));

    EXPECT_NE(policy, defaultPolicy);
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(policy));

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    PermissionPolicy TCPolicy;
    GeneratePermissivePolicy(TCPolicy, 1);
    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    EXPECT_EQ(ER_OK, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), AJ_METHOD_MANAGED_RESET, NULL));
    EXPECT_EQ(ER_PERMISSION_DENIED, TCBus.MethodCallReply());
    EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());
}

/*
 * Purpose:
 * Application manifest can deny secure management operations.
 *
 * Setup:
 * app. bus (Peer2) is claimed by the ASGA.
 * ASG bus (Peer1) has a MC signed by ASGA.
 * app. bus (Peer2) has default policy.
 *
 * ASG bus(Peer1) and app. bus (Peer2) have enabled ECDHE_ECDSA auth. mechanism.
 *
 * app. bus (Peer2) manifest has the following rules:
 * Allow everything
 * Deny 'Reset' method call
 *
 * ASG bus (Peer1) manifest has the following rules:
 * Allow everything
 * Deny 'UpdateIdentity' method call
 *
 * 1. ASG bus (Peer1) calls Reset on the app. bus
 * 2. ASG bus (Peer1) calls UpdateIdentity on the app. bus.
 *
 * Verification:
 * 1. Verify that Reset call cannot be sent by the ASG bus (Peer1).
 * 2. Verify that UpdateIdentity call cannot be received by the app. bus (Peer2).
 *      ASGA =     managerBus
 *      ASG bus = Peer1
 *      app. Bus = Peer2
 */
TEST_F(SecurityDefaultPolicyTest, manifest_can_deny_secure_management_operations)
{
    InstallMemberShipOnManager();
    InstallMemberShipOnSC();

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    PermissionPolicy SCPolicy;
    GeneratePermissivePolicy(SCPolicy, 1);

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy, true, true);
    }

    sapWithSC.UpdatePolicy(SCPolicy);

    /*
     * After having a new policy installed, the target bus clears out all of
     * its peer's secret and session keys, so the next call will get security
     * violation.  So just make the call and ignore the outcome.
     */
    PermissionPolicy retPolicy;
    sapWithSC.GetPolicy(retPolicy);

    const size_t manifestSize = 2;
    const size_t certChainSize = 1;
    /*************Update SC Manifest *************/
    //SC key
    KeyInfoNISTP256 SCKey;
    PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    SCManifest[0].SetInterfaceName("*");
    SCManifest[0].SetObjPath("*");
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                       PermissionPolicy::Rule::Member::ACTION_MODIFY |
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        SCManifest[0].SetMembers(1, members);
    }
    SCManifest[1].SetInterfaceName(org::alljoyn::Bus::Security::ManagedApplication::InterfaceName);
    SCManifest[1].SetObjPath(org::alljoyn::Bus::Security::ObjectPath);
    {
        PermissionPolicy::Rule::Member members[1];
        // This will block the UpdateIdentity method from being called.
        members[0].Set("UpdateIdentity",
                       PermissionPolicy::Rule::Member::METHOD_CALL,
                       0);
        SCManifest[0].SetMembers(1, members);
    }

    uint8_t SCDigest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(managerBus,
                                                               SCManifest, manifestSize,
                                                               SCDigest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    //Create SC identityCert
    IdentityCertificate identityCertChainSC[certChainSize];

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(managerBus,
                                                                  "1",
                                                                  managerGuid.ToString(),
                                                                  SCKey.GetPublicKey(),
                                                                  "SCAlias",
                                                                  3600,
                                                                  identityCertChainSC[0],
                                                                  SCDigest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

    EXPECT_EQ(ER_OK, sapWithSC.UpdateIdentity(identityCertChainSC, certChainSize, SCManifest, manifestSize));

    /*************Update TC Manifest *************/
    //TC key
    ECCPublicKey TCPublicKey;
    EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));

    // SC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    TCManifest[0].SetInterfaceName("*");
    TCManifest[0].SetObjPath("*");
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                       PermissionPolicy::Rule::Member::ACTION_MODIFY |
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        SCManifest[0].SetMembers(1, members);
    }
    TCManifest[1].SetInterfaceName(org::alljoyn::Bus::Security::ManagedApplication::InterfaceName);
    TCManifest[1].SetObjPath(org::alljoyn::Bus::Security::ObjectPath);
    {
        PermissionPolicy::Rule::Member members[1];
        // This will block the Reset method from being called.
        members[0].Set("Reset",
                       PermissionPolicy::Rule::Member::METHOD_CALL,
                       0);
        SCManifest[0].SetMembers(1, members);
    }

    uint8_t TCDigest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(managerBus,
                                                               TCManifest, manifestSize,
                                                               TCDigest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    //Create TC identityCert
    IdentityCertificate identityCertChainTC[certChainSize];

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(managerBus,
                                                                  "1",
                                                                  managerGuid.ToString(),
                                                                  &TCPublicKey,
                                                                  "TCAlias",
                                                                  3600,
                                                                  identityCertChainTC[0],
                                                                  TCDigest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

    EXPECT_EQ(ER_OK, sapWithTC.UpdateIdentity(identityCertChainTC, certChainSize, TCManifest, manifestSize));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), SCSessionPort, NULL, SCToTCSessionId, opts));
    SecurityApplicationProxy sapSCwithTC(SCBus, TCBus.GetUniqueName().c_str(), SCToTCSessionId);
    EXPECT_EQ(ER_PERMISSION_DENIED, sapSCwithTC.Reset());

    EXPECT_EQ(ER_PERMISSION_DENIED, sapSCwithTC.UpdateIdentity(identityCertChainSC, certChainSize, SCManifest, manifestSize));
}
