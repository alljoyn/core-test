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
#define WAIT_MSECS  5
#define WAIT_SIGNAL WAIT_TIME
#define TEN_MINS    600

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
#define APP_ALL_PROP        AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_GET_ALL)
#define APP_ECHO            AJ_APP_MESSAGE_ID(0, 1, 0)
#define APP_CHIRP           AJ_APP_MESSAGE_ID(0, 1, 1)
#define APP_PROP1           AJ_APP_PROPERTY_ID(0, 1, 2)
#define APP_PROP2           AJ_APP_PROPERTY_ID(0, 1, 3)

#define PRX_GET_PROP        AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_GET)
#define PRX_SET_PROP        AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_SET)
#define PRX_ALL_PROP        AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_GET_ALL)
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
    { "/test", testInterfaces, AJ_OBJ_FLAG_ANNOUNCED | AJ_OBJ_FLAG_SECURE },
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

class TCPolicyRulesAttachment : public TCBusAttachment {

  public:

    TCPolicyRulesAttachment(const char* name) : TCBusAttachment(name) {
        sessionPort = 0;
        prop1 = 42;
        prop2 = 17;
        signalReceivedFlag = FALSE;
        AJ_RegisterObjects(AppObjects, AppObjects);
    }

    void RecvMessage(AJ_Message* msg) {
        AJ_Status status;
        AJ_Message reply;
        bool handled = TRUE;

        switch (msg->msgId) {
        case APP_ECHO:
            const char* str;
            status = AJ_UnmarshalArgs(msg, "s", &str);
            AJ_ASSERT(AJ_OK == status);
            printf("Echo: %s\n", str);
            status = AJ_MarshalReplyMsg(msg, &reply);
            AJ_ASSERT(AJ_OK == status);
            status = AJ_MarshalArgs(&reply, "s", str);
            AJ_ASSERT(AJ_OK == status);
            status = AJ_DeliverMsg(&reply);
            AJ_ASSERT(AJ_OK == status);
            break;

        case APP_CHIRP:
            status = AJ_UnmarshalArgs(msg, "s", &str);
            AJ_ASSERT(AJ_OK == status);
            printf("Chirp: %s\n", str);
            signalReceivedFlag = TRUE;
            break;

        case APP_GET_PROP:
            status = AJ_BusPropGet(msg, PropGetHandler, NULL);
            AJ_ASSERT(AJ_OK == status);
            break;

        case APP_SET_PROP:
            status = AJ_BusPropSet(msg, PropSetHandler, NULL);
            AJ_ASSERT(AJ_OK == status);
            break;

        case APP_ALL_PROP:
            status = AJ_BusPropGetAll(msg, PropGetHandler, NULL);
            AJ_ASSERT(AJ_OK == status);
            break;

        case AJ_REPLY_ID(PRX_ECHO):
            if (AJ_MSG_ERROR == msg->hdr->msgType) {
                SCStatus = ER_BUS_REPLY_IS_ERROR_MESSAGE;
                response = msg->error;
            } else {
                const char* resp;
                status = AJ_UnmarshalArgs(msg, "s", &resp);
                AJ_ASSERT(AJ_OK == status);
                response = resp;
                SCStatus = ER_OK;
                printf("Echo Reply: %s\n", response.c_str());
            }
            break;

        case AJ_REPLY_ID(PRX_GET_PROP):
            if (AJ_MSG_ERROR == msg->hdr->msgType) {
                SCStatus = ER_BUS_REPLY_IS_ERROR_MESSAGE;
                response = msg->error;
            } else {
                const char* sig;
                status = AJ_UnmarshalVariant(msg, &sig);
                AJ_ASSERT(AJ_OK == status);
                status = AJ_UnmarshalArgs(msg, sig, &propval);
                AJ_ASSERT(AJ_OK == status);
                SCStatus = ER_OK;
            }
            break;

        case AJ_REPLY_ID(PRX_SET_PROP):
            if (AJ_MSG_ERROR == msg->hdr->msgType) {
                SCStatus = ER_BUS_REPLY_IS_ERROR_MESSAGE;
                response = msg->error;
            } else {
                SCStatus = ER_OK;
            }
            break;

        case AJ_REPLY_ID(PRX_ALL_PROP):
            if (AJ_MSG_ERROR == msg->hdr->msgType) {
                SCStatus = ER_BUS_REPLY_IS_ERROR_MESSAGE;
                response = msg->error;
            } else {
                properties.HandleReply(msg);
                SCStatus = ER_OK;
            }
            break;

        default:
            handled = FALSE;
            break;
        }
        if (handled) {
            HandleMessage(msg);
        } else {
            TCBusAttachment::RecvMessage(msg);
        }
    }

    QStatus JoinSession(const char* host, uint16_t port, uint32_t& id) {
        QStatus status;
        status = TCBusAttachment::JoinSession(host, port, id);
        if (ER_OK == status) {
            status = AuthenticatePeer(host);
        }
        return status;
    }

    QStatus GetProperty(const char* peer, uint32_t pid, int32_t& val) {
        return TCBusAttachment::GetProperty(peer, PRX_GET_PROP, pid, val);
    }

    QStatus SetProperty(const char* peer, uint32_t pid, int32_t val) {
        return TCBusAttachment::SetProperty(peer, PRX_SET_PROP, pid, val);
    }

    QStatus GetAllProperties(const char* peer, const char* ifn, TCProperties& val) {
        return TCBusAttachment::GetAllProperties(peer, PRX_ALL_PROP, ifn, val);
    }

    int32_t ReadProp1() {
        return prop1;
    }
    int32_t ReadProp2() {
        return prop2;
    }

    bool signalReceivedFlag;
};

static String PrintActionMask(uint8_t actionMask) {
    String result;
    bool addPipeChar = false;
    if (actionMask & PermissionPolicy::Rule::Member::ACTION_PROVIDE) {
        result += "PROVIDE";
        addPipeChar = true;
    }
    if (actionMask & PermissionPolicy::Rule::Member::ACTION_MODIFY) {
        if (addPipeChar) {
            result += " | MODIFY";
        } else {
            result += "MODIFY";
        }
        addPipeChar = true;
    }
    if (actionMask & PermissionPolicy::Rule::Member::ACTION_OBSERVE) {
        if (addPipeChar) {
            result += " | OBSERVE";
        } else {
            result += "OBSERVE";
        }
        addPipeChar = true;
    }
    // Since no other action is found its a DENY rule
    if (addPipeChar == false) {
        result += "DENY";
    }
    return result;
}

class PolicyRules_ApplicationStateListener : public ApplicationStateListener {
  public:
    PolicyRules_ApplicationStateListener() : stateMap() { }

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

class PolicyRulesTestSessionPortListener : public SessionPortListener {
  public:
    virtual bool AcceptSessionJoiner(SessionPort sessionPort, const char* joiner, const SessionOpts& opts) {
        QCC_UNUSED(sessionPort);
        QCC_UNUSED(joiner);
        QCC_UNUSED(opts);
        return true;
    }
};

class PolicyRulesTestBusObject : public BusObject {
  public:
    PolicyRulesTestBusObject(BusAttachment& bus, const char* path, const char* interfaceName, bool announce = true)
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
            { iface->GetMember("Echo"), static_cast<MessageReceiver::MethodHandler>(&PolicyRulesTestBusObject::Echo) }
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

static void GetAppPublicKey(BusAttachment& bus, ECCPublicKey& publicKey)
{
    KeyInfoNISTP256 keyInfo;
    bus.GetPermissionConfigurator().GetSigningPublicKey(keyInfo);
    publicKey = *keyInfo.GetPublicKey();
}

class SecurityPolicyRulesTest : public testing::Test {
  public:
    SecurityPolicyRulesTest() :
        managerBus("SecurityPolicyRulesManager"),
        SCBus("SecurityPolicyRulesSC"),
        TCBus("SecurityPolicyRulesTC"),
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

        TCBus.Connect(routingNodePrefix.c_str());
        TCBus.Start();

        EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", managerAuthListener, NULL, true));
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA"));

        interface = "<node>"
                    "<interface name='" + String(interfaceName) + "'>"
                    "<annotation name='org.alljoyn.Bus.Secure' value='true'/>"
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
        EXPECT_EQ(PermissionConfigurator::NOT_CLAIMABLE, applicationStateManager);

        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
        PermissionConfigurator::ApplicationState applicationStateSC;
        EXPECT_EQ(ER_OK, sapWithSC.GetApplicationState(applicationStateSC));
        EXPECT_EQ(PermissionConfigurator::NOT_CLAIMABLE, applicationStateSC);

        SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
        PermissionConfigurator::ApplicationState applicationStateTC;
        EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
        EXPECT_EQ(PermissionConfigurator::NOT_CLAIMABLE, applicationStateTC);

        EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));
        TCKey.SetPublicKey(&TCPublicKey);

        managerBus.RegisterApplicationStateListener(appStateListener);
        managerBus.AddApplicationStateRule();

        // All Inclusive manifest
        PermissionPolicy::Rule::Member member[1];
        member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        const size_t manifestSize = 1;
        PermissionPolicy::Rule manifest[manifestSize];
        manifest[0].SetObjPath("*");
        manifest[0].SetInterfaceName("*");
        manifest[0].SetMembers(1, member);

        //Get manager key
        KeyInfoNISTP256 managerKey;
        PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(managerKey));

        //Create SC key
        KeyInfoNISTP256 SCKey;
        PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

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

        /* set claimable */
        managerBus.GetPermissionConfigurator().SetApplicationState(PermissionConfigurator::CLAIMABLE);
        EXPECT_EQ(ER_OK, sapWithManager.Claim(managerKey,
                                              managerGuid,
                                              managerKey,
                                              identityCertChainMaster, certChainSize,
                                              manifest, manifestSize));

        for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
            if (appStateListener.isClaimed(managerBus.GetUniqueName())) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }

        ECCPublicKey managerPublicKey;
        GetAppPublicKey(managerBus, managerPublicKey);
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
        /* set claimable */
        SCBus.GetPermissionConfigurator().SetApplicationState(PermissionConfigurator::CLAIMABLE);
        EXPECT_EQ(ER_OK, sapWithSC.Claim(managerKey,
                                            managerGuid,
                                            managerKey,
                                            identityCertChainSC, certChainSize,
                                            manifest, manifestSize));

        for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
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
        /* set claimable */
        TCBus.SetApplicationState(APP_STATE_CLAIMABLE);
        EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));
        EXPECT_EQ(ER_OK, sapWithTC.Claim(managerKey,
                                            managerGuid,
                                            managerKey,
                                            identityCertChainTC, certChainSize,
                                            manifest, manifestSize));

        for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
            if (appStateListener.isClaimed(TCBus.GetUniqueName().c_str())) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }

        ASSERT_EQ(PermissionConfigurator::ApplicationState::CLAIMED, appStateListener.stateMap[SCBus.GetUniqueName()]);

        //Change the managerBus so it only uses ECDHE_ECDSA
        EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", managerAuthListener, NULL, true));

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
        EXPECT_EQ(ER_OK, sapWithManager.InstallMembership(managerMembershipCertificate, 1));

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
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", managerAuthListener, NULL, false));
        EXPECT_EQ(ER_OK, sapWithSC.InstallMembership(SCMembershipCertificate, 1));

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
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
        EXPECT_EQ(ER_OK, sapWithTC.InstallMembership(TCMembershipCertificate, 1));
    }

    virtual void TearDown() {
        TCBus.Stop();
        TCBus.Join();
        managerBus.Stop();
        managerBus.Join();
        SCBus.Stop();
        SCBus.Join();
        delete managerAuthListener;
        delete SCAuthListener;
    }

    QStatus UpdatePolicyWithValuesFromDefaultPolicy(const PermissionPolicy& defaultPolicy,
                                                    PermissionPolicy& policy,
                                                    bool keepCAentry = true,
                                                    bool keepAdminGroupEntry = false,
                                                    bool keepInstallMembershipEntry = false);

    /*
     * The policy for all of the GetAllProperties tests only differs by what is
     * defined in the members.  This Will build the same policy with only the members
     * changed for all of the GetAllProperties tests.
     */
    void CreatePolicyWithMembersForGetAllProperties(PermissionPolicy& policy, PermissionPolicy::Rule::Member* members, size_t membersSize);
    void UpdateSCManifest(PermissionPolicy::Rule* manifest, size_t manifestSize);
    void UpdateTCManifest(PermissionPolicy::Rule* manifest, size_t manifestSize);

    BusAttachment managerBus;
    BusAttachment SCBus;
    TCPolicyRulesAttachment TCBus;

    SessionPort managerSessionPort;
    SessionPort SCSessionPort;
    SessionPort TCSessionPort;

    PolicyRulesTestSessionPortListener managerSessionPortListener;
    PolicyRulesTestSessionPortListener SCSessionPortListener;

    SessionId managerToManagerSessionId;
    SessionId managerToSCSessionId;
    SessionId managerToTCSessionId;

    InMemoryKeyStoreListener managerKeyStoreListener;
    InMemoryKeyStoreListener SCKeyStoreListener;

    String interface;
    const char* interfaceName;
    DefaultECDHEAuthListener* managerAuthListener;
    DefaultECDHEAuthListener* SCAuthListener;

    PolicyRules_ApplicationStateListener appStateListener;

    //Random GUID used for the SecurityManager
    GUID128 managerGuid;

    ECCPublicKey TCPublicKey;
    KeyInfoNISTP256 TCKey;
};

QStatus SecurityPolicyRulesTest::UpdatePolicyWithValuesFromDefaultPolicy(const PermissionPolicy& defaultPolicy,
                                                                         PermissionPolicy& policy,
                                                                         bool keepCAentry,
                                                                         bool keepAdminGroupEntry,
                                                                         bool keepInstallMembershipEntry) {

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

void SecurityPolicyRulesTest::CreatePolicyWithMembersForGetAllProperties(PermissionPolicy& policy, PermissionPolicy::Rule::Member* members, size_t membersSize) {
    policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[2];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            rules[0].SetMembers(membersSize, members);
            //make sure peer1 can call UpdateIdentity to update the manifest
            rules[1].SetObjPath(org::alljoyn::Bus::Security::ObjectPath);
            rules[1].SetInterfaceName(org::alljoyn::Bus::Security::ManagedApplication::InterfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_MODIFY);
                rules[1].SetMembers(1, members);
            }
            acls[0].SetRules(2, rules);
        }
        policy.SetAcls(1, acls);
    }
}

void SecurityPolicyRulesTest::UpdateSCManifest(PermissionPolicy::Rule* manifest, size_t manifestSize) {
    const size_t certChainSize = 1;
    /*************Update SC Manifest *************/
    //SC key
    KeyInfoNISTP256 SCKey;
    PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

    uint8_t SCDigest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(managerBus,
                                                               manifest, manifestSize,
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

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());
    EXPECT_EQ(ER_OK, sapWithSC.UpdateIdentity(identityCertChainSC, certChainSize, manifest, manifestSize));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));
}

void SecurityPolicyRulesTest::UpdateTCManifest(PermissionPolicy::Rule* manifest, size_t manifestSize) {
    const size_t certChainSize = 1;
    /*************Update TC Manifest *************/

    uint8_t TCDigest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(managerBus,
                                                               manifest, manifestSize,
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

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());
    EXPECT_EQ(ER_OK, sapWithTC.UpdateIdentity(identityCertChainTC, certChainSize, manifest, manifestSize));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));
}

class MethodRulesTestValue {
  public:
    MethodRulesTestValue(uint8_t mask1, uint8_t mask2, bool makeMethodCall, bool respondToMethodCall) :
        peer1ActionMask(mask1),
        peer2ActionMask(mask2),
        proxyObjAllowedToCallMethod(makeMethodCall),
        busObjAllowedToRespondToMethodCall(respondToMethodCall) { }

    friend::std::ostream& operator<<(::std::ostream& os, const MethodRulesTestValue& val);
    uint8_t peer1ActionMask;
    uint8_t peer2ActionMask;
    bool proxyObjAllowedToCallMethod;
    bool busObjAllowedToRespondToMethodCall;
};

::std::ostream& operator<<(::std::ostream& os, const MethodRulesTestValue& val) {
    os << "peer1Mask = " << PrintActionMask(val.peer1ActionMask).c_str() << "\n";
    os << "peer2Mask = " << PrintActionMask(val.peer2ActionMask).c_str() << "\n";
    if (val.proxyObjAllowedToCallMethod) {
        os << "ProxyBusObject is expected to call Method\n";
    } else {
        os << "ProxyBusObject is NOT expected to call Method\n";
    }
    if (val.busObjAllowedToRespondToMethodCall) {
        os << "BusObject is expected to respond to Method call\n";
    } else {
        os << "BusObject is NOT expected to respond to Method call\n";
    }
    return os;
}

class SecurityPolicyRulesMethodCalls : public SecurityPolicyRulesTest,
    public testing::WithParamInterface<MethodRulesTestValue> {
};

TEST_P(SecurityPolicyRulesMethodCalls, PolicyRulesSC)
{
    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo", PermissionPolicy::Rule::Member::METHOD_CALL, GetParam().peer1ActionMask);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               GetParam().peer2ActionMask);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    qcc::String p1policyStr = "\n----Peer1 Policy-----\n" + SCPolicy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----Peer2 Policy-----\n" + TCPolicy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    QStatus methodCallStatus = proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg);

    if (GetParam().proxyObjAllowedToCallMethod && GetParam().busObjAllowedToRespondToMethodCall) {
        EXPECT_EQ(ER_OK, methodCallStatus);
        char* echoReply;
        replyMsg->GetArg(0)->Get("s", &echoReply);
        EXPECT_STREQ("String that should be Echoed back.", echoReply);
    } else if (GetParam().proxyObjAllowedToCallMethod && !GetParam().busObjAllowedToRespondToMethodCall) {
        EXPECT_EQ(ER_PERMISSION_DENIED, methodCallStatus);
        EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", replyMsg->GetErrorName());
    } else { //!GetParam().proxyObjAllowedToCallMethod
        EXPECT_EQ(ER_PERMISSION_DENIED, methodCallStatus);
        ASSERT_STREQ("org.alljoyn.Bus.ErStatus", replyMsg->GetErrorName());
        EXPECT_EQ(ER_PERMISSION_DENIED, (QStatus)replyMsg->GetArg(1)->v_uint16) << "\n" << replyMsg->GetArg(0)->ToString().c_str() << "\n" << replyMsg->GetArg(1)->ToString().c_str();
    }
}

TEST_P(SecurityPolicyRulesMethodCalls, PolicyRulesTC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo", PermissionPolicy::Rule::Member::METHOD_CALL, GetParam().peer1ActionMask);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               GetParam().peer2ActionMask);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));
    qcc::String p1policyStr = "\n----TC Policy-----\n" + TCPolicy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----SC Policy-----\n" + SCPolicy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    /* Create the ProxyBusObject and call the Echo method on the interface */
    const char* s = "String that should be Echoed back.";
    QStatus status = TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s);

    if (GetParam().proxyObjAllowedToCallMethod && GetParam().busObjAllowedToRespondToMethodCall) {
        ASSERT_EQ(ER_OK, status);
        EXPECT_STREQ(s, TCBus.GetResponse());
    } else if (GetParam().proxyObjAllowedToCallMethod && !GetParam().busObjAllowedToRespondToMethodCall) {
        EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, status);
        EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());
    } else { //!GetParam().proxyObjAllowedToCallMethod
        EXPECT_EQ(ER_PERMISSION_DENIED, status);
    }

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

INSTANTIATE_TEST_CASE_P(Method, SecurityPolicyRulesMethodCalls,
                        ::testing::Values(
                            MethodRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE, //0
                                                 PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                 true,   //Proxy object allowed to make method call
                                                 false), //bus object allowed to respond to method call
                            MethodRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE, //1
                                                 PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                 true,
                                                 true),
                            MethodRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE, //2
                                                 PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                 true,
                                                 false),
                            MethodRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY, //3
                                                 PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                 false,
                                                 false),
                            MethodRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY, //4
                                                 PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                 false,
                                                 true),
                            MethodRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY, //5
                                                 PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                 false,
                                                 false),
                            MethodRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE, //6
                                                 PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                 false,
                                                 false),
                            MethodRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE, //7
                                                 PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                 false,
                                                 true),
                            MethodRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE, //8
                                                 PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                 false,
                                                 false)
                            ));

class SecurityPolicyRulesMethodCallsManifest : public SecurityPolicyRulesTest,
    public testing::WithParamInterface<MethodRulesTestValue> {
};

TEST_P(SecurityPolicyRulesMethodCallsManifest, PolicyRulesSC)
{
    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];

            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];

            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_MODIFY);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy, true, true);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy, true, true);
    }

    qcc::String p1policyStr = "\n----SC Policy-----\n" + SCPolicy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----TC Policy-----\n" + TCPolicy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    const size_t manifestSize = 1;
    const size_t certChainSize = 1;
    /*************Update SC Manifest *************/
    //SC key
    KeyInfoNISTP256 SCKey;
    PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Echo", PermissionPolicy::Rule::Member::METHOD_CALL, GetParam().peer1ActionMask);
        SCManifest[0].SetObjPath("/test");
        SCManifest[0].SetInterfaceName(interfaceName);
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
    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Echo", PermissionPolicy::Rule::Member::METHOD_CALL, GetParam().peer2ActionMask);
        TCManifest[0].SetObjPath("/test");
        TCManifest[0].SetInterfaceName(interfaceName);
        TCManifest[0].SetMembers(1, members);
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
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    QStatus methodCallStatus = proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg);

    if (GetParam().proxyObjAllowedToCallMethod && GetParam().busObjAllowedToRespondToMethodCall) {
        EXPECT_EQ(ER_OK, methodCallStatus);
        char* echoReply;
        replyMsg->GetArg(0)->Get("s", &echoReply);
        EXPECT_STREQ("String that should be Echoed back.", echoReply);
    } else if (GetParam().proxyObjAllowedToCallMethod && !GetParam().busObjAllowedToRespondToMethodCall) {
        EXPECT_EQ(ER_PERMISSION_DENIED, methodCallStatus);
        EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", replyMsg->GetErrorName());
    } else { //!GetParam().proxyObjAllowedToCallMethod
        EXPECT_EQ(ER_PERMISSION_DENIED, methodCallStatus);
        ASSERT_STREQ("org.alljoyn.Bus.ErStatus", replyMsg->GetErrorName());
        EXPECT_EQ(ER_PERMISSION_DENIED, (QStatus)replyMsg->GetArg(1)->v_uint16) << "\n" << replyMsg->GetArg(0)->ToString().c_str() << "\n" << replyMsg->GetArg(1)->ToString().c_str();
    }

    /* clean up */
    //TCBus.UnregisterBusObject(TCBusObject);
}

TEST_P(SecurityPolicyRulesMethodCallsManifest, PolicyRulesTC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];

            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];

            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_MODIFY);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);


    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy, true, true);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy, true, true);
    }

    qcc::String p1policyStr = "\n----TC Policy-----\n" + TCPolicy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----SC Policy-----\n" + SCPolicy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    const size_t manifestSize = 1;
    const size_t certChainSize = 1;
    /*************Update TC Manifest *************/
    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Echo", PermissionPolicy::Rule::Member::METHOD_CALL, GetParam().peer1ActionMask);
        TCManifest[0].SetObjPath("/test");
        TCManifest[0].SetInterfaceName(interfaceName);
        TCManifest[0].SetMembers(1, members);
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

    /*************Update SC Manifest *************/
    //SC key
    KeyInfoNISTP256 SCKey;
    PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Echo", PermissionPolicy::Rule::Member::METHOD_CALL, GetParam().peer2ActionMask);
        SCManifest[0].SetObjPath("/test");
        SCManifest[0].SetInterfaceName(interfaceName);
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

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    /* Create the ProxyBusObject and call the Echo method on the interface */
    const char* s = "String that should be Echoed back.";
    QStatus status = TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s);

    if (GetParam().proxyObjAllowedToCallMethod && GetParam().busObjAllowedToRespondToMethodCall) {
        ASSERT_EQ(ER_OK, status);
        EXPECT_STREQ(s, TCBus.GetResponse());
    } else if (GetParam().proxyObjAllowedToCallMethod && !GetParam().busObjAllowedToRespondToMethodCall) {
        EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, status);
        EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());
    } else { //!GetParam().proxyObjAllowedToCallMethod
        EXPECT_EQ(ER_PERMISSION_DENIED, status);
    }

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

INSTANTIATE_TEST_CASE_P(Method, SecurityPolicyRulesMethodCallsManifest,
                        ::testing::Values(
                            MethodRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE, //0
                                                 PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                 true, //ProxyBusObject can make method call
                                                 false), //BusObject can respond to method call
                            MethodRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE, //1
                                                 PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                 false,
                                                 false),
                            MethodRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE, //2
                                                 PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                 false,
                                                 false),
                            MethodRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY, //3
                                                 PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                 true,
                                                 true),
                            MethodRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY, //4
                                                 PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                 false,
                                                 true),
                            MethodRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY, //5
                                                 PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                 false,
                                                 true),
                            MethodRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE, //6
                                                 PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                 true,
                                                 false),
                            MethodRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE, //7
                                                 PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                 false,
                                                 false),
                            MethodRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE, //8
                                                 PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                 false,
                                                 false)
                            ));

class GetPropertyRulesTestValue {
  public:
    GetPropertyRulesTestValue(uint8_t mask1, uint8_t mask2, bool makeGetPropertyCall, bool respondToGetPropertyCall) :
        peer1ActionMask(mask1),
        peer2ActionMask(mask2),
        proxyObjAllowedToCallGetProperty(makeGetPropertyCall),
        busObjAllowedToRespondToGetPropertyCall(respondToGetPropertyCall) { }
    friend ostream& operator<<(ostream& os, const GetPropertyRulesTestValue& val);

    uint8_t peer1ActionMask;
    uint8_t peer2ActionMask;
    bool proxyObjAllowedToCallGetProperty;
    bool busObjAllowedToRespondToGetPropertyCall;
};

::std::ostream& operator<<(::std::ostream& os, const GetPropertyRulesTestValue& val) {
    os << "peer1Mask = " << PrintActionMask(val.peer1ActionMask).c_str() << "\n";
    os << "peer2Mask = " << PrintActionMask(val.peer2ActionMask).c_str() << "\n";
    if (val.proxyObjAllowedToCallGetProperty) {
        os << "ProxyBusObject is expected to call GetProperty\n";
    } else {
        os << "ProxyBusObject is NOT expected to call GetProperty\n";
    }
    if (val.busObjAllowedToRespondToGetPropertyCall) {
        os << "BusObject is expected to respond to GetProperty call\n";
    } else {
        os << "BusObject is NOT expected to respond to GetProperty call\n";
    }
    return os;
}

class SecurityPolicyRulesGetProperty : public SecurityPolicyRulesTest,
    public testing::WithParamInterface<GetPropertyRulesTestValue> {
};

TEST_P(SecurityPolicyRulesGetProperty, PolicyRulesSC)
{
    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Prop1",
                               PermissionPolicy::Rule::Member::PROPERTY,
                               GetParam().peer1ActionMask);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Prop1",
                               PermissionPolicy::Rule::Member::PROPERTY,
                               GetParam().peer2ActionMask);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));

    qcc::String p1policyStr = "\n----SC Policy-----\n" + SCPolicy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----TC Policy-----\n" + TCPolicy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    QStatus getPropertyStatus = proxy.GetProperty(interfaceName, "Prop1", prop1Arg);
    if (GetParam().proxyObjAllowedToCallGetProperty && GetParam().busObjAllowedToRespondToGetPropertyCall) {
        EXPECT_EQ(ER_OK, getPropertyStatus);
        //Verify we got Prop1 prop1Arg should be changed from 513 to 42 (note prop1 defaults to 42 by the constructor)
        int32_t prop1;
        prop1Arg.Get("i", &prop1);
        EXPECT_EQ(42, prop1);
    } else if (GetParam().proxyObjAllowedToCallGetProperty && !GetParam().busObjAllowedToRespondToGetPropertyCall) {
        EXPECT_EQ(ER_PERMISSION_DENIED, getPropertyStatus);
        //Currently no way to find out that the error string is org.alljoyn.Bus.Security.Error.PermissionDenied
    } else { //!GetParam().proxyObjAllowedToCallGetProperty
        // Maybe this should be ER_PERMISSION_DENIED like it is for the SetProperty call
        EXPECT_EQ(ER_PERMISSION_DENIED, getPropertyStatus);
    }

    /* clean up */
}

TEST_P(SecurityPolicyRulesGetProperty, PolicyRulesTC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Prop1",
                               PermissionPolicy::Rule::Member::PROPERTY,
                               GetParam().peer1ActionMask);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Prop1",
                               PermissionPolicy::Rule::Member::PROPERTY,
                               GetParam().peer2ActionMask);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    qcc::String p1policyStr = "\n----TC Policy-----\n" + TCPolicy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----SC Policy-----\n" + SCPolicy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    /* Create the ProxyBusObject and call the Echo method on the interface */
    int32_t prop = 513;
    QStatus status = TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop);
    if (GetParam().proxyObjAllowedToCallGetProperty && GetParam().busObjAllowedToRespondToGetPropertyCall) {
        EXPECT_EQ(ER_OK, status);
        //Verify we got Prop1 prop1Arg should be changed from 513 to 42 (note prop1 defaults to 42 by the constructor)
        EXPECT_EQ(42, prop);
    } else if (GetParam().proxyObjAllowedToCallGetProperty && !GetParam().busObjAllowedToRespondToGetPropertyCall) {
        EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, status);
        EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());
    } else { //!GetParam().proxyObjAllowedToCallGetProperty
        EXPECT_EQ(ER_PERMISSION_DENIED, status);
    }

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

INSTANTIATE_TEST_CASE_P(GetProperty, SecurityPolicyRulesGetProperty,
                        ::testing::Values(
                            GetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE, //0
                                                      PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                      true,   //ProxyBusObj Allowed To Call GetProperty;
                                                      false), //BusObj Allowed To Respond To GetProperty Call
                            GetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE, //1
                                                      PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                      true,
                                                      false),
                            GetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE, //2
                                                      PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                      true,
                                                      true),
                            GetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY, //3
                                                      PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                      false,
                                                      false),
                            GetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY, //4
                                                      PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                      false,
                                                      false),
                            GetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY, //5
                                                      PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                      false,
                                                      true),
                            GetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE, //6
                                                      PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                      false,
                                                      false),
                            GetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE, //7
                                                      PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                      false,
                                                      false),
                            GetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE, //8
                                                      PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                      false,
                                                      true)
                            ));

class SecurityPolicyRulesGetPropertyManifest : public SecurityPolicyRulesTest,
    public testing::WithParamInterface<GetPropertyRulesTestValue> {
};

TEST_P(SecurityPolicyRulesGetPropertyManifest, PolicyRulesSC)
{
    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Prop1",
                               PermissionPolicy::Rule::Member::PROPERTY,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Prop1",
                               PermissionPolicy::Rule::Member::PROPERTY,
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy, true, true);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy, true, true);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    const size_t manifestSize = 1;
    const size_t certChainSize = 1;
    /*************Update SC Manifest *************/
    //SC key
    KeyInfoNISTP256 SCKey;
    PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, GetParam().peer1ActionMask);
        SCManifest[0].SetObjPath("/test");
        SCManifest[0].SetInterfaceName(interfaceName);
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
    // SC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, GetParam().peer2ActionMask);
        TCManifest[0].SetObjPath("/test");
        TCManifest[0].SetInterfaceName(interfaceName);
        TCManifest[0].SetMembers(1, members);
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
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    QStatus getPropertyStatus = proxy.GetProperty(interfaceName, "Prop1", prop1Arg);
    if (GetParam().proxyObjAllowedToCallGetProperty && GetParam().busObjAllowedToRespondToGetPropertyCall) {
        EXPECT_EQ(ER_OK, getPropertyStatus);
        //Verify we got Prop1 prop1Arg should be changed from 513 to 42 (note prop1 defaults to 42 by the constructor)
        int32_t prop1;
        prop1Arg.Get("i", &prop1);
        EXPECT_EQ(42, prop1);
    } else if (GetParam().proxyObjAllowedToCallGetProperty && !GetParam().busObjAllowedToRespondToGetPropertyCall) {
        EXPECT_EQ(ER_PERMISSION_DENIED, getPropertyStatus);
        //Currently no way to find out that the error string is org.alljoyn.Bus.Security.Error.PermissionDenied
    } else { //!GetParam().proxyObjAllowedToCallGetProperty
        // Maybe this should be ER_PERMISSION_DENIED like it is for the SetProperty call
        EXPECT_EQ(ER_PERMISSION_DENIED, getPropertyStatus);
    }

    /* clean up */
}

TEST_P(SecurityPolicyRulesGetPropertyManifest, PolicyRulesTC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Prop1",
                               PermissionPolicy::Rule::Member::PROPERTY,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Prop1",
                               PermissionPolicy::Rule::Member::PROPERTY,
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy, true, true);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy, true, true);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    const size_t manifestSize = 1;
    const size_t certChainSize = 1;
    /*************Update TC Manifest *************/
    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, GetParam().peer1ActionMask);
        TCManifest[0].SetObjPath("/test");
        TCManifest[0].SetInterfaceName(interfaceName);
        TCManifest[0].SetMembers(1, members);
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

    /*************Update SC Manifest *************/
    //SC key
    KeyInfoNISTP256 SCKey;
    PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, GetParam().peer2ActionMask);
        SCManifest[0].SetObjPath("/test");
        SCManifest[0].SetInterfaceName(interfaceName);
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

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    /* Create the ProxyBusObject and call the Echo method on the interface */
    int32_t prop = 513;
    QStatus status = TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop);
    if (GetParam().proxyObjAllowedToCallGetProperty && GetParam().busObjAllowedToRespondToGetPropertyCall) {
        EXPECT_EQ(ER_OK, status);
        //Verify we got Prop1 prop1Arg should be changed from 513 to 42 (note prop1 defaults to 42 by the constructor)
        EXPECT_EQ(42, prop);
    } else if (GetParam().proxyObjAllowedToCallGetProperty && !GetParam().busObjAllowedToRespondToGetPropertyCall) {
        EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, status);
        EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());
    } else { //!GetParam().proxyObjAllowedToCallGetProperty
        EXPECT_EQ(ER_PERMISSION_DENIED, status);
    }

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

INSTANTIATE_TEST_CASE_P(GetProperty, SecurityPolicyRulesGetPropertyManifest,
                        ::testing::Values(
                            GetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE, //0
                                                      PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                      true, //ProxyBusObj Allowed To Call GetProperty;
                                                      false), //BusObj Allowed To Respond To GetProperty Call
                            GetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE, //1
                                                      PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                      false,
                                                      false),
                            GetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE, //2
                                                      PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                      false,
                                                      false),
                            GetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY, //3
                                                      PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                      true,
                                                      false),
                            GetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY, //4
                                                      PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                      false,
                                                      false),
                            GetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY, //5
                                                      PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                      false,
                                                      false),
                            GetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE, //6
                                                      PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                      true,
                                                      true),
                            GetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE, //7
                                                      PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                      false,
                                                      true),
                            GetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE, //8
                                                      PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                      false,
                                                      true)
                            ));

class SetPropertyRulesTestValue {
  public:
    SetPropertyRulesTestValue(uint8_t mask1, uint8_t mask2, bool makeSetPropertyCall, bool respondToSetPropertyCall) :
        peer1ActionMask(mask1),
        peer2ActionMask(mask2),
        proxyObjAllowedToCallSetProperty(makeSetPropertyCall),
        busObjAllowedToRespondToSetPropertyCall(respondToSetPropertyCall) { }
    friend::std::ostream& operator<<(::std::ostream& os, const SetPropertyRulesTestValue& val);
    uint8_t peer1ActionMask;
    uint8_t peer2ActionMask;
    bool proxyObjAllowedToCallSetProperty;
    bool busObjAllowedToRespondToSetPropertyCall;
};

::std::ostream& operator<<(::std::ostream& os, const SetPropertyRulesTestValue& val) {
    os << "peer1Mask = " << PrintActionMask(val.peer1ActionMask).c_str() << "\n";
    os << "peer2Mask = " << PrintActionMask(val.peer2ActionMask).c_str() << "\n";
    if (val.proxyObjAllowedToCallSetProperty) {
        os << "ProxyBusObject is expected to call SetProperty\n";
    } else {
        os << "ProxyBusObject is NOT expected to call SetProperty\n";
    }
    if (val.busObjAllowedToRespondToSetPropertyCall) {
        os << "BusObject is expected to respond to SetProperty call\n";
    } else {
        os << "BusObject is NOT expected to respond to SetProperty call\n";
    }
    return os;
}

class SecurityPolicyRulesSetProperty : public SecurityPolicyRulesTest,
    public testing::WithParamInterface<SetPropertyRulesTestValue> {
};

TEST_P(SecurityPolicyRulesSetProperty, PolicyRulesSC)
{
    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Prop1",
                               PermissionPolicy::Rule::Member::PROPERTY,
                               GetParam().peer1ActionMask);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Prop1",
                               PermissionPolicy::Rule::Member::PROPERTY,
                               GetParam().peer2ActionMask);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));

    qcc::String p1policyStr = "\n----SC Policy-----\n" + SCPolicy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----TC Policy-----\n" + TCPolicy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    QStatus setPropertyStatus = proxy.SetProperty(interfaceName, "Prop1", prop1Arg);
    if (GetParam().proxyObjAllowedToCallSetProperty && GetParam().busObjAllowedToRespondToSetPropertyCall) {
        EXPECT_EQ(ER_OK, setPropertyStatus);
        //Verify Prop1 is changed.
        EXPECT_EQ(513, TCBus.ReadProp1());
    } else if (GetParam().proxyObjAllowedToCallSetProperty && !GetParam().busObjAllowedToRespondToSetPropertyCall) {
        EXPECT_EQ(ER_PERMISSION_DENIED, setPropertyStatus);
        //Currently no way to find out that the error string is org.alljoyn.Bus.Security.Error.PermissionDenied
        //Verify Prop1 is unchanged (note prop1 defaults to 42 by the constructor)
        EXPECT_EQ(42, TCBus.ReadProp1());
    } else { //!GetParam().proxyObjAllowedToCallSetProperty
        EXPECT_EQ(ER_PERMISSION_DENIED, setPropertyStatus);
        EXPECT_EQ(42, TCBus.ReadProp1());
    }

    /* clean up */
}

TEST_P(SecurityPolicyRulesSetProperty, PolicyRulesTC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Prop1",
                               PermissionPolicy::Rule::Member::PROPERTY,
                               GetParam().peer1ActionMask);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Prop1",
                               PermissionPolicy::Rule::Member::PROPERTY,
                               GetParam().peer2ActionMask);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    qcc::String p1policyStr = "\n----TC Policy-----\n" + TCPolicy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----SC Policy-----\n" + SCPolicy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    /* Create the ProxyBusObject and call the Set property method on the interface */
    int32_t prop = 513;
    QStatus status = TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop);
    if (GetParam().proxyObjAllowedToCallSetProperty && GetParam().busObjAllowedToRespondToSetPropertyCall) {
        EXPECT_EQ(ER_OK, status);
        //Verify Prop1 is changed.
        EXPECT_EQ(513, SCBusObject.ReadProp1());
    } else if (GetParam().proxyObjAllowedToCallSetProperty && !GetParam().busObjAllowedToRespondToSetPropertyCall) {
        EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, status);
        EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());
        EXPECT_EQ(42, SCBusObject.ReadProp1());
    } else { //!GetParam().proxyObjAllowedToCallSetProperty
        EXPECT_EQ(ER_PERMISSION_DENIED, status);
        EXPECT_EQ(42, SCBusObject.ReadProp1());
    }

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

INSTANTIATE_TEST_CASE_P(SetProperty, SecurityPolicyRulesSetProperty,
                        ::testing::Values(
                            SetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE, //0
                                                      PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                      true, //ProxyBusObj Allowed To Call SetProperty;
                                                      false), //BusObj Allowed To Respond To SetProperty Call
                            SetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE, //1
                                                      PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                      true,
                                                      true),
                            SetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE, //2
                                                      PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                      true,
                                                      false),
                            SetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY, //3
                                                      PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                      false,
                                                      false),
                            SetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY, //4
                                                      PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                      false,
                                                      true),
                            SetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY, //5
                                                      PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                      false,
                                                      false),
                            SetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE, //6
                                                      PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                      false,
                                                      false),
                            SetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE, //7
                                                      PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                      false,
                                                      true),
                            SetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE, //8
                                                      PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                      false,
                                                      false)
                            ));

class SecurityPolicyRulesSetPropertyManifest : public SecurityPolicyRulesTest,
    public testing::WithParamInterface<SetPropertyRulesTestValue> {
};

TEST_P(SecurityPolicyRulesSetPropertyManifest, PolicyRulesSC)
{
    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Prop1",
                               PermissionPolicy::Rule::Member::PROPERTY,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[2];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Prop1",
                               PermissionPolicy::Rule::Member::PROPERTY,
                               PermissionPolicy::Rule::Member::ACTION_MODIFY);
                rules[0].SetMembers(1, members);
            }
            //make sure TC can call UpdateIdentity to update the manifest
            rules[1].SetObjPath(org::alljoyn::Bus::Security::ObjectPath);
            rules[1].SetInterfaceName(org::alljoyn::Bus::Security::ManagedApplication::InterfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_MODIFY);
                rules[1].SetMembers(1, members);
            }
            acls[0].SetRules(2, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy, true, true);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy, true, true);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    const size_t manifestSize = 1;
    const size_t certChainSize = 1;
    /*************Update SC Manifest *************/
    //SC key
    KeyInfoNISTP256 SCKey;
    PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, GetParam().peer1ActionMask);
        SCManifest[0].SetObjPath("/test");
        SCManifest[0].SetInterfaceName(interfaceName);
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
    // SC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, GetParam().peer2ActionMask);
        TCManifest[0].SetObjPath("/test");
        TCManifest[0].SetInterfaceName(interfaceName);
        TCManifest[0].SetMembers(1, members);
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
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));

    /* Create the ProxyBusObject and call the Set property method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    QStatus setPropertyStatus = proxy.SetProperty(interfaceName, "Prop1", prop1Arg);
    if (GetParam().proxyObjAllowedToCallSetProperty && GetParam().busObjAllowedToRespondToSetPropertyCall) {
        EXPECT_EQ(ER_OK, setPropertyStatus);
        //Verify Prop1 is changed.
        EXPECT_EQ(513, TCBus.ReadProp1());
    } else { //!GetParam().proxyObjAllowedToCallSetProperty
        EXPECT_TRUE(ER_PERMISSION_DENIED == setPropertyStatus || ER_BUS_REPLY_IS_ERROR_MESSAGE == setPropertyStatus);
        EXPECT_EQ(42, TCBus.ReadProp1());
    }

    /* clean up */
}

TEST_P(SecurityPolicyRulesSetPropertyManifest, PolicyRulesTC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Prop1",
                               PermissionPolicy::Rule::Member::PROPERTY,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[2];
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Prop1",
                               PermissionPolicy::Rule::Member::PROPERTY,
                               PermissionPolicy::Rule::Member::ACTION_MODIFY);
                rules[0].SetMembers(1, members);
            }
            //make sure SC can call UpdateIdentity to update the manifest
            rules[1].SetObjPath(org::alljoyn::Bus::Security::ObjectPath);
            rules[1].SetInterfaceName(org::alljoyn::Bus::Security::ManagedApplication::InterfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_MODIFY);
                rules[1].SetMembers(1, members);
            }
            acls[0].SetRules(2, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy, true, true);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy, true, true);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    const size_t manifestSize = 1;
    const size_t certChainSize = 1;
    /*************Update TC Manifest *************/
    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, GetParam().peer1ActionMask);
        TCManifest[0].SetObjPath("/test");
        TCManifest[0].SetInterfaceName(interfaceName);
        TCManifest[0].SetMembers(1, members);
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

    /*************Update SC Manifest *************/
    //SC key
    KeyInfoNISTP256 SCKey;
    PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, GetParam().peer2ActionMask);
        SCManifest[0].SetObjPath("/test");
        SCManifest[0].SetInterfaceName(interfaceName);
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

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    /* Create the ProxyBusObject and call the Set property method on the interface */
    int32_t prop = 513;
    QStatus status = TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop);
    if (GetParam().proxyObjAllowedToCallSetProperty && GetParam().busObjAllowedToRespondToSetPropertyCall) {
        EXPECT_EQ(ER_OK, status);
        //Verify Prop1 is changed.
        EXPECT_EQ(513, prop);
    } else if (GetParam().proxyObjAllowedToCallSetProperty && !GetParam().busObjAllowedToRespondToSetPropertyCall) {
        EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, status);
        EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());
        EXPECT_EQ(42, SCBusObject.ReadProp1());
    } else { //!GetParam().proxyObjAllowedToCallSetProperty
        EXPECT_EQ(ER_PERMISSION_DENIED, status);
        EXPECT_EQ(42, SCBusObject.ReadProp1());
    }

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

INSTANTIATE_TEST_CASE_P(SetProperty, SecurityPolicyRulesSetPropertyManifest,
                        ::testing::Values(
                            SetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                      PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                      true,
                                                      false),
                            SetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                      PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                      false,
                                                      false),
                            SetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                      PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                      false,
                                                      false),
                            SetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                      PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                      true,
                                                      true),
                            SetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                      PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                      false,
                                                      true),
                            SetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                      PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                      false,
                                                      true),
                            SetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                      PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                      true,
                                                      false),
                            SetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                      PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                      false,
                                                      false),
                            SetPropertyRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                      PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                      false,
                                                      false)
                            ));

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

class SignalRulesTestValue {
  public:
    SignalRulesTestValue(uint8_t mask1, uint8_t mask2, bool canSendSignal, bool canReceiveSignal) :
        peer1ActionMask(mask1),
        peer2ActionMask(mask2),
        busObjAllowedToSendSignal(canSendSignal),
        allowedToReceiveSignal(canReceiveSignal) { }
    friend::std::ostream& operator<<(::std::ostream& os, const SignalRulesTestValue& val);
    uint8_t peer1ActionMask;
    uint8_t peer2ActionMask;
    bool busObjAllowedToSendSignal;
    bool allowedToReceiveSignal;
};

::std::ostream& operator<<(::std::ostream& os, const SignalRulesTestValue& val) {
    os << "peer1Mask = " << PrintActionMask(val.peer1ActionMask).c_str() << "\n";
    os << "peer2Mask = " << PrintActionMask(val.peer2ActionMask).c_str() << "\n";
    if (val.busObjAllowedToSendSignal) {
        os << "BusObject should be able to emit signals\n";
    } else {
        os << "BusObject should NOT be able to emit signals\n";
    }
    if (val.allowedToReceiveSignal) {
        os << "We are expected to be able to receive signals\n";
    } else {
        os << "We are NOT expected to be able to receive signals\n";
    }
    return os;
}

class SecurityPolicyRulesSignal : public SecurityPolicyRulesTest,
    public testing::WithParamInterface<SignalRulesTestValue> {
};

TEST_P(SecurityPolicyRulesSignal, PolicyRulesSC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Chirp",
                               PermissionPolicy::Rule::Member::SIGNAL,
                               GetParam().peer1ActionMask);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member TCPrms[1];
                TCPrms[0].Set("Chirp",
                                 PermissionPolicy::Rule::Member::SIGNAL,
                                 GetParam().peer2ActionMask);
                rules[0].SetMembers(1, TCPrms);
            }
            acls[0].SetRules(1, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));

    qcc::String p1policyStr = "\n----SC Policy-----\n" + SCPolicy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----TC Policy-----\n" + TCPolicy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    /*
     * Create the ProxyBusObject and call the SecureConnection this will make
     * sure any permission keys are exchanged between peers
     */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    EXPECT_EQ(ER_OK, proxy.SecureConnection(true));

    MsgArg arg("s", "Chirp this String out in the signal.");
    QStatus status = SCBusObject.Signal(TCBus.GetUniqueName().c_str(), SCToTCSessionId, *SCBus.GetInterface(interfaceName)->GetMember("Chirp"), &arg, 1);

    if (GetParam().busObjAllowedToSendSignal) {
        EXPECT_EQ(ER_OK, status);
        //Wait for a maximum of 2 sec for the Chirp Signal.
        for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
            if (TCBus.signalReceivedFlag) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }
        if (GetParam().allowedToReceiveSignal) {
            EXPECT_TRUE(TCBus.signalReceivedFlag);
        } else {
            EXPECT_FALSE(TCBus.signalReceivedFlag) << "According to the policy rules we should NOT be able to send a signal";
        }

    } else {
        EXPECT_EQ(ER_PERMISSION_DENIED, status);
        EXPECT_FALSE(TCBus.signalReceivedFlag) << "According to the policy rules we should NOT be able to send a signal";
    }

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

TEST_P(SecurityPolicyRulesSignal, PolicyRulesTC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Chirp",
                               PermissionPolicy::Rule::Member::SIGNAL,
                               GetParam().peer1ActionMask);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member SCPrms[1];
                SCPrms[0].Set("Chirp",
                                 PermissionPolicy::Rule::Member::SIGNAL,
                                 GetParam().peer2ActionMask);
                rules[0].SetMembers(1, SCPrms);
            }
            acls[0].SetRules(1, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    qcc::String p1policyStr = "\n----TC Policy-----\n" + TCPolicy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----SC Policy-----\n" + SCPolicy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    /*
     * Create the ProxyBusObject and call the SecureConnection this will make
     * sure any permission keys are exchanged between peers
     */
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver, static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler), SCBus.GetInterface(interfaceName)->GetMember("Chirp"), NULL));

    const char* s = "Chirp this String out in the signal.";
    QStatus status = TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_CHIRP, s);
    if (GetParam().busObjAllowedToSendSignal) {
        EXPECT_EQ(ER_OK, status);
        for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
            if (chirpSignalReceiver.signalReceivedFlag) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }
        if (GetParam().allowedToReceiveSignal) {
            EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag);
        } else {
            EXPECT_FALSE(chirpSignalReceiver.signalReceivedFlag) << "According to the policy rules we should NOT be able to send a signal";
        }
    } else {
        EXPECT_EQ(ER_PERMISSION_DENIED, status);
        EXPECT_FALSE(chirpSignalReceiver.signalReceivedFlag) << "According to the policy rules we should NOT be able to send a signal";
    }

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

INSTANTIATE_TEST_CASE_P(Signal, SecurityPolicyRulesSignal,
                        ::testing::Values(
                            SignalRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE, //0
                                                 PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                 false,      //can send signal
                                                 true),      //can receive signal
                            SignalRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE, //1
                                                 PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                 false,
                                                 false),
                            SignalRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE, //2
                                                 PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                 false,
                                                 false),
                            SignalRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY, //3
                                                 PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                 false,
                                                 true),
                            SignalRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY, //4
                                                 PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                 false,
                                                 false),
                            SignalRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY, //5
                                                 PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                 false,
                                                 false),
                            SignalRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE, //6
                                                 PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                 true,
                                                 true),
                            SignalRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE, //7
                                                 PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                 true,
                                                 false),
                            SignalRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE, //8
                                                 PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                 true,
                                                 false)
                            ));

class SecurityPolicyRulesSignalManifest : public SecurityPolicyRulesTest,
    public testing::WithParamInterface<SignalRulesTestValue> {
};

TEST_P(SecurityPolicyRulesSignalManifest, PolicyRulesSC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions to send signals */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Chirp",
                               PermissionPolicy::Rule::Member::SIGNAL,
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Chirp",
                               PermissionPolicy::Rule::Member::SIGNAL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy, true, true);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy, true, true);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    const size_t manifestSize = 1;
    const size_t certChainSize = 1;
    /*************Update SC Manifest *************/
    //SC key
    KeyInfoNISTP256 SCKey;
    PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    {
        PermissionPolicy::Rule::Member member[1];
        member[0].Set("Chirp", PermissionPolicy::Rule::Member::SIGNAL, GetParam().peer1ActionMask);
        SCManifest[0].SetObjPath("*");
        SCManifest[0].SetInterfaceName(interfaceName);
        SCManifest[0].SetMembers(1, member);
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
    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    {
        PermissionPolicy::Rule::Member member[1];
        member[0].Set("Chirp", PermissionPolicy::Rule::Member::SIGNAL, GetParam().peer2ActionMask);
        TCManifest[0].SetObjPath("*");
        TCManifest[0].SetInterfaceName(interfaceName);
        TCManifest[0].SetMembers(1, member);
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
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));

    /*
     * Create the ProxyBusObject and call the SecureConnection this will make
     * sure any permission keys are exchanged between peers
     */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    EXPECT_EQ(ER_OK, proxy.SecureConnection(true));

    TCBus.signalReceivedFlag = FALSE;
    MsgArg arg("s", "Chirp this String out in the signal.");
    QStatus status = SCBusObject.Signal(TCBus.GetUniqueName().c_str(), SCToTCSessionId, *SCBus.GetInterface(interfaceName)->GetMember("Chirp"), &arg, 1);

    if (GetParam().busObjAllowedToSendSignal) {
        EXPECT_EQ(ER_OK, status);
        //Wait for a maximum of 2 sec for the Chirp Signal.
        for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
            if (TCBus.signalReceivedFlag) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }
        if (GetParam().allowedToReceiveSignal) {
            EXPECT_TRUE(TCBus.signalReceivedFlag);
        } else {
            EXPECT_FALSE(TCBus.signalReceivedFlag) << "According to the policy rules we should NOT be able to send a signal";
        }
    } else {
        EXPECT_EQ(ER_PERMISSION_DENIED, status);
        EXPECT_FALSE(TCBus.signalReceivedFlag) << "According to the policy rules we should NOT be able to send a signal";
    }

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

TEST_P(SecurityPolicyRulesSignalManifest, PolicyRulesTC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions to send signals */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Chirp",
                               PermissionPolicy::Rule::Member::SIGNAL,
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Chirp",
                               PermissionPolicy::Rule::Member::SIGNAL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy, true, true);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy, true, true);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    const size_t manifestSize = 1;
    const size_t certChainSize = 1;
    /*************Update TC Manifest *************/
    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    {
        PermissionPolicy::Rule::Member member[1];
        member[0].Set("Chirp", PermissionPolicy::Rule::Member::SIGNAL, GetParam().peer1ActionMask);
        TCManifest[0].SetObjPath("*");
        TCManifest[0].SetInterfaceName(interfaceName);
        TCManifest[0].SetMembers(1, member);
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

    /*************Update SC Manifest *************/
    //SC key
    KeyInfoNISTP256 SCKey;
    PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    {
        PermissionPolicy::Rule::Member member[1];
        member[0].Set("Chirp", PermissionPolicy::Rule::Member::SIGNAL, GetParam().peer2ActionMask);
        SCManifest[0].SetObjPath("*");
        SCManifest[0].SetInterfaceName(interfaceName);
        SCManifest[0].SetMembers(1, member);
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

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    /*
     * Create the ProxyBusObject and call the SecureConnection this will make
     * sure any permission keys are exchanged between peers
     */
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver, static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler), SCBus.GetInterface(interfaceName)->GetMember("Chirp"), NULL));

    const char* s = "Chirp this String out in the signal.";
    QStatus status = TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_CHIRP, s);
    if (GetParam().busObjAllowedToSendSignal) {
        EXPECT_EQ(ER_OK, status);
        for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
            if (chirpSignalReceiver.signalReceivedFlag) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }
        if (GetParam().allowedToReceiveSignal) {
            EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag);
        } else {
            EXPECT_FALSE(chirpSignalReceiver.signalReceivedFlag) << "According to the policy rules we should NOT be able to send a signal";
        }
    } else {
        EXPECT_EQ(ER_PERMISSION_DENIED, status);
        EXPECT_FALSE(chirpSignalReceiver.signalReceivedFlag) << "According to the policy rules we should NOT be able to send a signal";
    }

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

INSTANTIATE_TEST_CASE_P(Signal, SecurityPolicyRulesSignalManifest,
                        ::testing::Values(
                            SignalRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE, //0
                                                 PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                 false,         //can send signal
                                                 true),         //can receive signal
                            SignalRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE, //1
                                                 PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                 false,
                                                 true),
                            SignalRulesTestValue(PermissionPolicy::Rule::Member::ACTION_PROVIDE, //2
                                                 PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                 true,
                                                 true),
                            SignalRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY, //3
                                                 PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                 false,
                                                 false),
                            SignalRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY, //4
                                                 PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                 false,
                                                 false),
                            SignalRulesTestValue(PermissionPolicy::Rule::Member::ACTION_MODIFY, //5
                                                 PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                 true,
                                                 false),
                            SignalRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE, //6
                                                 PermissionPolicy::Rule::Member::ACTION_PROVIDE,
                                                 false,
                                                 false),
                            SignalRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE, //7
                                                 PermissionPolicy::Rule::Member::ACTION_MODIFY,
                                                 false,
                                                 false),
                            SignalRulesTestValue(PermissionPolicy::Rule::Member::ACTION_OBSERVE, //8
                                                 PermissionPolicy::Rule::Member::ACTION_OBSERVE,
                                                 true,
                                                 false)
                            ));

/*
 * Setup following policies and manifests
 *
 * Peer1 policy
 * -----------------
 * PeerType: ANY_TRUSTED
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { *, Property, PROVIDE}
 * Peer1 manifest:
 * ------------------
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { Prop1, Property, OBSERVE}, {Prop2, Property, OBSERVE}
 * Peer2 policy
 * -----------------
 * PeerType: ANY_TRUSTED
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { Prop1, Property, OBSERVE}, {Prop2, Property, OBSERVE}
 * Peer2 manifest:
 * ------------------
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { *, Property, PROVIDE}
 *
 * Expected Result:
 * Both properties Prop1 and Prop2 will be fetched.
 */
TEST_F(SecurityPolicyRulesTest, GetAllProperties_test1_properties_succesfully_sent_SC)
{
    const size_t manifestSize = 1;

    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        CreatePolicyWithMembersForGetAllProperties(SCPolicy, members, 1);
    }

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    SCManifest[0].SetObjPath("/test");
    SCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        SCManifest[0].SetMembers(2, members);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        CreatePolicyWithMembersForGetAllProperties(TCPolicy, members, 2);
    }

    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    TCManifest[0].SetObjPath("/test");
    TCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        TCManifest[0].SetMembers(1, members);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    UpdateSCManifest(SCManifest, manifestSize);
    UpdateTCManifest(TCManifest, manifestSize);
    //------------------------------------------------------------------------//
    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    MsgArg props;
    EXPECT_EQ(ER_OK, proxy.GetAllProperties(interfaceName, props));

    {
        int32_t prop1;
        MsgArg* propArg;
        ASSERT_EQ(ER_OK, props.GetElement("{sv}", "Prop1", &propArg)) << props.ToString().c_str();
        EXPECT_EQ(ER_OK, propArg->Get("i", &prop1)) << propArg->ToString().c_str();
        EXPECT_EQ(42, prop1);
    }
    {
        int32_t prop2;
        MsgArg* propArg;
        ASSERT_EQ(ER_OK, props.GetElement("{sv}", "Prop2", &propArg)) << props.ToString().c_str();
        EXPECT_EQ(ER_OK, propArg->Get("i", &prop2)) << propArg->ToString().c_str();
        EXPECT_EQ(17, prop2);
    }

    /* clean up */
    //TCBus.UnregisterBusObject(TCBusObject);
}

TEST_F(SecurityPolicyRulesTest, GetAllProperties_test1_properties_succesfully_sent_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));
    const size_t manifestSize = 1;

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        CreatePolicyWithMembersForGetAllProperties(TCPolicy, members, 1);
    }

    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    TCManifest[0].SetObjPath("/test");
    TCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        TCManifest[0].SetMembers(2, members);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        CreatePolicyWithMembersForGetAllProperties(SCPolicy, members, 2);
    }

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    SCManifest[0].SetObjPath("/test");
    SCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        SCManifest[0].SetMembers(1, members);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    UpdateTCManifest(TCManifest, manifestSize);
    UpdateSCManifest(SCManifest, manifestSize);
    //------------------------------------------------------------------------//
    SessionOpts opts;
    SessionId TCToSCSessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    TCProperties props;
    QStatus status = TCBus.GetAllProperties(SCBus.GetUniqueName().c_str(), interfaceName, props);
    EXPECT_EQ(ER_OK, status);

    {
        int32_t prop1;
        EXPECT_EQ(ER_OK, props.GetElement("Prop1", prop1));
        EXPECT_EQ(42, prop1);
    }
    {
        int32_t prop2;
        EXPECT_EQ(ER_OK, props.GetElement("Prop2", prop2));
        EXPECT_EQ(17, prop2);
    }

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Setup following policies and manifests
 *
 * Peer1 policy
 * -----------------
 * PeerType: ANY_TRUSTED
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { *, Property, PROVIDE}
 * Peer1 manifest:
 * ------------------
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { Prop1, Property, OBSERVE}
 * Peer2 policy
 * -----------------
 * PeerType: ANY_TRUSTED
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { Prop1, Property, OBSERVE}, {Prop2, Property, OBSERVE}
 * Peer2 manifest:
 * ------------------
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { *, Property, PROVIDE}
 *
 * Expected Result:
 * GetAllProperties will be successfully sent.
 * Only Prop1 will be fetched.
 */
TEST_F(SecurityPolicyRulesTest, GetAllProperties_test2_only_prop1_successfully_fetched_SC)
{
    const size_t manifestSize = 1;

    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        CreatePolicyWithMembersForGetAllProperties(SCPolicy, members, 1);
    }

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    SCManifest[0].SetObjPath("/test");
    SCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        SCManifest[0].SetMembers(1, members);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        CreatePolicyWithMembersForGetAllProperties(TCPolicy, members, 2);
    }

    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    TCManifest[0].SetObjPath("/test");
    TCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        TCManifest[0].SetMembers(1, members);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    UpdateSCManifest(SCManifest, manifestSize);
    UpdateTCManifest(TCManifest, manifestSize);
    //------------------------------------------------------------------------//
    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    MsgArg props;
    ASSERT_EQ(ER_OK, proxy.GetAllProperties(interfaceName, props));

    {
        int32_t prop1;
        MsgArg* propArg;
        EXPECT_EQ(ER_OK, props.GetElement("{sv}", "Prop1", &propArg)) << props.ToString().c_str();
        EXPECT_EQ(ER_OK, propArg->Get("i", &prop1)) << propArg->ToString().c_str();
        EXPECT_EQ(42, prop1);
    }
    {
        MsgArg* propArg;
        EXPECT_EQ(ER_BUS_ELEMENT_NOT_FOUND, props.GetElement("{sv}", "Prop2", &propArg)) << props.ToString().c_str();
    }

    /* clean up */
    //TCBus.UnregisterBusObject(TCBusObject);
}

TEST_F(SecurityPolicyRulesTest, GetAllProperties_test2_only_prop1_successfully_fetched_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));
    const size_t manifestSize = 1;

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        CreatePolicyWithMembersForGetAllProperties(TCPolicy, members, 1);
    }

    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    TCManifest[0].SetObjPath("/test");
    TCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        TCManifest[0].SetMembers(1, members);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        CreatePolicyWithMembersForGetAllProperties(SCPolicy, members, 2);
    }

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    SCManifest[0].SetObjPath("/test");
    SCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        SCManifest[0].SetMembers(1, members);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    UpdateTCManifest(TCManifest, manifestSize);
    UpdateSCManifest(SCManifest, manifestSize);
    //------------------------------------------------------------------------//
    SessionOpts opts;
    SessionId TCToSCSessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    TCProperties props;
    QStatus status = TCBus.GetAllProperties(SCBus.GetUniqueName().c_str(), interfaceName, props);
    EXPECT_EQ(ER_OK, status);

    {
        int32_t prop1;
        EXPECT_EQ(ER_OK, props.GetElement("Prop1", prop1));
        EXPECT_EQ(42, prop1);
    }
    {
        int32_t prop2;
        EXPECT_EQ(ER_BUS_ELEMENT_NOT_FOUND, props.GetElement("Prop2", prop2));
    }

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Setup following policies and manifests
 *
 * Peer1 policy
 * -----------------
 * PeerType: ANY_TRUSTED
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { *, Property, PROVIDE}
 * Peer1 manifest:
 * ------------------
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { Prop1, Property, OBSERVE}, {Prop2, Property, OBSERVE}
 * Peer2 policy
 * -----------------
 * PeerType: ANY_TRUSTED
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { Prop1, Property, OBSERVE}
 * Peer2 manifest:
 * ------------------
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { *, Property, PROVIDE}
 *
 * Expected Result:
 * GetAllProperties will be successfully sent.
 * Only Prop1 will be fetched.
 */
TEST_F(SecurityPolicyRulesTest, GetAllProperties_test3_only_prop1_successfully_fetched_SC)
{
    const size_t manifestSize = 1;

    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        CreatePolicyWithMembersForGetAllProperties(SCPolicy, members, 1);
    }

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    SCManifest[0].SetObjPath("/test");
    SCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        SCManifest[0].SetMembers(2, members);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        CreatePolicyWithMembersForGetAllProperties(TCPolicy, members, 1);
    }

    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    TCManifest[0].SetObjPath("/test");
    TCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        TCManifest[0].SetMembers(1, members);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    UpdateSCManifest(SCManifest, manifestSize);
    UpdateTCManifest(TCManifest, manifestSize);
    //------------------------------------------------------------------------//
    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    MsgArg props;
    ASSERT_EQ(ER_OK, proxy.GetAllProperties(interfaceName, props));

    {
        int32_t prop1;
        MsgArg* propArg;
        EXPECT_EQ(ER_OK, props.GetElement("{sv}", "Prop1", &propArg)) << props.ToString().c_str();
        EXPECT_EQ(ER_OK, propArg->Get("i", &prop1)) << propArg->ToString().c_str();
        EXPECT_EQ(42, prop1);
    }
    {
        MsgArg* propArg;
        EXPECT_EQ(ER_BUS_ELEMENT_NOT_FOUND, props.GetElement("{sv}", "Prop2", &propArg)) << props.ToString().c_str();
    }

    /* clean up */
    //TCBus.UnregisterBusObject(TCBusObject);
}

TEST_F(SecurityPolicyRulesTest, GetAllProperties_test3_only_prop1_successfully_fetched_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));
    const size_t manifestSize = 1;

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        CreatePolicyWithMembersForGetAllProperties(TCPolicy, members, 1);
    }

    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    TCManifest[0].SetObjPath("/test");
    TCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        TCManifest[0].SetMembers(2, members);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        CreatePolicyWithMembersForGetAllProperties(SCPolicy, members, 1);
    }

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    SCManifest[0].SetObjPath("/test");
    SCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        SCManifest[0].SetMembers(1, members);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    UpdateTCManifest(TCManifest, manifestSize);
    UpdateSCManifest(SCManifest, manifestSize);
    //------------------------------------------------------------------------//
    SessionOpts opts;
    SessionId TCToSCSessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    TCProperties props;
    EXPECT_EQ(ER_OK, TCBus.GetAllProperties(SCBus.GetUniqueName().c_str(), interfaceName, props));

    {
        int32_t prop1;
        EXPECT_EQ(ER_OK, props.GetElement("Prop1", prop1));
        EXPECT_EQ(42, prop1);
    }
    {
        int32_t prop2;
        EXPECT_EQ(ER_BUS_ELEMENT_NOT_FOUND, props.GetElement("Prop2", prop2));
    }

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Setup following policies and manifests
 *
 * Peer1 policy
 * -----------------
 * PeerType: ANY_TRUSTED
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { *, Property, PROVIDE}
 * Peer1 manifest:
 * ------------------
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { Prop1, Property, OBSERVE}, {Prop2, Property, OBSERVE}
 * Peer2 policy
 * -----------------
 * PeerType: ANY_TRUSTED
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { Prop1, Property, OBSERVE}, {Prop2, Property, OBSERVE}
 * Peer2 manifest:
 * ------------------
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { *, Method_call, PROVIDE}
 *
 * Expected Result:
 * GetAllProperties won’t be sent. Because, The wildcard rule is for a Method
 * and not for a Property
 */
TEST_F(SecurityPolicyRulesTest, GetAllProperties_test4_no_properties_fetched_SC)
{
    const size_t manifestSize = 1;

    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        CreatePolicyWithMembersForGetAllProperties(SCPolicy, members, 1);
    }

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    SCManifest[0].SetObjPath("/test");
    SCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        SCManifest[0].SetMembers(2, members);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        CreatePolicyWithMembersForGetAllProperties(TCPolicy, members, 2);
    }

    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    TCManifest[0].SetObjPath("/test");
    TCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*", PermissionPolicy::Rule::Member::METHOD_CALL, PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        TCManifest[0].SetMembers(1, members);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    UpdateSCManifest(SCManifest, manifestSize);
    UpdateTCManifest(TCManifest, manifestSize);
    //------------------------------------------------------------------------//
    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    MsgArg props;
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.GetAllProperties(interfaceName, props));

    /* clean up */
    //TCBus.UnregisterBusObject(TCBusObject);
}

TEST_F(SecurityPolicyRulesTest, GetAllProperties_test4_no_properties_fetched_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));
    const size_t manifestSize = 1;

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        CreatePolicyWithMembersForGetAllProperties(TCPolicy, members, 1);
    }

    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    TCManifest[0].SetObjPath("/test");
    TCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        TCManifest[0].SetMembers(2, members);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        CreatePolicyWithMembersForGetAllProperties(SCPolicy, members, 2);
    }

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    SCManifest[0].SetObjPath("/test");
    SCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*", PermissionPolicy::Rule::Member::METHOD_CALL, PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        SCManifest[0].SetMembers(1, members);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    UpdateTCManifest(TCManifest, manifestSize);
    UpdateSCManifest(SCManifest, manifestSize);
    //------------------------------------------------------------------------//
    SessionOpts opts;
    SessionId TCToSCSessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    TCProperties props;
    EXPECT_EQ(ER_PERMISSION_DENIED, TCBus.GetAllProperties(SCBus.GetUniqueName().c_str(), interfaceName, props));

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Setup following policies and manifests
 *
 * Peer1 policy
 * -----------------
 * PeerType: ANY_TRUSTED
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { *, Method_call, PROVIDE}
 * Peer1 manifest:
 * ------------------
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { Prop1, Property, OBSERVE}, {Prop2, Property, OBSERVE}
 * Peer2 policy
 * -----------------
 * PeerType: ANY_TRUSTED
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { Prop1, Property, OBSERVE}, {Prop2, Property, OBSERVE}
 * Peer2 manifest:
 * ------------------
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { *, Property, PROVIDE}
 *
 * Expected Result:
 * GetAllProperties won’t be sent. Because, the wildcard rule is for a Method
 * and not for a Property
 */
TEST_F(SecurityPolicyRulesTest, GetAllProperties_test5_no_properties_fetched_SC)
{
    const size_t manifestSize = 1;

    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::METHOD_CALL,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        CreatePolicyWithMembersForGetAllProperties(SCPolicy, members, 1);
    }

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    SCManifest[0].SetObjPath("/test");
    SCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        SCManifest[0].SetMembers(2, members);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        CreatePolicyWithMembersForGetAllProperties(TCPolicy, members, 2);
    }

    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    TCManifest[0].SetObjPath("/test");
    TCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        TCManifest[0].SetMembers(1, members);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    UpdateSCManifest(SCManifest, manifestSize);
    UpdateTCManifest(TCManifest, manifestSize);
    //------------------------------------------------------------------------//
    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    MsgArg props;
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.GetAllProperties(interfaceName, props));

    /* clean up */
    //TCBus.UnregisterBusObject(TCBusObject);
}

TEST_F(SecurityPolicyRulesTest, GetAllProperties_test5_no_properties_fetched_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));
    const size_t manifestSize = 1;

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::METHOD_CALL,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        CreatePolicyWithMembersForGetAllProperties(TCPolicy, members, 1);
    }

    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    TCManifest[0].SetObjPath("/test");
    TCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        TCManifest[0].SetMembers(2, members);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        CreatePolicyWithMembersForGetAllProperties(SCPolicy, members, 2);
    }

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    SCManifest[0].SetObjPath("/test");
    SCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        SCManifest[0].SetMembers(1, members);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    UpdateTCManifest(TCManifest, manifestSize);
    UpdateSCManifest(SCManifest, manifestSize);
    //------------------------------------------------------------------------//
    SessionOpts opts;
    SessionId TCToSCSessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    TCProperties props;
    EXPECT_EQ(ER_PERMISSION_DENIED, TCBus.GetAllProperties(SCBus.GetUniqueName().c_str(), interfaceName, props));

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Setup following policies and manifests
 *
 * Peer1 policy
 * -----------------
 * PeerType: ANY_TRUSTED
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { *, Property, PROVIDE}
 * Peer1 manifest:
 * ------------------
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { Prop1, Property, OBSERVE}, {Prop2, Property, OBSERVE}
 * Peer2 policy
 * -----------------
 * PeerType: ANY_TRUSTED
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { *, Property, OBSERVE}
 * Peer2 manifest:
 * ------------------
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { *, Property, PROVIDE}
 *
 * Expected Result:
 * GetAllProperties will be successfully sent.
 * Both properties Prop1 and Prop2 will be fetched.
 */
TEST_F(SecurityPolicyRulesTest, GetAllProperties_test6_properties_successfully_fetched_SC)
{
    const size_t manifestSize = 1;

    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        CreatePolicyWithMembersForGetAllProperties(SCPolicy, members, 1);
    }

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    SCManifest[0].SetObjPath("/test");
    SCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        SCManifest[0].SetMembers(2, members);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        CreatePolicyWithMembersForGetAllProperties(TCPolicy, members, 1);
    }

    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    TCManifest[0].SetObjPath("/test");
    TCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        TCManifest[0].SetMembers(1, members);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    UpdateSCManifest(SCManifest, manifestSize);
    UpdateTCManifest(TCManifest, manifestSize);
    //------------------------------------------------------------------------//
    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    MsgArg props;
    ASSERT_EQ(ER_OK, proxy.GetAllProperties(interfaceName, props));

    {
        int32_t prop1;
        MsgArg* propArg;
        EXPECT_EQ(ER_OK, props.GetElement("{sv}", "Prop1", &propArg)) << props.ToString().c_str();
        EXPECT_EQ(ER_OK, propArg->Get("i", &prop1)) << propArg->ToString().c_str();
        EXPECT_EQ(42, prop1);
    }
    {
        int32_t prop2;
        MsgArg* propArg;
        EXPECT_EQ(ER_OK, props.GetElement("{sv}", "Prop2", &propArg)) << props.ToString().c_str();
        EXPECT_EQ(ER_OK, propArg->Get("i", &prop2)) << propArg->ToString().c_str();
        EXPECT_EQ(17, prop2);
    }

    /* clean up */
    //TCBus.UnregisterBusObject(TCBusObject);
}

TEST_F(SecurityPolicyRulesTest, GetAllProperties_test6_properties_successfully_fetched_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));
    const size_t manifestSize = 1;

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        CreatePolicyWithMembersForGetAllProperties(TCPolicy, members, 1);
    }

    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    TCManifest[0].SetObjPath("/test");
    TCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        TCManifest[0].SetMembers(2, members);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        CreatePolicyWithMembersForGetAllProperties(SCPolicy, members, 1);
    }

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    SCManifest[0].SetObjPath("/test");
    SCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        SCManifest[0].SetMembers(1, members);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    UpdateTCManifest(TCManifest, manifestSize);
    UpdateSCManifest(SCManifest, manifestSize);
    //------------------------------------------------------------------------//
    SessionOpts opts;
    SessionId TCToSCSessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    TCProperties props;
    QStatus status = TCBus.GetAllProperties(SCBus.GetUniqueName().c_str(), interfaceName, props);
    EXPECT_EQ(ER_OK, status);

    {
        int32_t prop1;
        EXPECT_EQ(ER_OK, props.GetElement("Prop1", prop1));
        EXPECT_EQ(42, prop1);
    }
    {
        int32_t prop2;
        EXPECT_EQ(ER_OK, props.GetElement("Prop2", prop2));
        EXPECT_EQ(17, prop2);
    }

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Setup following policies and manifests
 *
 * Peer1 policy
 * -----------------
 * PeerType: ANY_TRUSTED
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { *, Property, PROVIDE}
 * Peer1 manifest:
 * ------------------
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { *, Property, OBSERVE}
 * Peer2 policy
 * -----------------
 * PeerType: ANY_TRUSTED
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { Prop1, Property, OBSERVE}, {Prop2, Property, OBSERVE}
 * Peer2 manifest:
 * ------------------
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { *, Property, PROVIDE}
 *
 * Expected Result:
 * GetAllProperties will be successfully sent.
 * Both properties Prop1 and Prop2 will be fetched
 */
TEST_F(SecurityPolicyRulesTest, GetAllProperties_test7_properties_successfully_fetched_SC)
{
    const size_t manifestSize = 1;

    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        CreatePolicyWithMembersForGetAllProperties(SCPolicy, members, 1);
    }

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    SCManifest[0].SetObjPath("/test");
    SCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        SCManifest[0].SetMembers(1, members);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        CreatePolicyWithMembersForGetAllProperties(TCPolicy, members, 2);
    }

    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    TCManifest[0].SetObjPath("/test");
    TCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        TCManifest[0].SetMembers(1, members);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    UpdateSCManifest(SCManifest, manifestSize);
    UpdateTCManifest(TCManifest, manifestSize);
    //------------------------------------------------------------------------//
    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    MsgArg props;
    ASSERT_EQ(ER_OK, proxy.GetAllProperties(interfaceName, props));

    {
        int32_t prop1;
        MsgArg* propArg;
        EXPECT_EQ(ER_OK, props.GetElement("{sv}", "Prop1", &propArg)) << props.ToString().c_str();
        EXPECT_EQ(ER_OK, propArg->Get("i", &prop1)) << propArg->ToString().c_str();
        EXPECT_EQ(42, prop1);
    }
    {
        int32_t prop2;
        MsgArg* propArg;
        EXPECT_EQ(ER_OK, props.GetElement("{sv}", "Prop2", &propArg)) << props.ToString().c_str();
        EXPECT_EQ(ER_OK, propArg->Get("i", &prop2)) << propArg->ToString().c_str();
        EXPECT_EQ(17, prop2);
    }

    /* clean up */
    //TCBus.UnregisterBusObject(TCBusObject);
}

TEST_F(SecurityPolicyRulesTest, GetAllProperties_test7_properties_successfully_fetched_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));
    const size_t manifestSize = 1;

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        CreatePolicyWithMembersForGetAllProperties(TCPolicy, members, 1);
    }

    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    TCManifest[0].SetObjPath("/test");
    TCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        TCManifest[0].SetMembers(1, members);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        CreatePolicyWithMembersForGetAllProperties(SCPolicy, members, 2);
    }

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    SCManifest[0].SetObjPath("/test");
    SCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        SCManifest[0].SetMembers(1, members);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    UpdateTCManifest(TCManifest, manifestSize);
    UpdateSCManifest(SCManifest, manifestSize);
    //------------------------------------------------------------------------//
    SessionOpts opts;
    SessionId TCToSCSessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    TCProperties props;
    QStatus status = TCBus.GetAllProperties(SCBus.GetUniqueName().c_str(), interfaceName, props);
    EXPECT_EQ(ER_OK, status);

    {
        int32_t prop1;
        EXPECT_EQ(ER_OK, props.GetElement("Prop1", prop1));
        EXPECT_EQ(42, prop1);
    }
    {
        int32_t prop2;
        EXPECT_EQ(ER_OK, props.GetElement("Prop2", prop2));
        EXPECT_EQ(17, prop2);
    }

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Setup following policies and manifests
 *
 * Peer1 policy
 * -----------------
 * PeerType: ANY_TRUSTED
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { *, Property, PROVIDE}
 * Peer1 manifest:
 * ------------------
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { Prop1, Property, OBSERVE}, {Prop2, Property, OBSERVE}
 * Peer2 policy
 * -----------------
 * PeerType: ANY_TRUSTED
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { Prop1, Property, OBSERVE}, {Prop2, Property, OBSERVE}
 * Peer2 manifest:
 * ------------------
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { Prop1, Property, PROVIDE}
 *
 * Expected Result:
 * GetAllProperties won’t be sent. Because, the receiver manifest does not have
 * the wildcard for the property
 */
TEST_F(SecurityPolicyRulesTest, GetAllProperties_test8_no_properties_fetched_SC)
{
    const size_t manifestSize = 1;

    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        CreatePolicyWithMembersForGetAllProperties(SCPolicy, members, 1);
    }

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    SCManifest[0].SetObjPath("/test");
    SCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        SCManifest[0].SetMembers(2, members);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        CreatePolicyWithMembersForGetAllProperties(TCPolicy, members, 2);
    }

    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    TCManifest[0].SetObjPath("/test");
    TCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        TCManifest[0].SetMembers(1, members);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    UpdateSCManifest(SCManifest, manifestSize);
    UpdateTCManifest(TCManifest, manifestSize);
    //------------------------------------------------------------------------//
    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    MsgArg props;
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.GetAllProperties(interfaceName, props));

    /* clean up */
    //TCBus.UnregisterBusObject(TCBusObject);
}

TEST_F(SecurityPolicyRulesTest, GetAllProperties_test8_no_properties_fetched_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));
    const size_t manifestSize = 1;

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        CreatePolicyWithMembersForGetAllProperties(TCPolicy, members, 1);
    }

    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    TCManifest[0].SetObjPath("/test");
    TCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        TCManifest[0].SetMembers(2, members);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        CreatePolicyWithMembersForGetAllProperties(SCPolicy, members, 2);
    }

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    SCManifest[0].SetObjPath("/test");
    SCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        SCManifest[0].SetMembers(1, members);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    UpdateTCManifest(TCManifest, manifestSize);
    UpdateSCManifest(SCManifest, manifestSize);
    //------------------------------------------------------------------------//
    SessionOpts opts;
    SessionId TCToSCSessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    TCProperties props;
    EXPECT_EQ(ER_PERMISSION_DENIED, TCBus.GetAllProperties(SCBus.GetUniqueName().c_str(), interfaceName, props));

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Setup following policies and manifests
 *
 * Peer1 policy
 * -----------------
 * PeerType: ANY_TRUSTED
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { Prop1, Property, PROVIDE}
 * Peer1 manifest:
 * ------------------
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { Prop1, Property, OBSERVE}, {Prop2, Property, OBSERVE}
 * Peer2 policy
 * -----------------
 * PeerType: ANY_TRUSTED
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { Prop1, Property, OBSERVE}, {Prop2, Property, OBSERVE}
 * Peer2 manifest:
 * ------------------
 * Rule:
 *   ObjectPath: /test
 *   interfaceName: org.allseen.test.SecurityApplication.rules
 *   Members: { *, Property, PROVIDE}
 *
 * Expected Result:
 * GetAllProperties won’t be sent. Because, the sender local policy does not
 * have the wildcard for Property.
 */
TEST_F(SecurityPolicyRulesTest, GetAllProperties_test9_no_properties_fetched_SC)
{
    const size_t manifestSize = 1;

    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        CreatePolicyWithMembersForGetAllProperties(SCPolicy, members, 1);
    }

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    SCManifest[0].SetObjPath("/test");
    SCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        SCManifest[0].SetMembers(2, members);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        CreatePolicyWithMembersForGetAllProperties(TCPolicy, members, 2);
    }

    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    TCManifest[0].SetObjPath("/test");
    TCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        TCManifest[0].SetMembers(1, members);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    UpdateSCManifest(SCManifest, manifestSize);
    UpdateTCManifest(TCManifest, manifestSize);
    //------------------------------------------------------------------------//
    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    MsgArg props;
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.GetAllProperties(interfaceName, props));

    /* clean up */
    //TCBus.UnregisterBusObject(TCBusObject);
}

TEST_F(SecurityPolicyRulesTest, GetAllProperties_test9_no_properties_fetched_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));
    const size_t manifestSize = 1;

    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        CreatePolicyWithMembersForGetAllProperties(TCPolicy, members, 1);
    }

    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    TCManifest[0].SetObjPath("/test");
    TCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        TCManifest[0].SetMembers(2, members);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    {
        PermissionPolicy::Rule::Member members[2];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        members[1].Set("Prop2",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        CreatePolicyWithMembersForGetAllProperties(SCPolicy, members, 2);
    }

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    SCManifest[0].SetObjPath("/test");
    SCManifest[0].SetInterfaceName(interfaceName);
    {
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*", PermissionPolicy::Rule::Member::PROPERTY, PermissionPolicy::Rule::Member::ACTION_PROVIDE);
        SCManifest[0].SetMembers(1, members);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str());
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str());

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    UpdateTCManifest(TCManifest, manifestSize);
    UpdateSCManifest(SCManifest, manifestSize);
    //------------------------------------------------------------------------//
    SessionOpts opts;
    SessionId TCToSCSessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    TCProperties props;
    EXPECT_EQ(ER_PERMISSION_DENIED, TCBus.GetAllProperties(SCBus.GetUniqueName().c_str(), interfaceName, props));

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Purpose
 * Verify that DENY rules that are specific or wild card do not take effect if
 * the ACL has a peer type of ALL.
 *
 * Setup
 * Sender and Receiver bus implement the following :
 * Object Path:  /test
 * Interface Name: "org.allseen.test.SecurityApplication.rules"
 * Member name: Echo (method call)
 * Member name: Prop1  (property, read write)
 * Member name: Chirp (signal)
 * Peer1 and Peer2 set up an ECDHE_NULL based session.
 * Peer1 makes a method call to Peer2.
 * Peer1 sends a signal to Peer2.
 * Peer1 makes a get property call on Peer2
 * Peer1 makes a set property call on Peer2
 *
 * Peer1 rules:
 * ACL: Peer type: ALL
 * Rule 0: Object Path= *, Interface=*, Member name=*, Member Type = NS, Action mask = DENY
 * Rule 1: Object Path=/test, Interface = org.allseen.test.SecurityApplication.rules, Member name = *, Member type = NS, Action Mask = DENY
 * Rule 2: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 * Peer2 rules:
 * ACL: Peer type: ALL
 * Rule 0: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 * verification:
 * Verify that method call, get/set property calls are successful.
 * Verify that signal is received by B.
 */
TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_1_SC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ALL);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[3];
            //rule 0
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 1
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 2
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[2].SetMembers(1, members);
            }
            acls[0].SetRules(3, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ALL);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0
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
        TCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));

    /* We should be using a ECDHE_NULL based session */
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", managerAuthListener, NULL, false));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL"));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    // Verify Method call
    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    ASSERT_EQ(ER_OK, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
    char* echoReply;
    replyMsg->GetArg(0)->Get("s", &echoReply);
    EXPECT_STREQ("String that should be Echoed back.", echoReply);

    // Verify Set/Get Property
    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_OK, proxy.SetProperty(interfaceName, "Prop1", prop1Arg));
    EXPECT_EQ(513, TCBus.ReadProp1());

    MsgArg prop1ArgOut;
    EXPECT_EQ(ER_OK, proxy.GetProperty(interfaceName, "Prop1", prop1Arg));
    uint32_t prop1;
    prop1Arg.Get("i", &prop1);
    EXPECT_EQ((uint32_t)513, prop1);

    // Send/Receive Signal
    arg.Set("s", "Chirp this String out in the signal.");
    // Signals are send and forget.  They will always return ER_OK.
    EXPECT_EQ(ER_OK, SCBusObject.Signal(TCBus.GetUniqueName().c_str(), SCToTCSessionId, *SCBus.GetInterface(interfaceName)->GetMember("Chirp"), &arg, 1, 0, 0));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (TCBus.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(TCBus.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_1_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ALL);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[3];
            //rule 0
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 1
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 2
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[2].SetMembers(1, members);
            }
            acls[0].SetRules(3, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ALL);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0
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
        SCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));

    /* We should be using a ECDHE_NULL based session */
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL"));
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", managerAuthListener, NULL, false));

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    // Verify Method call
    const char* s = "String that should be Echoed back.";
    ASSERT_EQ(ER_OK, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));
    EXPECT_STREQ(s, TCBus.GetResponse());

    // Verify Set/Get Property
    EXPECT_EQ(ER_OK, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, 513));
    EXPECT_EQ(513, SCBusObject.ReadProp1());
    int32_t prop; 
    EXPECT_EQ(ER_OK, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop));
    EXPECT_EQ(513, prop);

    // Send/Receive Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver, static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler), SCBus.GetInterface(interfaceName)->GetMember("Chirp"), NULL));

    EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_CHIRP, "Chirp this String out in the signal."));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Purpose
 * Verify that DENY rules that are specific or wild card do not take effect if
 * the ACL has a peer type of ALL.
 *
 * Setup
 * Sender and Receiver bus implement the following :
 * Object Path:  /test
 * Interface Name: "org.allseen.test.SecurityApplication.rules"
 * Member name: Echo (method call)
 * Member name: Prop1  (property, read write)
 * Member name: Chirp (signal)
 * Peer1 and Peer2 set up an ECDHE_NULL based session.
 * Peer1 makes a method call to Peer2.
 * Peer1 makes a get property call on Peer2
 * Peer1 makes a set property call on Peer2
 * Peer1 sends a signal to Peer2.
 *
 * Peer1 rules:
 * ACL: Peer type: ALL
 * Rule 0: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 * Peer1 rules:
 * ACL: Peer type: ALL
 * Rule 0: Object Path= *, Interface=*, Member name=*, Member Type = NS, Action mask = DENY
 * Rule 1: Object Path=/test, Interface = org.allseen.test.SecurityApplication.rules, Member name = *, Member type = NS, Action Mask = DENY
 * Rule 2: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 *
 *
 * verification:
 * Verify that method call, get/set property calls are successful.
 * Verify that signal is received by B.
 */
TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_2_SC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ALL);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0
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
        SCPolicy.SetAcls(1, acls);
    }

    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ALL);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[3];
            //rule 0
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 1
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 2
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[2].SetMembers(1, members);
            }
            acls[0].SetRules(3, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));

    /* We should be using a ECDHE_NULL based session */
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", managerAuthListener, NULL, false));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL"));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    // Verify Method call
    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    ASSERT_EQ(ER_OK, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
    char* echoReply;
    replyMsg->GetArg(0)->Get("s", &echoReply);
    EXPECT_STREQ("String that should be Echoed back.", echoReply);

    // Verify Set/Get Property
    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_OK, proxy.SetProperty(interfaceName, "Prop1", prop1Arg));
    EXPECT_EQ(513, TCBus.ReadProp1());

    MsgArg prop1ArgOut;
    EXPECT_EQ(ER_OK, proxy.GetProperty(interfaceName, "Prop1", prop1Arg));
    uint32_t prop1;
    prop1Arg.Get("i", &prop1);
    EXPECT_EQ((uint32_t)513, prop1);

    // Send/Receive Signal
    arg.Set("s", "Chirp this String out in the signal.");
    // Signals are send and forget.  They will always return ER_OK.
    EXPECT_EQ(ER_OK, SCBusObject.Signal(TCBus.GetUniqueName().c_str(), SCToTCSessionId, *SCBus.GetInterface(interfaceName)->GetMember("Chirp"), &arg, 1, 0, 0));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (TCBus.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(TCBus.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_2_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ALL);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0
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
        TCPolicy.SetAcls(1, acls);
    }

    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ALL);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[3];
            //rule 0
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 1
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 2
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[2].SetMembers(1, members);
            }
            acls[0].SetRules(3, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));

    /* We should be using a ECDHE_NULL based session */
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL"));
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", managerAuthListener, NULL, false));

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    // Verify Method call
    const char* s = "String that should be Echoed back.";
    ASSERT_EQ(ER_OK, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));
    EXPECT_STREQ(s, TCBus.GetResponse());

    // Verify Set/Get Property
    EXPECT_EQ(ER_OK, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, 513));
    EXPECT_EQ(513, SCBusObject.ReadProp1());
    int32_t prop; 
    EXPECT_EQ(ER_OK, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop));
    EXPECT_EQ(513, prop);

    // Send/Receive Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver, static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler), SCBus.GetInterface(interfaceName)->GetMember("Chirp"), NULL));

    EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_CHIRP, "Chirp this String out in the signal."));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Purpose
 * Verify that DENY rules that are specific or wild card do not take effect if
 * the ACL has a peer type of ANY_TRUSTED.
 *
 * Setup
 * Sender and Receiver bus implement the following :
 * Object Path:  /test
 * Interface Name: "org.allseen.test.SecurityApplication.rules"
 * Member name: Echo (method call)
 * Member name: Prop1  (property, read write)
 * Member name: Chirp (signal)
 * Peer1 and Peer2 set up an ECDHE_ECDSA based session.
 * Peer1 makes a method call to Peer2.
 * Peer1 sends a signal to Peer2.
 * Peer1 makes a get property call on Peer2
 * Peer1 makes a set property call on Peer2
 *
 * Peer1 rules:
 * ACL: Peer type: ANY_TRUSTED
 * Rule 0: Object Path= *, Interface=*, Member name=*, Member Type = NS, Action mask = DENY
 * Rule 1: Object Path=/test, Interface = org.allseen.test.SecurityApplication.rules, Member name = *, Member type = NS, Action Mask = DENY
 * Rule 2: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 * Peer2 rules:
 * ACL: Peer type: ANY_TRUSTED
 * Rule 0: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 * verification:
 * Verify that method call, get/set property calls are successful.
 * Verify that signal is received by Peer2.
 */
TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_3_SC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[3];
            //rule 0
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 1
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 2
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[2].SetMembers(1, members);
            }
            acls[0].SetRules(3, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }
    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0
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
        TCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    // Verify Method call
    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_OK, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
    char* echoReply;
    replyMsg->GetArg(0)->Get("s", &echoReply);
    EXPECT_STREQ("String that should be Echoed back.", echoReply);

    // Verify Set/Get Property
    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_OK, proxy.SetProperty(interfaceName, "Prop1", prop1Arg));
    EXPECT_EQ(513, TCBus.ReadProp1());

    MsgArg prop1ArgOut;
    EXPECT_EQ(ER_OK, proxy.GetProperty(interfaceName, "Prop1", prop1Arg));
    uint32_t prop1;
    prop1Arg.Get("i", &prop1);
    EXPECT_EQ((uint32_t)513, prop1);

    // Send/Receive Signal
    arg.Set("s", "Chirp this String out in the signal.");
    // Signals are send and forget.  They will always return ER_OK.
    EXPECT_EQ(ER_OK, SCBusObject.Signal(TCBus.GetUniqueName().c_str(), SCToTCSessionId, *SCBus.GetInterface(interfaceName)->GetMember("Chirp"), &arg, 1, 0, 0));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (TCBus.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(TCBus.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_3_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[3];
            //rule 0
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 1
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 2
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[2].SetMembers(1, members);
            }
            acls[0].SetRules(3, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }
    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0
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
        SCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    // Verify Method call
    const char* s = "String that should be Echoed back.";
    ASSERT_EQ(ER_OK, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));
    EXPECT_STREQ(s, TCBus.GetResponse());

    // Verify Set/Get Property
    EXPECT_EQ(ER_OK, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, 513));
    EXPECT_EQ(513, SCBusObject.ReadProp1());
    int32_t prop; 
    EXPECT_EQ(ER_OK, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop));
    EXPECT_EQ(513, prop);

    // Send/Receive Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver, static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler), SCBus.GetInterface(interfaceName)->GetMember("Chirp"), NULL));

    EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_CHIRP, "Chirp this String out in the signal."));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Purpose
 * Verify that DENY rules that are specific or wild card do not take effect if
 * the ACL has a peer type of ANY_TRUSTED.
 *
 * Setup
 * Sender and Receiver bus implement the following :
 * Object Path:  /test
 * Interface Name: "org.allseen.test.SecurityApplication.rules"
 * Member name: Echo (method call)
 * Member name: Prop1  (property, read write)
 * Member name: Chirp (signal)
 * Peer1 and Peer2 set up an ECDHE_ECDSA based session.
 * Peer1 makes a method call to Peer2.
 * Peer1 sends a signal to Peer2.
 * Peer1 makes a get property call on Peer2
 * Peer1 makes a set property call on Peer2
 *
 * Peer1 rules:
 * ACL: Peer type: ANY_TRUSTED
 * Rule 0: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 * Peer2 rules:
 * ACL: Peer type: ANY_TRUSTED
 * Rule 0: Object Path= *, Interface=*, Member name=*, Member Type = NS, Action mask = DENY
 * Rule 1: Object Path=/test, Interface = org.allseen.test.SecurityApplication.rules, Member name = *, Member type = NS, Action Mask = DENY
 * Rule 2: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 *
 *
 * verification:
 * Verify that method call, get/set property calls are successful.
 * Verify that signal is received by Peer2.
 */
TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_4_SC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0
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
        SCPolicy.SetAcls(1, acls);
    }

    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[3];
            //rule 0
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 1
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 2
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[2].SetMembers(1, members);
            }
            acls[0].SetRules(3, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    // Verify Method call
    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_OK, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
    char* echoReply;
    replyMsg->GetArg(0)->Get("s", &echoReply);
    EXPECT_STREQ("String that should be Echoed back.", echoReply);

    // Verify Set/Get Property
    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_OK, proxy.SetProperty(interfaceName, "Prop1", prop1Arg));
    EXPECT_EQ(513, TCBus.ReadProp1());

    MsgArg prop1ArgOut;
    EXPECT_EQ(ER_OK, proxy.GetProperty(interfaceName, "Prop1", prop1Arg));
    uint32_t prop1;
    prop1Arg.Get("i", &prop1);
    EXPECT_EQ((uint32_t)513, prop1);

    // Send/Receive Signal
    arg.Set("s", "Chirp this String out in the signal.");
    // Signals are send and forget.  They will always return ER_OK.
    EXPECT_EQ(ER_OK, SCBusObject.Signal(TCBus.GetUniqueName().c_str(), SCToTCSessionId, *SCBus.GetInterface(interfaceName)->GetMember("Chirp"), &arg, 1, 0, 0));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (TCBus.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(TCBus.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_4_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0
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
        TCPolicy.SetAcls(1, acls);
    }

    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[3];
            //rule 0
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 1
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 2
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[2].SetMembers(1, members);
            }
            acls[0].SetRules(3, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    // Verify Method call
    const char* s = "String that should be Echoed back.";
    ASSERT_EQ(ER_OK, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));
    EXPECT_STREQ(s, TCBus.GetResponse());

    // Verify Set/Get Property
    EXPECT_EQ(ER_OK, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, 513));
    EXPECT_EQ(513, SCBusObject.ReadProp1());
    int32_t prop; 
    EXPECT_EQ(ER_OK, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop));
    EXPECT_EQ(513, prop);

    // Send/Receive Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver, static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler), SCBus.GetInterface(interfaceName)->GetMember("Chirp"), NULL));

    EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_CHIRP, "Chirp this String out in the signal."));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Purpose
 * Verify that DENY rules that are specific or wild card do not take effect
 * if the ACL has a peer type of WITH_CA
 *
 * Setup
 * Sender and Receiver bus implement the following :
 * Object Path:  /test
 * Interface Name: "org.allseen.test.SecurityApplication.rules"
 * Member name: Echo (method call)
 * Member name: Prop1  (property, read write)
 * Member name: Chirp (signal)
 * ICC of Peer2: CA1->Peer2
 * Peer1 and Peer2 set up an ECDHE_ECDSA based session.
 * Peer1 makes a method call to Peer2.
 * Peer1 sends a signal to Peer2.
 * Peer1 makes a get property call on Peer2
 * Peer1 makes a set property call on Peer2
 *
 * Peer1 rules:
 * ACL: Peer type: WITH_CA Public Key: CA1
 * Rule 0: Object Path= *, Interface=*, Member name=*, Member Type = NS, Action mask = DENY
 * Rule 1: Object Path=/test, Interface = org.allseen.test.SecurityApplication.rules, Member name = *, Member type = NS, Action Mask = DENY
 * Rule 2: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 * Peer2 rules:
 * ACL: Peer type: ANY_TRUSTED
 * Rule 0: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 * verification:
 * Verify that method call, get/set property calls are successful.
 * Verify that signal is received by Peer2.
 */
TEST_F(SecurityPolicyRulesTest, DISABLED_PolicyRules_DENY_5_SC)
{
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    PermissionMgmtObj::GenerateManifestDigest(managerBus, manifest, 1, digest, Crypto_SHA256::DIGEST_SIZE);

    uint8_t subjectCN[] = { 1, 2, 3, 4 };
    uint8_t issuerCN[] = { 5, 6, 7, 8 };

    Crypto_ECC caKey;
    ASSERT_EQ(ER_OK, caKey.GenerateDSAKeyPair());

    //Create the CA1 cert
    qcc::IdentityCertificate CACert;
    CACert.SetSerial((uint8_t*)"5678", 5);
    CACert.SetIssuerCN(issuerCN, 4);
    CACert.SetSubjectCN(issuerCN, 4);
    CertificateX509::ValidPeriod validityCA;
    validityCA.validFrom = qcc::GetEpochTimestamp() / 1000;
    validityCA.validTo = validityCA.validFrom + TEN_MINS;
    CACert.SetValidity(&validityCA);
    CACert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    KeyInfoNISTP256 SCPublicKey;
    PermissionConfigurator& SCPermissionConfigurator = SCBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, SCPermissionConfigurator.GetSigningPublicKey(SCPublicKey));

    CACert.SetSubjectPublicKey(caKey.GetDSAPublicKey());
    CACert.SetAlias("ca1-cert-alias");
    CACert.SetCA(true);

    //sign the ca1 cert
    EXPECT_EQ(ER_OK, CACert.Sign(caKey.GetDSAPrivateKey()));

    // Create the TCCert
    qcc::IdentityCertificate TCCert;
    TCCert.SetSerial((uint8_t*)"1234", 5);
    TCCert.SetIssuerCN(issuerCN, 4);
    TCCert.SetSubjectCN(subjectCN, 4);
    CertificateX509::ValidPeriod validity;
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    TCCert.SetValidity(&validity);
    TCCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    TCCert.SetSubjectPublicKey(&TCPublicKey);
    TCCert.SetAlias("TC-cert-alias");
    TCCert.SetCA(true);

    //sign the leaf cert
    EXPECT_EQ(ER_OK, TCCert.Sign(caKey.GetDSAPrivateKey()));

    //We need identityCert chain CA1->TC
    const size_t certChainSize = 2;
    IdentityCertificate identityCertChain[certChainSize];
    identityCertChain[0] = TCCert;
    identityCertChain[1] = CACert;

    // Call UpdateIdentity to install the cert chain
    EXPECT_EQ(ER_OK, sapWithTC.UpdateIdentity(identityCertChain, certChainSize, manifest, manifestSize))
        << "Failed to update Identity cert or manifest ";
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_FROM_CERTIFICATE_AUTHORITY);
            peers[0].SetKeyInfo(&SCPublicKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[3];
            //rule 0
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 1
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 2
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[2].SetMembers(1, members);
            }
            acls[0].SetRules(3, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }
    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0
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
        TCPolicy.SetAcls(1, acls);
    }

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    // Verify Method call
    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_OK, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
    char* echoReply;
    replyMsg->GetArg(0)->Get("s", &echoReply);
    EXPECT_STREQ("String that should be Echoed back.", echoReply);

    // Verify Set/Get Property
    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_OK, proxy.SetProperty(interfaceName, "Prop1", prop1Arg));
    EXPECT_EQ(513, TCBus.ReadProp1());

    MsgArg prop1ArgOut;
    EXPECT_EQ(ER_OK, proxy.GetProperty(interfaceName, "Prop1", prop1Arg));
    uint32_t prop1;
    prop1Arg.Get("i", &prop1);
    EXPECT_EQ((uint32_t)513, prop1);

    // Send/Receive Signal
    arg.Set("s", "Chirp this String out in the signal.");
    // Signals are send and forget.  They will always return ER_OK.
    EXPECT_EQ(ER_OK, SCBusObject.Signal(TCBus.GetUniqueName().c_str(), SCToTCSessionId, *SCBus.GetInterface(interfaceName)->GetMember("Chirp"), &arg, 1, 0, 0));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (TCBus.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(TCBus.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

TEST_F(SecurityPolicyRulesTest, DISABLED_PolicyRules_DENY_5_TC)
{
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    PermissionMgmtObj::GenerateManifestDigest(managerBus, manifest, 1, digest, Crypto_SHA256::DIGEST_SIZE);

    uint8_t subjectCN[] = { 1, 2, 3, 4 };
    uint8_t issuerCN[] = { 5, 6, 7, 8 };

    Crypto_ECC caKey;
    ASSERT_EQ(ER_OK, caKey.GenerateDSAKeyPair());

    //Create the CA1 cert
    qcc::IdentityCertificate CACert;
    CACert.SetSerial((uint8_t*)"5678", 5);
    CACert.SetIssuerCN(issuerCN, 4);
    CACert.SetSubjectCN(issuerCN, 4);
    CertificateX509::ValidPeriod validityCA;
    validityCA.validFrom = qcc::GetEpochTimestamp() / 1000;
    validityCA.validTo = validityCA.validFrom + TEN_MINS;
    CACert.SetValidity(&validityCA);
    CACert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    CACert.SetSubjectPublicKey(caKey.GetDSAPublicKey());
    CACert.SetAlias("ca1-cert-alias");
    CACert.SetCA(true);

    //sign the ca1 cert
    EXPECT_EQ(ER_OK, CACert.Sign(caKey.GetDSAPrivateKey()));

    // Create the SCCert
    qcc::IdentityCertificate SCCert;
    SCCert.SetSerial((uint8_t*)"1234", 5);
    SCCert.SetIssuerCN(issuerCN, 4);
    SCCert.SetSubjectCN(subjectCN, 4);
    CertificateX509::ValidPeriod validity;
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    SCCert.SetValidity(&validity);
    SCCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    ECCPublicKey SCPublicKey;
    GetAppPublicKey(SCBus, SCPublicKey);

    SCCert.SetSubjectPublicKey(&SCPublicKey);
    SCCert.SetAlias("SC-cert-alias");
    SCCert.SetCA(true);

    //sign the leaf cert
    EXPECT_EQ(ER_OK, SCCert.Sign(caKey.GetDSAPrivateKey()));

    //We need identityCert chain CA1->SC
    const size_t certChainSize = 2;
    IdentityCertificate identityCertChain[certChainSize];
    identityCertChain[0] = SCCert;
    identityCertChain[1] = CACert;

    // Call UpdateIdentity to install the cert chain
    EXPECT_EQ(ER_OK, sapWithSC.UpdateIdentity(identityCertChain, certChainSize, manifest, manifestSize))
        << "Failed to update Identity cert or manifest ";
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_FROM_CERTIFICATE_AUTHORITY);
            peers[0].SetKeyInfo(&TCKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[3];
            //rule 0
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 1
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 2
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[2].SetMembers(1, members);
            }
            acls[0].SetRules(3, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }
    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0
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
        SCPolicy.SetAcls(1, acls);
    }

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    SessionOpts opts;
    SessionId TCToSCSessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    // Verify Method call
    const char* s = "String that should be Echoed back.";
    EXPECT_EQ(ER_OK, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));
    EXPECT_STREQ(s, TCBus.GetResponse());

    // Verify Set/Get Property
    EXPECT_EQ(ER_OK, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, 513));
    EXPECT_EQ(513, SCBusObject.ReadProp1());
    int32_t prop; 
    EXPECT_EQ(ER_OK, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop));
    EXPECT_EQ(513, prop);

    // Send/Receive Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver, static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler), SCBus.GetInterface(interfaceName)->GetMember("Chirp"), NULL));

    EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_CHIRP, "Chirp this String out in the signal."));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
} 

/*
 * Purpose
 * Verify that DENY rules that are specific or wild card do not
 * take effect if the ACL has a peer type of WITH_CA.
 *
 * Setup
 * Sender and Receiver bus implement the following :
 * Object Path:  /test
 * Interface Name: "org.allseen.test.SecurityApplication.rules"
 * Member name: Echo (method call)
 * Member name: Prop1  (property, read write)
 * Member name: Chirp (signal)
 * Peer1 and Peer2 set up an ECDHE_ECDSA based session.
 * Peer1 makes a method call to Peer2.
 * Peer1 sends a signal to Peer2.
 * Peer1 makes a get property call on Peer2
 * Peer1 makes a set property call on Peer2
 *
 * Peer1 rules:
 * ACL: Peer type: ANY_TRUSTED
 * Rule 0: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 * Peer2 rules:
 * ACL: Peer type: WITH_CA Public Key: CA1
 * Rule 0: Object Path= *, Interface=*, Member name=*, Member Type = NS, Action mask = DENY
 * Rule 1: Object Path=/test, Interface = org.allseen.test.SecurityApplication.rules, Member name = *, Member type = NS, Action Mask = DENY
 * Rule 2: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 *
 *
 * verification:
 * Verify that method call, get/set property calls are successful.
 * Verify that signal is received by Peer2.
 */
TEST_F(SecurityPolicyRulesTest, DISABLED_PolicyRules_DENY_6_SC)
{
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    PermissionMgmtObj::GenerateManifestDigest(managerBus, manifest, 1, digest, Crypto_SHA256::DIGEST_SIZE);

    uint8_t subjectCN[] = { 1, 2, 3, 4 };
    uint8_t issuerCN[] = { 5, 6, 7, 8 };

    Crypto_ECC caKey;
    ASSERT_EQ(ER_OK, caKey.GenerateDSAKeyPair());

    //Create the CA cert
    qcc::IdentityCertificate CACert;
    CACert.SetSerial((uint8_t*)"5678", 5);
    CACert.SetIssuerCN(issuerCN, 4);
    CACert.SetSubjectCN(issuerCN, 4);
    CertificateX509::ValidPeriod validityCA;
    validityCA.validFrom = 1427404154;
    validityCA.validTo = 1427404154 + 630720000;
    CACert.SetValidity(&validityCA);
    CACert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    KeyInfoNISTP256 SCPublicKey;
    PermissionConfigurator& SCPermissionConfigurator = SCBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, SCPermissionConfigurator.GetSigningPublicKey(SCPublicKey));

    CACert.SetSubjectPublicKey(caKey.GetDSAPublicKey());
    CACert.SetAlias("ca1-cert-alias");
    CACert.SetCA(true);

    //sign the ca1 cert
    EXPECT_EQ(ER_OK, CACert.Sign(caKey.GetDSAPrivateKey()));

    // Create the TCCert
    qcc::IdentityCertificate TCCert;
    TCCert.SetSerial((uint8_t*)"1234", 5);
    TCCert.SetIssuerCN(issuerCN, 4);
    TCCert.SetSubjectCN(subjectCN, 4);
    CertificateX509::ValidPeriod validity;
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    TCCert.SetValidity(&validity);
    TCCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    TCCert.SetSubjectPublicKey(&TCPublicKey);
    TCCert.SetAlias("TC-cert-alias");
    TCCert.SetCA(true);

    //sign the leaf cert
    EXPECT_EQ(ER_OK, TCCert.Sign(caKey.GetDSAPrivateKey()));

    //We need identityCert chain CA1->TC
    const size_t certChainSize = 2;
    IdentityCertificate identityCertChain[certChainSize];
    identityCertChain[0] = TCCert;
    identityCertChain[1] = CACert;

    // Call UpdateIdentity to install the cert chain
    EXPECT_EQ(ER_OK, sapWithSC.UpdateIdentity(identityCertChain, certChainSize, manifest, manifestSize))
        << "Failed to update Identity cert or manifest ";
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0
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
        SCPolicy.SetAcls(1, acls);
    }

    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_FROM_CERTIFICATE_AUTHORITY);
            peers[0].SetKeyInfo(&SCPublicKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[3];
            //rule 0
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 1
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 2
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[2].SetMembers(1, members);
            }
            acls[0].SetRules(3, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    // Verify Method call
    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_OK, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
    char* echoReply;
    replyMsg->GetArg(0)->Get("s", &echoReply);
    EXPECT_STREQ("String that should be Echoed back.", echoReply);

    // Verify Set/Get Property
    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_OK, proxy.SetProperty(interfaceName, "Prop1", prop1Arg));
    EXPECT_EQ(513, TCBus.ReadProp1());

    MsgArg prop1ArgOut;
    EXPECT_EQ(ER_OK, proxy.GetProperty(interfaceName, "Prop1", prop1Arg));
    uint32_t prop1;
    prop1Arg.Get("i", &prop1);
    EXPECT_EQ((uint32_t)513, prop1);

    arg.Set("s", "Chirp this String out in the signal.");
    // Signals are send and forget.  They will always return ER_OK.
    EXPECT_EQ(ER_OK, SCBusObject.Signal(TCBus.GetUniqueName().c_str(), SCToTCSessionId, *SCBus.GetInterface(interfaceName)->GetMember("Chirp"), &arg, 1, 0, 0));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (TCBus.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(TCBus.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

TEST_F(SecurityPolicyRulesTest, DISABLED_PolicyRules_DENY_6_TC)
{
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    PermissionMgmtObj::GenerateManifestDigest(managerBus, manifest, 1, digest, Crypto_SHA256::DIGEST_SIZE);

    uint8_t subjectCN[] = { 1, 2, 3, 4 };
    uint8_t issuerCN[] = { 5, 6, 7, 8 };

    Crypto_ECC caKey;
    ASSERT_EQ(ER_OK, caKey.GenerateDSAKeyPair());

    //Create the CA1 cert
    qcc::IdentityCertificate CACert;
    CACert.SetSerial((uint8_t*)"5678", 5);
    CACert.SetIssuerCN(issuerCN, 4);
    CACert.SetSubjectCN(issuerCN, 4);
    CertificateX509::ValidPeriod validityCA;
    validityCA.validFrom = 1427404154;
    validityCA.validTo = 1427404154 + 630720000;
    CACert.SetValidity(&validityCA);
    CACert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    CACert.SetSubjectPublicKey(caKey.GetDSAPublicKey());
    CACert.SetAlias("ca1-cert-alias");
    CACert.SetCA(true);

    //sign the ca1 cert
    EXPECT_EQ(ER_OK, CACert.Sign(caKey.GetDSAPrivateKey()));

    // Create the SCCert
    qcc::IdentityCertificate SCCert;
    SCCert.SetSerial((uint8_t*)"1234", 5);
    SCCert.SetIssuerCN(issuerCN, 4);
    SCCert.SetSubjectCN(subjectCN, 4);
    CertificateX509::ValidPeriod validity;
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    SCCert.SetValidity(&validity);
    SCCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    ECCPublicKey SCPublicKey;
    GetAppPublicKey(SCBus, SCPublicKey);

    SCCert.SetSubjectPublicKey(&SCPublicKey);
    SCCert.SetAlias("SC-cert-alias");
    SCCert.SetCA(true);

    //sign the leaf cert
    EXPECT_EQ(ER_OK, SCCert.Sign(caKey.GetDSAPrivateKey()));

    //We need identityCert chain CA1->SC
    const size_t certChainSize = 2;
    IdentityCertificate identityCertChain[certChainSize];
    identityCertChain[0] = SCCert;
    identityCertChain[1] = CACert;

    // Call UpdateIdentity to install the cert chain
    EXPECT_EQ(ER_OK, sapWithTC.UpdateIdentity(identityCertChain, certChainSize, manifest, manifestSize))
        << "Failed to update Identity cert or manifest ";
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0
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
        TCPolicy.SetAcls(1, acls);
    }

    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_FROM_CERTIFICATE_AUTHORITY);
            peers[0].SetKeyInfo(&TCKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[3];
            //rule 0
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 1
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 2
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[2].SetMembers(1, members);
            }
            acls[0].SetRules(3, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    SessionOpts opts;
    SessionId TCToSCSessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    // Verify Method call
    const char* s = "String that should be Echoed back.";
    EXPECT_EQ(ER_OK, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));
    EXPECT_STREQ(s, TCBus.GetResponse());

    // Verify Set/Get Property
    EXPECT_EQ(ER_OK, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, 513));
    EXPECT_EQ(513, SCBusObject.ReadProp1());
    int32_t prop; 
    EXPECT_EQ(ER_OK, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop));
    EXPECT_EQ(513, prop);

    // Send/Receive Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver, static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler), SCBus.GetInterface(interfaceName)->GetMember("Chirp"), NULL));

    EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_CHIRP, "Chirp this String out in the signal."));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Purpose
 * Verify that DENY rules that are specific or wild card do not take effect if
 * the ACL has a peer type of WITH_MEMBERSHIP.
 *
 * Setup
 * Sender and Receiver bus implement the following :
 * Object Path:  /test
 * Interface Name: "org.allseen.test.SecurityApplication.rules"
 * Member name: Echo (method call)
 * Member name: Prop1  (property, read write)
 * Member name: Chirp (signal)
 * Peer2 has membership certificate installed.
 * Peer1 and Peer2 set up an ECDHE_ECDSA based session.
 * Peer1 makes a method call to Peer2.
 * Peer1 sends a signal to Peer2.
 * Peer1 makes a get property call on Peer2
 * Peer1 makes a set property call on Peer2
 *
 * Peer1 rules:
 * ACL: Peer type: WITH_MEMBERSHIP, SGID: Living Room, Security Group Authority public key
 * Rule 1: Object Path= *, Interface=*, Member name=*, Member Type = NS, Action mask = DENY
 * Rule 2: Object Path=/test, Interface = org.allseen.test.SecurityApplication.rules, Member name = *, Member type = NS, Action Mask = DENY
 * Rule 3: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 * Peer2 rules:
 * ACL: Peer type: ANY_TRUSTED
 * Rule 0: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 * verification:
 * Verify that method call, get/set property calls are successful.
 * Verify that signal is received by Peer2.
 */
TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_7_SC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);
            peers[0].SetSecurityGroupId(managerGuid);
            //Get manager key
            KeyInfoNISTP256 managerKey;
            PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(managerKey));
            peers[0].SetKeyInfo(&managerKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[3];
            //rule 0
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 1
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 2
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[2].SetMembers(1, members);
            }
            acls[0].SetRules(3, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }
    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0
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
        TCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    // Verify Method call
    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_OK, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
    char* echoReply;
    replyMsg->GetArg(0)->Get("s", &echoReply);
    EXPECT_STREQ("String that should be Echoed back.", echoReply);

    // Verify Set/Get Property
    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_OK, proxy.SetProperty(interfaceName, "Prop1", prop1Arg));
    EXPECT_EQ(513, TCBus.ReadProp1());

    MsgArg prop1ArgOut;
    EXPECT_EQ(ER_OK, proxy.GetProperty(interfaceName, "Prop1", prop1Arg));
    uint32_t prop1;
    prop1Arg.Get("i", &prop1);
    EXPECT_EQ((uint32_t)513, prop1);

    // Send/Receive Signal
    arg.Set("s", "Chirp this String out in the signal.");
    // Signals are send and forget.  They will always return ER_OK.
    EXPECT_EQ(ER_OK, SCBusObject.Signal(TCBus.GetUniqueName().c_str(), SCToTCSessionId, *SCBus.GetInterface(interfaceName)->GetMember("Chirp"), &arg, 1, 0, 0));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (TCBus.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(TCBus.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_7_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);
            peers[0].SetSecurityGroupId(managerGuid);
            //Get manager key
            KeyInfoNISTP256 managerKey;
            PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(managerKey));
            peers[0].SetKeyInfo(&managerKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[3];
            //rule 0
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 1
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 2
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[2].SetMembers(1, members);
            }
            acls[0].SetRules(3, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }
    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0
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
        SCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    // Verify Method call
    const char* s = "String that should be Echoed back.";
    ASSERT_EQ(ER_OK, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));
    EXPECT_STREQ(s, TCBus.GetResponse());

    // Verify Set/Get Property
    EXPECT_EQ(ER_OK, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, 513));
    EXPECT_EQ(513, SCBusObject.ReadProp1());
    int32_t prop; 
    EXPECT_EQ(ER_OK, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop));
    EXPECT_EQ(513, prop);

    // Send/Receive Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver, static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler), SCBus.GetInterface(interfaceName)->GetMember("Chirp"), NULL));

    EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_CHIRP, "Chirp this String out in the signal."));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Purpose
 * Verify that DENY rules that are specific or wild card do not take effect if
 * the ACL has a peer type of WITH_MEMBERSHIP.
 *
 * Setup
 * Sender and Receiver bus implement the following :
 * Object Path:  /test
 * Interface Name: "org.allseen.test.SecurityApplication.rules"
 * Member name: Echo (method call)
 * Member name: Prop1  (property, read write)
 * Member name: Chirp (signal)
 * Peer2 has membership certificate installed.
 * Peer1 and Peer2 set up an ECDHE_ECDSA based session.
 * Peer1 makes a method call to Peer2.
 * Peer1 sends a signal to Peer2.
 * Peer1 makes a get property call on Peer2
 * Peer1 makes a set property call on Peer2
 *
 * Peer1 rules:
 * ACL: Peer type: ANY_TRUSTED
 * Rule 0: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 * Peer2 rules:
 * ACL: Peer type: WITH_MEMBERSHIP, SGID: Living Room, Security Group Authority public key
 * Rule 1: Object Path= *, Interface=*, Member name=*, Member Type = NS, Action mask = DENY
 * Rule 2: Object Path=/test, Interface = org.allseen.test.SecurityApplication.rules, Member name = *, Member type = NS, Action Mask = DENY
 * Rule 3: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 * verification:
 * Verify that method call, get/set property calls are successful.
 * Verify that signal is received by Peer2.
 */
TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_8_SC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0
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
        SCPolicy.SetAcls(1, acls);
    }

    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);
            peers[0].SetSecurityGroupId(managerGuid);
            //Get manager key
            KeyInfoNISTP256 managerKey;
            PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(managerKey));
            peers[0].SetKeyInfo(&managerKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[3];
            //rule 0
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 1
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 2
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[2].SetMembers(1, members);
            }
            acls[0].SetRules(3, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    // Verify Method call
    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_OK, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
    char* echoReply;
    replyMsg->GetArg(0)->Get("s", &echoReply);
    EXPECT_STREQ("String that should be Echoed back.", echoReply);

    // Verify Set/Get Property
    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_OK, proxy.SetProperty(interfaceName, "Prop1", prop1Arg));
    EXPECT_EQ(513, TCBus.ReadProp1());

    MsgArg prop1ArgOut;
    EXPECT_EQ(ER_OK, proxy.GetProperty(interfaceName, "Prop1", prop1Arg));
    uint32_t prop1;
    prop1Arg.Get("i", &prop1);
    EXPECT_EQ((uint32_t)513, prop1);

    // Send/Receive Signal
    arg.Set("s", "Chirp this String out in the signal.");
    // Signals are send and forget.  They will always return ER_OK.
    EXPECT_EQ(ER_OK, SCBusObject.Signal(TCBus.GetUniqueName().c_str(), SCToTCSessionId, *SCBus.GetInterface(interfaceName)->GetMember("Chirp"), &arg, 1, 0, 0));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (TCBus.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(TCBus.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_8_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0
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
        TCPolicy.SetAcls(1, acls);
    }

    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);
            peers[0].SetSecurityGroupId(managerGuid);
            //Get manager key
            KeyInfoNISTP256 managerKey;
            PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(managerKey));
            peers[0].SetKeyInfo(&managerKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[3];
            //rule 0
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 1
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 2
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[2].SetMembers(1, members);
            }
            acls[0].SetRules(3, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    // Verify Method call
    const char* s = "String that should be Echoed back.";
    ASSERT_EQ(ER_OK, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));
    EXPECT_STREQ(s, TCBus.GetResponse());

    // Verify Set/Get Property
    EXPECT_EQ(ER_OK, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, 513));
    EXPECT_EQ(513, SCBusObject.ReadProp1());
    int32_t prop; 
    EXPECT_EQ(ER_OK, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop));
    EXPECT_EQ(513, prop);

    // Send/Receive Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver, static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler), SCBus.GetInterface(interfaceName)->GetMember("Chirp"), NULL));

    EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_CHIRP, "Chirp this String out in the signal."));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Purpose
 * Verify that DENY rules takes effect and precedence over other rules only if
 * it is a wild card under the peer type: WITH_PUBLICKEY DUT is sender.
 *
 * Setup
 * Sender and Receiver bus implement the following :
 * Object Path:  /test
 * Interface Name: "org.allseen.test.SecurityApplication.rules"
 * Member name: Echo (method call)
 * Member name: Prop1  (property, read write)
 * Member name: Chirp (signal)
 * Peer1 and Peer2 set up an ECDHE_ECDSA based session.
 * Peer1 makes a method call to Peer2.
 * Peer1 sends a signal to Peer2.
 * Peer1 makes a get property call on Peer2
 * Peer1 makes a set property call on Peer2
 *
 * Peer1 rules:
 * ACL: Peer type: WITH_PUBLICKEY, Public Key of Peer2
 * Rule 1: Object Path= *, Interface=*, Member name=*, Member Type = NS, Action mask = DENY
 * Rule 2: Object Path=/test, Interface = org.allseen.test.SecurityApplication.rules, Member name = *, Member type = NS, Action Mask = DENY
 * Rule 3: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 * Peer2 rules:
 * ACL: Peer type: ANY_TRUSTED
 * Rule 0: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 * verification:
 * Verify that method call, get/set property calls, signal cannot be sent by
 * sender.
 */
TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_9_SC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public Key of TC
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
            peers[0].SetKeyInfo(&TCKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[3];
            //rule 0 Object Path= *, Interface=*, Member name=*, Member Type = NS, Action mask = DENY
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 1 Object Path=/test, Interface = org.allseen.test.SecurityApplication.rules, Member name = *, Member type = NS, Action Mask = DENY
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 2 Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[2].SetMembers(1, members);
            }
            acls[0].SetRules(3, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: ANY_TRUSTED
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0 Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
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
        TCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    // Verify Method call
    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
    ASSERT_STREQ("org.alljoyn.Bus.ErStatus", replyMsg->GetErrorName());
    EXPECT_EQ(ER_PERMISSION_DENIED, (QStatus)replyMsg->GetArg(1)->v_uint16)
        << "\n" << replyMsg->GetArg(0)->ToString().c_str() << "\n" << replyMsg->GetArg(1)->ToString().c_str();

    // Verify Set/Get Property
    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.SetProperty(interfaceName, "Prop1", prop1Arg));

    MsgArg prop1ArgOut;
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.GetProperty(interfaceName, "Prop1", prop1Arg));

    // Send/Receive Signal
    arg.Set("s", "Chirp this String out in the signal.");
    EXPECT_EQ(ER_PERMISSION_DENIED, SCBusObject.Signal(TCBus.GetUniqueName().c_str(), SCToTCSessionId, *SCBus.GetInterface(interfaceName)->GetMember("Chirp"), &arg, 1, 0, 0));

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_9_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public Key of SC
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
            //Get manager key
            KeyInfoNISTP256 SCKey;
            PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));
            peers[0].SetKeyInfo(&SCKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[3];
            //rule 0 Object Path= *, Interface=*, Member name=*, Member Type = NS, Action mask = DENY
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 1 Object Path=/test, Interface = org.allseen.test.SecurityApplication.rules, Member name = *, Member type = NS, Action Mask = DENY
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 2 Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[2].SetMembers(1, members);
            }
            acls[0].SetRules(3, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: ANY_TRUSTED
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0 Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
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
        SCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    // Verify Method call
    const char* s = "String that should be Echoed back.";
    EXPECT_EQ(ER_PERMISSION_DENIED, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));

    // Verify Set/Get Property
    EXPECT_EQ(ER_PERMISSION_DENIED, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, 513));
    int32_t prop; 
    EXPECT_EQ(ER_PERMISSION_DENIED, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop));

    // Send/Receive Signal
    EXPECT_EQ(ER_PERMISSION_DENIED, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_CHIRP, "Chirp this String out in the signal."));

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Purpose
 * Verify that DENY rules takes effect and precedence over other rules only if
 * it is a wild card under the peer type: WITH_PUBLICKEY DUT is receiver.
 *
 * Setup
 * Sender and Receiver bus implement the following :
 * Object Path:  /test
 * Interface Name: "org.allseen.test.SecurityApplication.rules"
 * Member name: Echo (method call)
 * Member name: Prop1  (property, read write)
 * Member name: Chirp (signal)
 * Peer1 and Peer2 set up an ECDHE_ECDSA based session.
 * Peer1 makes a method call to Peer2.
 * Peer1 sends a signal to Peer2.
 * Peer1 makes a get property call on Peer2
 * Peer1 makes a set property call on Peer2
 *
 * Peer1 rules:
 * ACL: Peer type: ANY_TRUSTED
 * Rule 0: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 * Peer2 rules:
 * ACL: Peer type: WITH_PUBLICKEY, Public Key of Peer1
 * Rule 1: Object Path= *, Interface=*, Member name=*, Member Type = NS, Action mask = DENY
 * Rule 2: Object Path=/test, Interface = org.allseen.test.SecurityApplication.rules, Member name = *, Member type = NS, Action Mask = DENY
 * Rule 3: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 * verification:
 * Verify that method call, get/set property calls, signal can be sent, but are
 * not received by Peer2.
 */
TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_10_SC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0
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
        SCPolicy.SetAcls(1, acls);
    }

    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
            //Get manager key
            KeyInfoNISTP256 SCKey;
            PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));
            peers[0].SetKeyInfo(&SCKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[3];
            //rule 0
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 1
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 2
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[2].SetMembers(1, members);
            }
            acls[0].SetRules(3, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    // Verify Method call
    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
    EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", replyMsg->GetErrorName());

    // Verify Set/Get Property
    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.SetProperty(interfaceName, "Prop1", prop1Arg));

    MsgArg prop1ArgOut;
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.GetProperty(interfaceName, "Prop1", prop1Arg));

    arg.Set("s", "Chirp this String out in the signal.");
    // Signals are send and forget.  They will always return ER_OK.
    EXPECT_EQ(ER_OK, SCBusObject.Signal(TCBus.GetUniqueName().c_str(), SCToTCSessionId, *SCBus.GetInterface(interfaceName)->GetMember("Chirp"), &arg, 1, 0, 0));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (TCBus.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_FALSE(TCBus.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_10_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0
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
        TCPolicy.SetAcls(1, acls);
    }

    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
            peers[0].SetKeyInfo(&TCKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[3];
            //rule 0
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 1
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 2
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[2].SetMembers(1, members);
            }
            acls[0].SetRules(3, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    // Verify Method call
    const char* s = "String that should be Echoed back.";
    EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));
    EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());

    // Verify Set/Get Property
    EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, 513));
    EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());
    int32_t prop; 
    EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop));
    EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());

    // Send/Receive Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver, static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler), SCBus.GetInterface(interfaceName)->GetMember("Chirp"), NULL));

    EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_CHIRP, "Chirp this String out in the signal."));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_FALSE(chirpSignalReceiver.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Purpose
 * Verify that DENY rule does not take effect if it is a specific rule under the
 * peer type: WITH_PUBLICKEY
 *
 * Setup
 * Sender and Receiver bus implement the following :
 * Object Path:  /test
 * Interface Name: "org.allseen.test.SecurityApplication.rules"
 * Member name: Echo (method call)
 * Member name: Prop1  (property, read write)
 * Member name: Chirp (signal)
 * Peer1 and Peer2 set up an ECDHE_ECDSA based session.
 * Peer1 makes a method call to Peer2.
 * Peer1 sends a signal to Peer2.
 * Peer1 makes a get property call on Peer2
 * Peer1 makes a set property call on Peer2
 *
 * Peer1 rules:
 * ACL: Peer type: WITH_PUBLICKEY, Public Key of peer2
 * Rule1: Object Path: *; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
 * Rule2: Object Path: /test ; Interface: *; Member Name: *, Action: DENY
 * Rule3: Object Path: * ; Interface: *; Member Name: Echo , Action: DENY
 * Rule4: Object Path: * ; Interface: *; Member Name: Prop1 , Action: DENY
 * Rule5: Object Path: * ; Interface: *; Member Name: Chirp , Action: DENY
 * Rule6: Object Path: /test ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
 * Rule7: Object Path: /t*  ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
 * Rule8: Object Path: *  ; Interface: org.allseen.test.*; Member Name: *; Action: DENY
 * Rule9: Object Path: /test  ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: Chirp, Action: DENY
 * Rule 10: Object Path: *, Interface: *, Member Name: NS; Action: PROVIDE|OBSERVE|MODIFY
 *
 * Peer2 rules:
 * ACL: Peer type: ANY_TRUSTED
 * Rule 1: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 *
 *
 * verification:
 * Verify that method call, get/set property calls are successful.
 * Verify that signal is received by Peer2.
 */
TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_11_SC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
            peers[0].SetKeyInfo(&TCKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[10];
            //rule 1
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 2
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 3
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               0 /*DENY*/);
                rules[2].SetMembers(1, members);
            }
            //rule 4
            rules[3].SetObjPath("*");
            rules[3].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Prop1",
                               PermissionPolicy::Rule::Member::PROPERTY,
                               0 /*DENY*/);
                rules[3].SetMembers(1, members);
            }
            //rule 5
            rules[4].SetObjPath("/test");
            rules[4].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Chirp",
                               PermissionPolicy::Rule::Member::SIGNAL,
                               0 /*DENY*/);
                rules[4].SetMembers(1, members);
            }
            //rule 6
            rules[5].SetObjPath("/test");
            rules[5].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[5].SetMembers(1, members);
            }
            //rule 7
            rules[6].SetObjPath("/t*");
            rules[6].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[6].SetMembers(1, members);
            }
            //rule 8
            rules[7].SetObjPath("*");
            rules[7].SetInterfaceName("org.allseen.test.*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[7].SetMembers(1, members);
            }
            //rule 9
            rules[8].SetObjPath("/test");
            rules[8].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Chirp",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[8].SetMembers(1, members);
            }
            //rule 10
            rules[9].SetObjPath("*");
            rules[9].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].SetMemberName("*");
                members[0].SetActionMask(PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                                         PermissionPolicy::Rule::Member::ACTION_MODIFY |
                                         PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[9].SetMembers(1, members);
            }
            acls[0].SetRules(10, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0
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
        TCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    // Verify Method call
    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_OK, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
    char* echoReply;
    replyMsg->GetArg(0)->Get("s", &echoReply);
    EXPECT_STREQ("String that should be Echoed back.", echoReply);

    // Verify Set/Get Property
    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_OK, proxy.SetProperty(interfaceName, "Prop1", prop1Arg));
    EXPECT_EQ(513, TCBus.ReadProp1());

    MsgArg prop1ArgOut;
    EXPECT_EQ(ER_OK, proxy.GetProperty(interfaceName, "Prop1", prop1Arg));
    uint32_t prop1;
    prop1Arg.Get("i", &prop1);
    EXPECT_EQ((uint32_t)513, prop1);

    // Send/Receive Signal
    arg.Set("s", "Chirp this String out in the signal.");
    // Signals are send and forget.  They will always return ER_OK.
    EXPECT_EQ(ER_OK, SCBusObject.Signal(TCBus.GetUniqueName().c_str(), SCToTCSessionId, *SCBus.GetInterface(interfaceName)->GetMember("Chirp"), &arg, 1, 0, 0));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (TCBus.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(TCBus.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_11_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
            //Get SC key
            KeyInfoNISTP256 SCKey;
            PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));
            peers[0].SetKeyInfo(&SCKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[10];
            //rule 1
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 2
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 3
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               0 /*DENY*/);
                rules[2].SetMembers(1, members);
            }
            //rule 4
            rules[3].SetObjPath("*");
            rules[3].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Prop1",
                               PermissionPolicy::Rule::Member::PROPERTY,
                               0 /*DENY*/);
                rules[3].SetMembers(1, members);
            }
            //rule 5
            rules[4].SetObjPath("/test");
            rules[4].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Chirp",
                               PermissionPolicy::Rule::Member::SIGNAL,
                               0 /*DENY*/);
                rules[4].SetMembers(1, members);
            }
            //rule 6
            rules[5].SetObjPath("/test");
            rules[5].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[5].SetMembers(1, members);
            }
            //rule 7
            rules[6].SetObjPath("/t*");
            rules[6].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[6].SetMembers(1, members);
            }
            //rule 8
            rules[7].SetObjPath("*");
            rules[7].SetInterfaceName("org.allseen.test.*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[7].SetMembers(1, members);
            }
            //rule 9
            rules[8].SetObjPath("/test");
            rules[8].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Chirp",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[8].SetMembers(1, members);
            }
            //rule 10
            rules[9].SetObjPath("*");
            rules[9].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[9].SetMembers(1, members);
            }
            acls[0].SetRules(10, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 0
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
        SCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    // Verify Method call
    const char* s = "String that should be Echoed back.";
    ASSERT_EQ(ER_OK, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));
    EXPECT_STREQ(s, TCBus.GetResponse());

    // Verify Set/Get Property
    EXPECT_EQ(ER_OK, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, 513));
    EXPECT_EQ(513, SCBusObject.ReadProp1());
    int32_t prop; 
    EXPECT_EQ(ER_OK, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop));
    EXPECT_EQ(513, prop);

    // Send/Receive Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver, static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler), SCBus.GetInterface(interfaceName)->GetMember("Chirp"), NULL));

    EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_CHIRP, "Chirp this String out in the signal."));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Purpose
 * Verify that DENY rule does not take effect if it is a specific rule under the
 * peer type: WITH_PUBLICKEY
 *
 * Setup
 * Sender and Receiver bus implement the following :
 * Object Path:  /test
 * Interface Name: "org.allseen.test.SecurityApplication.rules"
 * Member name: Echo (method call)
 * Member name: Prop1  (property, read write)
 * Member name: Chirp (signal)
 * Peer1 and Peer2 set up an ECDHE_ECDSA based session.
 * Peer1 makes a method call to Peer2.
 * Peer1 sends a signal to Peer2.
 * Peer1 makes a get property call on Peer2
 * Peer1 makes a set property call on Peer2
 *
 * Peer1 rules:
 * ACL: Peer type: ANY_TRUSTED
 * Rule 1: Object Path= *, Interface=*, Member Name=*, Member Type= NS, Action Mask = PROVIDE|MODIFY|OBSERVE
 *
 * Peer2 rules:
 * ACL: Peer type: WITH_PUBLICKEY, Public Key of peer1
 * Rule1: Object Path: *; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
 * Rule2: Object Path: /test ; Interface: *; Member Name: *, Action: DENY
 * Rule3: Object Path: * ; Interface: *; Member Name: Echo , Action: DENY
 * Rule4: Object Path: * ; Interface: *; Member Name: Prop1 , Action: DENY
 * Rule5: Object Path: * ; Interface: *; Member Name: Chirp , Action: DENY
 * Rule6: Object Path: /test ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
 * Rule7: Object Path: /t*  ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
 * Rule8: Object Path: *  ; Interface: org.allseen.test.*; Member Name: *; Action: DENY
 * Rule9: Object Path: /test  ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: Chirp, Action: DENY
 * Rule 10: Object Path: *, Interface: *, Member Name: NS; Action: PROVIDE|OBSERVE|MODIFY
 *
 * verification:
 * Verify that method call, get/set property calls are successful.
 * Verify that signal is received by Peer2.
 */
TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_12_SC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 1
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
        SCPolicy.SetAcls(1, acls);
    }

    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            /* ACL: Peer type: WITH_PUBLICKEY, Public Key of SC */
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
            //Get manager key
            KeyInfoNISTP256 SCKey;
            PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));
            peers[0].SetKeyInfo(&SCKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[10];
            //rule 1  Object Path: *; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY

            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 2 Object Path: /test ; Interface: *; Member Name: *, Action: DENY
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 3 Object Path: * ; Interface: *; Member Name: Echo , Action: DENY
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               0 /*DENY*/);
                rules[2].SetMembers(1, members);
            }
            //rule 4 Object Path: * ; Interface: *; Member Name: Prop1 , Action: DENY
            rules[3].SetObjPath("*");
            rules[3].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Prop1",
                               PermissionPolicy::Rule::Member::PROPERTY,
                               0 /*DENY*/);
                rules[3].SetMembers(1, members);
            }
            //rule 5 Object Path: * ; Interface: *; Member Name: Chirp , Action: DENY
            rules[4].SetObjPath("/test");
            rules[4].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Chirp",
                               PermissionPolicy::Rule::Member::SIGNAL,
                               0 /*DENY*/);
                rules[4].SetMembers(1, members);
            }
            //rule 6 Object Path: /test ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
            rules[5].SetObjPath("/test");
            rules[5].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[5].SetMembers(1, members);
            }
            //rule 7 Object Path: /a*  ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
            rules[6].SetObjPath("/t*");
            rules[6].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[6].SetMembers(1, members);
            }
            //rule 8 Object Path: *  ; Interface: test.*; Member Name: *; Action: DENY
            rules[7].SetObjPath("*");
            rules[7].SetInterfaceName("org.allseen.test.*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[7].SetMembers(1, members);
            }
            //rule 9 Object Path: /test  ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: Chirp, Action: DENY
            rules[8].SetObjPath("/test");
            rules[8].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Chirp",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[8].SetMembers(1, members);
            }
            //rule 10 Object Path: *, Interface: *, Member Name: *; Action: PROVIDE|OBSERVE|MODIFY
            rules[9].SetObjPath("*");
            rules[9].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[9].SetMembers(1, members);
            }
            acls[0].SetRules(10, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    // Verify Method call
    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_OK, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
    char* echoReply;
    replyMsg->GetArg(0)->Get("s", &echoReply);
    EXPECT_STREQ("String that should be Echoed back.", echoReply);

    // Verify Set/Get Property
    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_OK, proxy.SetProperty(interfaceName, "Prop1", prop1Arg));
    EXPECT_EQ(513, TCBus.ReadProp1());

    MsgArg prop1ArgOut;
    EXPECT_EQ(ER_OK, proxy.GetProperty(interfaceName, "Prop1", prop1Arg));
    uint32_t prop1;
    prop1Arg.Get("i", &prop1);
    EXPECT_EQ((uint32_t)513, prop1);

    // Send/Receive Signal
    arg.Set("s", "Chirp this String out in the signal.");
    // Signals are send and forget.  They will always return ER_OK.
    EXPECT_EQ(ER_OK, SCBusObject.Signal(TCBus.GetUniqueName().c_str(), SCToTCSessionId, *SCBus.GetInterface(interfaceName)->GetMember("Chirp"), &arg, 1, 0, 0));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (TCBus.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(TCBus.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_12_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            //rule 1
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
        TCPolicy.SetAcls(1, acls);
    }

    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            /* ACL: Peer type: WITH_PUBLICKEY, Public Key of TC */
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
            peers[0].SetKeyInfo(&TCKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[10];
            //rule 1  Object Path: *; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY

            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[0].SetMembers(1, members);
            }
            //rule 2 Object Path: /test ; Interface: *; Member Name: *, Action: DENY
            rules[1].SetObjPath("/test");
            rules[1].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[1].SetMembers(1, members);
            }
            //rule 3 Object Path: * ; Interface: *; Member Name: Echo , Action: DENY
            rules[2].SetObjPath("*");
            rules[2].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               0 /*DENY*/);
                rules[2].SetMembers(1, members);
            }
            //rule 4 Object Path: * ; Interface: *; Member Name: Prop1 , Action: DENY
            rules[3].SetObjPath("*");
            rules[3].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Prop1",
                               PermissionPolicy::Rule::Member::PROPERTY,
                               0 /*DENY*/);
                rules[3].SetMembers(1, members);
            }
            //rule 5 Object Path: * ; Interface: *; Member Name: Chirp , Action: DENY
            rules[4].SetObjPath("/test");
            rules[4].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Chirp",
                               PermissionPolicy::Rule::Member::SIGNAL,
                               0 /*DENY*/);
                rules[4].SetMembers(1, members);
            }
            //rule 6 Object Path: /test ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
            rules[5].SetObjPath("/test");
            rules[5].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[5].SetMembers(1, members);
            }
            //rule 7 Object Path: /a*  ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
            rules[6].SetObjPath("/t*");
            rules[6].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[6].SetMembers(1, members);
            }
            //rule 8 Object Path: *  ; Interface: test.*; Member Name: *; Action: DENY
            rules[7].SetObjPath("*");
            rules[7].SetInterfaceName("org.allseen.test.*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[7].SetMembers(1, members);
            }
            //rule 9 Object Path: /test  ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: Chirp, Action: DENY
            rules[8].SetObjPath("/test");
            rules[8].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Chirp",
                               PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                               0 /*DENY*/);
                rules[8].SetMembers(1, members);
            }
            //rule 10 Object Path: *, Interface: *, Member Name: NS; Action: PROVIDE|OBSERVE|MODIFY
            rules[9].SetObjPath("*");
            rules[9].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].SetMemberName("*");
                members[0].SetActionMask(PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                                         PermissionPolicy::Rule::Member::ACTION_MODIFY |
                                         PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[9].SetMembers(1, members);
            }
            acls[0].SetRules(10, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    // Verify Method call
    const char* s = "String that should be Echoed back.";
    ASSERT_EQ(ER_OK, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));
    EXPECT_STREQ(s, TCBus.GetResponse());

    // Verify Set/Get Property
    EXPECT_EQ(ER_OK, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, 513));
    EXPECT_EQ(513, SCBusObject.ReadProp1());
    int32_t prop; 
    EXPECT_EQ(ER_OK, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop));
    EXPECT_EQ(513, prop);

    // Send/Receive Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver, static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler), SCBus.GetInterface(interfaceName)->GetMember("Chirp"), NULL));

    EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_CHIRP, "Chirp this String out in the signal."));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Purpose
 * Verify that specific rules with DENY action mask are ignored in the manifest.
 *
 * Setup
 * Sender and Receiver bus implement the following :
 * Object Path:  /test
 * Interface Name: "org.allseen.test.SecurityApplication.rules"
 * Member name: Echo (method call)
 * Member name: Prop1  (property, read write)
 * Member name: Chirp (signal)
 *
 * Policy rules allow everything
 * Peer1 and Peer2 set up an ECDHE_ECDSA based session.
 * Peer1 makes a method call to Peer2.
 * Peer1 sends a signal to Peer2.
 * Peer1 makes a get property call on Peer2
 * Peer1 makes a set property call on Peer2
 *
 * Peer1 Policy:
 * ACL 1: Peer type: ANY_TRUSTED, Rule: Allow everything
 *
 * Peer1 manifest:
 * Rule1: Object Path: *; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
 * Rule2: Object Path: /test ; Interface: *; Member Name: *, Action: DENY
 * Rule3: Object Path: * ; Interface: *; Member Name: Echo , Action: DENY
 * Rule4: Object Path: * ; Interface: *; Member Name: Prop1 , Action: DENY
 * Rule5: Object Path: * ; Interface: *; Member Name: Chirp , Action: DENY
 * Rule6: Object Path: /test ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
 * Rule7: Object Path: /t*  ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
 * Rule8: Object Path: *  ; Interface: org.allseen.test.*; Member Name: *; Action: DENY
 * Rule9: Object Path: /test  ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: Chirp, Action: DENY
 * Rule 10: Object Path: *, Interface: *, Member Name: NS; Action: PROVIDE|OBSERVE|MODIFY

 * Peer2 Policy:
 * ACL 1: Peer type: ANY_TRUSTED: Allow everything
 *
 * Peer2 manifest:
 * Rule 1: Allow everything
 *
 * verification:
 * Verify that method call, get/set property calls are successful.
 * Verify that signal is received by Peer2.
 */
TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_13_SC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    const size_t manifestSize = 10;
    const size_t certChainSize = 1;
    /*************Update SC Manifest *************/
    //SC key
    KeyInfoNISTP256 SCKey;
    PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    { //Rule1: Object Path: *; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
        SCManifest[0].SetObjPath("*");
        SCManifest[0].SetInterfaceName(interfaceName);
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        SCManifest[0].SetMembers(1, members);
    }
    { //Rule2: Object Path: /test ; Interface: *; Member Name: *, Action: DENY
        SCManifest[1].SetObjPath("/test");
        SCManifest[1].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        SCManifest[1].SetMembers(1, members);
    }
    { //Rule3: Object Path: * ; Interface: *; Member Name: Echo , Action: DENY
        SCManifest[2].SetObjPath("*");
        SCManifest[2].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Echo",
                       PermissionPolicy::Rule::Member::METHOD_CALL,
                       0 /*DENY*/);
        SCManifest[2].SetMembers(1, members);
    }
    { //Rule4: Object Path: * ; Interface: *; Member Name: Prop1 , Action: DENY
        SCManifest[3].SetObjPath("*");
        SCManifest[3].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       0 /*DENY*/);
        SCManifest[3].SetMembers(1, members);
    }
    { //Rule5: Object Path: * ; Interface: *; Member Name: Chirp , Action: DENY
        SCManifest[4].SetObjPath("*");
        SCManifest[4].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Chirp",
                       PermissionPolicy::Rule::Member::SIGNAL,
                       0 /*DENY*/);
        SCManifest[4].SetMembers(1, members);
    }
    { //Rule6: Object Path: /test ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
        SCManifest[5].SetObjPath("/test");
        SCManifest[5].SetInterfaceName(interfaceName);
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        SCManifest[5].SetMembers(1, members);
    }
    { //Rule7: Object Path: /t*  ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
        SCManifest[6].SetObjPath("/t*");
        SCManifest[6].SetInterfaceName(interfaceName);
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        SCManifest[6].SetMembers(1, members);
    }
    { //Rule8: Object Path: *  ; Interface: org.allseen.test.*; Member Name: *; Action: DENY
        SCManifest[7].SetObjPath("*");
        SCManifest[7].SetInterfaceName("org.allseen.test.*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        SCManifest[7].SetMembers(1, members);
    }
    { //Rule9: Object Path: /test  ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: Chirp, Action: DENY
        SCManifest[8].SetObjPath("/test");
        SCManifest[8].SetInterfaceName(interfaceName);
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Chirp",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        SCManifest[8].SetMembers(1, members);
    }
    { //Rule 10: Object Path: *, Interface: *, Member Name: *; Action: PROVIDE|OBSERVE|MODIFY
        SCManifest[9].SetObjPath("*");
        SCManifest[9].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                       PermissionPolicy::Rule::Member::ACTION_MODIFY |
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        SCManifest[9].SetMembers(1, members);
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

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    EXPECT_EQ(ER_OK, sapWithSC.UpdateIdentity(identityCertChainSC, certChainSize, SCManifest, manifestSize))
        << "Failed to update Identity cert or manifest ";

    //TC already has a manifest installed that allows everything from the SetUp

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    // Verify Method call
    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_OK, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
    char* echoReply;
    replyMsg->GetArg(0)->Get("s", &echoReply);
    EXPECT_STREQ("String that should be Echoed back.", echoReply);

    // Verify Set/Get Property
    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_OK, proxy.SetProperty(interfaceName, "Prop1", prop1Arg));
    EXPECT_EQ(513, TCBus.ReadProp1());

    MsgArg prop1ArgOut;
    EXPECT_EQ(ER_OK, proxy.GetProperty(interfaceName, "Prop1", prop1Arg));
    uint32_t prop1;
    prop1Arg.Get("i", &prop1);
    EXPECT_EQ((uint32_t)513, prop1);

    // Send/Receive Signal
    arg.Set("s", "Chirp this String out in the signal.");
    // Signals are send and forget.  They will always return ER_OK.
    EXPECT_EQ(ER_OK, SCBusObject.Signal(TCBus.GetUniqueName().c_str(), SCToTCSessionId, *SCBus.GetInterface(interfaceName)->GetMember("Chirp"), &arg, 1, 0, 0));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (TCBus.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(TCBus.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_13_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    const size_t manifestSize = 10;
    const size_t certChainSize = 1;
    /*************Update TC Manifest *************/

    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    { //Rule1: Object Path: *; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
        TCManifest[0].SetObjPath("*");
        TCManifest[0].SetInterfaceName(interfaceName);
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        TCManifest[0].SetMembers(1, members);
    }
    { //Rule2: Object Path: /test ; Interface: *; Member Name: *, Action: DENY
        TCManifest[1].SetObjPath("/test");
        TCManifest[1].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        TCManifest[1].SetMembers(1, members);
    }
    { //Rule3: Object Path: * ; Interface: *; Member Name: Echo , Action: DENY
        TCManifest[2].SetObjPath("*");
        TCManifest[2].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Echo",
                       PermissionPolicy::Rule::Member::METHOD_CALL,
                       0 /*DENY*/);
        TCManifest[2].SetMembers(1, members);
    }
    { //Rule4: Object Path: * ; Interface: *; Member Name: Prop1 , Action: DENY
        TCManifest[3].SetObjPath("*");
        TCManifest[3].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       0 /*DENY*/);
        TCManifest[3].SetMembers(1, members);
    }
    { //Rule5: Object Path: * ; Interface: *; Member Name: Chirp , Action: DENY
        TCManifest[4].SetObjPath("*");
        TCManifest[4].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Chirp",
                       PermissionPolicy::Rule::Member::SIGNAL,
                       0 /*DENY*/);
        TCManifest[4].SetMembers(1, members);
    }
    { //Rule6: Object Path: /test ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
        TCManifest[5].SetObjPath("/test");
        TCManifest[5].SetInterfaceName(interfaceName);
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        TCManifest[5].SetMembers(1, members);
    }
    { //Rule7: Object Path: /t*  ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
        TCManifest[6].SetObjPath("/t*");
        TCManifest[6].SetInterfaceName(interfaceName);
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        TCManifest[6].SetMembers(1, members);
    }
    { //Rule8: Object Path: *  ; Interface: org.allseen.test.*; Member Name: *; Action: DENY
        TCManifest[7].SetObjPath("*");
        TCManifest[7].SetInterfaceName("org.allseen.test.*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        TCManifest[7].SetMembers(1, members);
    }
    { //Rule9: Object Path: /test  ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: Chirp, Action: DENY
        TCManifest[8].SetObjPath("/test");
        TCManifest[8].SetInterfaceName(interfaceName);
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Chirp",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        TCManifest[8].SetMembers(1, members);
    }
    { //Rule 10: Object Path: *, Interface: *, Member Name: NS; Action: PROVIDE|OBSERVE|MODIFY
        TCManifest[9].SetObjPath("*");
        TCManifest[9].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].SetMemberName("*");
        members[0].SetActionMask(PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                                 PermissionPolicy::Rule::Member::ACTION_MODIFY |
                                 PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        TCManifest[9].SetMembers(1, members);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

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

    EXPECT_EQ(ER_OK, sapWithTC.UpdateIdentity(identityCertChainTC, certChainSize, TCManifest, manifestSize))
        << "Failed to update Identity cert or manifest ";

    //SC already has a manifest installed that allows everything from the SetUp

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    // Verify Method call
    const char* s = "String that should be Echoed back.";
    ASSERT_EQ(ER_OK, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));
    EXPECT_STREQ(s, TCBus.GetResponse());

    // Verify Set/Get Property
    EXPECT_EQ(ER_OK, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, 513));
    EXPECT_EQ(513, SCBusObject.ReadProp1());
    int32_t prop; 
    EXPECT_EQ(ER_OK, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop));
    EXPECT_EQ(513, prop);

    // Send/Receive Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver, static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler), SCBus.GetInterface(interfaceName)->GetMember("Chirp"), NULL));

    ASSERT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_CHIRP, "Chirp this String out in the signal."));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Purpose
 * Verify that specific rules with DENY action mask are ignored in the manifest.
 *
 * Setup
 * Sender and Receiver bus implement the following :
 * Object Path:  /test
 * Interface Name: "org.allseen.test.SecurityApplication.rules"
 * Member name: Echo (method call)
 * Member name: Prop1  (property, read write)
 * Member name: Chirp (signal)
 *
 * Policy rules allow everything
 * Peer1 and Peer2 set up an ECDHE_ECDSA based session.
 * Peer1 makes a method call to Peer2.
 * Peer1 sends a signal to Peer2.
 * Peer1 makes a get property call on Peer2
 * Peer1 makes a set property call on Peer2
 *
 * Peer1 Policy:
 * ACL 1: Peer type: ANY_TRUSTED: Allow everything
 *
 * Peer1 manifest:
 * Rule 1: Allow everything
 *
 * Peer2 Policy:
 * ACL 1: Peer type: ANY_TRUSTED, Rule: Allow everything
 *
 * Peer2 manifest:
 * Rule1: Object Path: *; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
 * Rule2: Object Path: /test ; Interface: *; Member Name: *, Action: DENY
 * Rule3: Object Path: * ; Interface: *; Member Name: Echo , Action: DENY
 * Rule4: Object Path: * ; Interface: *; Member Name: Prop1 , Action: DENY
 * Rule5: Object Path: * ; Interface: *; Member Name: Chirp , Action: DENY
 * Rule6: Object Path: /test ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
 * Rule7: Object Path: /t*  ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
 * Rule8: Object Path: *  ; Interface: org.allseen.test.*; Member Name: *; Action: DENY
 * Rule9: Object Path: /test  ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: Chirp, Action: DENY
 * Rule 10: Object Path: *, Interface: *, Member Name: NS; Action: PROVIDE|OBSERVE|MODIFY
 *
 * verification:
 * Verify that method call, get/set property calls are successful.
 * Verify that signal is received by Peer2.
 */
TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_14_SC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    //TC already has a manifest installed that allows everything from the SetUp

    const size_t manifestSize = 10;
    const size_t certChainSize = 1;
    /*************Update SC Manifest *************/
    //SC key

    // SC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    { //Rule1: Object Path: *; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
        TCManifest[0].SetObjPath("*");
        TCManifest[0].SetInterfaceName(interfaceName);
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        TCManifest[0].SetMembers(1, members);
    }
    { //Rule2: Object Path: /test ; Interface: *; Member Name: *, Action: DENY
        TCManifest[1].SetObjPath("/test");
        TCManifest[1].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        TCManifest[1].SetMembers(1, members);
    }
    { //Rule3: Object Path: * ; Interface: *; Member Name: Echo , Action: DENY
        TCManifest[2].SetObjPath("*");
        TCManifest[2].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Echo",
                       PermissionPolicy::Rule::Member::METHOD_CALL,
                       0 /*DENY*/);
        TCManifest[2].SetMembers(1, members);
    }
    { //Rule4: Object Path: * ; Interface: *; Member Name: Prop1 , Action: DENY
        TCManifest[3].SetObjPath("*");
        TCManifest[3].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       0 /*DENY*/);
        TCManifest[3].SetMembers(1, members);
    }
    { //Rule5: Object Path: * ; Interface: *; Member Name: Chirp , Action: DENY
        TCManifest[4].SetObjPath("*");
        TCManifest[4].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Chirp",
                       PermissionPolicy::Rule::Member::SIGNAL,
                       0 /*DENY*/);
        TCManifest[4].SetMembers(1, members);
    }
    { //Rule6: Object Path: /test ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
        TCManifest[5].SetObjPath("/test");
        TCManifest[5].SetInterfaceName(interfaceName);
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        TCManifest[5].SetMembers(1, members);
    }
    { //Rule7: Object Path: /t*  ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
        TCManifest[6].SetObjPath("/t*");
        TCManifest[6].SetInterfaceName(interfaceName);
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        TCManifest[6].SetMembers(1, members);
    }
    { //Rule8: Object Path: *  ; Interface: org.allseen.test.*; Member Name: *; Action: DENY
        TCManifest[7].SetObjPath("*");
        TCManifest[7].SetInterfaceName("org.allseen.test.*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        TCManifest[7].SetMembers(1, members);
    }
    { //Rule9: Object Path: /test  ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: Chirp, Action: DENY
        TCManifest[8].SetObjPath("/test");
        TCManifest[8].SetInterfaceName(interfaceName);
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Chirp",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        TCManifest[8].SetMembers(1, members);
    }
    { //Rule 10: Object Path: *, Interface: *, Member Name: NS; Action: PROVIDE|OBSERVE|MODIFY
        TCManifest[9].SetObjPath("*");
        TCManifest[9].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].SetMemberName("*");
        members[0].SetActionMask(PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                                 PermissionPolicy::Rule::Member::ACTION_MODIFY |
                                 PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        TCManifest[9].SetMembers(1, members);
    }

    uint8_t TCDigest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(managerBus,
                                                               TCManifest, manifestSize,
                                                               TCDigest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    //Create TC identityCert
    IdentityCertificate identityCertChainTC[certChainSize];

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToSCSessionId);

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(managerBus,
                                                                  "1",
                                                                  managerGuid.ToString(),
                                                                  TCKey.GetPublicKey(),
                                                                  "SCAlias",
                                                                  3600,
                                                                  identityCertChainTC[0],
                                                                  TCDigest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

    EXPECT_EQ(ER_OK, sapWithTC.UpdateIdentity(identityCertChainTC, certChainSize, TCManifest, manifestSize))
        << "Failed to update Identity cert or manifest ";

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    // Verify Method call
    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_OK, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
    char* echoReply;
    replyMsg->GetArg(0)->Get("s", &echoReply);
    EXPECT_STREQ("String that should be Echoed back.", echoReply);

    // Verify Set/Get Property
    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_OK, proxy.SetProperty(interfaceName, "Prop1", prop1Arg));
    EXPECT_EQ(513, TCBus.ReadProp1());

    MsgArg prop1ArgOut;
    EXPECT_EQ(ER_OK, proxy.GetProperty(interfaceName, "Prop1", prop1Arg));
    uint32_t prop1;
    prop1Arg.Get("i", &prop1);
    EXPECT_EQ((uint32_t)513, prop1);

    // Send/Receive Signal
    arg.Set("s", "Chirp this String out in the signal.");
    // Signals are send and forget.  They will always return ER_OK.
    EXPECT_EQ(ER_OK, SCBusObject.Signal(TCBus.GetUniqueName().c_str(), SCToTCSessionId, *SCBus.GetInterface(interfaceName)->GetMember("Chirp"), &arg, 1, 0, 0));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (TCBus.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(TCBus.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_14_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    //SC already has a manifest installed that allows everything from the SetUp

    const size_t manifestSize = 10;
    const size_t certChainSize = 1;
    /*************Update TC Manifest *************/
    //TC key

    // TC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    { //Rule1: Object Path: *; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
        SCManifest[0].SetObjPath("*");
        SCManifest[0].SetInterfaceName(interfaceName);
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        SCManifest[0].SetMembers(1, members);
    }
    { //Rule2: Object Path: /test ; Interface: *; Member Name: *, Action: DENY
        SCManifest[1].SetObjPath("/test");
        SCManifest[1].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        SCManifest[1].SetMembers(1, members);
    }
    { //Rule3: Object Path: * ; Interface: *; Member Name: Echo , Action: DENY
        SCManifest[2].SetObjPath("*");
        SCManifest[2].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Echo",
                       PermissionPolicy::Rule::Member::METHOD_CALL,
                       0 /*DENY*/);
        SCManifest[2].SetMembers(1, members);
    }
    { //Rule4: Object Path: * ; Interface: *; Member Name: Prop1 , Action: DENY
        SCManifest[3].SetObjPath("*");
        SCManifest[3].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Prop1",
                       PermissionPolicy::Rule::Member::PROPERTY,
                       0 /*DENY*/);
        SCManifest[3].SetMembers(1, members);
    }
    { //Rule5: Object Path: * ; Interface: *; Member Name: Chirp , Action: DENY
        SCManifest[4].SetObjPath("*");
        SCManifest[4].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Chirp",
                       PermissionPolicy::Rule::Member::SIGNAL,
                       0 /*DENY*/);
        SCManifest[4].SetMembers(1, members);
    }
    { //Rule6: Object Path: /test ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
        SCManifest[5].SetObjPath("/test");
        SCManifest[5].SetInterfaceName(interfaceName);
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        SCManifest[5].SetMembers(1, members);
    }
    { //Rule7: Object Path: /t*  ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: *, Action: DENY
        SCManifest[6].SetObjPath("/t*");
        SCManifest[6].SetInterfaceName(interfaceName);
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        SCManifest[6].SetMembers(1, members);
    }
    { //Rule8: Object Path: *  ; Interface: org.allseen.test.*; Member Name: *; Action: DENY
        SCManifest[7].SetObjPath("*");
        SCManifest[7].SetInterfaceName("org.allseen.test.*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        SCManifest[7].SetMembers(1, members);
    }
    { //Rule9: Object Path: /test  ; Interface: org.allseen.test.SecurityApplication.rules; Member Name: Chirp, Action: DENY
        SCManifest[8].SetObjPath("/test");
        SCManifest[8].SetInterfaceName(interfaceName);
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("Chirp",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        SCManifest[8].SetMembers(1, members);
    }
    { //Rule 10: Object Path: *, Interface: *, Member Name: *; Action: PROVIDE|OBSERVE|MODIFY
        SCManifest[9].SetObjPath("*");
        SCManifest[9].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].SetMemberName("*");
        members[0].SetActionMask(PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                                 PermissionPolicy::Rule::Member::ACTION_MODIFY |
                                 PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        SCManifest[9].SetMembers(1, members);
    }

    uint8_t SCDigest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(managerBus,
                                                               SCManifest, manifestSize,
                                                               SCDigest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    //Create SC identityCert
    IdentityCertificate identityCertChainSC[certChainSize];

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToTCSessionId);

    ECCPublicKey SCPublicKey;
    GetAppPublicKey(SCBus, SCPublicKey);
    KeyInfoNISTP256 SCKey;
    SCKey.SetPublicKey(&SCPublicKey);

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(managerBus,
                                                                  "1",
                                                                  managerGuid.ToString(),
                                                                  SCKey.GetPublicKey(),
                                                                  "SCAlias",
                                                                  3600,
                                                                  identityCertChainSC[0],
                                                                  SCDigest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

    EXPECT_EQ(ER_OK, sapWithSC.UpdateIdentity(identityCertChainSC, certChainSize, SCManifest, manifestSize))
        << "Failed to update Identity cert or manifest ";

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    // Verify Method call
    const char* s = "String that should be Echoed back.";
    ASSERT_EQ(ER_OK, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));
    EXPECT_STREQ(s, TCBus.GetResponse());

    // Verify Set/Get Property
    EXPECT_EQ(ER_OK, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, 513));
    EXPECT_EQ(513, SCBusObject.ReadProp1());
    int32_t prop; 
    EXPECT_EQ(ER_OK, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop));
    EXPECT_EQ(513, prop);

    // Send/Receive Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver, static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler), SCBus.GetInterface(interfaceName)->GetMember("Chirp"), NULL));

    EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_CHIRP, "Chirp this String out in the signal."));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Purpose
 * Verify that wild card DENY rule does not take effect in the manifest file.
 *
 * Setup
 * Peer2 and Peer2 bus implement the following :
 * Object Path:  /test
 * Interface Name: "org.allseen.test.SecurityApplication.rules"
 * Member name: Echo (method call)
 * Member name: Prop1  (property, read write)
 * Member name: Chirp (signal)
 *
 * Policy rules allow everything
 * Peer1 and Peer2 set up an ECDHE_ECDSA based session.
 * Peer1 makes a method call to Peer2.
 * Peer1 sends a signal to Peer2.
 * Peer1 makes a get property call on Peer2
 * Peer1 makes a set property call on Peer2
 *
 * Peer1 Policy:
 * ACL 1: Peer type: ANY_TRUSTED, Rule: Allow everything
 *
 * Peer1 manifest:
 * Sender Manifest:
 * Rule 1: Object Path: *, Interface: *, Member Name: *: Action: DENY
 * Rule 2: Object Path: *, Interface: *, Member Name: NS; Action: PROVIDE|OBSERVE|MODIFY

 * Peer2 Policy:
 * ACL 1: Peer type: ANY_TRUSTED: Allow everything
 *
 * Peer2 manifest:
 * Rule 1: Allow everything
 *
 * verification:
 * Verify that method call, get/set property calls are successful.
 * Verify that signal is received by Peer2.
 */
TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_15_SC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    const size_t manifestSize = 2;
    const size_t certChainSize = 1;
    /*************Update SC Manifest *************/
    //SC key
    KeyInfoNISTP256 SCKey;
    PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

    // SC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    { //Rule 1: Object Path: *, Interface: *, Member Name: *: Action: DENY
        SCManifest[0].SetObjPath("*");
        SCManifest[0].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        SCManifest[0].SetMembers(1, members);
    }
    { //Rule 2: Object Path: *, Interface: *, Member Name: *; Action: PROVIDE|OBSERVE|MODIFY
        SCManifest[1].SetObjPath("*");
        SCManifest[1].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                       PermissionPolicy::Rule::Member::ACTION_MODIFY |
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        SCManifest[1].SetMembers(1, members);
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

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    EXPECT_EQ(ER_OK, sapWithSC.UpdateIdentity(identityCertChainSC, certChainSize, SCManifest, manifestSize))
        << "Failed to update Identity cert or manifest ";

    //TC already has a manifest installed that allows everything from the SetUp

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    // Verify Method call
    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_OK, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
    char* echoReply;
    replyMsg->GetArg(0)->Get("s", &echoReply);
    EXPECT_STREQ("String that should be Echoed back.", echoReply);

    // Verify Set/Get Property
    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_OK, proxy.SetProperty(interfaceName, "Prop1", prop1Arg));
    EXPECT_EQ(513, TCBus.ReadProp1());

    MsgArg prop1ArgOut;
    EXPECT_EQ(ER_OK, proxy.GetProperty(interfaceName, "Prop1", prop1Arg));
    uint32_t prop1;
    prop1Arg.Get("i", &prop1);
    EXPECT_EQ((uint32_t)513, prop1);

    // Send/Receive Signal
    arg.Set("s", "Chirp this String out in the signal.");
    // Signals are send and forget.  They will always return ER_OK.
    EXPECT_EQ(ER_OK, SCBusObject.Signal(TCBus.GetUniqueName().c_str(), SCToTCSessionId, *SCBus.GetInterface(interfaceName)->GetMember("Chirp"), &arg, 1, 0, 0));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (TCBus.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(TCBus.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_15_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    const size_t manifestSize = 2;
    const size_t certChainSize = 1;
    /*************Update TC Manifest *************/

    // TC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    { //Rule 1: Object Path: *, Interface: *, Member Name: *: Action: DENY
        TCManifest[0].SetObjPath("*");
        TCManifest[0].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        TCManifest[0].SetMembers(1, members);
    }
    { //Rule 2: Object Path: *, Interface: *, Member Name: NS; Action: PROVIDE|OBSERVE|MODIFY
        TCManifest[1].SetObjPath("*");
        TCManifest[1].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].SetMemberName("*");
        members[0].SetActionMask(PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                                 PermissionPolicy::Rule::Member::ACTION_MODIFY |
                                 PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        TCManifest[1].SetMembers(1, members);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

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

    EXPECT_EQ(ER_OK, sapWithTC.UpdateIdentity(identityCertChainTC, certChainSize, TCManifest, manifestSize))
        << "Failed to update Identity cert or manifest ";

    //SC already has a manifest installed that allows everything from the SetUp

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    // Verify Method call
    const char* s = "String that should be Echoed back.";
    ASSERT_EQ(ER_OK, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));
    EXPECT_STREQ(s, TCBus.GetResponse());

    // Verify Set/Get Property
    EXPECT_EQ(ER_OK, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, 513));
    EXPECT_EQ(513, SCBusObject.ReadProp1());
    int32_t prop; 
    EXPECT_EQ(ER_OK, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop));
    EXPECT_EQ(513, prop);

    // Send/Receive Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver, static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler), SCBus.GetInterface(interfaceName)->GetMember("Chirp"), NULL));

    EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_CHIRP, "Chirp this String out in the signal."));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/*
 * Purpose
 * Verify that wild card DENY rule does not take effect in the manifest file.
 *
 * Setup
 * Peer1 and Peer2 bus implement the following :
 * Object Path:  /test
 * Interface Name: "org.allseen.test.SecurityApplication.rules"
 * Member name: Echo (method call)
 * Member name: Prop1  (property, read write)
 * Member name: Chirp (signal)
 *
 * Policy rules allow everything
 * Peer1 and Peer2 set up an ECDHE_ECDSA based session.
 * Peer1 makes a method call to Peer2.
 * Peer1 sends a signal to Peer2.
 * Peer1 makes a get property call on Peer2
 * Peer1 makes a set property call on Peer2
 *
 * Peer1 Policy:
 * ACL 1: Peer type: ANY_TRUSTED: Allow everything
 *
 * Peer1 manifest:
 * Rule 1: Allow everything
 *
 * Peer2 Policy:
 * ACL 1: Peer type: ANY_TRUSTED, Rule: Allow everything
 *
 * Peer2 manifest:
 * Sender Manifest:
 * Rule 1: Object Path: *, Interface: *, Member Name: *: Action: DENY
 * Rule 2: Object Path: *, Interface: *, Member Name: NS; Action: PROVIDE|OBSERVE|MODIFY
 *
 * verification:
 * Verify that method call, get/set property calls are successful.
 * Verify that signal is received by Peer2.
 */
TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_16_SC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    //TC already has a manifest installed that allows everything from the SetUp

    const size_t manifestSize = 2;
    const size_t certChainSize = 1;
    /*************Update SC Manifest *************/
    //SC key

    // SC manifest
    PermissionPolicy::Rule TCManifest[manifestSize];
    { //Rule 1: Object Path: *, Interface: *, Member Name: *: Action: DENY
        TCManifest[0].SetObjPath("*");
        TCManifest[0].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        TCManifest[0].SetMembers(1, members);
    }
    { //Rule 2: Object Path: *, Interface: *, Member Name: NS; Action: PROVIDE|OBSERVE|MODIFY
        TCManifest[1].SetObjPath("*");
        TCManifest[1].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].SetMemberName("*");
        members[0].SetActionMask(PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                                 PermissionPolicy::Rule::Member::ACTION_MODIFY |
                                 PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        TCManifest[1].SetMembers(1, members);
    }


    uint8_t TCDigest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(managerBus,
                                                               TCManifest, manifestSize,
                                                               TCDigest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    //Create TC identityCert
    IdentityCertificate identityCertChainTC[certChainSize];

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToSCSessionId);

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(managerBus,
                                                                  "1",
                                                                  managerGuid.ToString(),
                                                                  TCKey.GetPublicKey(),
                                                                  "SCAlias",
                                                                  3600,
                                                                  identityCertChainTC[0],
                                                                  TCDigest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

    EXPECT_EQ(ER_OK, sapWithTC.UpdateIdentity(identityCertChainTC, certChainSize, TCManifest, manifestSize))
        << "Failed to update Identity cert or manifest ";

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    // Verify Method call
    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_OK, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
    char* echoReply;
    replyMsg->GetArg(0)->Get("s", &echoReply);
    EXPECT_STREQ("String that should be Echoed back.", echoReply);

    // Verify Set/Get Property
    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_OK, proxy.SetProperty(interfaceName, "Prop1", prop1Arg));
    EXPECT_EQ(513, TCBus.ReadProp1());

    MsgArg prop1ArgOut;
    EXPECT_EQ(ER_OK, proxy.GetProperty(interfaceName, "Prop1", prop1Arg));
    uint32_t prop1;
    prop1Arg.Get("i", &prop1);
    EXPECT_EQ((uint32_t)513, prop1);

    // Send/Receive Signal
    arg.Set("s", "Chirp this String out in the signal.");
    // Signals are send and forget.  They will always return ER_OK.
    EXPECT_EQ(ER_OK, SCBusObject.Signal(TCBus.GetUniqueName().c_str(), SCToTCSessionId, *SCBus.GetInterface(interfaceName)->GetMember("Chirp"), &arg, 1, 0, 0));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (TCBus.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(TCBus.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

TEST_F(SecurityPolicyRulesTest, PolicyRules_DENY_16_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    //SC already has a manifest installed that allows everything from the SetUp

    const size_t manifestSize = 2;
    const size_t certChainSize = 1;
    /*************Update TC Manifest *************/
    //TC key

    // TC manifest
    PermissionPolicy::Rule SCManifest[manifestSize];
    { //Rule 1: Object Path: *, Interface: *, Member Name: *: Action: DENY
        SCManifest[0].SetObjPath("*");
        SCManifest[0].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       0 /*DENY*/);
        SCManifest[0].SetMembers(1, members);
    }
    { //Rule 2: Object Path: *, Interface: *, Member Name: *; Action: PROVIDE|OBSERVE|MODIFY
        SCManifest[1].SetObjPath("*");
        SCManifest[1].SetInterfaceName("*");
        PermissionPolicy::Rule::Member members[1];
        members[0].Set("*",
                       PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                       PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                       PermissionPolicy::Rule::Member::ACTION_MODIFY |
                       PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        SCManifest[1].SetMembers(1, members);
    }


    uint8_t SCDigest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(managerBus,
                                                               SCManifest, manifestSize,
                                                               SCDigest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    //Create SC identityCert
    IdentityCertificate identityCertChainSC[certChainSize];

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToTCSessionId);

    ECCPublicKey SCPublicKey;
    GetAppPublicKey(SCBus, SCPublicKey);
    KeyInfoNISTP256 SCKey;
    SCKey.SetPublicKey(&SCPublicKey);

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(managerBus,
                                                                  "1",
                                                                  managerGuid.ToString(),
                                                                  SCKey.GetPublicKey(),
                                                                  "TCAlias",
                                                                  3600,
                                                                  identityCertChainSC[0],
                                                                  SCDigest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

    EXPECT_EQ(ER_OK, sapWithSC.UpdateIdentity(identityCertChainSC, certChainSize, SCManifest, manifestSize))
        << "Failed to update Identity cert or manifest ";

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));

    // Verify Method call
    const char* s = "String that should be Echoed back.";
    ASSERT_EQ(ER_OK, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));
    EXPECT_STREQ(s, TCBus.GetResponse());

    // Verify Set/Get Property
    EXPECT_EQ(ER_OK, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, 513));
    EXPECT_EQ(513, SCBusObject.ReadProp1());
    int32_t prop; 
    EXPECT_EQ(ER_OK, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_PROP1, prop));
    EXPECT_EQ(513, prop);

    // Send/Receive Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver, static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler), SCBus.GetInterface(interfaceName)->GetMember("Chirp"), NULL));

    EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_CHIRP, "Chirp this String out in the signal."));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag);

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}


TEST_F(SecurityPolicyRulesTest, acl_ECDHE_NULL_methodcall_fails_for_ANY_TRUSTED_in_receiver_policy)
{
    /* install permissions make method calls */
    //Permission policy that will be installed on peer1
    PermissionPolicy peer1Policy;
    peer1Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public Key of Peer2
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
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer1Policy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on peer2
    PermissionPolicy peer2Policy;
    peer2Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public key of Peer1
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
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer2Policy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithPeer1(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithPeer2(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy peer1DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer1.GetDefaultPolicy(peer1DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer1DefaultPolicy, peer1Policy);
    }
    {
        PermissionPolicy peer2DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer2.GetDefaultPolicy(peer2DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer2DefaultPolicy, peer2Policy);
    }

    EXPECT_EQ(ER_OK, sapWithPeer1.UpdatePolicy(peer1Policy));
    EXPECT_EQ(ER_OK, sapWithPeer1.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithPeer2.UpdatePolicy(peer2Policy));
    EXPECT_EQ(ER_OK, sapWithPeer2.SecureConnection(true));

    /* We should be using a ECDHE_NULL based session */
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL"));
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", SCAuthListener));

    SessionOpts opts;
    SessionId peer1ToPeer2SessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, peer1ToPeer2SessionId, opts));
    qcc::String p1policyStr = "\n----TC Policy-----\n" + peer1Policy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----SC Policy-----\n" + peer2Policy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", peer1ToPeer2SessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
}

TEST_F(SecurityPolicyRulesTest, acl_ECDHE_NULL_methodcall_fails_for_ANY_TRUSTED_in_sender_policy)
{
    /* install permissions make method calls */
    // Permission policy that will be installed on peer2
    PermissionPolicy peer1Policy;
    peer1Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public key of Peer1
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
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer1Policy.SetAcls(1, acls);
    }

    //Permission policy that will be installed on peer1
    PermissionPolicy peer2Policy;
    peer2Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public Key of Peer2
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
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer2Policy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithPeer1(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithPeer2(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy peer1DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer1.GetDefaultPolicy(peer1DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer1DefaultPolicy, peer1Policy);
    }
    {
        PermissionPolicy peer2DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer2.GetDefaultPolicy(peer2DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer2DefaultPolicy, peer2Policy);
    }

    EXPECT_EQ(ER_OK, sapWithPeer1.UpdatePolicy(peer1Policy));
    EXPECT_EQ(ER_OK, sapWithPeer1.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithPeer2.UpdatePolicy(peer2Policy));
    EXPECT_EQ(ER_OK, sapWithPeer2.SecureConnection(true));

    /* We should be using a ECDHE_NULL based session */
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL"));
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", SCAuthListener));

    SessionOpts opts;
    SessionId peer1ToPeer2SessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, peer1ToPeer2SessionId, opts));
    qcc::String p1policyStr = "\n----Peer1 Policy-----\n" + peer1Policy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----Peer2 Policy-----\n" + peer2Policy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", peer1ToPeer2SessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));

}

TEST_F(SecurityPolicyRulesTest, acl_verify_peers_using_FROM_CERTIFICATE_AUTHORITY_different_identity_certs)
{
    BusAttachment busUsedAsCA1("busUsedAsCA1");
    BusAttachment busUsedAsCA2("busUsedAsCA2");

    EXPECT_EQ(ER_OK, busUsedAsCA1.Start());
    EXPECT_EQ(ER_OK, busUsedAsCA1.Connect());
    EXPECT_EQ(ER_OK, busUsedAsCA2.Start());
    EXPECT_EQ(ER_OK, busUsedAsCA2.Connect());

    InMemoryKeyStoreListener busUsedAsCA1KeyStoreListener;
    EXPECT_EQ(ER_OK, busUsedAsCA1.RegisterKeyStoreListener(busUsedAsCA1KeyStoreListener));
    InMemoryKeyStoreListener busUsedAsCA2KeyStoreListener;
    EXPECT_EQ(ER_OK, busUsedAsCA2.RegisterKeyStoreListener(busUsedAsCA2KeyStoreListener));

    DefaultECDHEAuthListener busUsedAsCA1AuthListener;
    EXPECT_EQ(ER_OK, busUsedAsCA1.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &busUsedAsCA1AuthListener));
    DefaultECDHEAuthListener busUsedAsCA2AuthListener;
    EXPECT_EQ(ER_OK, busUsedAsCA2.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &busUsedAsCA2AuthListener));

    KeyInfoNISTP256 ca1Key;
    EXPECT_EQ(ER_OK, busUsedAsCA1.GetPermissionConfigurator().GetSigningPublicKey(ca1Key));
    KeyInfoNISTP256 ca2Key;
    EXPECT_EQ(ER_OK, busUsedAsCA2.GetPermissionConfigurator().GetSigningPublicKey(ca2Key));
    KeyInfoNISTP256 peer1Key;
    EXPECT_EQ(ER_OK, SCBus.GetPermissionConfigurator().GetSigningPublicKey(peer1Key));
    KeyInfoNISTP256& peer2Key = TCKey;

    /* install permissions make method calls */
    // Permission policy that will be installed on peer2
    PermissionPolicy peer1Policy;
    peer1Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public key of Peer1
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_FROM_CERTIFICATE_AUTHORITY);
            peers[0].SetKeyInfo(&ca1Key);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer1Policy.SetAcls(1, acls);
    }

    //Permission policy that will be installed on peer1
    PermissionPolicy peer2Policy;
    peer2Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public Key of Peer2
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_FROM_CERTIFICATE_AUTHORITY);
            peers[0].SetKeyInfo(&ca2Key);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer2Policy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithPeer1(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithPeer2(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy peer1DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer1.GetDefaultPolicy(peer1DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer1DefaultPolicy, peer1Policy, true, true, true);
    }
    {
        PermissionPolicy peer2DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer2.GetDefaultPolicy(peer2DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer2DefaultPolicy, peer2Policy, true, true, true);
    }

    EXPECT_EQ(ER_OK, sapWithPeer1.UpdatePolicy(peer1Policy));
    EXPECT_EQ(ER_OK, sapWithPeer1.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithPeer2.UpdatePolicy(peer2Policy));
    EXPECT_EQ(ER_OK, sapWithPeer2.SecureConnection(true));

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t ca2Digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(busUsedAsCA2,
                                                               manifest, manifestSize,
                                                               ca2Digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    //Create peer1 identityCert
    const size_t certChainSize = 1;
    IdentityCertificate identityCertChainPeer1[certChainSize];

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(busUsedAsCA2,
                                                                  "2",
                                                                  managerGuid.ToString(),
                                                                  peer1Key.GetPublicKey(),
                                                                  "Peer1Alias",
                                                                  3600,
                                                                  identityCertChainPeer1[0],
                                                                  ca2Digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

    EXPECT_EQ(ER_OK, sapWithPeer1.UpdateIdentity(identityCertChainPeer1, certChainSize, manifest, manifestSize));

    uint8_t ca1Digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(busUsedAsCA1,
                                                               manifest, manifestSize,
                                                               ca1Digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    //Create peer2 identityCert
    IdentityCertificate identityCertChainPeer2[certChainSize];

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(busUsedAsCA1,
                                                                  "2",
                                                                  managerGuid.ToString(),
                                                                  peer2Key.GetPublicKey(),
                                                                  "Peer2Alias",
                                                                  3600,
                                                                  identityCertChainPeer2[0],
                                                                  ca1Digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

    EXPECT_EQ(ER_OK, sapWithPeer2.UpdateIdentity(identityCertChainPeer2, certChainSize, manifest, manifestSize));

    SessionOpts opts;
    SessionId peer1ToPeer2SessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, peer1ToPeer2SessionId, opts));
    qcc::String p1policyStr = "\n----Peer1 Policy-----\n" + peer1Policy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----Peer2 Policy-----\n" + peer2Policy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", peer1ToPeer2SessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    EXPECT_EQ(ER_OK, proxy.SecureConnection());

    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_OK, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
    char* echoReply;
    replyMsg->GetArg(0)->Get("s", &echoReply);
    EXPECT_STREQ("String that should be Echoed back.", echoReply);
}

TEST_F(SecurityPolicyRulesTest, acl_verify_peers_using_FROM_CERTIFICATE_AUTHORITY_peer_signed_by_different_CA_sender)
{
    BusAttachment busUsedAsCA1("busUsedAsCA1");
    BusAttachment busUsedAsCA2("busUsedAsCA2");

    EXPECT_EQ(ER_OK, busUsedAsCA1.Start());
    EXPECT_EQ(ER_OK, busUsedAsCA1.Connect());
    EXPECT_EQ(ER_OK, busUsedAsCA2.Start());
    EXPECT_EQ(ER_OK, busUsedAsCA2.Connect());

    InMemoryKeyStoreListener busUsedAsCA1KeyStoreListener;
    EXPECT_EQ(ER_OK, busUsedAsCA1.RegisterKeyStoreListener(busUsedAsCA1KeyStoreListener));
    InMemoryKeyStoreListener busUsedAsCA2KeyStoreListener;
    EXPECT_EQ(ER_OK, busUsedAsCA2.RegisterKeyStoreListener(busUsedAsCA2KeyStoreListener));

    DefaultECDHEAuthListener busUsedAsCA1AuthListener;
    EXPECT_EQ(ER_OK, busUsedAsCA1.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &busUsedAsCA1AuthListener));
    DefaultECDHEAuthListener busUsedAsCA2AuthListener;
    EXPECT_EQ(ER_OK, busUsedAsCA2.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &busUsedAsCA2AuthListener));

    KeyInfoNISTP256 ca1Key;
    EXPECT_EQ(ER_OK, busUsedAsCA1.GetPermissionConfigurator().GetSigningPublicKey(ca1Key));
    KeyInfoNISTP256 ca2Key;
    EXPECT_EQ(ER_OK, busUsedAsCA2.GetPermissionConfigurator().GetSigningPublicKey(ca2Key));
    KeyInfoNISTP256 peer1Key;
    EXPECT_EQ(ER_OK, SCBus.GetPermissionConfigurator().GetSigningPublicKey(peer1Key));
    KeyInfoNISTP256& peer2Key = TCKey;

    /* install permissions make method calls */
    // Permission policy that will be installed on peer2
    PermissionPolicy peer1Policy;
    peer1Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public key of Peer1
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_FROM_CERTIFICATE_AUTHORITY);
            peers[0].SetKeyInfo(&ca1Key);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer1Policy.SetAcls(1, acls);
    }

    //Permission policy that will be installed on peer1
    PermissionPolicy peer2Policy;
    peer2Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public Key of Peer2
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_FROM_CERTIFICATE_AUTHORITY);
            peers[0].SetKeyInfo(&ca2Key);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer2Policy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithPeer1(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithPeer2(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy peer1DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer1.GetDefaultPolicy(peer1DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer1DefaultPolicy, peer1Policy, true, true, true);
    }
    {
        PermissionPolicy peer2DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer2.GetDefaultPolicy(peer2DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer2DefaultPolicy, peer2Policy, true, true, true);
    }

    EXPECT_EQ(ER_OK, sapWithPeer1.UpdatePolicy(peer1Policy));
    EXPECT_EQ(ER_OK, sapWithPeer1.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithPeer2.UpdatePolicy(peer2Policy));
    EXPECT_EQ(ER_OK, sapWithPeer2.SecureConnection(true));

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t ca2Digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(busUsedAsCA2,
                                                               manifest, manifestSize,
                                                               ca2Digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    //Create peer1 identityCert
    const size_t certChainSize = 1;
    IdentityCertificate identityCertChainPeer1[certChainSize];

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(busUsedAsCA2,
                                                                  "2",
                                                                  managerGuid.ToString(),
                                                                  peer1Key.GetPublicKey(),
                                                                  "Peer1Alias",
                                                                  3600,
                                                                  identityCertChainPeer1[0],
                                                                  ca2Digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

    EXPECT_EQ(ER_OK, sapWithPeer1.UpdateIdentity(identityCertChainPeer1, certChainSize, manifest, manifestSize));

    //Create peer2 identityCert
    IdentityCertificate identityCertChainPeer2[certChainSize];

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(busUsedAsCA2,
                                                                  "2",
                                                                  managerGuid.ToString(),
                                                                  peer2Key.GetPublicKey(),
                                                                  "Peer2Alias",
                                                                  3600,
                                                                  identityCertChainPeer2[0],
                                                                  ca2Digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

    EXPECT_EQ(ER_OK, sapWithPeer2.UpdateIdentity(identityCertChainPeer2, certChainSize, manifest, manifestSize));

    SessionOpts opts;
    SessionId peer1ToPeer2SessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, peer1ToPeer2SessionId, opts));
    qcc::String p1policyStr = "\n----Peer1 Policy-----\n" + peer1Policy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----Peer2 Policy-----\n" + peer2Policy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", peer1ToPeer2SessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    EXPECT_EQ(ER_AUTH_FAIL, proxy.SecureConnection());

    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
    ASSERT_STREQ("org.alljoyn.Bus.ErStatus", replyMsg->GetErrorName());
    EXPECT_EQ(ER_AUTH_FAIL, (QStatus)replyMsg->GetArg(1)->v_uint16) << "\n" << replyMsg->GetArg(0)->ToString().c_str() << "\n" << replyMsg->GetArg(1)->ToString().c_str();

}

TEST_F(SecurityPolicyRulesTest, acl_verify_peers_using_FROM_CERTIFICATE_AUTHORITY_peer_signed_by_different_CA_receiver)
{
    BusAttachment busUsedAsCA1("busUsedAsCA1");
    BusAttachment busUsedAsCA2("busUsedAsCA2");

    EXPECT_EQ(ER_OK, busUsedAsCA1.Start());
    EXPECT_EQ(ER_OK, busUsedAsCA1.Connect());
    EXPECT_EQ(ER_OK, busUsedAsCA2.Start());
    EXPECT_EQ(ER_OK, busUsedAsCA2.Connect());

    InMemoryKeyStoreListener busUsedAsCA1KeyStoreListener;
    EXPECT_EQ(ER_OK, busUsedAsCA1.RegisterKeyStoreListener(busUsedAsCA1KeyStoreListener));
    InMemoryKeyStoreListener busUsedAsCA2KeyStoreListener;
    EXPECT_EQ(ER_OK, busUsedAsCA2.RegisterKeyStoreListener(busUsedAsCA2KeyStoreListener));

    DefaultECDHEAuthListener busUsedAsCA1AuthListener;
    EXPECT_EQ(ER_OK, busUsedAsCA1.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &busUsedAsCA1AuthListener));
    DefaultECDHEAuthListener busUsedAsCA2AuthListener;
    EXPECT_EQ(ER_OK, busUsedAsCA2.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &busUsedAsCA2AuthListener));

    KeyInfoNISTP256 ca1Key;
    EXPECT_EQ(ER_OK, busUsedAsCA1.GetPermissionConfigurator().GetSigningPublicKey(ca1Key));
    KeyInfoNISTP256 ca2Key;
    EXPECT_EQ(ER_OK, busUsedAsCA2.GetPermissionConfigurator().GetSigningPublicKey(ca2Key));
    KeyInfoNISTP256 peer1Key;
    EXPECT_EQ(ER_OK, SCBus.GetPermissionConfigurator().GetSigningPublicKey(peer1Key));
    KeyInfoNISTP256& peer2Key = TCKey;

    /* install permissions make method calls */
    // Permission policy that will be installed on peer2
    PermissionPolicy peer1Policy;
    peer1Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public key of Peer1
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_FROM_CERTIFICATE_AUTHORITY);
            peers[0].SetKeyInfo(&ca2Key);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer1Policy.SetAcls(1, acls);
    }

    //Permission policy that will be installed on peer1
    PermissionPolicy peer2Policy;
    peer2Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public Key of Peer2
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_FROM_CERTIFICATE_AUTHORITY);
            peers[0].SetKeyInfo(&ca1Key);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                               PermissionPolicy::Rule::Member::ACTION_MODIFY |
                               PermissionPolicy::Rule::Member::ACTION_OBSERVE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer2Policy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithPeer1(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithPeer2(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy peer1DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer1.GetDefaultPolicy(peer1DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer1DefaultPolicy, peer1Policy, true, true, true);
    }
    {
        PermissionPolicy peer2DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer2.GetDefaultPolicy(peer2DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer2DefaultPolicy, peer2Policy, true, true, true);
    }

    EXPECT_EQ(ER_OK, sapWithPeer1.UpdatePolicy(peer1Policy));
    EXPECT_EQ(ER_OK, sapWithPeer1.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithPeer2.UpdatePolicy(peer2Policy));
    EXPECT_EQ(ER_OK, sapWithPeer2.SecureConnection(true));

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t ca2Digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(busUsedAsCA2,
                                                               manifest, manifestSize,
                                                               ca2Digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    //Create peer1 identityCert
    const size_t certChainSize = 1;
    IdentityCertificate identityCertChainPeer1[certChainSize];

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(busUsedAsCA2,
                                                                  "2",
                                                                  managerGuid.ToString(),
                                                                  peer1Key.GetPublicKey(),
                                                                  "Peer1Alias",
                                                                  3600,
                                                                  identityCertChainPeer1[0],
                                                                  ca2Digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

    EXPECT_EQ(ER_OK, sapWithPeer1.UpdateIdentity(identityCertChainPeer1, certChainSize, manifest, manifestSize));

    //Create peer2 identityCert
    IdentityCertificate identityCertChainPeer2[certChainSize];

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(busUsedAsCA2,
                                                                  "2",
                                                                  managerGuid.ToString(),
                                                                  peer2Key.GetPublicKey(),
                                                                  "Peer2Alias",
                                                                  3600,
                                                                  identityCertChainPeer2[0],
                                                                  ca2Digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

    EXPECT_EQ(ER_OK, sapWithPeer2.UpdateIdentity(identityCertChainPeer2, certChainSize, manifest, manifestSize));

    SessionOpts opts;
    SessionId peer1ToPeer2SessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, peer1ToPeer2SessionId, opts));
    qcc::String p1policyStr = "\n----Peer1 Policy-----\n" + peer1Policy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----Peer2 Policy-----\n" + peer2Policy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", peer1ToPeer2SessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    EXPECT_EQ(ER_AUTH_FAIL, proxy.SecureConnection());

    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
    ASSERT_STREQ("org.alljoyn.Bus.ErStatus", replyMsg->GetErrorName());
    EXPECT_EQ(ER_AUTH_FAIL, (QStatus)replyMsg->GetArg(1)->v_uint16) << "\n" << replyMsg->GetArg(0)->ToString().c_str() << "\n" << replyMsg->GetArg(1)->ToString().c_str();

}


TEST_F(SecurityPolicyRulesTest, acl_policy_WITH_MEMBERSHIP_successfull)
{
    SecurityApplicationProxy sapWithPeer1(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithPeer2(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    BusAttachment busUsedAsSGA1("busUsedAsSGA1");
    BusAttachment busUsedAsSGA2("busUsedAsSGA2");

    EXPECT_EQ(ER_OK, busUsedAsSGA1.Start());
    EXPECT_EQ(ER_OK, busUsedAsSGA1.Connect());
    EXPECT_EQ(ER_OK, busUsedAsSGA2.Start());
    EXPECT_EQ(ER_OK, busUsedAsSGA2.Connect());

    InMemoryKeyStoreListener busUsedAsCA1KeyStoreListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA1.RegisterKeyStoreListener(busUsedAsCA1KeyStoreListener));
    InMemoryKeyStoreListener busUsedAsCA2KeyStoreListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA2.RegisterKeyStoreListener(busUsedAsCA2KeyStoreListener));

    DefaultECDHEAuthListener busUsedAsCA1AuthListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA1.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &busUsedAsCA1AuthListener));
    DefaultECDHEAuthListener busUsedAsCA2AuthListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA2.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &busUsedAsCA2AuthListener));

    KeyInfoNISTP256 peer1Key;
    EXPECT_EQ(ER_OK, SCBus.GetPermissionConfigurator().GetSigningPublicKey(peer1Key));
    KeyInfoNISTP256& peer2Key = TCKey;
    KeyInfoNISTP256 sga1Key;
    EXPECT_EQ(ER_OK, busUsedAsSGA1.GetPermissionConfigurator().GetSigningPublicKey(sga1Key));
    KeyInfoNISTP256 sga2Key;
    EXPECT_EQ(ER_OK, busUsedAsSGA2.GetPermissionConfigurator().GetSigningPublicKey(sga2Key));

    GUID128 peer1Guid;
    PermissionMgmtTestHelper::GetGUID(SCBus, peer1Guid);
    GUID128 peer2Guid;
    TCBus.GetGuid(peer2Guid);
    GUID128 sgid1Guid;
    PermissionMgmtTestHelper::GetGUID(busUsedAsSGA1, sgid1Guid);
    GUID128 sgid2Guid;
    PermissionMgmtTestHelper::GetGUID(busUsedAsSGA2, sgid2Guid);

    qcc::MembershipCertificate peer1MembershipCertificate[2];
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-1",
                                                                    managerBus,
                                                                    sgid2Guid.ToString(),
                                                                    sga2Key.GetPublicKey(),
                                                                    sgid2Guid,
                                                                    true,
                                                                    3600,
                                                                    peer1MembershipCertificate[1]
                                                                    ));
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-0",
                                                                    busUsedAsSGA2,
                                                                    peer1Guid.ToString(),
                                                                    peer1Key.GetPublicKey(),
                                                                    sgid2Guid,
                                                                    false,
                                                                    3600,
                                                                    peer1MembershipCertificate[0]
                                                                    ));
    EXPECT_EQ(ER_OK, sapWithPeer1.InstallMembership(peer1MembershipCertificate, 2));

    qcc::MembershipCertificate peer2MembershipCertificate[2];
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-1",
                                                                    managerBus,
                                                                    sgid1Guid.ToString(),
                                                                    sga1Key.GetPublicKey(),
                                                                    sgid1Guid,
                                                                    true,
                                                                    3600,
                                                                    peer2MembershipCertificate[1]
                                                                    ));
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-0",
                                                                    busUsedAsSGA1,
                                                                    peer2Guid.ToString(),
                                                                    peer2Key.GetPublicKey(),
                                                                    sgid1Guid,
                                                                    false,
                                                                    3600,
                                                                    peer2MembershipCertificate[0]
                                                                    ));
    EXPECT_EQ(ER_OK, sapWithPeer2.InstallMembership(peer2MembershipCertificate, 2));
    /* install permissions make method calls */
    //Permission policy that will be installed on peer1
    PermissionPolicy peer1Policy;
    peer1Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);
            peers[0].SetSecurityGroupId(sgid1Guid);
            //Get manager key
            KeyInfoNISTP256 sga1Key;
            PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(sga1Key));
            peers[0].SetKeyInfo(&sga1Key);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer1Policy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on peer2
    PermissionPolicy peer2Policy;
    peer2Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);
            peers[0].SetSecurityGroupId(sgid2Guid);
            //Get manager key
            KeyInfoNISTP256 sga2Key;
            PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(sga2Key));
            peers[0].SetKeyInfo(&sga2Key);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_MODIFY);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer2Policy.SetAcls(1, acls);
    }

    {
        PermissionPolicy peer1DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer1.GetDefaultPolicy(peer1DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer1DefaultPolicy, peer1Policy);
    }
    {
        PermissionPolicy peer2DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer2.GetDefaultPolicy(peer2DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer2DefaultPolicy, peer2Policy);
    }

    EXPECT_EQ(ER_OK, sapWithPeer1.UpdatePolicy(peer1Policy));
    EXPECT_EQ(ER_OK, sapWithPeer1.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithPeer2.UpdatePolicy(peer2Policy));
    EXPECT_EQ(ER_OK, sapWithPeer2.SecureConnection(true));

    SessionOpts opts;
    SessionId peer1ToPeer2SessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, peer1ToPeer2SessionId, opts));
    qcc::String p1policyStr = "\n----Peer1 Policy-----\n" + peer1Policy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----Peer2 Policy-----\n" + peer2Policy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", peer1ToPeer2SessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    EXPECT_EQ(ER_OK, proxy.SecureConnection());

    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_OK, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
    char* echoReply;
    replyMsg->GetArg(0)->Get("s", &echoReply);
    EXPECT_STREQ("String that should be Echoed back.", echoReply);
}

TEST_F(SecurityPolicyRulesTest, acl_policy_WITH_MEMBERSHIP_security_group_id_does_not_match_sender)
{
    SecurityApplicationProxy sapWithPeer1(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithPeer2(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    BusAttachment busUsedAsSGA1("busUsedAsSGA1");
    BusAttachment busUsedAsSGA2("busUsedAsSGA2");

    EXPECT_EQ(ER_OK, busUsedAsSGA1.Start());
    EXPECT_EQ(ER_OK, busUsedAsSGA1.Connect());
    EXPECT_EQ(ER_OK, busUsedAsSGA2.Start());
    EXPECT_EQ(ER_OK, busUsedAsSGA2.Connect());

    InMemoryKeyStoreListener busUsedAsCA1KeyStoreListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA1.RegisterKeyStoreListener(busUsedAsCA1KeyStoreListener));
    InMemoryKeyStoreListener busUsedAsCA2KeyStoreListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA2.RegisterKeyStoreListener(busUsedAsCA2KeyStoreListener));

    DefaultECDHEAuthListener busUsedAsCA1AuthListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA1.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &busUsedAsCA1AuthListener));
    DefaultECDHEAuthListener busUsedAsCA2AuthListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA2.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &busUsedAsCA2AuthListener));

    KeyInfoNISTP256 peer1Key;
    EXPECT_EQ(ER_OK, SCBus.GetPermissionConfigurator().GetSigningPublicKey(peer1Key));
    KeyInfoNISTP256& peer2Key = TCKey;
    KeyInfoNISTP256 sga1Key;
    EXPECT_EQ(ER_OK, busUsedAsSGA1.GetPermissionConfigurator().GetSigningPublicKey(sga1Key));
    KeyInfoNISTP256 sga2Key;
    EXPECT_EQ(ER_OK, busUsedAsSGA2.GetPermissionConfigurator().GetSigningPublicKey(sga2Key));

    GUID128 peer1Guid;
    PermissionMgmtTestHelper::GetGUID(SCBus, peer1Guid);
    GUID128 peer2Guid;
    TCBus.GetGuid(peer2Guid);
    GUID128 sgid1Guid;
    PermissionMgmtTestHelper::GetGUID(busUsedAsSGA1, sgid1Guid);
    GUID128 sgid2Guid;
    PermissionMgmtTestHelper::GetGUID(busUsedAsSGA2, sgid2Guid);

    qcc::MembershipCertificate peer1MembershipCertificate[2];
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-1",
                                                                    managerBus,
                                                                    sgid2Guid.ToString(),
                                                                    sga2Key.GetPublicKey(),
                                                                    sgid2Guid,
                                                                    true,
                                                                    3600,
                                                                    peer1MembershipCertificate[1]
                                                                    ));
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-0",
                                                                    busUsedAsSGA2,
                                                                    peer1Guid.ToString(),
                                                                    peer1Key.GetPublicKey(),
                                                                    sgid2Guid,
                                                                    false,
                                                                    3600,
                                                                    peer1MembershipCertificate[0]
                                                                    ));
    EXPECT_EQ(ER_OK, sapWithPeer1.InstallMembership(peer1MembershipCertificate, 2));

    qcc::MembershipCertificate peer2MembershipCertificate[2];
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-1",
                                                                    managerBus,
                                                                    sgid1Guid.ToString(),
                                                                    sga1Key.GetPublicKey(),
                                                                    sgid1Guid,
                                                                    true,
                                                                    3600,
                                                                    peer2MembershipCertificate[1]
                                                                    ));
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-0",
                                                                    busUsedAsSGA1,
                                                                    peer2Guid.ToString(),
                                                                    peer2Key.GetPublicKey(),
                                                                    sgid1Guid,
                                                                    false,
                                                                    3600,
                                                                    peer2MembershipCertificate[0]
                                                                    ));
    EXPECT_EQ(ER_OK, sapWithPeer2.InstallMembership(peer2MembershipCertificate, 2));
    /* install permissions make method calls */
    //Permission policy that will be installed on peer1
    PermissionPolicy peer1Policy;
    peer1Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);
            peers[0].SetSecurityGroupId(sgid1Guid);
            //Get manager key
            KeyInfoNISTP256 sga1Key;
            PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(sga1Key));
            peers[0].SetKeyInfo(&sga1Key);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer1Policy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on peer2
    GUID128 sgid3Guid;
    PermissionPolicy peer2Policy;
    peer2Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);
            peers[0].SetSecurityGroupId(sgid3Guid);
            //Get manager key
            KeyInfoNISTP256 sga2Key;
            PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(sga2Key));
            peers[0].SetKeyInfo(&sga2Key);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_MODIFY);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer2Policy.SetAcls(1, acls);
    }

    {
        PermissionPolicy peer1DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer1.GetDefaultPolicy(peer1DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer1DefaultPolicy, peer1Policy);
    }
    {
        PermissionPolicy peer2DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer2.GetDefaultPolicy(peer2DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer2DefaultPolicy, peer2Policy);
    }

    EXPECT_EQ(ER_OK, sapWithPeer1.UpdatePolicy(peer1Policy));
    EXPECT_EQ(ER_OK, sapWithPeer1.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithPeer2.UpdatePolicy(peer2Policy));
    EXPECT_EQ(ER_OK, sapWithPeer2.SecureConnection(true));

    SessionOpts opts;
    SessionId peer1ToPeer2SessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, peer1ToPeer2SessionId, opts));
    qcc::String p1policyStr = "\n----Peer1 Policy-----\n" + peer1Policy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----Peer2 Policy-----\n" + peer2Policy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", peer1ToPeer2SessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    EXPECT_EQ(ER_OK, proxy.SecureConnection());

    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));

}


TEST_F(SecurityPolicyRulesTest, acl_policy_WITH_MEMBERSHIP_security_group_authority_does_not_match_sender)
{
    SecurityApplicationProxy sapWithPeer1(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithPeer2(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    BusAttachment busUsedAsSGA1("busUsedAsSGA1");

    EXPECT_EQ(ER_OK, busUsedAsSGA1.Start());
    EXPECT_EQ(ER_OK, busUsedAsSGA1.Connect());

    InMemoryKeyStoreListener busUsedAsCA1KeyStoreListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA1.RegisterKeyStoreListener(busUsedAsCA1KeyStoreListener));

    DefaultECDHEAuthListener busUsedAsCA1AuthListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA1.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &busUsedAsCA1AuthListener));

    BusAttachment busUsedAsSGA2("busUsedAsSGA2");

    EXPECT_EQ(ER_OK, busUsedAsSGA2.Start());
    EXPECT_EQ(ER_OK, busUsedAsSGA2.Connect());

    InMemoryKeyStoreListener busUsedAsCA2KeyStoreListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA2.RegisterKeyStoreListener(busUsedAsCA2KeyStoreListener));

    DefaultECDHEAuthListener busUsedAsCA2AuthListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA2.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &busUsedAsCA2AuthListener));

    BusAttachment busUsedAsSGA3("busUsedAsSGA3");
    EXPECT_EQ(ER_OK, busUsedAsSGA3.Start());
    EXPECT_EQ(ER_OK, busUsedAsSGA3.Connect());

    InMemoryKeyStoreListener busUsedAsCA3KeyStoreListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA3.RegisterKeyStoreListener(busUsedAsCA3KeyStoreListener));

    DefaultECDHEAuthListener busUsedAsCA3AuthListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA3.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &busUsedAsCA3AuthListener));

    KeyInfoNISTP256 peer1Key;
    EXPECT_EQ(ER_OK, SCBus.GetPermissionConfigurator().GetSigningPublicKey(peer1Key));
    KeyInfoNISTP256& peer2Key = TCKey;
    KeyInfoNISTP256 sga1Key;
    EXPECT_EQ(ER_OK, busUsedAsSGA1.GetPermissionConfigurator().GetSigningPublicKey(sga1Key));
    KeyInfoNISTP256 sga2Key;
    EXPECT_EQ(ER_OK, busUsedAsSGA2.GetPermissionConfigurator().GetSigningPublicKey(sga2Key));

    GUID128 peer1Guid;
    PermissionMgmtTestHelper::GetGUID(SCBus, peer1Guid);
    GUID128 peer2Guid;
    TCBus.GetGuid(peer2Guid);
    GUID128 sgid1Guid;
    PermissionMgmtTestHelper::GetGUID(busUsedAsSGA1, sgid1Guid);
    GUID128 sgid2Guid;
    PermissionMgmtTestHelper::GetGUID(busUsedAsSGA2, sgid2Guid);

    qcc::MembershipCertificate peer1MembershipCertificate[2];
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-1",
                                                                    managerBus,
                                                                    sgid2Guid.ToString(),
                                                                    sga2Key.GetPublicKey(),
                                                                    sgid2Guid,
                                                                    true,
                                                                    3600,
                                                                    peer1MembershipCertificate[1]
                                                                    ));
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-0",
                                                                    busUsedAsSGA2,
                                                                    peer1Guid.ToString(),
                                                                    peer1Key.GetPublicKey(),
                                                                    sgid2Guid,
                                                                    false,
                                                                    3600,
                                                                    peer1MembershipCertificate[0]
                                                                    ));
    EXPECT_EQ(ER_OK, sapWithPeer1.InstallMembership(peer1MembershipCertificate, 2));

    qcc::MembershipCertificate peer2MembershipCertificate[2];
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-1",
                                                                    managerBus,
                                                                    sgid1Guid.ToString(),
                                                                    sga1Key.GetPublicKey(),
                                                                    sgid1Guid,
                                                                    true,
                                                                    3600,
                                                                    peer2MembershipCertificate[1]
                                                                    ));
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-0",
                                                                    busUsedAsSGA1,
                                                                    peer2Guid.ToString(),
                                                                    peer2Key.GetPublicKey(),
                                                                    sgid1Guid,
                                                                    false,
                                                                    3600,
                                                                    peer2MembershipCertificate[0]
                                                                    ));
    EXPECT_EQ(ER_OK, sapWithPeer2.InstallMembership(peer2MembershipCertificate, 2));
    /* install permissions make method calls */
    //Permission policy that will be installed on peer1
    PermissionPolicy peer1Policy;
    peer1Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);
            peers[0].SetSecurityGroupId(sgid1Guid);
            //Get manager key
            KeyInfoNISTP256 sga1Key;
            PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(sga1Key));
            peers[0].SetKeyInfo(&sga1Key);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer1Policy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on peer2
    PermissionPolicy peer2Policy;
    peer2Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);
            peers[0].SetSecurityGroupId(sgid2Guid);
            //Get manager key
            KeyInfoNISTP256 sga3Key;
            PermissionConfigurator& pcSGA3 = busUsedAsSGA3.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcSGA3.GetSigningPublicKey(sga3Key));
            peers[0].SetKeyInfo(&sga3Key);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_MODIFY);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer2Policy.SetAcls(1, acls);
    }

    {
        PermissionPolicy peer1DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer1.GetDefaultPolicy(peer1DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer1DefaultPolicy, peer1Policy);
    }
    {
        PermissionPolicy peer2DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer2.GetDefaultPolicy(peer2DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer2DefaultPolicy, peer2Policy);
    }

    EXPECT_EQ(ER_OK, sapWithPeer1.UpdatePolicy(peer1Policy));
    EXPECT_EQ(ER_OK, sapWithPeer1.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithPeer2.UpdatePolicy(peer2Policy));
    EXPECT_EQ(ER_OK, sapWithPeer2.SecureConnection(true));

    SessionOpts opts;
    SessionId peer1ToPeer2SessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, peer1ToPeer2SessionId, opts));
    qcc::String p1policyStr = "\n----Peer1 Policy-----\n" + peer1Policy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----Peer2 Policy-----\n" + peer2Policy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", peer1ToPeer2SessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    EXPECT_EQ(ER_OK, proxy.SecureConnection());

    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));

}

TEST_F(SecurityPolicyRulesTest, acl_policy_WITH_MEMBERSHIP_security_group_id_does_not_match_receiver)
{
    SecurityApplicationProxy sapWithPeer1(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithPeer2(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    BusAttachment busUsedAsSGA1("busUsedAsSGA1");
    BusAttachment busUsedAsSGA2("busUsedAsSGA2");

    EXPECT_EQ(ER_OK, busUsedAsSGA1.Start());
    EXPECT_EQ(ER_OK, busUsedAsSGA1.Connect());
    EXPECT_EQ(ER_OK, busUsedAsSGA2.Start());
    EXPECT_EQ(ER_OK, busUsedAsSGA2.Connect());

    InMemoryKeyStoreListener busUsedAsCA1KeyStoreListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA1.RegisterKeyStoreListener(busUsedAsCA1KeyStoreListener));
    InMemoryKeyStoreListener busUsedAsCA2KeyStoreListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA2.RegisterKeyStoreListener(busUsedAsCA2KeyStoreListener));

    DefaultECDHEAuthListener busUsedAsCA1AuthListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA1.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &busUsedAsCA1AuthListener));
    DefaultECDHEAuthListener busUsedAsCA2AuthListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA2.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &busUsedAsCA2AuthListener));

    KeyInfoNISTP256 peer1Key;
    EXPECT_EQ(ER_OK, SCBus.GetPermissionConfigurator().GetSigningPublicKey(peer1Key));
    KeyInfoNISTP256& peer2Key = TCKey;
    KeyInfoNISTP256 sga1Key;
    EXPECT_EQ(ER_OK, busUsedAsSGA1.GetPermissionConfigurator().GetSigningPublicKey(sga1Key));
    KeyInfoNISTP256 sga2Key;
    EXPECT_EQ(ER_OK, busUsedAsSGA2.GetPermissionConfigurator().GetSigningPublicKey(sga2Key));

    GUID128 peer1Guid;
    PermissionMgmtTestHelper::GetGUID(SCBus, peer1Guid);
    GUID128 peer2Guid;
    TCBus.GetGuid(peer2Guid);
    GUID128 sgid1Guid;
    PermissionMgmtTestHelper::GetGUID(busUsedAsSGA1, sgid1Guid);
    GUID128 sgid2Guid;
    PermissionMgmtTestHelper::GetGUID(busUsedAsSGA2, sgid2Guid);

    qcc::MembershipCertificate peer1MembershipCertificate[2];
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-1",
                                                                    managerBus,
                                                                    sgid2Guid.ToString(),
                                                                    sga2Key.GetPublicKey(),
                                                                    sgid2Guid,
                                                                    true,
                                                                    3600,
                                                                    peer1MembershipCertificate[1]
                                                                    ));
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-0",
                                                                    busUsedAsSGA2,
                                                                    peer1Guid.ToString(),
                                                                    peer1Key.GetPublicKey(),
                                                                    sgid2Guid,
                                                                    false,
                                                                    3600,
                                                                    peer1MembershipCertificate[0]
                                                                    ));
    EXPECT_EQ(ER_OK, sapWithPeer1.InstallMembership(peer1MembershipCertificate, 2));

    qcc::MembershipCertificate peer2MembershipCertificate[2];
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-1",
                                                                    managerBus,
                                                                    sgid1Guid.ToString(),
                                                                    sga1Key.GetPublicKey(),
                                                                    sgid1Guid,
                                                                    true,
                                                                    3600,
                                                                    peer2MembershipCertificate[1]
                                                                    ));
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-0",
                                                                    busUsedAsSGA1,
                                                                    peer2Guid.ToString(),
                                                                    peer2Key.GetPublicKey(),
                                                                    sgid1Guid,
                                                                    false,
                                                                    3600,
                                                                    peer2MembershipCertificate[0]
                                                                    ));
    EXPECT_EQ(ER_OK, sapWithPeer2.InstallMembership(peer2MembershipCertificate, 2));
    /* install permissions make method calls */

    GUID128 sgid3Guid;

    //Permission policy that will be installed on peer1
    PermissionPolicy peer1Policy;
    peer1Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);
            peers[0].SetSecurityGroupId(sgid3Guid);
            //Get manager key
            KeyInfoNISTP256 sga1Key;
            PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(sga1Key));
            peers[0].SetKeyInfo(&sga1Key);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer1Policy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on peer2
    PermissionPolicy peer2Policy;
    peer2Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);
            peers[0].SetSecurityGroupId(sgid2Guid);
            //Get manager key
            KeyInfoNISTP256 sga2Key;
            PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(sga2Key));
            peers[0].SetKeyInfo(&sga2Key);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_MODIFY);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer2Policy.SetAcls(1, acls);
    }

    {
        PermissionPolicy peer1DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer1.GetDefaultPolicy(peer1DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer1DefaultPolicy, peer1Policy);
    }
    {
        PermissionPolicy peer2DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer2.GetDefaultPolicy(peer2DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer2DefaultPolicy, peer2Policy);
    }

    EXPECT_EQ(ER_OK, sapWithPeer1.UpdatePolicy(peer1Policy));
    EXPECT_EQ(ER_OK, sapWithPeer1.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithPeer2.UpdatePolicy(peer2Policy));
    EXPECT_EQ(ER_OK, sapWithPeer2.SecureConnection(true));

    SessionOpts opts;
    SessionId peer1ToPeer2SessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, peer1ToPeer2SessionId, opts));
    qcc::String p1policyStr = "\n----Peer1 Policy-----\n" + peer1Policy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----Peer2 Policy-----\n" + peer2Policy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", peer1ToPeer2SessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    EXPECT_EQ(ER_OK, proxy.SecureConnection(true));

    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
}

TEST_F(SecurityPolicyRulesTest, acl_policy_WITH_MEMBERSHIP_security_group_authority_does_not_match_receiver)
{
    SecurityApplicationProxy sapWithPeer1(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithPeer2(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    BusAttachment busUsedAsSGA1("busUsedAsSGA1");

    EXPECT_EQ(ER_OK, busUsedAsSGA1.Start());
    EXPECT_EQ(ER_OK, busUsedAsSGA1.Connect());

    InMemoryKeyStoreListener busUsedAsCA1KeyStoreListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA1.RegisterKeyStoreListener(busUsedAsCA1KeyStoreListener));

    DefaultECDHEAuthListener busUsedAsCA1AuthListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA1.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &busUsedAsCA1AuthListener));

    BusAttachment busUsedAsSGA2("busUsedAsSGA2");

    EXPECT_EQ(ER_OK, busUsedAsSGA2.Start());
    EXPECT_EQ(ER_OK, busUsedAsSGA2.Connect());

    InMemoryKeyStoreListener busUsedAsCA2KeyStoreListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA2.RegisterKeyStoreListener(busUsedAsCA2KeyStoreListener));

    DefaultECDHEAuthListener busUsedAsCA2AuthListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA2.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &busUsedAsCA2AuthListener));

    BusAttachment busUsedAsSGA3("busUsedAsSGA3");
    EXPECT_EQ(ER_OK, busUsedAsSGA3.Start());
    EXPECT_EQ(ER_OK, busUsedAsSGA3.Connect());

    InMemoryKeyStoreListener busUsedAsCA3KeyStoreListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA3.RegisterKeyStoreListener(busUsedAsCA3KeyStoreListener));

    DefaultECDHEAuthListener busUsedAsCA3AuthListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA3.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &busUsedAsCA3AuthListener));

    KeyInfoNISTP256 peer1Key;
    EXPECT_EQ(ER_OK, SCBus.GetPermissionConfigurator().GetSigningPublicKey(peer1Key));
    KeyInfoNISTP256& peer2Key = TCKey;
    KeyInfoNISTP256 sga1Key;
    EXPECT_EQ(ER_OK, busUsedAsSGA1.GetPermissionConfigurator().GetSigningPublicKey(sga1Key));
    KeyInfoNISTP256 sga2Key;
    EXPECT_EQ(ER_OK, busUsedAsSGA2.GetPermissionConfigurator().GetSigningPublicKey(sga2Key));

    GUID128 peer1Guid;
    PermissionMgmtTestHelper::GetGUID(SCBus, peer1Guid);
    GUID128 peer2Guid;
    TCBus.GetGuid(peer2Guid);
    GUID128 sgid1Guid;
    PermissionMgmtTestHelper::GetGUID(busUsedAsSGA1, sgid1Guid);
    GUID128 sgid2Guid;
    PermissionMgmtTestHelper::GetGUID(busUsedAsSGA2, sgid2Guid);

    qcc::MembershipCertificate peer1MembershipCertificate[2];
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-1",
                                                                    managerBus,
                                                                    sgid2Guid.ToString(),
                                                                    sga2Key.GetPublicKey(),
                                                                    sgid2Guid,
                                                                    true,
                                                                    3600,
                                                                    peer1MembershipCertificate[1]
                                                                    ));
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-0",
                                                                    busUsedAsSGA2,
                                                                    peer1Guid.ToString(),
                                                                    peer1Key.GetPublicKey(),
                                                                    sgid2Guid,
                                                                    false,
                                                                    3600,
                                                                    peer1MembershipCertificate[0]
                                                                    ));
    EXPECT_EQ(ER_OK, sapWithPeer1.InstallMembership(peer1MembershipCertificate, 2));

    qcc::MembershipCertificate peer2MembershipCertificate[2];
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-1",
                                                                    managerBus,
                                                                    sgid1Guid.ToString(),
                                                                    sga1Key.GetPublicKey(),
                                                                    sgid1Guid,
                                                                    true,
                                                                    3600,
                                                                    peer2MembershipCertificate[1]
                                                                    ));
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-0",
                                                                    busUsedAsSGA1,
                                                                    peer2Guid.ToString(),
                                                                    peer2Key.GetPublicKey(),
                                                                    sgid1Guid,
                                                                    false,
                                                                    3600,
                                                                    peer2MembershipCertificate[0]
                                                                    ));
    EXPECT_EQ(ER_OK, sapWithPeer2.InstallMembership(peer2MembershipCertificate, 2));
    /* install permissions make method calls */
    //Permission policy that will be installed on peer1
    PermissionPolicy peer1Policy;
    peer1Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);
            peers[0].SetSecurityGroupId(sgid1Guid);
            //Get manager key
            KeyInfoNISTP256 sga3Key;
            PermissionConfigurator& pcSGA3 = busUsedAsSGA3.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcSGA3.GetSigningPublicKey(sga3Key));
            peers[0].SetKeyInfo(&sga3Key);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer1Policy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on peer2
    PermissionPolicy peer2Policy;
    peer2Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);
            peers[0].SetSecurityGroupId(sgid2Guid);
            //Get manager key
            KeyInfoNISTP256 sga2Key;
            PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(sga2Key));
            peers[0].SetKeyInfo(&sga2Key);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_MODIFY);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer2Policy.SetAcls(1, acls);
    }

    {
        PermissionPolicy peer1DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer1.GetDefaultPolicy(peer1DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer1DefaultPolicy, peer1Policy);
    }
    {
        PermissionPolicy peer2DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer2.GetDefaultPolicy(peer2DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer2DefaultPolicy, peer2Policy);
    }

    EXPECT_EQ(ER_OK, sapWithPeer1.UpdatePolicy(peer1Policy));
    EXPECT_EQ(ER_OK, sapWithPeer1.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithPeer2.UpdatePolicy(peer2Policy));
    EXPECT_EQ(ER_OK, sapWithPeer2.SecureConnection(true));

    SessionOpts opts;
    SessionId peer1ToPeer2SessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, peer1ToPeer2SessionId, opts));
    qcc::String p1policyStr = "\n----Peer1 Policy-----\n" + peer1Policy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----Peer2 Policy-----\n" + peer2Policy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", peer1ToPeer2SessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    EXPECT_EQ(ER_OK, proxy.SecureConnection());

    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
}

TEST_F(SecurityPolicyRulesTest, acl_policy_WITH_MEMBERSHIP_membership_not_present_receiver)
{
    SecurityApplicationProxy sapWithPeer1(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithPeer2(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    BusAttachment busUsedAsSGA1("busUsedAsSGA1");
    BusAttachment busUsedAsSGA2("busUsedAsSGA2");

    EXPECT_EQ(ER_OK, busUsedAsSGA1.Start());
    EXPECT_EQ(ER_OK, busUsedAsSGA1.Connect());
    EXPECT_EQ(ER_OK, busUsedAsSGA2.Start());
    EXPECT_EQ(ER_OK, busUsedAsSGA2.Connect());

    InMemoryKeyStoreListener busUsedAsCA1KeyStoreListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA1.RegisterKeyStoreListener(busUsedAsCA1KeyStoreListener));
    InMemoryKeyStoreListener busUsedAsCA2KeyStoreListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA2.RegisterKeyStoreListener(busUsedAsCA2KeyStoreListener));

    DefaultECDHEAuthListener busUsedAsCA1AuthListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA1.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &busUsedAsCA1AuthListener));
    DefaultECDHEAuthListener busUsedAsCA2AuthListener;
    EXPECT_EQ(ER_OK, busUsedAsSGA2.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &busUsedAsCA2AuthListener));

    KeyInfoNISTP256 peer1Key;
    EXPECT_EQ(ER_OK, SCBus.GetPermissionConfigurator().GetSigningPublicKey(peer1Key));
    //KeyInfoNISTP256& peer2Key = TCKey;
    KeyInfoNISTP256 sga1Key;
    EXPECT_EQ(ER_OK, busUsedAsSGA1.GetPermissionConfigurator().GetSigningPublicKey(sga1Key));
    KeyInfoNISTP256 sga2Key;
    EXPECT_EQ(ER_OK, busUsedAsSGA2.GetPermissionConfigurator().GetSigningPublicKey(sga2Key));

    GUID128 peer1Guid;
    PermissionMgmtTestHelper::GetGUID(SCBus, peer1Guid);
    GUID128 peer2Guid;
    TCBus.GetGuid(peer2Guid);
    GUID128 sgid1Guid;
    PermissionMgmtTestHelper::GetGUID(busUsedAsSGA1, sgid1Guid);
    GUID128 sgid2Guid;
    PermissionMgmtTestHelper::GetGUID(busUsedAsSGA2, sgid2Guid);

    qcc::MembershipCertificate peer1MembershipCertificate[2];
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-1",
                                                                    managerBus,
                                                                    sgid2Guid.ToString(),
                                                                    sga2Key.GetPublicKey(),
                                                                    sgid2Guid,
                                                                    true,
                                                                    3600,
                                                                    peer1MembershipCertificate[1]
                                                                    ));
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2-0",
                                                                    busUsedAsSGA2,
                                                                    peer1Guid.ToString(),
                                                                    peer1Key.GetPublicKey(),
                                                                    sgid2Guid,
                                                                    false,
                                                                    3600,
                                                                    peer1MembershipCertificate[0]
                                                                    ));
    EXPECT_EQ(ER_OK, sapWithPeer1.InstallMembership(peer1MembershipCertificate, 2));

    /* install permissions make method calls */
    //Permission policy that will be installed on peer1
    PermissionPolicy peer1Policy;
    peer1Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);
            peers[0].SetSecurityGroupId(sgid1Guid);
            //Get manager key
            KeyInfoNISTP256 sga1Key;
            PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(sga1Key));
            peers[0].SetKeyInfo(&sga1Key);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer1Policy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on peer2
    PermissionPolicy peer2Policy;
    peer2Policy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);
            peers[0].SetSecurityGroupId(sgid2Guid);
            //Get manager key
            KeyInfoNISTP256 sga2Key;
            PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(sga2Key));
            peers[0].SetKeyInfo(&sga2Key);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_MODIFY);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        peer2Policy.SetAcls(1, acls);
    }

    {
        PermissionPolicy peer1DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer1.GetDefaultPolicy(peer1DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer1DefaultPolicy, peer1Policy);
    }
    {
        PermissionPolicy peer2DefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithPeer2.GetDefaultPolicy(peer2DefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(peer2DefaultPolicy, peer2Policy);
    }

    EXPECT_EQ(ER_OK, sapWithPeer1.UpdatePolicy(peer1Policy));
    EXPECT_EQ(ER_OK, sapWithPeer1.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithPeer2.UpdatePolicy(peer2Policy));
    EXPECT_EQ(ER_OK, sapWithPeer2.SecureConnection(true));

    SessionOpts opts;
    SessionId peer1ToPeer2SessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, peer1ToPeer2SessionId, opts));
    qcc::String p1policyStr = "\n----Peer1 Policy-----\n" + peer1Policy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----Peer2 Policy-----\n" + peer2Policy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", peer1ToPeer2SessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;
    EXPECT_EQ(ER_OK, proxy.SecureConnection());

    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));

}



/**
 * Purpose:
 * Method call is successful between two peers both of whom have a local policy
 * with WITH_PUBLIC_KEY peer type. The public key for this peer type is the
 * public key of each of the peers.
 *
 * Setup:
 * Peer 1 has a local policy WITH_PUBLIC_KEY Peer Type with public key of Peer 2.
 * Peer 2 has a local policy WITH_PUBLIC_KEY Peer Type with public key of Peer 1.
 * Both peers implement rules that allows method call.
 * The secure session is ECDHE_ECDSA based.
 * A makes a method call to B.
 *
 * verification:
 * Peers authentication are sucecssful.
 * Method call is successful.
 */
TEST_F(SecurityPolicyRulesTest, acl_with_public_key_method_call_should_pass_SC)
{
    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public Key of TC
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
            peers[0].SetKeyInfo(&TCKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public key of SC
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
            //Get manager key
            KeyInfoNISTP256 SCKey;
            PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));
            peers[0].SetKeyInfo(&SCKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_MODIFY);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    qcc::String p1policyStr = "\n----SC Policy-----\n" + SCPolicy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----TC Policy-----\n" + TCPolicy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_OK, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));
    char* echoReply;
    replyMsg->GetArg(0)->Get("s", &echoReply);
    EXPECT_STREQ("String that should be Echoed back.", echoReply);

    /* clean up */
}

TEST_F(SecurityPolicyRulesTest, acl_with_public_key_method_call_should_pass_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public Key of SC
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
            KeyInfoNISTP256 SCKey;
            PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));
            peers[0].SetKeyInfo(&SCKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public key of TC
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
            peers[0].SetKeyInfo(&TCKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_MODIFY);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    SessionOpts opts;
    SessionId TCToSCSessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));
    qcc::String p1policyStr = "\n----TC Policy-----\n" + TCPolicy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----SC Policy-----\n" + SCPolicy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    // Verify Method call
    const char* s = "String that should be Echoed back.";
    EXPECT_EQ(ER_OK, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));
    EXPECT_STREQ(s, TCBus.GetResponse());

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/**
 * Purpose:
 * Method call is not successful if the public key in the policy of the receiver
 * does not match with that of the remote peer (sender).
 *
 * Setup:
 * Peer 1 has a local policy with WITH_PUBLIC_KEY Peer Type with public key of Peer 2.
 * Peer 2 has a local policy with WITH_PUBLIC_KEY Peer Type with a public key NOT of Peer 1 (managerBus).
 * Both peers implement rules that allows method call.
 * The secure session is ECDHE_ECDSA based.
 * A makes a method call to B.
 *
 * verification:
 * Peers authentication are sucecssful.
 * Method call is sent but cannot be received.
 */
TEST_F(SecurityPolicyRulesTest, acl_with_public_key_recieving_peer_has_incorrect_public_key_SC)
{
    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public Key of TC
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
            peers[0].SetKeyInfo(&TCKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public key of managerBus
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
            //Get manager key
            KeyInfoNISTP256 managerKey;
            PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(managerKey));
            peers[0].SetKeyInfo(&managerKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_MODIFY);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    qcc::String p1policyStr = "\n----SC Policy-----\n" + SCPolicy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----TC Policy-----\n" + TCPolicy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));

    /* clean up */
}

TEST_F(SecurityPolicyRulesTest, acl_with_public_key_recieving_peer_has_incorrect_public_key_TC)
{
    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public Key of SC
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
            KeyInfoNISTP256 SCKey;
            PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));
            peers[0].SetKeyInfo(&SCKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public key of managerBus
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
            //Get manager key
            KeyInfoNISTP256 managerKey;
            PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(managerKey));
            peers[0].SetKeyInfo(&managerKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_MODIFY);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    SessionOpts opts;
    SessionId TCToSCSessionId;
    ASSERT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));
    qcc::String p1policyStr = "\n----TC Policy-----\n" + TCPolicy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----SC Policy-----\n" + SCPolicy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    // Verify Method call
    const char* s = "String that should be Echoed back.";
    EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));
    EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}

/**
 * Purpose:
 * Method call is not successful if the public key in the policy of the sender
 * does not match with that of the remote peer (receiver).
 *
 * Setup:
 * Peer 1 has a local policy with WITH_PUBLIC_KEY Peer Type with a public key NOT of Peer2 (managerBus).
 * Peer 2 has a local policy with WITH_PUBLIC_KEY Peer Type with public key of Peer 1.
 * Both peers implement rules that allows method call.
 * The secure session is ECDHE_ECDSA based.
 * A makes a method call to B.
 *
 * verification:
 * Peers authentication are successful.
 * Method call cannot be sent.
 */
TEST_F(SecurityPolicyRulesTest, acl_with_public_key_sending_peer_has_incorrect_public_key_SC)
{
    /* install permissions make method calls */
    //Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public Key of managerBus
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
            KeyInfoNISTP256 managerKey;
            PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(managerKey));
            peers[0].SetKeyInfo(&managerKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public key of SC
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
            //Get manager key
            KeyInfoNISTP256 SCKey;
            PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));
            peers[0].SetKeyInfo(&SCKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_MODIFY);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }
    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    SessionOpts opts;
    SessionId SCToTCSessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SCToTCSessionId, opts));
    qcc::String p1policyStr = "\n----SC Policy-----\n" + SCPolicy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----TC Policy-----\n" + TCPolicy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    /* Create the ProxyBusObject and call the Echo method on the interface */
    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test", SCToTCSessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName)) << interface.c_str() << "\n" << interfaceName;

    MsgArg arg("s", "String that should be Echoed back.");
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.MethodCall(interfaceName, "Echo", &arg, static_cast<size_t>(1), replyMsg));

    /* clean up */
}

TEST_F(SecurityPolicyRulesTest, acl_with_public_key_sending_peer_has_incorrect_public_key_TC)
{

    PolicyRulesTestBusObject SCBusObject(SCBus, "/test", interfaceName);
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject));

    /* install permissions make method calls */
    //Permission policy that will be installed on TC
    PermissionPolicy TCPolicy;
    TCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public Key of managerBus
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
            KeyInfoNISTP256 managerKey;
            PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
            EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(managerKey));
            peers[0].SetKeyInfo(&managerKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/test");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        TCPolicy.SetAcls(1, acls);
    }

    // Permission policy that will be installed on SC
    PermissionPolicy SCPolicy;
    SCPolicy.SetVersion(1);
    {
        PermissionPolicy::Acl acls[1];
        {
            // Peer type: WITH_PUBLICKEY, Public key of TC
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
            peers[0].SetKeyInfo(&TCKey);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("*");
            rules[0].SetInterfaceName(interfaceName);
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("Echo",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_MODIFY);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        SCPolicy.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, TCPolicy);
    }
    {
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(TCPolicy));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
    EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));

    SessionOpts opts;
    SessionId TCToSCSessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, TCToSCSessionId));
    qcc::String p1policyStr = "\n----TC Policy-----\n" + TCPolicy.ToString();
    SCOPED_TRACE(p1policyStr.c_str());
    qcc::String p2policyStr = "\n----SC Policy-----\n" + SCPolicy.ToString();
    SCOPED_TRACE(p2policyStr.c_str());

    // Verify Method call
    const char* s = "String that should be Echoed back.";
    EXPECT_EQ(ER_PERMISSION_DENIED, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_ECHO, s));

    /* clean up */
    SCBus.UnregisterBusObject(SCBusObject);
}
