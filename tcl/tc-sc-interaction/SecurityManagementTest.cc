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

#include "PermissionMgmtObj.h"
#include "PermissionMgmtTest.h"
#include "InMemoryKeyStore.h"

using namespace ajn;
using namespace qcc;
using namespace std;
/*
 * The unit test use many busy wait loops.  The busy wait loops were chosen
 * over thread sleeps because of the ease of understanding the busy wait loops.
 * Also busy wait loops do not require any platform specific threading code.
 */
#define WAIT_MSECS 5
#define TEN_MINS 600 // 600 secs is 10 mins

class TCManagementAttachment : public TCBusAttachment {
  public:
    TCManagementAttachment(const char* name) : TCBusAttachment(name) { }
};

class SecurityManagement_ApplicationStateListener : public ApplicationStateListener {
  public:
    SecurityManagement_ApplicationStateListener() : stateMap() { }

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

class SecurityManagementTestSessionPortListener : public SessionPortListener {
  public:
    virtual bool AcceptSessionJoiner(SessionPort sessionPort, const char* joiner, const SessionOpts& opts) {
        QCC_UNUSED(sessionPort);
        QCC_UNUSED(joiner);
        QCC_UNUSED(opts);
        return true;
    }
};

class SecurityManagementTestBusObject : public BusObject {
  public:
    SecurityManagementTestBusObject(BusAttachment& bus, const char* path, const char* interfaceName, bool announce = true)
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
            { iface->GetMember("Echo"), static_cast<MessageReceiver::MethodHandler>(&SecurityManagementTestBusObject::Echo) }
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

static void GetAppPublicKey(BusAttachment& bus, ECCPublicKey& publicKey)
{
    KeyInfoNISTP256 keyInfo;
    bus.GetPermissionConfigurator().GetSigningPublicKey(keyInfo);
    publicKey = *keyInfo.GetPublicKey();
}

class SecurityManagementPolicyTest : public testing::Test {
  public:
    SecurityManagementPolicyTest() :
        managerBus("SecurityPolicyRulesManager"),
        TCBus("SecurityPolicyRulesTC"),
        SC1Bus("SecurityPolicyRulesSC1"),
        SC2Bus("SecurityPolicyRulesSC2"),
        managerSessionPort(42),
        TCSessionPort(42),
        SC1SessionPort(42),
        managerToManagerSessionId(0),
        managerToTCSessionId(0),
        managerToSC1SessionId(0),
        interfaceName("org.allseen.test.SecurityApplication.rules"),
        managerAuthListener(NULL),
        SC1AuthListener(NULL),
        SC2AuthListener(NULL),
        appStateListener()
    {
    }

    virtual void SetUp() {
        EXPECT_EQ(ER_OK, managerBus.Start());
        EXPECT_EQ(ER_OK, managerBus.Connect());
        EXPECT_EQ(ER_OK, SC1Bus.Start());
        EXPECT_EQ(ER_OK, SC1Bus.Connect());
        EXPECT_EQ(ER_OK, SC2Bus.Start());
        EXPECT_EQ(ER_OK, SC2Bus.Connect());

        // Register in memory keystore listeners
        EXPECT_EQ(ER_OK, managerBus.RegisterKeyStoreListener(managerKeyStoreListener));
        EXPECT_EQ(ER_OK, SC1Bus.RegisterKeyStoreListener(SC1KeyStoreListener));
        EXPECT_EQ(ER_OK, SC2Bus.RegisterKeyStoreListener(SC2KeyStoreListener));

        // To avoid cross-talk, i.e. thin leaf node connect to unintended
        // routing nodes, generate and advertise a random routing node prefix.
        qcc::String routingNodePrefix = "test.rnPrefix.randhex" +
                                        qcc::RandHexString(64);
        qcc::String advertisingPrefix = "quiet@" + routingNodePrefix;
        ASSERT_EQ(ER_OK, managerBus.AdvertiseName(advertisingPrefix.c_str(), ajn::TRANSPORT_ANY));

        TCBus.Connect(routingNodePrefix.c_str());
        TCBus.Start();

        managerAuthListener = new DefaultECDHEAuthListener();
        SC1AuthListener = new DefaultECDHEAuthListener();
        SC2AuthListener = new DefaultECDHEAuthListener();

        EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", managerAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA"));
        EXPECT_EQ(ER_OK, SC1Bus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", SC1AuthListener));
        EXPECT_EQ(ER_OK, SC2Bus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", SC2AuthListener));

        PermissionMgmtTestHelper::GetGUID(managerBus, managerGuid);
        SetManifestTemplate(managerBus);
        SetManifestTemplate(SC1Bus);
        SetManifestTemplate(SC2Bus);
        TCBus.SetApplicationState(APP_STATE_CLAIMABLE);

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
        EXPECT_EQ(ER_OK, SC1Bus.CreateInterfacesFromXml(interface.c_str()));
        EXPECT_EQ(ER_OK, SC2Bus.CreateInterfacesFromXml(interface.c_str()));

        SessionOpts opts1;
        EXPECT_EQ(ER_OK, managerBus.BindSessionPort(managerSessionPort, opts1, managerSessionPortListener));

        SessionOpts opts2;
        EXPECT_EQ(ER_OK, TCBus.BindSessionPort(TCSessionPort));

        SessionOpts opts3;
        EXPECT_EQ(ER_OK, SC1Bus.BindSessionPort(SC1SessionPort, opts3, SC1SessionPortListener));

        EXPECT_EQ(ER_OK, managerBus.JoinSession(managerBus.GetUniqueName().c_str(), managerSessionPort, NULL, managerToManagerSessionId, opts1));
        EXPECT_EQ(ER_OK, managerBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, managerToTCSessionId, opts2));
        EXPECT_EQ(ER_OK, managerBus.JoinSession(SC1Bus.GetUniqueName().c_str(), SC1SessionPort, NULL, managerToSC1SessionId, opts3));

        SecurityApplicationProxy sapWithManager(managerBus, managerBus.GetUniqueName().c_str(), managerToManagerSessionId);
        PermissionConfigurator::ApplicationState applicationStateManager;
        EXPECT_EQ(ER_OK, sapWithManager.GetApplicationState(applicationStateManager));
        EXPECT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateManager);

        SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
        PermissionConfigurator::ApplicationState applicationStateTC;
        EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
        EXPECT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateTC);

        SecurityApplicationProxy sapWithSC1(managerBus, SC1Bus.GetUniqueName().c_str(), managerToSC1SessionId);
        PermissionConfigurator::ApplicationState applicationStateSC1;
        EXPECT_EQ(ER_OK, sapWithSC1.GetApplicationState(applicationStateSC1));
        EXPECT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateSC1);

		EXPECT_EQ(ER_OK, managerBus.RegisterApplicationStateListener(appStateListener));

        // All Inclusive manifest
        const size_t manifestSize = 1;
        PermissionPolicy::Rule manifest[manifestSize];
        {
            PermissionPolicy::Rule::Member member[1];
            member[0].Set("*",
                          PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                          PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                          PermissionPolicy::Rule::Member::ACTION_MODIFY |
                          PermissionPolicy::Rule::Member::ACTION_OBSERVE);
            manifest[0].SetObjPath("*");
            manifest[0].SetInterfaceName("*");
            manifest[0].SetMembers(1, member);
        }

        //Get manager key
        KeyInfoNISTP256 managerKey;
        PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(managerKey));

        //Create TC key
        EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));
        TCKey.SetPublicKey(&TCPublicKey);

        //Create SC1 key
        KeyInfoNISTP256 SC1Key;
        PermissionConfigurator& pcSC1 = SC1Bus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcSC1.GetSigningPublicKey(SC1Key));

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
        GetAppPublicKey(managerBus, managerPublicKey);
        ASSERT_EQ(*managerKey.GetPublicKey(), managerPublicKey);

        ASSERT_EQ(PermissionConfigurator::ApplicationState::CLAIMED, appStateListener.stateMap[managerBus.GetUniqueName()]);

        //Create TC identityCert
        IdentityCertificate identityCertChainTC[certChainSize];


        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(managerBus,
                                                                      "0",
                                                                      managerGuid.ToString(),
                                                                      TCKey.GetPublicKey(),
                                                                      "TCAlias",
                                                                      3600,
                                                                      identityCertChainTC[0],
                                                                      digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

        //Manager claims Peers
        EXPECT_EQ(ER_OK, sapWithTC.Claim(managerKey,
                                            managerGuid,
                                            managerKey,
                                            identityCertChainTC, certChainSize,
                                            manifest, manifestSize));

        for (int msec = 0; msec < 10000; msec += WAIT_MSECS) {
            if (appStateListener.isClaimed(TCBus.GetUniqueName())) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }

        ASSERT_EQ(PermissionConfigurator::ApplicationState::CLAIMED, appStateListener.stateMap[TCBus.GetUniqueName()]);

        //Create SC1 identityCert
        IdentityCertificate identityCertChainSC1[certChainSize];


        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(managerBus,
                                                                      "0",
                                                                      managerGuid.ToString(),
                                                                      SC1Key.GetPublicKey(),
                                                                      "SC1Alias",
                                                                      3600,
                                                                      identityCertChainSC1[0],
                                                                      digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";
        EXPECT_EQ(ER_OK, sapWithSC1.Claim(managerKey,
                                            managerGuid,
                                            managerKey,
                                            identityCertChainSC1, certChainSize,
                                            manifest, manifestSize));

        for (int msec = 0; msec < 10000; msec += WAIT_MSECS) {
            if (appStateListener.isClaimed(SC1Bus.GetUniqueName())) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }


        ASSERT_EQ(PermissionConfigurator::ApplicationState::CLAIMED, appStateListener.stateMap[TCBus.GetUniqueName()]);

        //Change the managerBus so it only uses ECDHE_ECDSA
        EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", managerAuthListener, NULL, true));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
        EXPECT_EQ(ER_OK, SC1Bus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", managerAuthListener));

    }

    virtual void TearDown() {
        TCBus.Stop();
        TCBus.Join();
        managerBus.Stop();
        managerBus.Join();
        SC1Bus.Stop();
        SC1Bus.Join();
        SC2Bus.Stop();
        SC2Bus.Join();

        delete managerAuthListener;
        delete SC1AuthListener;
        delete SC2AuthListener;
    }


    void InstallMembershipOnManager() {
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
                                                                        true,
                                                                        3600,
                                                                        managerMembershipCertificate[0]
                                                                        ));
        SecurityApplicationProxy sapWithManagerBus(managerBus, managerBus.GetUniqueName().c_str());
        EXPECT_EQ(ER_OK, sapWithManagerBus.InstallMembership(managerMembershipCertificate, 1));
    }


    void InstallMembershipOnTC() {
        String membershipSerial = "1";
        qcc::MembershipCertificate TCMembershipCertificate[1];
        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert(membershipSerial,
                                                                        managerBus,
                                                                        TCBus.GetUniqueName(),
                                                                        TCKey.GetPublicKey(),
                                                                        managerGuid,
                                                                        false,
                                                                        3600,
                                                                        TCMembershipCertificate[0]
                                                                        ));
        SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
        EXPECT_EQ(ER_OK, sapWithTC.InstallMembership(TCMembershipCertificate, 1));
    }


    void InstallMembershipOnSC1() {
        //Create SC1 key
        KeyInfoNISTP256 SC1Key;
        PermissionConfigurator& pcSC1 = SC1Bus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcSC1.GetSigningPublicKey(SC1Key));

        String membershipSerial = "1";
        qcc::MembershipCertificate SC1MembershipCertificate[1];
        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert(membershipSerial,
                                                                        managerBus,
                                                                        SC1Bus.GetUniqueName(),
                                                                        SC1Key.GetPublicKey(),
                                                                        managerGuid,
                                                                        false,
                                                                        3600,
                                                                        SC1MembershipCertificate[0]
                                                                        ));
        SecurityApplicationProxy sapWithSC1(managerBus, SC1Bus.GetUniqueName().c_str(), managerToSC1SessionId);
        EXPECT_EQ(ER_OK, sapWithSC1.InstallMembership(SC1MembershipCertificate, 1));
    }

    void SetManifestTemplate(BusAttachment& bus)
    {
        // All Inclusive manifest template
        PermissionPolicy::Rule::Member member[1];
        member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        const size_t manifestSize = 1;
        PermissionPolicy::Rule manifestTemplate[manifestSize];
        manifestTemplate[0].SetObjPath("*");
        manifestTemplate[0].SetInterfaceName("*");
        manifestTemplate[0].SetMembers(1, member);
        EXPECT_EQ(ER_OK, bus.GetPermissionConfigurator().SetPermissionManifest(manifestTemplate, manifestSize));
    }

    static QStatus UpdatePolicyWithValuesFromDefaultPolicy(const PermissionPolicy& defaultPolicy,
                                                           PermissionPolicy& policy,
                                                           bool keepCAentry = true,
                                                           bool keepAdminGroupEntry = false,
                                                           bool keepInstallMembershipEntry = false);

    /*
     * this will create a Policy that will allow access to everything.
     * Many of the tests assume that a Bus is able to respond to method calls
     * The value of the policy is unimportant just that the bus is using security
     * and is responsive.
     *
     * DOES NOT add the CA entry from the default policy
     */
    static void CreatePermissivePolicy(PermissionPolicy& policy, uint32_t version);

    BusAttachment managerBus;
    TCManagementAttachment TCBus;
    BusAttachment SC1Bus;
    BusAttachment SC2Bus;

    SessionPort managerSessionPort;
    SessionPort TCSessionPort;
    SessionPort SC1SessionPort;

    SecurityManagementTestSessionPortListener managerSessionPortListener;
    SecurityManagementTestSessionPortListener SC1SessionPortListener;

    SessionId managerToManagerSessionId;
    SessionId managerToTCSessionId;
    SessionId managerToSC1SessionId;

    InMemoryKeyStoreListener managerKeyStoreListener;
    InMemoryKeyStoreListener SC1KeyStoreListener;
    InMemoryKeyStoreListener SC2KeyStoreListener;

    String interface;
    const char* interfaceName;
    DefaultECDHEAuthListener* managerAuthListener;
    DefaultECDHEAuthListener* SC1AuthListener;
    DefaultECDHEAuthListener* SC2AuthListener;

    SecurityManagement_ApplicationStateListener appStateListener;

    //Random GUID used for the SecurityManager
    GUID128 managerGuid;

    ECCPublicKey TCPublicKey;
    KeyInfoNISTP256 TCKey;
};

QStatus SecurityManagementPolicyTest::UpdatePolicyWithValuesFromDefaultPolicy(const PermissionPolicy& defaultPolicy,
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
        QCC_ASSERT(idx <= count);
        acls[idx++] = policy.GetAcls()[cnt];
    }

    policy.SetAcls(count, acls);
    delete [] acls;
    return ER_OK;
}

void SecurityManagementPolicyTest::CreatePermissivePolicy(PermissionPolicy& policy, uint32_t version) {
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

/*
 * Purpose:
 * Latest Policy to be installed should have a serial number greater than the
 * previous policy's serial number. Else, the previous policy should not be deleted.
 *
 * SetUp:
 * manager claims the peer1
 * manager creates a policy  (policy 1):
 * Serial number: 1234
 * ACL: ANY_TRUSTED
 * Rule1: Object Path=*, Interface=*, Member Name=*, Type=Method, Action mask:  PROVIDE
 *
 * manager calls UpdatePolicy on peer1.
 * manager calls GetProperty ("policy") on the peer1
 *
 * manager creates another policy  (policy 2):
 * Serial number: 1200
 * ACL: ALL
 * Rule1: Object Path=/abc, Interface=*, Member Name=*, Type=Method, Action mask:  PROVIDE
 * manager calls UpdatePolicy on peer1
 * manager calls GetProperty ("policy") on peer1.
 *
 * Verify:
 * UpdatePolicy (policy1) should succeed.
 * GetProperty ("Policy") should fetch policy 1.
 * Update policy ("Policy2") should fail with ER_POLICY_NOT_NEWER.
 * GetProperty("Policy") should still fetch policy1.
 */
TEST_F(SecurityManagementPolicyTest, UpdatePolicy_fails_if_version_not_newer)
{
    InstallMembershipOnManager();
    InstallMembershipOnTC();

    /*
     * creates a policy  (policy 1):
     * Serial number: 1234
     * ACL: ANY_TRUSTED
     * Rule1: Object Path=*, Interface=*, Member Name=*, Type=Method, Action mask:  PROVIDE
     */
    PermissionPolicy policy1;
    policy1.SetVersion(1234);
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
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        policy1.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, policy1, true, true);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(policy1));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    PermissionPolicy fetchedPolicy;
    EXPECT_EQ(ER_OK, sapWithTC.GetPolicy(fetchedPolicy));
    EXPECT_EQ(static_cast<uint32_t>(1234), fetchedPolicy.GetVersion());
    EXPECT_EQ(policy1.GetVersion(), fetchedPolicy.GetVersion());
    EXPECT_EQ(policy1, fetchedPolicy);

    /*
     * creates another policy  (policy 2):
     * Serial number: 1200
     * ACL: ALL
     * Rule1: Object Path=/abc, Interface=*, Member Name=*, Type=Method, Action mask:  PROVIDE
     * manager calls UpdatePolicy on TC
     * manager calls GetProperty ("policy") on TC.
     */
    PermissionPolicy policy2;
    policy2.SetVersion(1200);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ALL);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/abc");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        policy2.SetAcls(1, acls);
    }


    EXPECT_EQ(ER_POLICY_NOT_NEWER, sapWithTC.UpdatePolicy(policy2));

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, policy2, true, true);
    }

    EXPECT_EQ(ER_OK, sapWithTC.GetPolicy(fetchedPolicy));
    EXPECT_EQ(policy1.GetVersion(), fetchedPolicy.GetVersion());
    EXPECT_EQ(policy1, fetchedPolicy);
}

/*
 * Purpose:
 * New policy installed should override the older policy.
 *
 * SetUp:
 * manager claims the peer1
 *
 * manager creates a policy  (policy 1):
 * Serial number: 1234
 * ACL: ANY_TRUSTED
 * Rule1: Object Path=*, Interface=*, Member Name=*, Type=Method, Action mask:  PROVIDE
 *
 * manager calls UpdatePolicy on peer1
 * manager calls GetProperty ("policy") on peer1
 *
 * manager creates another policy  (policy 2):
 * Serial number: 1235
 * ACL: ALL
 * Rule1: Object Path=/abc, Interface=*, Member Name=*, Type=Method, Action mask:  PROVIDE
 *
 * manager calls UpdatePolicy on peer1
 * manager calls GetProperty ("policy") on peer1
 *
 * Verify:
 * UpdatePolicy (policy1) should succeed.
 * GetProperty ("Policy") should fetch policy 1.
 * Update policy ("Policy2") should succeed.
 * GetProperty("Policy") should still fetch policy2.
 */
TEST_F(SecurityManagementPolicyTest, UpdatePolicy_new_policy_should_override_older_policy)
{

    InstallMembershipOnManager();
    InstallMembershipOnTC();

    /*
     * manager creates a policy  (policy 1):
     * Serial number: 1234
     * ACL: ANY_TRUSTED
     * Rule1: Object Path=*, Interface=*, Member Name=*, Type=Method, Action mask:  PROVIDE
     */
    PermissionPolicy policy1;
    policy1.SetVersion(1234);
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
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        policy1.SetAcls(1, acls);
    }

    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, policy1, true, true);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(policy1));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    PermissionPolicy fetchedPolicy;
    EXPECT_EQ(ER_OK, sapWithTC.GetPolicy(fetchedPolicy));

    EXPECT_EQ(policy1.GetVersion(), fetchedPolicy.GetVersion());
    EXPECT_EQ(policy1, fetchedPolicy);

    /*
     * manager creates another policy  (policy 2):
     * Serial number: 1235
     * ACL: ALL
     * Rule1: Object Path=/abc, Interface=*, Member Name=*, Type=Method, Action mask:  PROVIDE
     */
    PermissionPolicy policy2;
    policy2.SetVersion(1235);
    {
        PermissionPolicy::Acl acls[1];
        {
            PermissionPolicy::Peer peers[1];
            peers[0].SetType(PermissionPolicy::Peer::PEER_ALL);
            acls[0].SetPeers(1, peers);
        }
        {
            PermissionPolicy::Rule rules[1];
            rules[0].SetObjPath("/abc");
            rules[0].SetInterfaceName("*");
            {
                PermissionPolicy::Rule::Member members[1];
                members[0].Set("*",
                               PermissionPolicy::Rule::Member::METHOD_CALL,
                               PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                rules[0].SetMembers(1, members);
            }
            acls[0].SetRules(1, rules);
        }
        policy2.SetAcls(1, acls);
    }

    {
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, policy2, true, true);
    }

    EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(policy2));
    EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));

    PermissionPolicy fetchedPolicy2;

    EXPECT_EQ(ER_OK, sapWithTC.GetPolicy(fetchedPolicy2));
    EXPECT_NE(policy1, fetchedPolicy2);
    EXPECT_EQ(policy2.GetVersion(), fetchedPolicy2.GetVersion());
    EXPECT_EQ(policy2, fetchedPolicy2);
}

/* these keys were generated by the unit test common/unit_test/CertificateECCTest.GenSelfSignECCX509CertForBBservice */
static const char ecdsaPrivateKeyPEM[] = {
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MDECAQEEIICSqj3zTadctmGnwyC/SXLioO39pB1MlCbNEX04hjeioAoGCCqGSM49\n"
    "AwEH\n"
    "-----END EC PRIVATE KEY-----"
};

static const char ecdsaCertChainX509PEM[] = {
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBWjCCAQGgAwIBAgIHMTAxMDEwMTAKBggqhkjOPQQDAjArMSkwJwYDVQQDDCAw\n"
    "ZTE5YWZhNzlhMjliMjMwNDcyMGJkNGY2ZDVlMWIxOTAeFw0xNTAyMjYyMTU1MjVa\n"
    "Fw0xNjAyMjYyMTU1MjVaMCsxKTAnBgNVBAMMIDZhYWM5MjQwNDNjYjc5NmQ2ZGIy\n"
    "NmRlYmRkMGM5OWJkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEP/HbYga30Afm\n"
    "0fB6g7KaB5Vr5CDyEkgmlif/PTsgwM2KKCMiAfcfto0+L1N0kvyAUgff6sLtTHU3\n"
    "IdHzyBmKP6MQMA4wDAYDVR0TBAUwAwEB/zAKBggqhkjOPQQDAgNHADBEAiAZmNVA\n"
    "m/H5EtJl/O9x0P4zt/UdrqiPg+gA+wm0yRY6KgIgetWANAE2otcrsj3ARZTY/aTI\n"
    "0GOQizWlQm8mpKaQ3uE=\n"
    "-----END CERTIFICATE-----"
};

class SecurityManagementPolicy2AuthListener : public AuthListener {

  public:
    SecurityManagementPolicy2AuthListener() : authenticationSuccessfull(false) {
    }

    QStatus RequestCredentialsAsync(const char* authMechanism, const char* authPeer, uint16_t authCount, const char* userId, uint16_t credMask, void* context)
    {
        QCC_UNUSED(userId);
        QCC_UNUSED(authCount);
        QCC_UNUSED(authPeer);
        Credentials creds;
        if (strcmp(authMechanism, "ALLJOYN_ECDHE_ECDSA") == 0) {
            if ((credMask& AuthListener::CRED_PRIVATE_KEY) == AuthListener::CRED_PRIVATE_KEY) {
                String pk(ecdsaPrivateKeyPEM, strlen(ecdsaPrivateKeyPEM));
                creds.SetPrivateKey(pk);
                //printf("AuthListener::RequestCredentials for key exchange %s sends DSA private key %s\n", authMechanism, pk.c_str());
            }
            if ((credMask& AuthListener::CRED_CERT_CHAIN) == AuthListener::CRED_CERT_CHAIN) {
                String cert(ecdsaCertChainX509PEM, strlen(ecdsaCertChainX509PEM));
                creds.SetCertChain(cert);
                //printf("AuthListener::RequestCredentials for key exchange %s sends DSA public cert %s\n", authMechanism, cert.c_str());
            }
            return RequestCredentialsResponse(context, true, creds);
        }
        return RequestCredentialsResponse(context, false, creds);
    }
    QStatus VerifyCredentialsAsync(const char* authMechanism, const char* authPeer, const Credentials& creds, void* context) {
        QCC_UNUSED(authPeer);
        if (strcmp(authMechanism, "ALLJOYN_ECDHE_ECDSA") == 0) {
            if (creds.IsSet(AuthListener::CRED_CERT_CHAIN)) {
                //printf("Verify\n%s\n", creds.GetCertChain().c_str());
                return VerifyCredentialsResponse(context, true);
            }
        }
        return VerifyCredentialsResponse(context, false);
    }

    void AuthenticationComplete(const char* authMechanism, const char* authPeer, bool success) {
        QCC_UNUSED(authMechanism);
        QCC_UNUSED(authPeer);
        QCC_UNUSED(success);
        if (success) {
            authenticationSuccessfull = true;
        }
    }

    void SecurityViolation(QStatus status, const Message& msg) {
        QCC_UNUSED(status);
        QCC_UNUSED(msg);
    }
    bool authenticationSuccessfull;

};


TEST_F(SecurityManagementPolicyTest, Update_identity_fails_on_digest_mismatch)
{
    SecurityApplicationProxy sapWithManager(managerBus, managerBus.GetUniqueName().c_str(), managerToManagerSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    SecurityApplicationProxy sapWithSC1(managerBus, SC1Bus.GetUniqueName().c_str(), managerToSC1SessionId);

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::METHOD_CALL, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    PermissionMgmtObj::GenerateManifestDigest(managerBus, manifest, 1, digest, Crypto_SHA256::DIGEST_SIZE);

    // Intentionally set the digest so that it does not match the one with the manifest above
    for (uint8_t i = 0; i < Crypto_SHA256::DIGEST_SIZE; i++) {
        digest[i] = 0;
    }
    uint8_t managerCN[] = { 1, 2, 3, 4 };
    uint8_t intermediateCN[] = { 5, 6, 7, 8 };
    uint8_t leafCN[] = { 9, 0, 1, 2 };

    //Create the CA cert
    qcc::IdentityCertificate caCert;
    caCert.SetSerial((uint8_t*)"1234", 5);
    caCert.SetIssuerCN(managerCN, 4);
    caCert.SetSubjectCN(managerCN, 4);
    CertificateX509::ValidPeriod validityCA;
    validityCA.validFrom = 1427404154;
    validityCA.validTo = 1427404154 + 630720000;
    caCert.SetValidity(&validityCA);
    caCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    KeyInfoNISTP256 managerPublicKey;
    PermissionConfigurator& permissionConfigurator = managerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(managerPublicKey));

    caCert.SetSubjectPublicKey(managerPublicKey.GetPublicKey());
    caCert.SetAlias("ca-cert-alias");
    caCert.SetCA(true);

    //sign the ca cert
    EXPECT_EQ(ER_OK, permissionConfigurator.SignCertificate(caCert));

    // Create the intermediate certificate using SC1
    qcc::IdentityCertificate SC1Cert;
    SC1Cert.SetSerial((uint8_t*)"5678", 5);
    SC1Cert.SetIssuerCN(managerCN, 4);
    SC1Cert.SetSubjectCN(intermediateCN, 4);
    CertificateX509::ValidPeriod validity;
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    SC1Cert.SetValidity(&validity);
    SC1Cert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    ECCPublicKey SC1PublicKey;
    GetAppPublicKey(SC1Bus, SC1PublicKey);

    SC1Cert.SetSubjectPublicKey(&SC1PublicKey);
    SC1Cert.SetAlias("intermediate-cert-alias");
    SC1Cert.SetCA(true);

    //sign the leaf cert
    EXPECT_EQ(ER_OK, permissionConfigurator.SignCertificate(SC1Cert));

    // Create the leaf certificate using SC1
    qcc::IdentityCertificate TCCert;
    TCCert.SetSerial((uint8_t*)"9123", 5);
    TCCert.SetIssuerCN(intermediateCN, 4);
    TCCert.SetSubjectCN(leafCN, 4);
    TCCert.SetValidity(&validity);
    TCCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    TCCert.SetSubjectPublicKey(&TCPublicKey);
    TCCert.SetAlias("SC1-cert-alias");
    TCCert.SetCA(false);

    //sign the leaf cert
    PermissionConfigurator& SC1PermissionConfigurator = SC1Bus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, SC1PermissionConfigurator.SignCertificate(TCCert));

    //We need identityCert chain CA1->TC
    const size_t certChainSize = 3;
    IdentityCertificate identityCertChain[certChainSize];
    identityCertChain[0] = TCCert;
    identityCertChain[1] = SC1Cert;
    identityCertChain[2] = caCert;

    InstallMembershipOnManager();

    EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", managerAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
    EXPECT_EQ(ER_OK, SC1Bus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", SC1AuthListener));

    // Call UpdateIdentity to install the cert chain
    EXPECT_EQ(ER_DIGEST_MISMATCH, sapWithTC.UpdateIdentity(identityCertChain, certChainSize, manifest, manifestSize)) << "Failed to update Identity cert or manifest ";

}

TEST_F(SecurityManagementPolicyTest, Update_identity_fails_on_invalid_icc_chain)
{
    SecurityApplicationProxy sapWithSC1(managerBus, SC1Bus.GetUniqueName().c_str(), managerToSC1SessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    InstallMembershipOnManager();

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::METHOD_CALL, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    PermissionMgmtObj::GenerateManifestDigest(managerBus, manifest, 1, digest, Crypto_SHA256::DIGEST_SIZE);

    uint8_t managerCN[] = { 1, 2, 3, 4 };
    uint8_t intermediateCN[] = { 5, 6, 7, 8 };
    uint8_t leafCN[] = { 9, 0, 1, 2 };

    //Create the CA cert
    qcc::IdentityCertificate caCert;
    caCert.SetSerial((uint8_t*)"5678", 5);
    caCert.SetIssuerCN(managerCN, 4);
    caCert.SetSubjectCN(managerCN, 4);
    CertificateX509::ValidPeriod validityCA;
    validityCA.validFrom = 1427404154;
    validityCA.validTo = 1427404154 + 630720000;
    caCert.SetValidity(&validityCA);
    caCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    KeyInfoNISTP256 managerPublicKey;
    PermissionConfigurator& permissionConfigurator = managerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(managerPublicKey));

    caCert.SetSubjectPublicKey(managerPublicKey.GetPublicKey());
    caCert.SetAlias("ca-cert-alias");
    caCert.SetCA(true);

    //sign the ca cert
    EXPECT_EQ(ER_OK, permissionConfigurator.SignCertificate(caCert));

    // Create the intermediate certificate using SC1
    qcc::IdentityCertificate SC1Cert;
    SC1Cert.SetSerial((uint8_t*)"1234", 5);
    SC1Cert.SetIssuerCN(managerCN, 4);
    SC1Cert.SetSubjectCN(intermediateCN, 4);
    CertificateX509::ValidPeriod validity;
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    SC1Cert.SetValidity(&validity);
    SC1Cert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    ECCPublicKey SC1PublicKey;
    GetAppPublicKey(SC1Bus, SC1PublicKey);

    SC1Cert.SetSubjectPublicKey(&SC1PublicKey);
    SC1Cert.SetAlias("intermediate-cert-alias");
    SC1Cert.SetCA(true);

    //We intentionally skip signing the leaf cert
    PermissionConfigurator& SC2PermissionConfigurator = SC2Bus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, SC2PermissionConfigurator.SignCertificate(SC1Cert));

    // Create the leaf certificate using TC
    qcc::IdentityCertificate TCCert;
    TCCert.SetSerial((uint8_t*)"1234", 5);
    TCCert.SetIssuerCN(intermediateCN, 4);
    TCCert.SetSubjectCN(leafCN, 4);
    TCCert.SetValidity(&validity);
    TCCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    TCCert.SetSubjectPublicKey(&TCPublicKey);
    TCCert.SetAlias("TC-cert-alias");
    TCCert.SetCA(true);

    //sign the leaf cert
    PermissionConfigurator& SC1PermissionConfigurator = SC1Bus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, SC1PermissionConfigurator.SignCertificate(TCCert));

    //We need identityCert chain CA1->TC
    const size_t certChainSize = 3;
    IdentityCertificate identityCertChain[certChainSize];
    identityCertChain[0] = TCCert;
    identityCertChain[1] = SC1Cert;
    identityCertChain[2] = caCert;

    EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", managerAuthListener));
    EXPECT_EQ(ER_OK, SC1Bus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", SC1AuthListener));

    // Call UpdateIdentity to install the cert chain
    EXPECT_EQ(ER_INVALID_CERTIFICATE, sapWithTC.UpdateIdentity(identityCertChain, certChainSize, manifest, manifestSize))
        << "Failed to update Identity cert or manifest ";
}

TEST_F(SecurityManagementPolicyTest, Update_identity_fails_on_intermediate_ca_flag_false)
{
    SecurityApplicationProxy sapWithSC1(managerBus, SC1Bus.GetUniqueName().c_str(), managerToSC1SessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    InstallMembershipOnManager();

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    PermissionMgmtObj::GenerateManifestDigest(managerBus, manifest, 1, digest, Crypto_SHA256::DIGEST_SIZE);

    uint8_t managerCN[] = { 1, 2, 3, 4 };
    uint8_t intermediateCN[] = { 5, 6, 7, 8 };
    uint8_t leafCN[] = { 9, 0, 1, 2 };

    //Create the CA cert
    qcc::IdentityCertificate caCert;
    caCert.SetSerial((uint8_t*)"5678", 5);
    caCert.SetIssuerCN(managerCN, 4);
    caCert.SetSubjectCN(managerCN, 4);
    CertificateX509::ValidPeriod validityCA;
    validityCA.validFrom = 1427404154;
    validityCA.validTo = 1427404154 + 630720000;
    caCert.SetValidity(&validityCA);
    caCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    KeyInfoNISTP256 managerPublicKey;
    PermissionConfigurator& permissionConfigurator = managerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(managerPublicKey));

    caCert.SetSubjectPublicKey(managerPublicKey.GetPublicKey());
    caCert.SetAlias("ca-cert-alias");
    caCert.SetCA(true);

    //sign the ca cert
    EXPECT_EQ(ER_OK, permissionConfigurator.SignCertificate(caCert));

    // Create the intermediate certificate using SC1
    qcc::IdentityCertificate SC1Cert;
    SC1Cert.SetSerial((uint8_t*)"1234", 5);
    SC1Cert.SetIssuerCN(managerCN, 4);
    SC1Cert.SetSubjectCN(intermediateCN, 4);
    CertificateX509::ValidPeriod validity;
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    SC1Cert.SetValidity(&validity);
    SC1Cert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    ECCPublicKey SC1PublicKey;
    GetAppPublicKey(SC1Bus, SC1PublicKey);

    SC1Cert.SetSubjectPublicKey(&SC1PublicKey);
    SC1Cert.SetAlias("intermediate-cert-alias");
    SC1Cert.SetCA(false);

    //sign the leaf cert
    EXPECT_EQ(ER_OK, permissionConfigurator.SignCertificate(SC1Cert));

    // Create the leaf certificate using TC
    qcc::IdentityCertificate TCCert;
    TCCert.SetSerial((uint8_t*)"1234", 5);
    TCCert.SetIssuerCN(intermediateCN, 4);
    TCCert.SetSubjectCN(leafCN, 4);
    TCCert.SetValidity(&validity);
    TCCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    TCCert.SetSubjectPublicKey(&TCPublicKey);
    TCCert.SetAlias("TC-cert-alias");
    TCCert.SetCA(true);

    //sign the leaf cert
    PermissionConfigurator& SC1PermissionConfigurator = SC1Bus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, SC1PermissionConfigurator.SignCertificate(TCCert));

    //We need identityCert chain CA1->TC
    const size_t certChainSize = 3;
    IdentityCertificate identityCertChain[certChainSize];
    identityCertChain[0] = TCCert;
    identityCertChain[1] = SC1Cert;
    identityCertChain[2] = caCert;

    EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", managerAuthListener));
    EXPECT_EQ(ER_OK, SC1Bus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", SC1AuthListener));

    // Call UpdateIdentity to install the cert chain
    EXPECT_EQ(ER_INVALID_CERTIFICATE, sapWithTC.UpdateIdentity(identityCertChain, certChainSize, manifest, manifestSize))
        << "Failed to update Identity cert or manifest ";
}

TEST_F(SecurityManagementPolicyTest, Update_identity_fails_on_different_subject_leaf_node)
{
    SecurityApplicationProxy sapWithSC1(managerBus, SC1Bus.GetUniqueName().c_str(), managerToSC1SessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    InstallMembershipOnManager();

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    PermissionMgmtObj::GenerateManifestDigest(managerBus, manifest, 1, digest, Crypto_SHA256::DIGEST_SIZE);

    uint8_t managerCN[] = { 1, 2, 3, 4 };
    uint8_t intermediateCN[] = { 5, 6, 7, 8 };
    uint8_t leafCN[] = { 9, 0, 1, 2 };

    //Create the CA cert
    qcc::IdentityCertificate caCert;
    caCert.SetSerial((uint8_t*)"5678", 5);
    caCert.SetIssuerCN(managerCN, 4);
    caCert.SetSubjectCN(managerCN, 4);
    CertificateX509::ValidPeriod validityCA;
    validityCA.validFrom = 1427404154;
    validityCA.validTo = 1427404154 + 630720000;
    caCert.SetValidity(&validityCA);
    caCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    KeyInfoNISTP256 managerPublicKey;
    PermissionConfigurator& permissionConfigurator = managerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(managerPublicKey));

    caCert.SetSubjectPublicKey(managerPublicKey.GetPublicKey());
    caCert.SetAlias("ca-cert-alias");
    caCert.SetCA(true);

    //sign the ca cert
    EXPECT_EQ(ER_OK, permissionConfigurator.SignCertificate(caCert));

    // Create the intermediate certificate using SC1
    qcc::IdentityCertificate SC1Cert;
    SC1Cert.SetSerial((uint8_t*)"1234", 5);
    SC1Cert.SetIssuerCN(managerCN, 4);
    SC1Cert.SetSubjectCN(intermediateCN, 4);
    CertificateX509::ValidPeriod validity;
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    SC1Cert.SetValidity(&validity);
    SC1Cert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    ECCPublicKey SC1PublicKey;
    GetAppPublicKey(SC1Bus, SC1PublicKey);

    SC1Cert.SetSubjectPublicKey(&SC1PublicKey);
    SC1Cert.SetAlias("intermediate-cert-alias");
    SC1Cert.SetCA(false);

    //sign the leaf cert
    EXPECT_EQ(ER_OK, permissionConfigurator.SignCertificate(SC1Cert));

    // Create the leaf certificate using TC
    qcc::IdentityCertificate TCCert;
    TCCert.SetSerial((uint8_t*)"1234", 5);
    TCCert.SetIssuerCN(intermediateCN, 4);
    TCCert.SetSubjectCN(leafCN, 4);
    TCCert.SetValidity(&validity);
    TCCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    // We are intentionally making the leaf certificate public key different
    TCCert.SetSubjectPublicKey(&SC1PublicKey);
    TCCert.SetAlias("TC-cert-alias");
    TCCert.SetCA(true);

    //sign the leaf cert
    PermissionConfigurator& SC1PermissionConfigurator = SC1Bus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, SC1PermissionConfigurator.SignCertificate(TCCert));

    //We need identityCert chain CA1->TC
    const size_t certChainSize = 3;
    IdentityCertificate identityCertChain[certChainSize];
    identityCertChain[0] = TCCert;
    identityCertChain[1] = SC1Cert;
    identityCertChain[2] = caCert;

    EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", managerAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));

    // Call UpdateIdentity to install the cert chain
    EXPECT_EQ(ER_INVALID_CERTIFICATE, sapWithTC.UpdateIdentity(identityCertChain, certChainSize, manifest, manifestSize))
        << "Failed to update Identity cert or manifest ";
}

TEST_F(SecurityManagementPolicyTest, Update_identity_succeeds_on_long_icc)
{
    SecurityApplicationProxy sapWithSC1(managerBus, SC1Bus.GetUniqueName().c_str(), managerToSC1SessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    InstallMembershipOnManager();

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

    uint8_t managerCN[] = { 1, 2, 3, 4 };
    uint8_t intermediateCN[] = { 5, 6, 7, 8 };
    uint8_t intermediate2CN[] = { 4, 3, 2, 1 };
    uint8_t leafCN[] = { 9, 0, 1, 2 };

    //Create the CA cert
    qcc::IdentityCertificate caCert;
    caCert.SetSerial((uint8_t*)"1234", 5);
    caCert.SetIssuerCN(managerCN, 4);
    caCert.SetSubjectCN(managerCN, 4);
    CertificateX509::ValidPeriod validityCA;
    validityCA.validFrom = qcc::GetEpochTimestamp() / 1000;
    validityCA.validTo = validityCA.validFrom + TEN_MINS;
    caCert.SetValidity(&validityCA);
    caCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    KeyInfoNISTP256 managerPublicKey;
    PermissionConfigurator& permissionConfigurator = managerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(managerPublicKey));

    caCert.SetSubjectPublicKey(managerPublicKey.GetPublicKey());
    caCert.SetAlias("ca-cert-alias");
    caCert.SetCA(true);

    //sign the ca cert
    EXPECT_EQ(ER_OK, permissionConfigurator.SignCertificate(caCert));

    // Create the intermediate certificate using SC1
    qcc::IdentityCertificate SC1Cert;
    SC1Cert.SetSerial((uint8_t*)"2345", 5);
    SC1Cert.SetIssuerCN(managerCN, 4);
    SC1Cert.SetSubjectCN(intermediateCN, 4);
    CertificateX509::ValidPeriod validity;
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    SC1Cert.SetValidity(&validity);
    SC1Cert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    ECCPublicKey SC1PublicKey;
    GetAppPublicKey(SC1Bus, SC1PublicKey);

    SC1Cert.SetSubjectPublicKey(&SC1PublicKey);
    SC1Cert.SetAlias("intermediate-cert-alias");
    SC1Cert.SetCA(true);

    //sign the leaf cert
    EXPECT_EQ(ER_OK, permissionConfigurator.SignCertificate(SC1Cert));

    // Create third intermediate CA
    KeyInfoNISTP256 SC2PublicKey;
    PermissionConfigurator& SC2PermissionConfigurator = SC2Bus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, SC2PermissionConfigurator.GetSigningPublicKey(SC2PublicKey));

    qcc::IdentityCertificate intermediateCACert;
    intermediateCACert.SetSerial((uint8_t*)"1234", 5);
    intermediateCACert.SetIssuerCN(intermediateCN, 4);
    intermediateCACert.SetSubjectCN(intermediate2CN, 4);
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    intermediateCACert.SetValidity(&validity);
    intermediateCACert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    intermediateCACert.SetSubjectPublicKey(SC2PublicKey.GetPublicKey());
    intermediateCACert.SetAlias("intermediate-ca-cert-alias");
    intermediateCACert.SetCA(true);

    //sign the intermediate 2 cert
    PermissionConfigurator& SC1PermissionConfigurator = SC1Bus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, SC1PermissionConfigurator.SignCertificate(intermediateCACert));

    // Create the leaf certificate using TC
    qcc::IdentityCertificate TCCert;
    TCCert.SetSerial((uint8_t*)"1234", 5);
    TCCert.SetIssuerCN(intermediate2CN, 4);
    TCCert.SetSubjectCN(leafCN, 4);
    TCCert.SetValidity(&validity);
    TCCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    TCCert.SetSubjectPublicKey(&TCPublicKey);
    TCCert.SetAlias("TC-cert-alias");
    TCCert.SetCA(false);

    //sign the leaf cert
    EXPECT_EQ(ER_OK, SC2PermissionConfigurator.SignCertificate(TCCert));

    const size_t certChainSize = 4;
    IdentityCertificate identityCertChain[certChainSize];
    identityCertChain[0] = TCCert;
    identityCertChain[1] = intermediateCACert;
    identityCertChain[2] = SC1Cert;
    identityCertChain[3] = caCert;

    EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", managerAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
    EXPECT_EQ(ER_OK, SC2Bus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", SC2AuthListener));

    // Call UpdateIdentity to install the cert chain
    EXPECT_EQ(ER_OK, sapWithTC.UpdateIdentity(identityCertChain, certChainSize, manifest, manifestSize))
        << "Failed to update Identity cert or manifest ";
}

TEST_F(SecurityManagementPolicyTest, Update_identity_single_icc_any_sign)
{
    SecurityApplicationProxy sapWithSC1(managerBus, SC1Bus.GetUniqueName().c_str(), managerToSC1SessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    InstallMembershipOnManager();

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

    uint8_t leafCN[] = { 9, 0, 1, 2 };

    KeyInfoNISTP256 SC1PublicKey;
    PermissionConfigurator& SC1PermissionConfigurator = SC1Bus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, SC1PermissionConfigurator.GetSigningPublicKey(SC1PublicKey));

    // Create the leaf certificate using TC
    qcc::IdentityCertificate TCCert;
    TCCert.SetSerial((uint8_t*)"1234", 5);
    TCCert.SetIssuerCN(leafCN, 4);
    TCCert.SetSubjectCN(leafCN, 4);
    CertificateX509::ValidPeriod validity;
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    TCCert.SetValidity(&validity);
    TCCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    TCCert.SetSubjectPublicKey(&TCPublicKey);
    TCCert.SetAlias("TC-cert-alias");
    TCCert.SetCA(true);

    //sign the leaf cert
    EXPECT_EQ(ER_OK, SC1PermissionConfigurator.SignCertificate(TCCert));

    //We need identityCert chain CA1->TC
    const size_t certChainSize = 1;
    IdentityCertificate identityCertChain[certChainSize];
    identityCertChain[0] = TCCert;

    EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", managerAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));

    // Call UpdateIdentity to install the cert chain
    EXPECT_EQ(ER_OK, sapWithTC.UpdateIdentity(identityCertChain, certChainSize, manifest, manifestSize))
        << "Failed to update Identity cert or manifest ";
}

TEST_F(SecurityManagementPolicyTest, install_membership_fails_with_invalid_public_key)
{
    SecurityApplicationProxy sapWithSC1(managerBus, SC1Bus.GetUniqueName().c_str(), managerToSC1SessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    InstallMembershipOnManager();

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    PermissionMgmtObj::GenerateManifestDigest(managerBus, manifest, 1, digest, Crypto_SHA256::DIGEST_SIZE);

    KeyInfoNISTP256 managerPublicKey;
    PermissionConfigurator& permissionConfigurator = managerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(managerPublicKey));

    KeyInfoNISTP256 SC1PublicKey;
    PermissionConfigurator& SC1PermissionConfigurator = SC1Bus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, SC1PermissionConfigurator.GetSigningPublicKey(SC1PublicKey));


    qcc::MembershipCertificate membershipCertificate[2];
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("1",
                                                                    managerBus,
                                                                    managerBus.GetUniqueName(),
                                                                    managerPublicKey.GetPublicKey(),
                                                                    managerGuid,
                                                                    true,
                                                                    3600,
                                                                    membershipCertificate[1]
                                                                    ));

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("2",
                                                                    managerBus,
                                                                    SC1Bus.GetUniqueName(),
                                                                    SC1PublicKey.GetPublicKey(),
                                                                    managerGuid,
                                                                    false,
                                                                    3600,
                                                                    membershipCertificate[0]
                                                                    ));


    EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", managerAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));

    // Call UpdateIdentity to install the cert chain
    EXPECT_EQ(ER_INVALID_CERTIFICATE, sapWithTC.InstallMembership(membershipCertificate, 2)) << "Failed to install membership ";
}

TEST_F(SecurityManagementPolicyTest, install_membership_fails_with_same_cert_serial)
{
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    InstallMembershipOnManager();

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    PermissionMgmtObj::GenerateManifestDigest(managerBus, manifest, 1, digest, Crypto_SHA256::DIGEST_SIZE);

    EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", managerAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));

    qcc::MembershipCertificate membershipCertificate[1];
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("1",
                                                                    managerBus,
                                                                    TCBus.GetUniqueName(),
                                                                    TCKey.GetPublicKey(),
                                                                    managerGuid,
                                                                    true,
                                                                    3600,
                                                                    membershipCertificate[0]
                                                                    ));


    // Call InstallMembership
    EXPECT_EQ(ER_OK, sapWithTC.InstallMembership(membershipCertificate, 1)) << "Failed to install membership ";


    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("1",
                                                                    managerBus,
                                                                    TCBus.GetUniqueName(),
                                                                    TCKey.GetPublicKey(),
                                                                    managerGuid,
                                                                    true,
                                                                    3600,
                                                                    membershipCertificate[0]
                                                                    ));

    // Call InstallMembership
    EXPECT_EQ(ER_DUPLICATE_CERTIFICATE, sapWithTC.InstallMembership(membershipCertificate, 1)) << "Failed to install membership ";
}

TEST_F(SecurityManagementPolicyTest, remove_membership_succeeds)
{
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    InstallMembershipOnManager();

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    PermissionMgmtObj::GenerateManifestDigest(managerBus, manifest, 1, digest, Crypto_SHA256::DIGEST_SIZE);

    uint8_t issuerCN[] = { 1, 2, 3, 4 };
    uint8_t leafCN[] = { 5, 6, 7, 8 };

    // Create the membership certificate from the first issuer
    qcc::MembershipCertificate memCert;
    memCert.SetSerial((uint8_t*)"1234", 5);
    memCert.SetIssuerCN(issuerCN, 4);
    memCert.SetSubjectCN(leafCN, 4);
    CertificateX509::ValidPeriod validity;
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    memCert.SetValidity(&validity);
    memCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    memCert.SetSubjectPublicKey(&TCPublicKey);
    memCert.SetCA(true);
    GUID128 asgaGUID;
    memCert.SetGuild(asgaGUID);

    //sign the leaf cert
    PermissionConfigurator& permissionConfigurator = managerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.SignCertificate(memCert));

    // Call InstallMembership
    EXPECT_EQ(ER_OK, sapWithTC.InstallMembership(&memCert, 1)) << "Failed to install membership ";

    // Create the membership certificate from the second issuer Peer 1
    qcc::MembershipCertificate memCert2;
    memCert2.SetSerial((uint8_t*)"5678", 5);
    memCert2.SetIssuerCN(issuerCN, 4);
    memCert2.SetSubjectCN(leafCN, 4);
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    memCert2.SetValidity(&validity);
    memCert2.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);
    memCert2.SetSubjectPublicKey(&TCPublicKey);
    memCert2.SetCA(true);
    memCert.SetGuild(asgaGUID);

    //sign the leaf cert
    EXPECT_EQ(ER_OK, permissionConfigurator.SignCertificate(memCert2));

    // Call InstallMembership
    EXPECT_EQ(ER_OK, sapWithTC.InstallMembership(&memCert2, 1)) << "Failed to install membership ";

    // Call GetProperty("MembershipSummaries"). This call should show 2 membership certificates
    MsgArg arg;
    EXPECT_EQ(ER_OK, sapWithTC.GetMembershipSummaries(arg)) << "GetMembershipSummaries failed.";

    size_t count = arg.v_array.GetNumElements();
    EXPECT_EQ((uint32_t)2, count);
    String*serials = new String[count];
    KeyInfoNISTP256* keyInfos = new KeyInfoNISTP256[count];
    EXPECT_EQ(ER_OK, sapWithTC.MsgArgToCertificateIds(arg, serials, keyInfos, count));

    String serial0("1234");
    String serial1("5678");
    // Compare the serial  in the certificates just retrieved
    EXPECT_STREQ(serials[0].c_str(), serial0.c_str());
    EXPECT_STREQ(serials[1].c_str(), serial1.c_str());

    // Call RemoveMembership
    EXPECT_EQ(ER_OK, sapWithTC.RemoveMembership(serials[0], keyInfos[0]));

    // Call GetProperty("MembershipSummaries"). This call should show 1 membership certificate
    EXPECT_EQ(ER_OK, sapWithTC.GetMembershipSummaries(arg)) << "GetMembershipSummaries failed.";
    count = arg.v_array.GetNumElements();
    EXPECT_EQ((uint32_t)1, count);
    serials = new String[count];
    keyInfos = new KeyInfoNISTP256[count];
    EXPECT_EQ(ER_OK, sapWithTC.MsgArgToCertificateIds(arg, serials, keyInfos, count));
    EXPECT_EQ(count, (uint32_t)1);
    EXPECT_STREQ(serials[0].c_str(), "5678");
}

TEST_F(SecurityManagementPolicyTest, remove_membership_fails_if_serial_does_not_match)
{
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    InstallMembershipOnManager();

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

    EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", managerAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));

    qcc::MembershipCertificate membershipCertificate[1];
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("123",
                                                                    managerBus,
                                                                    TCBus.GetUniqueName(),
                                                                    TCKey.GetPublicKey(),
                                                                    managerGuid,
                                                                    true,
                                                                    3600,
                                                                    membershipCertificate[0]
                                                                    ));

    // Call InstallMembership
    EXPECT_EQ(ER_OK, sapWithTC.InstallMembership(membershipCertificate, 1)) << "Failed to install membership ";

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("456",
                                                                    managerBus,
                                                                    TCBus.GetUniqueName(),
                                                                    TCKey.GetPublicKey(),
                                                                    managerGuid,
                                                                    true,
                                                                    3600,
                                                                    membershipCertificate[0]
                                                                    ));


    // Call InstallMembership
    EXPECT_EQ(ER_OK, sapWithTC.InstallMembership(membershipCertificate, 1)) << "Failed to install membership ";

    // Call GetProperty("MembershipSummaries"). This call should show 2 membership certificates
    MsgArg arg;
    EXPECT_EQ(ER_OK, sapWithTC.GetMembershipSummaries(arg)) << "GetMembershipSummaries failed.";

    size_t count = arg.v_array.GetNumElements();
    EXPECT_EQ((uint32_t)2, count);
    String*serials = new String[count];
    KeyInfoNISTP256* keyInfos = new KeyInfoNISTP256[count];
    EXPECT_EQ(ER_OK, sapWithTC.MsgArgToCertificateIds(arg, serials, keyInfos, count));

    String serial0("123");
    String serial1("456");
    // Compare the serial  in the certificates just retrieved
    EXPECT_STREQ(serials[0].c_str(), serial0.c_str());
    EXPECT_STREQ(serials[1].c_str(), serial1.c_str());

    // Call RemoveMembership
    String fakeSerial("333");
    EXPECT_EQ(ER_CERTIFICATE_NOT_FOUND, sapWithTC.RemoveMembership(fakeSerial, keyInfos[0]));

}

TEST_F(SecurityManagementPolicyTest, remove_membership_fails_if_issuer_does_not_match)
{
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    InstallMembershipOnManager();
    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    PermissionMgmtObj::GenerateManifestDigest(managerBus, manifest, 1, digest, Crypto_SHA256::DIGEST_SIZE);

    EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", managerAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));

    qcc::MembershipCertificate membershipCertificate[1];
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("123",
                                                                    managerBus,
                                                                    TCBus.GetUniqueName(),
                                                                    TCKey.GetPublicKey(),
                                                                    managerGuid,
                                                                    true,
                                                                    3600,
                                                                    membershipCertificate[0]
                                                                    ));

    // Call InstallMembership
    EXPECT_EQ(ER_OK, sapWithTC.InstallMembership(membershipCertificate, 1)) << "Failed to install membership ";

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("456",
                                                                    managerBus,
                                                                    TCBus.GetUniqueName(),
                                                                    TCKey.GetPublicKey(),
                                                                    managerGuid,
                                                                    true,
                                                                    3600,
                                                                    membershipCertificate[0]
                                                                    ));


    // Call InstallMembership
    EXPECT_EQ(ER_OK, sapWithTC.InstallMembership(membershipCertificate, 1)) << "Failed to install membership ";

    // Call GetProperty("MembershipSummaries"). This call should show 2 membership certificates
    MsgArg arg;
    EXPECT_EQ(ER_OK, sapWithTC.GetMembershipSummaries(arg)) << "GetMembershipSummaries failed.";

    size_t count = arg.v_array.GetNumElements();
    EXPECT_EQ((uint32_t)2, count);
    String*serials = new String[count];
    KeyInfoNISTP256* keyInfos = new KeyInfoNISTP256[count];
    EXPECT_EQ(ER_OK, sapWithTC.MsgArgToCertificateIds(arg, serials, keyInfos, count));

    String serial0("123");
    String serial1("456");
    // Compare the serial  in the certificates just retrieved
    EXPECT_STREQ(serials[0].c_str(), serial0.c_str());
    EXPECT_STREQ(serials[1].c_str(), serial1.c_str());

    // Call RemoveMembership
    EXPECT_EQ(ER_CERTIFICATE_NOT_FOUND, sapWithTC.RemoveMembership(serials[0], TCKey));
}

TEST_F(SecurityManagementPolicyTest, successful_method_call_after_chained_membership_installation)
{
    BusAttachment busUsedAsCA("caBus");
    busUsedAsCA.Start();
    busUsedAsCA.Connect();

    DefaultECDHEAuthListener* caAuthListener;
    caAuthListener = new DefaultECDHEAuthListener();

    EXPECT_EQ(ER_OK, busUsedAsCA.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", caAuthListener));

    qcc::GUID128 guildAuthorityGUID;
    GUID128 leafGuid;
    GUID128 interGuid;
    GUID128 caGUID;

    PermissionMgmtTestHelper::GetGUID(SC1Bus, leafGuid);
    PermissionMgmtTestHelper::GetGUID(SC2Bus, interGuid);
    PermissionMgmtTestHelper::GetGUID(busUsedAsCA, caGUID);


    SecurityApplicationProxy sapWithManager(managerBus, managerBus.GetUniqueName().c_str(), managerToManagerSessionId);
    SecurityApplicationProxy sapWithSC1(managerBus, SC1Bus.GetUniqueName().c_str(), managerToSC1SessionId);
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
    PermissionMgmtObj::GenerateManifestDigest(busUsedAsCA, manifest, 1, digest, Crypto_SHA256::DIGEST_SIZE);

    uint8_t managerCN[] = { 1, 2, 3, 4 };
    uint8_t intermediateCN[] = { 9, 9, 9, 9 };
    uint8_t caCN[] = { 9, 9, 9, 9 };
    uint8_t leafCN[] = { 9, 0, 1, 2 };

    //Create the CA cert
    qcc::IdentityCertificate caCert;
    caCert.SetSerial((uint8_t*)"1234", 5);
    caCert.SetIssuerCN(caCN, 4);
    caCert.SetSubjectCN(caCN, 4);
    CertificateX509::ValidPeriod validityCA;
    validityCA.validFrom = qcc::GetEpochTimestamp() / 1000;
    validityCA.validTo = validityCA.validFrom + TEN_MINS;
    caCert.SetValidity(&validityCA);
    caCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    KeyInfoNISTP256 caKey;
    PermissionConfigurator& caPC = busUsedAsCA.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, caPC.GetSigningPublicKey(caKey));

    caCert.SetSubjectPublicKey(caKey.GetPublicKey());
    caCert.SetAlias("ca-cert-alias");
    caCert.SetCA(true);

    //sign the ca cert
    caPC.SignCertificate(caCert);

    // Create the intermediate certificate using SC1
    qcc::IdentityCertificate SC1Cert;
    SC1Cert.SetSerial((uint8_t*)"2345", 5);
    SC1Cert.SetIssuerCN(caCN, 4);
    SC1Cert.SetSubjectCN(leafCN, 4);
    CertificateX509::ValidPeriod validity;
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    SC1Cert.SetValidity(&validity);
    SC1Cert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    ECCPublicKey SC1PublicKey;
    GetAppPublicKey(SC1Bus, SC1PublicKey);

    SC1Cert.SetSubjectPublicKey(&SC1PublicKey);
    SC1Cert.SetAlias("intermediate-cert-alias");
    SC1Cert.SetCA(false);

    //sign the leaf cert
    EXPECT_EQ(ER_OK, caPC.SignCertificate(SC1Cert));

    //We need identityCert chain CA1->SC1
    const size_t certChainSize = 2;
    IdentityCertificate identityCertChain[certChainSize];
    identityCertChain[0] = SC1Cert;
    identityCertChain[1] = caCert;

    //
    // Create membership chain to be installed on peer 1
    //

    PermissionMgmtTestHelper::GetGUID(managerBus, guildAuthorityGUID);
    KeyInfoNISTP256 sgaKey;
    PermissionConfigurator& managerPC = managerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, managerPC.GetSigningPublicKey(sgaKey));

    // SGA membership certificate
    qcc::MembershipCertificate sgaMembershipCert;
    sgaMembershipCert.SetSerial((uint8_t*)"1234", 5);
    sgaMembershipCert.SetIssuerCN(managerCN, 4);
    sgaMembershipCert.SetSubjectCN(managerCN, 4);
    sgaMembershipCert.SetSubjectPublicKey(sgaKey.GetPublicKey());
    sgaMembershipCert.SetGuild(managerGuid);
    sgaMembershipCert.SetCA(true);
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    sgaMembershipCert.SetValidity(&validity);

    managerPC.SignCertificate(sgaMembershipCert);

    MembershipCertificate managerMembershipCertChain[1];
    managerMembershipCertChain[0] = sgaMembershipCert;

    EXPECT_EQ(ER_OK, sapWithManager.InstallMembership(managerMembershipCertChain, 1));

    // Intermediate membership certificate
    qcc::MembershipCertificate intermediateMembershipCert;
    intermediateMembershipCert.SetSerial((uint8_t*)"2345", 5);
    intermediateMembershipCert.SetIssuerCN(managerCN, 4);
    intermediateMembershipCert.SetSubjectCN(intermediateCN, 4);
    KeyInfoNISTP256 interKey;
    PermissionConfigurator& SC2PC = SC2Bus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, SC2PC.GetSigningPublicKey(interKey));
    intermediateMembershipCert.SetSubjectPublicKey(interKey.GetPublicKey());
    intermediateMembershipCert.SetGuild(interGuid);
    intermediateMembershipCert.SetCA(true);
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    intermediateMembershipCert.SetValidity(&validity);
    /* use the signing bus to sign the cert */
    managerPC.SignCertificate(intermediateMembershipCert);

    // Leaf membership certificate
    qcc::MembershipCertificate leafMembershipCert;
    leafMembershipCert.SetSerial((uint8_t*)"3456", 5);
    leafMembershipCert.SetIssuerCN(intermediateCN, 4);
    leafMembershipCert.SetSubjectCN(leafCN, 4);
    KeyInfoNISTP256 leafKey;
    PermissionConfigurator& SC1PC = SC1Bus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, SC1PC.GetSigningPublicKey(leafKey));
    leafMembershipCert.SetSubjectPublicKey(leafKey.GetPublicKey());
    leafMembershipCert.SetGuild(leafGuid);
    leafMembershipCert.SetCA(false);
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    leafMembershipCert.SetValidity(&validity);
    /* use the signing bus to sign the cert */
    SC2PC.SignCertificate(leafMembershipCert);

    const size_t membershipChainSize = 3;
    MembershipCertificate membershipCertChain[membershipChainSize];
    membershipCertChain[0] = leafMembershipCert;
    membershipCertChain[1] = intermediateMembershipCert;
    membershipCertChain[2] = sgaMembershipCert;

    EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", managerAuthListener));
    EXPECT_EQ(ER_OK, SC1Bus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", SC1AuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
    EXPECT_EQ(ER_OK, SC2Bus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", SC2AuthListener));

    //EXPECT_EQ(ER_OK, sapWithSC1.Reset());
    EXPECT_EQ(ER_OK, sapWithSC1.InstallMembership(membershipCertChain, 3));

    // Call UpdateIdentity on Peer 1 to install the cert chain
    EXPECT_EQ(ER_OK, sapWithSC1.UpdateIdentity(identityCertChain, certChainSize, manifest, manifestSize))
        << "Failed to update Identity cert or manifest ";

    // Create the intermediate certificate using TC
    qcc::IdentityCertificate TCCert;
    TCCert.SetSerial((uint8_t*)"5678", 5);
    TCCert.SetIssuerCN(caCN, 4);
    TCCert.SetSubjectCN(leafCN, 4);
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    TCCert.SetValidity(&validity);
    TCCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    TCCert.SetSubjectPublicKey(TCKey.GetPublicKey());
    TCCert.SetAlias("TC-cert-alias");
    TCCert.SetCA(true);

    //sign the leaf cert
    EXPECT_EQ(ER_OK, caPC.SignCertificate(TCCert));

    //We need identityCert chain CA1->TC
    identityCertChain[0] = TCCert;
    identityCertChain[1] = caCert;

    // Call UpdateIdentity on Peer 1 to install the cert chain
    EXPECT_EQ(ER_OK, sapWithTC.UpdateIdentity(identityCertChain, certChainSize, manifest, manifestSize))
        << "Failed to update Identity cert or manifest ";

    uint32_t SC1ToTCSessionId;
    SessionOpts opts;
    EXPECT_EQ(ER_OK, SC1Bus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, SC1ToTCSessionId, opts));
    ProxyBusObject TCObj;
    TCObj = ProxyBusObject(SC1Bus, org::alljoyn::Bus::InterfaceName, org::alljoyn::Bus::ObjectPath, SC1ToTCSessionId, false);

    EXPECT_EQ(ER_OK, TCObj.IntrospectRemoteObject());
}

TEST_F(SecurityManagementPolicyTest, unsuccessful_method_call_after_chained_membership_installation)
{
    BusAttachment busUsedAsCA("caBus");
    busUsedAsCA.Start();
    busUsedAsCA.Connect();

    DefaultECDHEAuthListener* caAuthListener;
    caAuthListener = new DefaultECDHEAuthListener();

    EXPECT_EQ(ER_OK, busUsedAsCA.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", caAuthListener));

    qcc::GUID128 guildAuthorityGUID;
    GUID128 leafGuid;
    GUID128 interGuid;
    GUID128 caGUID;

    //PermissionMgmtTestHelper::GetGUID(TCBus, leafGuid);
    PermissionMgmtTestHelper::GetGUID(SC1Bus, leafGuid);
    PermissionMgmtTestHelper::GetGUID(SC2Bus, interGuid);
    PermissionMgmtTestHelper::GetGUID(busUsedAsCA, caGUID);


    SecurityApplicationProxy sapWithManager(managerBus, managerBus.GetUniqueName().c_str(), managerToManagerSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    SecurityApplicationProxy sapWithSC1(managerBus, SC1Bus.GetUniqueName().c_str(), managerToSC1SessionId);

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    PermissionMgmtObj::GenerateManifestDigest(busUsedAsCA, manifest, 1, digest, Crypto_SHA256::DIGEST_SIZE);

    uint8_t managerCN[] = { 1, 2, 3, 4 };
    uint8_t intermediateCN[] = { 9, 9, 9, 9 };
    uint8_t caCN[] = { 9, 9, 9, 9 };
    uint8_t leafCN[] = { 9, 0, 1, 2 };

    //Create the CA cert
    qcc::IdentityCertificate caCert;
    caCert.SetSerial((uint8_t*)"1234", 5);
    caCert.SetIssuerCN(caCN, 4);
    caCert.SetSubjectCN(caCN, 4);
    CertificateX509::ValidPeriod validityCA;
    validityCA.validFrom = qcc::GetEpochTimestamp() / 1000;
    validityCA.validTo = validityCA.validFrom + TEN_MINS;
    caCert.SetValidity(&validityCA);
    caCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    KeyInfoNISTP256 caKey;
    PermissionConfigurator& caPC = busUsedAsCA.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, caPC.GetSigningPublicKey(caKey));

    caCert.SetSubjectPublicKey(caKey.GetPublicKey());
    caCert.SetAlias("ca-cert-alias");
    caCert.SetCA(true);

    //sign the ca cert
    caPC.SignCertificate(caCert);

    // Create the intermediate certificate using TC
    qcc::IdentityCertificate TCCert;
    TCCert.SetSerial((uint8_t*)"2345", 5);
    TCCert.SetIssuerCN(caCN, 4);
    TCCert.SetSubjectCN(leafCN, 4);
    CertificateX509::ValidPeriod validity;
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    TCCert.SetValidity(&validity);
    TCCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    TCCert.SetSubjectPublicKey(&TCPublicKey);
    TCCert.SetAlias("intermediate-cert-alias");
    TCCert.SetCA(false);

    //sign the leaf cert
    EXPECT_EQ(ER_OK, caPC.SignCertificate(TCCert));

    //We need identityCert chain CA1->TC
    const size_t certChainSize = 2;
    IdentityCertificate identityCertChain[certChainSize];
    identityCertChain[0] = TCCert;
    identityCertChain[1] = caCert;

    //
    // Create membership chain to be installed on peer 1
    //

    PermissionMgmtTestHelper::GetGUID(managerBus, guildAuthorityGUID);
    KeyInfoNISTP256 sgaKey;
    PermissionConfigurator& managerPC = managerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, managerPC.GetSigningPublicKey(sgaKey));

    // SGA membership certificate
    qcc::MembershipCertificate sgaMembershipCert;
    sgaMembershipCert.SetSerial((uint8_t*)"1234", 5);
    sgaMembershipCert.SetIssuerCN(managerCN, 4);
    sgaMembershipCert.SetSubjectCN(managerCN, 4);
    sgaMembershipCert.SetSubjectPublicKey(sgaKey.GetPublicKey());
    sgaMembershipCert.SetGuild(managerGuid);
    sgaMembershipCert.SetCA(true);
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    sgaMembershipCert.SetValidity(&validity);

    managerPC.SignCertificate(sgaMembershipCert);

    MembershipCertificate managerMembershipCertChain[1];
    managerMembershipCertChain[0] = sgaMembershipCert;

    EXPECT_EQ(ER_OK, sapWithManager.InstallMembership(managerMembershipCertChain, 1));

    // Intermediate membership certificate
    qcc::MembershipCertificate intermediateMembershipCert;
    intermediateMembershipCert.SetSerial((uint8_t*)"2345", 5);
    intermediateMembershipCert.SetIssuerCN(managerCN, 4);
    intermediateMembershipCert.SetSubjectCN(intermediateCN, 4);
    KeyInfoNISTP256 interKey;
    PermissionConfigurator& SC2PC = SC2Bus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, SC2PC.GetSigningPublicKey(interKey));
    intermediateMembershipCert.SetSubjectPublicKey(interKey.GetPublicKey());
    intermediateMembershipCert.SetGuild(interGuid);
    intermediateMembershipCert.SetCA(false);
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    intermediateMembershipCert.SetValidity(&validity);
    /* use the signing bus to sign the cert */
    managerPC.SignCertificate(intermediateMembershipCert);

    // Leaf membership certificate
    qcc::MembershipCertificate leafMembershipCert;
    leafMembershipCert.SetSerial((uint8_t*)"3456", 5);
    leafMembershipCert.SetIssuerCN(intermediateCN, 4);
    leafMembershipCert.SetSubjectCN(leafCN, 4);
    leafMembershipCert.SetSubjectPublicKey(TCKey.GetPublicKey());
    leafMembershipCert.SetGuild(leafGuid);
    leafMembershipCert.SetCA(false);
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    leafMembershipCert.SetValidity(&validity);
    /* use the signing bus to sign the cert */
    SC2PC.SignCertificate(leafMembershipCert);

    const size_t membershipChainSize = 3;
    MembershipCertificate membershipCertChain[membershipChainSize];
    membershipCertChain[0] = leafMembershipCert;
    membershipCertChain[1] = intermediateMembershipCert;
    membershipCertChain[2] = sgaMembershipCert;

    EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", managerAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
    EXPECT_EQ(ER_OK, SC1Bus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", SC1AuthListener));
    EXPECT_EQ(ER_OK, SC2Bus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", SC2AuthListener));

    EXPECT_EQ(ER_INVALID_CERTIFICATE, sapWithTC.InstallMembership(membershipCertChain, 3));
}

TEST_F(SecurityManagementPolicyTest, chained_membership_signed_upto_ca_fails)
{
    BusAttachment busUsedAsCA("caBus");
    busUsedAsCA.Start();
    busUsedAsCA.Connect();

    DefaultECDHEAuthListener* caAuthListener;
    caAuthListener = new DefaultECDHEAuthListener();

    EXPECT_EQ(ER_OK, busUsedAsCA.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", caAuthListener));

    qcc::GUID128 guildAuthorityGUID;
    GUID128 leafGuid;
    GUID128 interGuid;
    GUID128 caGUID;

    //PermissionMgmtTestHelper::GetGUID(TCBus, leafGuid);
    PermissionMgmtTestHelper::GetGUID(SC1Bus, leafGuid);
    PermissionMgmtTestHelper::GetGUID(SC2Bus, interGuid);
    PermissionMgmtTestHelper::GetGUID(busUsedAsCA, caGUID);

    SecurityApplicationProxy sapWithManager(managerBus, managerBus.GetUniqueName().c_str(), managerToManagerSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    SecurityApplicationProxy sapWithSC1(managerBus, SC1Bus.GetUniqueName().c_str(), managerToSC1SessionId);

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    PermissionMgmtObj::GenerateManifestDigest(busUsedAsCA, manifest, 1, digest, Crypto_SHA256::DIGEST_SIZE);

    uint8_t managerCN[] = { 1, 2, 3, 4 };
    uint8_t intermediateCN[] = { 9, 9, 9, 9 };
    uint8_t leafCN[] = { 9, 0, 1, 2 };

    KeyInfoNISTP256 caKey;
    PermissionConfigurator& caPC = busUsedAsCA.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, caPC.GetSigningPublicKey(caKey));

    //
    // Create membership chain to be installed on peer 1
    //

    PermissionMgmtTestHelper::GetGUID(managerBus, guildAuthorityGUID);

    // SGA membership certificate
    qcc::MembershipCertificate caMembershipCert;
    caMembershipCert.SetSerial((uint8_t*)"1234", 5);
    caMembershipCert.SetIssuerCN(managerCN, 4);
    caMembershipCert.SetSubjectCN(managerCN, 4);
    caMembershipCert.SetSubjectPublicKey(caKey.GetPublicKey());
    caMembershipCert.SetGuild(managerGuid);
    caMembershipCert.SetCA(true);
    CertificateX509::ValidPeriod validity;
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    caMembershipCert.SetValidity(&validity);

    caPC.SignCertificate(caMembershipCert);

    InstallMembershipOnManager();

    // Intermediate membership certificate
    qcc::MembershipCertificate intermediateMembershipCert;
    intermediateMembershipCert.SetSerial((uint8_t*)"2345", 5);
    intermediateMembershipCert.SetIssuerCN(managerCN, 4);
    intermediateMembershipCert.SetSubjectCN(intermediateCN, 4);
    KeyInfoNISTP256 interKey;
    PermissionConfigurator& SC2PC = SC2Bus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, SC2PC.GetSigningPublicKey(interKey));
    intermediateMembershipCert.SetSubjectPublicKey(interKey.GetPublicKey());
    intermediateMembershipCert.SetGuild(interGuid);
    intermediateMembershipCert.SetCA(false);
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    intermediateMembershipCert.SetValidity(&validity);
    /* use the signing bus to sign the cert */
    caPC.SignCertificate(intermediateMembershipCert);

    // Leaf membership certificate
    qcc::MembershipCertificate leafMembershipCert;
    leafMembershipCert.SetSerial((uint8_t*)"3456", 5);
    leafMembershipCert.SetIssuerCN(intermediateCN, 4);
    leafMembershipCert.SetSubjectCN(leafCN, 4);
    leafMembershipCert.SetSubjectPublicKey(TCKey.GetPublicKey());
    leafMembershipCert.SetGuild(leafGuid);
    leafMembershipCert.SetCA(false);
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    leafMembershipCert.SetValidity(&validity);
    /* use the signing bus to sign the cert */
    SC2PC.SignCertificate(leafMembershipCert);

    const size_t membershipChainSize = 3;
    MembershipCertificate membershipCertChain[membershipChainSize];
    membershipCertChain[0] = leafMembershipCert;
    membershipCertChain[1] = intermediateMembershipCert;
    membershipCertChain[2] = caMembershipCert;

    EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", managerAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
    EXPECT_EQ(ER_OK, SC1Bus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", SC1AuthListener));
    EXPECT_EQ(ER_OK, SC2Bus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", SC2AuthListener));

    EXPECT_EQ(ER_INVALID_CERTIFICATE, sapWithTC.InstallMembership(membershipCertChain, 3));
}

TEST_F(SecurityManagementPolicyTest, chained_membership_with_two_levels_fails)
{
    BusAttachment busUsedAsCA("caBus");
    busUsedAsCA.Start();
    busUsedAsCA.Connect();

    DefaultECDHEAuthListener* caAuthListener;
    caAuthListener = new DefaultECDHEAuthListener();

    EXPECT_EQ(ER_OK, busUsedAsCA.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", caAuthListener));

    qcc::GUID128 guildAuthorityGUID;
    GUID128 leafGuid;
    GUID128 interGuid;
    GUID128 inter2Guid;
    GUID128 caGUID;

    //PermissionMgmtTestHelper::GetGUID(TCBus, leafGuid);
    PermissionMgmtTestHelper::GetGUID(SC1Bus, leafGuid);
    PermissionMgmtTestHelper::GetGUID(SC1Bus, inter2Guid);
    PermissionMgmtTestHelper::GetGUID(SC2Bus, interGuid);
    PermissionMgmtTestHelper::GetGUID(busUsedAsCA, caGUID);

    SecurityApplicationProxy sapWithManager(managerBus, managerBus.GetUniqueName().c_str(), managerToManagerSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);

    uint8_t managerCN[] = { 1, 2, 3, 4 };
    uint8_t intermediateCN[] = { 9, 9, 9, 9 };
    uint8_t intermediate2CN[] = { 9, 9, 9, 9 };
    uint8_t leafCN[] = { 9, 0, 1, 2 };

    KeyInfoNISTP256 caKey;
    PermissionConfigurator& caPC = busUsedAsCA.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, caPC.GetSigningPublicKey(caKey));

    //
    // Create membership chain to be installed on peer 1
    //

    PermissionMgmtTestHelper::GetGUID(managerBus, guildAuthorityGUID);

    // SGA membership certificate
    qcc::MembershipCertificate caMembershipCert;
    caMembershipCert.SetSerial((uint8_t*)"1234", 5);
    caMembershipCert.SetIssuerCN(managerCN, 4);
    caMembershipCert.SetSubjectCN(managerCN, 4);
    caMembershipCert.SetSubjectPublicKey(caKey.GetPublicKey());
    caMembershipCert.SetGuild(managerGuid);
    caMembershipCert.SetCA(true);
    CertificateX509::ValidPeriod validity;
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    caMembershipCert.SetValidity(&validity);

    caPC.SignCertificate(caMembershipCert);

    InstallMembershipOnManager();

    // Intermediate membership certificate
    qcc::MembershipCertificate intermediateMembershipCert;
    intermediateMembershipCert.SetSerial((uint8_t*)"2345", 5);
    intermediateMembershipCert.SetIssuerCN(managerCN, 4);
    intermediateMembershipCert.SetSubjectCN(intermediateCN, 4);
    KeyInfoNISTP256 interKey;
    PermissionConfigurator& SC2PC = SC2Bus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, SC2PC.GetSigningPublicKey(interKey));
    intermediateMembershipCert.SetSubjectPublicKey(interKey.GetPublicKey());
    intermediateMembershipCert.SetGuild(interGuid);
    intermediateMembershipCert.SetCA(false);
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    intermediateMembershipCert.SetValidity(&validity);
    /* use the signing bus to sign the cert */
    caPC.SignCertificate(intermediateMembershipCert);

    // Intermediate 2 membership certificate
    qcc::MembershipCertificate intermediate2MembershipCert;
    intermediate2MembershipCert.SetSerial((uint8_t*)"2345", 5);
    intermediate2MembershipCert.SetIssuerCN(intermediateCN, 4);
    intermediate2MembershipCert.SetSubjectCN(intermediate2CN, 4);
    KeyInfoNISTP256 inter2Key;
    PermissionConfigurator& SC1PC = SC1Bus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, SC1PC.GetSigningPublicKey(inter2Key));
    intermediate2MembershipCert.SetSubjectPublicKey(inter2Key.GetPublicKey());
    intermediate2MembershipCert.SetGuild(interGuid);
    intermediate2MembershipCert.SetCA(false);
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    intermediate2MembershipCert.SetValidity(&validity);
    /* use the signing bus to sign the cert */
    SC2PC.SignCertificate(intermediateMembershipCert);

    // Leaf membership certificate
    qcc::MembershipCertificate leafMembershipCert;
    leafMembershipCert.SetSerial((uint8_t*)"3456", 5);
    leafMembershipCert.SetIssuerCN(intermediate2CN, 4);
    leafMembershipCert.SetSubjectCN(leafCN, 4);
    leafMembershipCert.SetSubjectPublicKey(TCKey.GetPublicKey());
    leafMembershipCert.SetGuild(leafGuid);
    leafMembershipCert.SetCA(false);
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    leafMembershipCert.SetValidity(&validity);
    /* use the signing bus to sign the cert */
    SC1PC.SignCertificate(leafMembershipCert);

    const size_t membershipChainSize = 4;
    MembershipCertificate membershipCertChain[membershipChainSize];
    membershipCertChain[0] = leafMembershipCert;
    membershipCertChain[1] = intermediate2MembershipCert;
    membershipCertChain[2] = intermediateMembershipCert;
    membershipCertChain[3] = caMembershipCert;

    EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", managerAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
    EXPECT_EQ(ER_OK, SC1Bus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", SC1AuthListener));
    EXPECT_EQ(ER_OK, SC2Bus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", SC2AuthListener));

    EXPECT_EQ(ER_FAIL, sapWithTC.InstallMembership(membershipCertChain, 4));
}

TEST_F(SecurityManagementPolicyTest, admin_security_group_members_can_also_call_members_for_managedapplication_default_policy)
{
    InstallMembershipOnManager();
    InstallMembershipOnSC1();
    InstallMembershipOnTC();

    SessionOpts opts;
    uint32_t sessionId;
    EXPECT_EQ(ER_OK, SC1Bus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts));

    SecurityApplicationProxy sapWithPeer1toPeer2(SC1Bus, TCBus.GetUniqueName().c_str(), sessionId);

    // Call UpdateIdentity
    // All Inclusive manifest
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");

    {
        PermissionPolicy::Rule::Member member[1];
        member[0].Set("*",
                      PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                      PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                      PermissionPolicy::Rule::Member::ACTION_MODIFY |
                      PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        manifest[0].SetMembers(1, member);
    }

    //Get manager key
    KeyInfoNISTP256& peer2Key = TCKey;

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(SC1Bus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    //Create identityCert
    const size_t certChainSize = 1;
    IdentityCertificate identityCertChain[certChainSize];
    GUID128 guid;


    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(managerBus,
                                                                  "1",
                                                                  managerGuid.ToString(),
                                                                  peer2Key.GetPublicKey(),
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

    EXPECT_EQ(ER_OK, sapWithPeer1toPeer2.UpdateIdentity(identityCertChain, certChainSize, manifest, manifestSize));
    EXPECT_EQ(ER_OK, sapWithPeer1toPeer2.SecureConnection(true));

    MsgArg identityArg;
    EXPECT_EQ(ER_OK, sapWithPeer1toPeer2.GetIdentity(identityArg));

    IdentityCertificate identityCertChain_out[certChainSize];
    EXPECT_EQ(ER_OK, sapWithPeer1toPeer2.MsgArgToIdentityCertChain(identityArg, identityCertChain_out, 1));

    ASSERT_EQ(identityCertChain[0].GetSerialLen(), identityCertChain_out[0].GetSerialLen());
    for (size_t i = 0; i < identityCertChain[0].GetSerialLen(); ++i) {
        EXPECT_EQ(identityCertChain[0].GetSerial()[i], identityCertChain_out[0].GetSerial()[i]);
    }

    PermissionPolicy policy;
    EXPECT_EQ(ER_OK, sapWithPeer1toPeer2.GetDefaultPolicy(policy));

    // Assume the default policy which is always 0
    EXPECT_EQ(static_cast<uint32_t>(0), policy.GetVersion());

    policy.SetVersion(policy.GetVersion() + 1);
    EXPECT_EQ(ER_OK, sapWithPeer1toPeer2.UpdatePolicy(policy));
    EXPECT_EQ(ER_OK, sapWithPeer1toPeer2.SecureConnection(true));

    EXPECT_EQ(ER_OK, sapWithPeer1toPeer2.GetPolicy(policy));

    EXPECT_EQ(static_cast<uint32_t>(1), policy.GetVersion());

    EXPECT_EQ(ER_OK, sapWithPeer1toPeer2.ResetPolicy());
    EXPECT_EQ(ER_OK, sapWithPeer1toPeer2.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithPeer1toPeer2.GetDefaultPolicy(policy));

    // Reset back to the default policy which is always 0
    EXPECT_EQ(static_cast<uint32_t>(0), policy.GetVersion());

    String membershipSerial = "2";
    qcc::MembershipCertificate peer2MembershipCertificate[1];
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert(membershipSerial,
                                                                    managerBus,
                                                                    TCBus.GetUniqueName(),
                                                                    peer2Key.GetPublicKey(),
                                                                    managerGuid,
                                                                    false,
                                                                    3600,
                                                                    peer2MembershipCertificate[0]
                                                                    ));
    EXPECT_EQ(ER_OK, sapWithPeer1toPeer2.InstallMembership(peer2MembershipCertificate, 1));

    MsgArg membershipSummariesArg;
    EXPECT_EQ(ER_OK, sapWithPeer1toPeer2.GetMembershipSummaries(membershipSummariesArg));

    // Call GetProperty("MembershipSummaries"). This call should show 2 membership certificates
    size_t count = membershipSummariesArg.v_array.GetNumElements();
    EXPECT_EQ((uint32_t)2, count);
    String*serials = new String[count];
    KeyInfoNISTP256* keyInfos = new KeyInfoNISTP256[count];
    ASSERT_EQ(ER_OK, sapWithPeer1toPeer2.MsgArgToCertificateIds(membershipSummariesArg, serials, keyInfos, count));

    String serial0("2");
    String serial1("1");
    // Compare the serial  in the certificates just retrieved
    // Membership certs are stored as a non-deterministic set so the order can
    // change. We just want to make sure both certificates are returned. The
    // only time order will remain the same is if the certificates are in a
    // certificate chain.
    if (serials[0] == serial0) {
        EXPECT_STREQ(serials[0].c_str(), serial0.c_str());
        EXPECT_STREQ(serials[1].c_str(), serial1.c_str());
    } else {
        EXPECT_STREQ(serials[0].c_str(), serial1.c_str());
        EXPECT_STREQ(serials[1].c_str(), serial0.c_str());
    }

    //Get manager key
    KeyInfoNISTP256 managerKey;
    PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(managerKey));

    EXPECT_EQ(ER_OK, sapWithPeer1toPeer2.RemoveMembership("2", managerKey));

    EXPECT_EQ(ER_OK, sapWithPeer1toPeer2.Reset());
}

TEST_F(SecurityManagementPolicyTest, non_group_members_can_not_call_managedapplication)
{
    InstallMembershipOnManager();
    InstallMembershipOnTC();

    SessionOpts opts;
    uint32_t sessionId;
    EXPECT_EQ(ER_OK, SC1Bus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts));

    SecurityApplicationProxy sapWithPeer1toPeer2(SC1Bus, TCBus.GetUniqueName().c_str());

    EXPECT_EQ(ER_PERMISSION_DENIED, sapWithPeer1toPeer2.Reset());

    // Call UpdateIdentity
    // All Inclusive manifest
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");

    {
        PermissionPolicy::Rule::Member member[1];
        member[0].Set("*",
                      PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                      PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                      PermissionPolicy::Rule::Member::ACTION_MODIFY |
                      PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        manifest[0].SetMembers(1, member);
    }

    //Get manager key
    KeyInfoNISTP256& peer2Key = TCKey;
    //PermissionConfigurator& pcPeer2 = peer2Bus.GetPermissionConfigurator();
    //EXPECT_EQ(ER_OK, pcPeer2.GetSigningPublicKey(peer2Key));

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(SC1Bus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    //Create identityCert
    const size_t certChainSize = 1;
    IdentityCertificate identityCertChain[certChainSize];
    GUID128 guid;


    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(managerBus,
                                                                  "1",
                                                                  managerGuid.ToString(),
                                                                  peer2Key.GetPublicKey(),
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

    EXPECT_EQ(ER_PERMISSION_DENIED, sapWithPeer1toPeer2.UpdateIdentity(identityCertChain, certChainSize, manifest, manifestSize));


    PermissionPolicy policy;
    CreatePermissivePolicy(policy, 1);
    EXPECT_EQ(ER_PERMISSION_DENIED, sapWithPeer1toPeer2.UpdatePolicy(policy));

    EXPECT_EQ(ER_PERMISSION_DENIED, sapWithPeer1toPeer2.ResetPolicy());

    String membershipSerial = "2";
    qcc::MembershipCertificate peer2MembershipCertificate[1];
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert(membershipSerial,
                                                                    managerBus,
                                                                    TCBus.GetUniqueName(),
                                                                    peer2Key.GetPublicKey(),
                                                                    managerGuid,
                                                                    false,
                                                                    3600,
                                                                    peer2MembershipCertificate[0]
                                                                    ));
    EXPECT_EQ(ER_PERMISSION_DENIED, sapWithPeer1toPeer2.InstallMembership(peer2MembershipCertificate, 1));

    //Get manager key
    KeyInfoNISTP256 managerKey;
    PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(managerKey));

    EXPECT_EQ(ER_PERMISSION_DENIED, sapWithPeer1toPeer2.RemoveMembership("1", managerKey));

    MsgArg identityCertArg;
    EXPECT_EQ(ER_PERMISSION_DENIED, sapWithPeer1toPeer2.GetIdentity(identityCertArg));
    MsgArg manifestArg;
    EXPECT_EQ(ER_PERMISSION_DENIED, sapWithPeer1toPeer2.GetManifest(manifestArg));
    String serial;
    qcc::KeyInfoNISTP256 issuerKey;
    EXPECT_EQ(ER_PERMISSION_DENIED, sapWithPeer1toPeer2.GetIdentityCertificateId(serial, issuerKey));
    uint32_t policyVersion;
    EXPECT_EQ(ER_PERMISSION_DENIED, sapWithPeer1toPeer2.GetPolicyVersion(policyVersion));
    EXPECT_EQ(ER_PERMISSION_DENIED, sapWithPeer1toPeer2.GetPolicy(policy));
    MsgArg membershipSummariesArg;
    EXPECT_EQ(ER_PERMISSION_DENIED, sapWithPeer1toPeer2.GetMembershipSummaries(membershipSummariesArg));
}

TEST_F(SecurityManagementPolicyTest, non_group_members_can_not_get_managedapplication_version)
{
    InstallMembershipOnManager();
    InstallMembershipOnTC();

    SessionOpts opts;
    uint32_t sessionId;
    EXPECT_EQ(ER_OK, SC1Bus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts));

    SecurityApplicationProxy sapWithPeer1toPeer2(SC1Bus, TCBus.GetUniqueName().c_str());

    uint16_t managedAppVersion;
    EXPECT_EQ(ER_PERMISSION_DENIED, sapWithPeer1toPeer2.GetManagedApplicationVersion(managedAppVersion));
}

TEST_F(SecurityManagementPolicyTest, non_members_can_call_managedapplication_methods_if_policy_allows)
{
    InstallMembershipOnManager();
    InstallMembershipOnTC();

    // peer2 == TC

    SecurityApplicationProxy sapWithPeer2(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    PermissionPolicy defaultPolicy;
    EXPECT_EQ(ER_OK, sapWithPeer2.GetDefaultPolicy(defaultPolicy));
    PermissionPolicy policy;
    CreatePermissivePolicy(policy, 1);
    EXPECT_EQ(ER_OK, UpdatePolicyWithValuesFromDefaultPolicy(defaultPolicy, policy, true, true, true));

    EXPECT_EQ(ER_OK, sapWithPeer2.UpdatePolicy(policy));
    EXPECT_EQ(ER_OK, sapWithPeer2.SecureConnection(true));

    BusAttachment nonASGBus("non-ASGBus", true);
    EXPECT_EQ(ER_OK, nonASGBus.Start());
    EXPECT_EQ(ER_OK, nonASGBus.Connect());

    InMemoryKeyStoreListener keyStoreListener;
    EXPECT_EQ(ER_OK, nonASGBus.RegisterKeyStoreListener(keyStoreListener));

    DefaultECDHEAuthListener authListener;
    EXPECT_EQ(ER_OK, nonASGBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", &authListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA ALLJOYN_ECDHE_NULL"));

    SessionOpts opts;
    uint32_t sessionId;
    EXPECT_EQ(ER_OK, nonASGBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts));

    SecurityApplicationProxy sapWithNonASGBustoPeer2(nonASGBus, TCBus.GetUniqueName().c_str());

    // Policy updated must secure connection to update keys.
    EXPECT_EQ(ER_OK, sapWithNonASGBustoPeer2.SecureConnection(true));
    EXPECT_EQ(ER_OK, sapWithNonASGBustoPeer2.Reset());

    EXPECT_EQ(ER_OK, nonASGBus.Stop());
    EXPECT_EQ(ER_OK, nonASGBus.Join());
}

TEST_F(SecurityManagementPolicyTest, unsuccessful_method_call_when_sga_delegation_is_false)
{
    BusAttachment busUsedAsCA("caBus");
    busUsedAsCA.Start();
    busUsedAsCA.Connect();

    DefaultECDHEAuthListener* caAuthListener;
    caAuthListener = new DefaultECDHEAuthListener();

    EXPECT_EQ(ER_OK, busUsedAsCA.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", caAuthListener));

    qcc::GUID128 guildAuthorityGUID;
    GUID128 leafGuid;
    GUID128 interGuid;
    GUID128 caGUID;

    //PermissionMgmtTestHelper::GetGUID(TCBus, leafGuid);
    PermissionMgmtTestHelper::GetGUID(SC1Bus, leafGuid);
    PermissionMgmtTestHelper::GetGUID(SC2Bus, interGuid);
    PermissionMgmtTestHelper::GetGUID(busUsedAsCA, caGUID);


    SecurityApplicationProxy sapWithManager(managerBus, managerBus.GetUniqueName().c_str(), managerToManagerSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    SecurityApplicationProxy sapWithSC1(managerBus, SC1Bus.GetUniqueName().c_str(), managerToSC1SessionId);

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    PermissionMgmtObj::GenerateManifestDigest(busUsedAsCA, manifest, 1, digest, Crypto_SHA256::DIGEST_SIZE);

    uint8_t managerCN[] = { 1, 2, 3, 4 };
    //uint8_t intermediateCN[] = { 9, 9, 9, 9 };
    uint8_t caCN[] = { 9, 9, 9, 9 };
    uint8_t leafCN[] = { 9, 0, 1, 2 };

    //Create the CA cert
    qcc::IdentityCertificate caCert;
    caCert.SetSerial((uint8_t*)"1234", 5);
    caCert.SetIssuerCN(caCN, 4);
    caCert.SetSubjectCN(caCN, 4);
    CertificateX509::ValidPeriod validityCA;
    validityCA.validFrom = qcc::GetEpochTimestamp() / 1000;
    validityCA.validTo = validityCA.validFrom + TEN_MINS;
    caCert.SetValidity(&validityCA);
    caCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    KeyInfoNISTP256 caKey;
    PermissionConfigurator& caPC = busUsedAsCA.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, caPC.GetSigningPublicKey(caKey));

    caCert.SetSubjectPublicKey(caKey.GetPublicKey());
    caCert.SetAlias("ca-cert-alias");
    caCert.SetCA(true);

    //sign the ca cert
    caPC.SignCertificate(caCert);

    // Create the intermediate certificate using TC
    qcc::IdentityCertificate TCCert;
    TCCert.SetSerial((uint8_t*)"2345", 5);
    TCCert.SetIssuerCN(caCN, 4);
    TCCert.SetSubjectCN(leafCN, 4);
    CertificateX509::ValidPeriod validity;
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    TCCert.SetValidity(&validity);
    TCCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);

    TCCert.SetSubjectPublicKey(&TCPublicKey);
    TCCert.SetAlias("intermediate-cert-alias");
    TCCert.SetCA(false);

    //sign the leaf cert
    EXPECT_EQ(ER_OK, caPC.SignCertificate(TCCert));

    //We need identityCert chain CA1->TC
    const size_t certChainSize = 2;
    IdentityCertificate identityCertChain[certChainSize];
    identityCertChain[0] = TCCert;
    identityCertChain[1] = caCert;

    //
    // Create membership chain to be installed on peer 1
    //

    PermissionMgmtTestHelper::GetGUID(managerBus, guildAuthorityGUID);
    KeyInfoNISTP256 sgaKey;
    PermissionConfigurator& managerPC = managerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, managerPC.GetSigningPublicKey(sgaKey));

    // SGA membership certificate
    qcc::MembershipCertificate sgaMembershipCert;
    sgaMembershipCert.SetSerial((uint8_t*)"1234", 5);
    sgaMembershipCert.SetIssuerCN(managerCN, 4);
    sgaMembershipCert.SetSubjectCN(managerCN, 4);
    sgaMembershipCert.SetSubjectPublicKey(sgaKey.GetPublicKey());
    sgaMembershipCert.SetGuild(managerGuid);
    sgaMembershipCert.SetCA(false);
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    sgaMembershipCert.SetValidity(&validity);

    managerPC.SignCertificate(sgaMembershipCert);

    MembershipCertificate managerMembershipCertChain[1];
    managerMembershipCertChain[0] = sgaMembershipCert;

    EXPECT_EQ(ER_OK, sapWithManager.InstallMembership(managerMembershipCertChain, 1));

    // Leaf membership certificate
    qcc::MembershipCertificate leafMembershipCert;
    leafMembershipCert.SetSerial((uint8_t*)"3456", 5);
    leafMembershipCert.SetIssuerCN(managerCN, 4);
    leafMembershipCert.SetSubjectCN(leafCN, 4);
    leafMembershipCert.SetSubjectPublicKey(TCKey.GetPublicKey());
    leafMembershipCert.SetGuild(leafGuid);
    leafMembershipCert.SetCA(false);
    validity.validFrom = qcc::GetEpochTimestamp() / 1000;
    validity.validTo = validity.validFrom + TEN_MINS;
    leafMembershipCert.SetValidity(&validity);
    /* use the signing bus to sign the cert */
    managerPC.SignCertificate(leafMembershipCert);

    const size_t membershipChainSize = 2;
    MembershipCertificate membershipCertChain[membershipChainSize];
    membershipCertChain[0] = leafMembershipCert;
    membershipCertChain[1] = sgaMembershipCert;

    EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", managerAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
    EXPECT_EQ(ER_OK, SC1Bus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", SC1AuthListener));
    EXPECT_EQ(ER_OK, SC2Bus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", SC2AuthListener));

    //EXPECT_EQ(ER_OK, sapWithTC.Reset());
    EXPECT_EQ(ER_INVALID_CERTIFICATE, sapWithTC.InstallMembership(membershipCertChain, 2));
}

/*
 * Purpose:
 * Before claim, any peer trying to call methods on the
 * org.alljoyn.Bus.Security.ManagedApplication interface should fail.
 *
 * Setup:
 * Establish an ECDHE_ECDSA based session between peer1 and peer2.
 *
 * Peer1 calls the following methods on the peer2:
 *
 * Reset
 * UpdateIdentity
 * UpdatePolicy
 * ResetPolicy
 * InstallMembership
 * RemoveMembership
 *
 * Peer1 tries to fetch the following properties on peer2:
 * Version
 * Identity
 * Manifest
 * IdentityCertificateId
 * PolicyVersion
 * Policy
 * DefaultPolicy
 * MembershipSummaries
 *
 * Verify:
 * The method calls and Get property calls should fail peer2. bus is not
 * yet claimed.
 */
TEST(SecurityManagementPolicy2Test, DISABLED_ManagedApplication_method_calls_should_fail_before_claim)
{
    BusAttachment SC("SC");
    TCManagementAttachment TC("TC");

    EXPECT_EQ(ER_OK, SC.Start());
    EXPECT_EQ(ER_OK, SC.Connect());

    TC.Connect(NULL);
    TC.Start();

    InMemoryKeyStoreListener bus1KeyStoreListener;

    // Register in memory keystore listeners
    EXPECT_EQ(ER_OK, SC.RegisterKeyStoreListener(bus1KeyStoreListener));

    SecurityManagementPolicy2AuthListener bus1AuthListener;

    EXPECT_EQ(ER_OK, SC.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", &bus1AuthListener));
    EXPECT_EQ(ER_OK, TC.EnablePeerSecurity("ALLJOYN_ECDHE_NULL"));

    SessionOpts opts;
    SessionPort sessionPort = 42;
    SecurityManagementTestSessionPortListener sessionPortListener;
    EXPECT_EQ(ER_OK, TC.BindSessionPort(sessionPort));

    uint32_t sessionId;
    EXPECT_EQ(ER_OK, SC.JoinSession(TC.GetUniqueName().c_str(), sessionPort, NULL, sessionId, opts));

    SecurityApplicationProxy sapWithBus1toSelf(SC, SC.GetUniqueName().c_str());
    PermissionConfigurator::ApplicationState applicationStateManager;
    EXPECT_EQ(ER_OK, sapWithBus1toSelf.GetApplicationState(applicationStateManager));
    EXPECT_EQ(PermissionConfigurator::NOT_CLAIMABLE, applicationStateManager);

    {
        SecurityApplicationProxy sapBus1toBus2(SC, TC.GetUniqueName().c_str(), sessionId);
        PermissionConfigurator::ApplicationState applicationStateSC;
        EXPECT_EQ(ER_OK, sapBus1toBus2.GetApplicationState(applicationStateSC));
        EXPECT_EQ(PermissionConfigurator::NOT_CLAIMABLE, applicationStateSC);

        // Call Reset
        EXPECT_EQ(ER_PERMISSION_DENIED, sapBus1toBus2.Reset());

        // Call UpdateIdentity
        // All Inclusive manifest
        const size_t manifestSize = 1;
        PermissionPolicy::Rule manifest[manifestSize];
        manifest[0].SetObjPath("*");
        manifest[0].SetInterfaceName("*");

        {
            PermissionPolicy::Rule::Member member[1];
            member[0].Set("*",
                          PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                          PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                          PermissionPolicy::Rule::Member::ACTION_MODIFY |
                          PermissionPolicy::Rule::Member::ACTION_OBSERVE);
            manifest[0].SetMembers(1, member);
        }

        //Get manager key
        KeyInfoNISTP256 bus1Key;
        PermissionConfigurator& pcBus1 = SC.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcBus1.GetSigningPublicKey(bus1Key));

        uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
        EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(SC,
                                                                   manifest, manifestSize,
                                                                   digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

        //Create identityCert
        const size_t certChainSize = 1;
        IdentityCertificate identityCertChain[certChainSize];
        GUID128 guid;


        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(SC,
                                                                      "0",
                                                                      guid.ToString(),
                                                                      bus1Key.GetPublicKey(),
                                                                      "Alias",
                                                                      3600,
                                                                      identityCertChain[0],
                                                                      digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

        EXPECT_EQ(ER_PERMISSION_DENIED, sapBus1toBus2.UpdateIdentity(identityCertChain, certChainSize, manifest, manifestSize));
        EXPECT_EQ(ER_OK, sapBus1toBus2.SecureConnection(true));

        // Call UpdatePolicy
        PermissionPolicy policy;
        sapBus1toBus2.GetDefaultPolicy(policy);
        policy.SetVersion(1);
        EXPECT_EQ(ER_PERMISSION_DENIED, sapBus1toBus2.UpdatePolicy(policy));

        // Call ResetPolicy
        EXPECT_EQ(ER_PERMISSION_DENIED, sapBus1toBus2.ResetPolicy());

        // Call InstallMembership
        qcc::MembershipCertificate membershipCertificate[1];
        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("1",
                                                                        SC,
                                                                        SC.GetUniqueName(),
                                                                        bus1Key.GetPublicKey(),
                                                                        guid,
                                                                        false,
                                                                        3600,
                                                                        membershipCertificate[0]
                                                                        ));
        EXPECT_EQ(ER_PERMISSION_DENIED, sapBus1toBus2.InstallMembership(membershipCertificate, 1));
        // Call RemoveMembership
        EXPECT_EQ(ER_PERMISSION_DENIED, sapBus1toBus2.RemoveMembership("1", bus1Key));
    }

    {
        SecurityApplicationProxy sapBus1toBus2(SC, TC.GetUniqueName().c_str(), sessionId);
        sapBus1toBus2.SecureConnection(true);
        // If ECDHE_ECDSA security is not established none of the method calls
        // will succeed.
        ASSERT_TRUE(bus1AuthListener.authenticationSuccessfull);

        // Fetch Version property
        uint16_t version;
        EXPECT_EQ(ER_PERMISSION_DENIED, sapBus1toBus2.GetManagedApplicationVersion(version));

        // Fetch Identity property
        MsgArg identityCertificate;
        EXPECT_EQ(ER_PERMISSION_DENIED, sapBus1toBus2.GetIdentity(identityCertificate));

        // Fetch Manifest property
        MsgArg manifest;
        EXPECT_EQ(ER_PERMISSION_DENIED, sapBus1toBus2.GetManifest(manifest));

        // Fetch IdentityCertificateId property
        String serial;
        qcc::KeyInfoNISTP256 issuerKey;
        EXPECT_EQ(ER_PERMISSION_DENIED, sapBus1toBus2.GetIdentityCertificateId(serial, issuerKey));

        // Fetch PolicyVersion property
        uint32_t policyVersion;
        EXPECT_EQ(ER_PERMISSION_DENIED, sapBus1toBus2.GetPolicyVersion(policyVersion));

        // Fetch Policy property
        PermissionPolicy policy;
        EXPECT_EQ(ER_PERMISSION_DENIED, sapBus1toBus2.GetPolicy(policy));

        // Fetch DefaultPolicy property
        EXPECT_EQ(ER_PERMISSION_DENIED, sapBus1toBus2.GetDefaultPolicy(policy));

        // Fetch MembershipSummaries property
        MsgArg membershipSummaries;
        EXPECT_EQ(ER_PERMISSION_DENIED, sapBus1toBus2.GetMembershipSummaries(membershipSummaries));
    }
}
