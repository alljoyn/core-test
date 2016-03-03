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

/**
 * This is a collection of misc. test cases that did not fit into another
 * catagory but are still related to security2.0 feature.
 */

#define WAIT_SIGNAL 1000

static const char psk_hint[] = "<anonymous>";
static const char psk_char[] = "faaa0af3dd3f1e0379da046a3ab6ca44";
static const char ecspeke_password[] = "1234";
static uint32_t authenticationSuccessfull = FALSE;
static AJ_Status TCAuthListener(uint32_t mechanism, uint32_t command, AJ_Credential* cred)
{
    AJ_Status status = AJ_ERR_INVALID;

    AJ_AlwaysPrintf(("TCAuthListener mechanism %x command %x\n", mechanism, command));

    switch (mechanism) {
    case AUTH_SUITE_ECDHE_NULL:
        cred->expiration = 1;
        status = AJ_OK;
        break;

    case AUTH_SUITE_ECDHE_SPEKE:
        switch (command) {
        case AJ_CRED_PASSWORD:
            cred->data = (uint8_t*)ecspeke_password;
            cred->len = strlen(ecspeke_password);
            cred->expiration = 1;
            status = AJ_OK;
            break;
        }
        break;

    case AUTH_SUITE_ECDHE_PSK:
        switch (command) {
        case AJ_CRED_PUB_KEY:
            cred->data = (uint8_t*) psk_hint;
            cred->len = strlen(psk_hint);
            cred->expiration = 1;
            status = AJ_OK;
            break;

        case AJ_CRED_PRV_KEY:
            cred->data = (uint8_t*) psk_char;
            cred->len = strlen(psk_char);
            cred->expiration = 1;
            status = AJ_OK;
            break;
        }
        break;

    default:
        break;
    }
    return status;
}

static void TCAuthCallback(const void* context, AJ_Status status)
{
    if (AJ_OK == status) {
        authenticationSuccessfull = TRUE;
    }
    Promise<AJ_Status>* p = (Promise<AJ_Status>*) context;
    p->SetResult(status);
}

static void ClearFlags() {
    authenticationSuccessfull = FALSE;
}

class TCAuthenticationAttachment : public TCBusAttachment {
  public:
    TCAuthenticationAttachment(const char* name) : TCBusAttachment(name, TCAuthListener, TCAuthCallback) { }
};

class SecurityAuthenticationTestSessionPortListener : public SessionPortListener {
  public:
    virtual bool AcceptSessionJoiner(SessionPort sessionPort, const char* joiner, const SessionOpts& opts) {
        QCC_UNUSED(sessionPort);
        QCC_UNUSED(joiner);
        QCC_UNUSED(opts);
        return true;
    }
};

class SecurityAuthTestHelper {
  public:
    static QStatus UpdatePolicyWithValuesFromDefaultPolicy(const PermissionPolicy& defaultPolicy,
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
            QCC_ASSERT(idx <= count);
            acls[idx++] = policy.GetAcls()[cnt];
        }
        policy.SetAcls(count, acls);
        delete [] acls;
        return ER_OK;
    }

    /*
     * Creates a PermissionPolicy that allows everything.
     * @policy[out] the policy to set
     * @version[in] the version number for the policy
     */
    static void GeneratePermissivePolicyAll(PermissionPolicy& policy, uint32_t version) {
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
     * Creates a PermissionPolicy that allows everything.
     * @policy[out] the policy to set
     * @version[in] the version number for the policy
     */
    static void GeneratePermissivePolicyAnyTrusted(PermissionPolicy& policy, uint32_t version) {
        policy.SetVersion(version);
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
};

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

class SecurityAuthenticationAuthListener : public AuthListener {
  public:
    SecurityAuthenticationAuthListener() :
        requestCredentialsCalled(false),
        verifyCredentialsCalled(false),
        authenticationSuccessfull(false),
        securityViolationCalled(false)
    {
    }

    void ClearFlags() {
        requestCredentialsCalled = false;
        verifyCredentialsCalled = false;
        authenticationSuccessfull = false;
        securityViolationCalled = false;
    }
    QStatus RequestCredentialsAsync(const char* authMechanism, const char* authPeer, uint16_t authCount, const char* userId, uint16_t credMask, void* context)
    {
        QCC_UNUSED(authPeer);
        QCC_UNUSED(authCount);
        QCC_UNUSED(userId);
        QCC_UNUSED(credMask);
        requestCredentialsCalled = true;
        Credentials creds;
        if (strcmp(authMechanism, "ALLJOYN_ECDHE_NULL") == 0) {
            return RequestCredentialsResponse(context, true, creds);
        }
        if (strcmp(authMechanism, "ALLJOYN_ECDHE_PSK") == 0) {
            creds.SetPassword(psk_char);
            return RequestCredentialsResponse(context, true, creds);
        }
        if (strcmp(authMechanism, "ALLJOYN_ECDHE_SPEKE") == 0) {
            creds.SetPassword(ecspeke_password);
            return RequestCredentialsResponse(context, true, creds);
        }
        if (strcmp(authMechanism, "ALLJOYN_SRP_KEYX") == 0) {
            if (credMask & AuthListener::CRED_PASSWORD) {
                creds.SetPassword("123456");
            }
            return RequestCredentialsResponse(context, true, creds);
        }
        if (strcmp(authMechanism, "ALLJOYN_ECDHE_ECDSA") == 0) {
            if ((credMask& AuthListener::CRED_PRIVATE_KEY) == AuthListener::CRED_PRIVATE_KEY) {
                String pk(ecdsaPrivateKeyPEM, strlen(ecdsaPrivateKeyPEM));
                creds.SetPrivateKey(pk);
            }
            if ((credMask& AuthListener::CRED_CERT_CHAIN) == AuthListener::CRED_CERT_CHAIN) {
                String cert(ecdsaCertChainX509PEM, strlen(ecdsaCertChainX509PEM));
                creds.SetCertChain(cert);
            }
            return RequestCredentialsResponse(context, true, creds);
        }
        return RequestCredentialsResponse(context, false, creds);
    }
    QStatus VerifyCredentialsAsync(const char* authMechanism, const char* authPeer, const Credentials& creds, void* context) {
        QCC_UNUSED(authMechanism);
        QCC_UNUSED(authPeer);
        QCC_UNUSED(creds);
        verifyCredentialsCalled = true;
        if (strcmp(authMechanism, "ALLJOYN_ECDHE_ECDSA") == 0) {
            if (creds.IsSet(AuthListener::CRED_CERT_CHAIN)) {
                return VerifyCredentialsResponse(context, false);
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
        securityViolationCalled = true;
    }
    bool requestCredentialsCalled;
    bool verifyCredentialsCalled;
    bool authenticationSuccessfull;
    bool securityViolationCalled;

};

static void GetAppPublicKey(BusAttachment& bus, ECCPublicKey& publicKey)
{
    KeyInfoNISTP256 keyInfo;
    bus.GetPermissionConfigurator().GetSigningPublicKey(keyInfo);
    publicKey = *keyInfo.GetPublicKey();
}

class SecurityAuthenticationTest : public testing::Test {
  public:
    SecurityAuthenticationTest() :
        managerBus("SecurityAuthenticationManager", true),
        SCBus("SecurityAuthenticationSC", true),
        TCBus("SecurityAuthenticationTC"),
        managerKeyStoreListener(),
        SCKeyStoreListener(),
        managerAuthListener(),
        SCAuthListener(),
        managerSessionPortListener(),
        SCSessionPortListener(),
        managerToSCSessionId(0),
        managerToTCSessionId(0),
        SCSessionPort(42),
        TCSessionPort(42)
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

        // To avoid cross-talk, i.e. thin leaf node connect to unintended
        // routing nodes, generate and advertise a random routing node prefix.
        qcc::String routingNodePrefix = "test.rnPrefix.randhex" +
                                        qcc::RandHexString(64);
        qcc::String advertisingPrefix = "quiet@" + routingNodePrefix;
        ASSERT_EQ(ER_OK, managerBus.AdvertiseName(advertisingPrefix.c_str(), ajn::TRANSPORT_ANY));

        TCBus.Connect(routingNodePrefix.c_str());
        TCBus.Start();

        EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &managerAuthListener));
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA"));
        /* set claimable */
        TCBus.SetApplicationState(APP_STATE_CLAIMABLE);

        SessionOpts opts1;
        SessionId managerToManagerSessionId;
        SessionPort managerSessionPort = 42;
        EXPECT_EQ(ER_OK, managerBus.BindSessionPort(managerSessionPort, opts1, managerSessionPortListener));

        SessionOpts opts2;
        EXPECT_EQ(ER_OK, SCBus.BindSessionPort(SCSessionPort, opts2, SCSessionPortListener));

        SessionOpts opts3;
        EXPECT_EQ(ER_OK, TCBus.BindSessionPort(TCSessionPort));

        EXPECT_EQ(ER_OK, managerBus.JoinSession(managerBus.GetUniqueName().c_str(), managerSessionPort, NULL, managerToManagerSessionId, opts1));
        EXPECT_EQ(ER_OK, managerBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, NULL, managerToSCSessionId, opts2));
        EXPECT_EQ(ER_OK, managerBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, managerToTCSessionId, opts3));

        //-----------------------Claim each bus Attachments------------------
        SecurityApplicationProxy sapWithManager(managerBus, managerBus.GetUniqueName().c_str(), managerToManagerSessionId);
        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
        SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);


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
        KeyInfoNISTP256 managerKey;
        PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(managerKey));

        //Create SC key
        KeyInfoNISTP256 SCKey;
        PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

        //Create TC key
        EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));
        TCKey.SetPublicKey(&TCPublicKey);

        //------------ Claim self(managerBus), SC, and TC --------
        //Random GUID used for the SecurityManager
        GUID128 managerGuid;

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


        ECCPublicKey managerPublicKey;
        GetAppPublicKey(managerBus, managerPublicKey);
        ASSERT_EQ(*managerKey.GetPublicKey(), managerPublicKey);

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

        /* set claimable */
        SCBus.GetPermissionConfigurator().SetApplicationState(PermissionConfigurator::CLAIMABLE);
        //Manager claims Peers
        EXPECT_EQ(ER_OK, sapWithSC.Claim(managerKey,
                                            managerGuid,
                                            managerKey,
                                            identityCertChainSC, certChainSize,
                                            manifest, manifestSize));

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
        EXPECT_EQ(ER_OK, sapWithTC.Claim(managerKey,
                                            managerGuid,
                                            managerKey,
                                            identityCertChainTC, certChainSize,
                                            manifest, manifestSize));

        EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &managerAuthListener));
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));

        //--------- InstallMembership certificates on self, SC, and TC

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

        EXPECT_EQ(ER_OK, sapWithSC.InstallMembership(SCMembershipCertificate, 1));

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
        EXPECT_EQ(ER_OK, sapWithTC.InstallMembership(TCMembershipCertificate, 1));
    }

    virtual void TearDown() {
        EXPECT_EQ(ER_OK, TCBus.Stop());
        EXPECT_EQ(ER_OK, TCBus.Join());
        EXPECT_EQ(ER_OK, managerBus.Stop());
        EXPECT_EQ(ER_OK, managerBus.Join());
        EXPECT_EQ(ER_OK, SCBus.Stop());
        EXPECT_EQ(ER_OK, SCBus.Join());
    }
    BusAttachment managerBus;
    BusAttachment SCBus;
    TCAuthenticationAttachment TCBus;

    InMemoryKeyStoreListener managerKeyStoreListener;
    InMemoryKeyStoreListener SCKeyStoreListener;

    SecurityAuthenticationAuthListener managerAuthListener;
    SecurityAuthenticationAuthListener SCAuthListener;

    SecurityAuthenticationTestSessionPortListener managerSessionPortListener;
    SecurityAuthenticationTestSessionPortListener SCSessionPortListener;

    SessionId managerToSCSessionId;
    SessionId managerToTCSessionId;

    SessionPort SCSessionPort;
    SessionPort TCSessionPort;

    ECCPublicKey TCPublicKey;
    KeyInfoNISTP256 TCKey;
};

/*
 * Purpose:
 * Verify that when both sides have one policy ACL with peer type
 * ALL, ECDHE_ECDSA based session cannot be set up. But, all other sessions like
 * NULL, ECDHE_PSK, ECHDE_SPEKE and SRP based sessions can be set.
 *
 * Setup:
 * A and B are claimed.
 * Both their identity certificates are signed by the CA.
 *
 * Peer A has a local policy with ALL Peer Type
 * Peer B has a local policy with ALL Peer Type
 * Policy rules and manifest rules allow everything.
 *
 * Case 1: A and B set up a ECDHE_NULL based session.
 * Case 2: A and B set up a ECDHE_PSK based session.
 * Case 2.1: A and B set up an ECDHE_SPEKE based session.
 * Case 3: A and B set up a SRP based session.
 * Case 4: A and B set up a ECDHE_ECDSA based session.
 *
 * Verification:
 * Case 1-3: Secure sessions can be set up successfully.
 * Case 4: Secure session cannot be set up because the policy does not have any
 *         authorities who can verify the IC of the remote peer.
 */
TEST_F(SecurityAuthenticationTest, authenticate_test1_case1_ECDHE_NULL) {
    //---------------- Install Policy --------------
    {
        PermissionPolicy policy;
        SecurityAuthTestHelper::GeneratePermissivePolicyAll(policy, 1);
        SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
        EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(policy));
        // Don't instantly call SecureConnection we want to control when SecureConnection is called.
    }
    {
        PermissionPolicy policy;
        SecurityAuthTestHelper::GeneratePermissivePolicyAll(policy, 1);
        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
        EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(policy));
        // Don't instantly call SecureConnection we want to control when SecureConnection is called.
    }

    uint32_t sessionId;
    SessionOpts opts;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, sessionId));
    {
        ClearFlags();
        SCAuthListener.ClearFlags();
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL"));
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));

        EXPECT_TRUE(authenticationSuccessfull);

        EXPECT_TRUE(SCAuthListener.requestCredentialsCalled);
        EXPECT_FALSE(SCAuthListener.verifyCredentialsCalled);
        EXPECT_TRUE(SCAuthListener.authenticationSuccessfull);
        EXPECT_FALSE(SCAuthListener.securityViolationCalled);
    }
}

TEST_F(SecurityAuthenticationTest, authenticate_test1_case2_ECDHE_PSK) {
    //---------------- Install Policy --------------
    {
        PermissionPolicy policy;
        SecurityAuthTestHelper::GeneratePermissivePolicyAll(policy, 1);
        SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
        EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(policy));
        // Don't instantly call SecureConnection we want to control when SecureConnection is called.
    }
    {
        PermissionPolicy policy;
        SecurityAuthTestHelper::GeneratePermissivePolicyAll(policy, 1);
        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
        EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(policy));
        // Don't instantly call SecureConnection we want to control when SecureConnection is called.
    }

    uint32_t sessionId;
    SessionOpts opts;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, sessionId));
    {
        ClearFlags();
        SCAuthListener.ClearFlags();
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_PSK"));
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_PSK", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));

        EXPECT_TRUE(authenticationSuccessfull);

        EXPECT_TRUE(SCAuthListener.requestCredentialsCalled);
        EXPECT_FALSE(SCAuthListener.verifyCredentialsCalled);
        EXPECT_TRUE(SCAuthListener.authenticationSuccessfull);
        EXPECT_FALSE(SCAuthListener.securityViolationCalled);
    }
}

TEST_F(SecurityAuthenticationTest, authenticate_test1_case2_1_ECDHE_SPEKE) {
    //---------------- Install Policy --------------
    {
        PermissionPolicy policy;
        SecurityAuthTestHelper::GeneratePermissivePolicyAll(policy, 1);
        SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
        EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(policy));
        // Don't instantly call SecureConnection we want to control when SecureConnection is called.
    }
    {
        PermissionPolicy policy;
        SecurityAuthTestHelper::GeneratePermissivePolicyAll(policy, 1);
        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
        EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(policy));
        // Don't instantly call SecureConnection we want to control when SecureConnection is called.
    }

    uint32_t sessionId;
    SessionOpts opts;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, sessionId));
    {
        ClearFlags();
        SCAuthListener.ClearFlags();
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_SPEKE"));
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_SPEKE", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));

        EXPECT_TRUE(authenticationSuccessfull);

        EXPECT_TRUE(SCAuthListener.requestCredentialsCalled);
        EXPECT_FALSE(SCAuthListener.verifyCredentialsCalled);
        EXPECT_TRUE(SCAuthListener.authenticationSuccessfull);
        EXPECT_FALSE(SCAuthListener.securityViolationCalled);
    }
}

TEST_F(SecurityAuthenticationTest, authenticate_test1_case4_ECDHE_ECDSA) {
    //---------------- Install Policy --------------
    {
        PermissionPolicy policy;
        SecurityAuthTestHelper::GeneratePermissivePolicyAll(policy, 1);
        SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
        EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(policy));
        // Don't instantly call SecureConnection we want to control when SecureConnection is called.
    }
    {
        PermissionPolicy policy;
        SecurityAuthTestHelper::GeneratePermissivePolicyAll(policy, 1);
        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
        EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(policy));
        // Don't instantly call SecureConnection we want to control when SecureConnection is called.
    }

    uint32_t sessionId;
    SessionOpts opts;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, sessionId));
    {
        ClearFlags();
        SCAuthListener.ClearFlags();
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
        EXPECT_EQ(ER_AUTH_FAIL, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));

        EXPECT_FALSE(authenticationSuccessfull);

        EXPECT_FALSE(SCAuthListener.requestCredentialsCalled);
        EXPECT_TRUE(SCAuthListener.verifyCredentialsCalled);
        EXPECT_FALSE(SCAuthListener.authenticationSuccessfull);
        EXPECT_FALSE(SCAuthListener.securityViolationCalled);
    }
}

/*
 * Purpose:
 * Verify that when both sides have one policy ACL with peer type ANY_TRUSTED,
 * ECDHE_ECDSA based session cannot be set up. But, all other sessions like
 * NULL, ECDHE_PSK, ECDHE_SPEKE and SRP based sessions can be set.
 *
 * Setup:
 * A and B are claimed.
 * Both their identity certificates are signed by the CA.
 *
 * Peer A has a local policy with ANY_TRUSTED Peer Type
 * Peer B has a local policy with ANY_TRUSTED Peer Type
 * Policy rules and manifest rules allow everything.
 *
 * Case 1: A and B set up a ECDHE_NULL based session.
 * Case 2: A and B set up a ECDHE_PSK based session.
 * Case 2.1: A and B set up a ECDHE_SPEKE based session.
 * Case 3: A and B set up a SRP based session.
 * Case 4: A and B set up a ECDHE_ECDSA based session.
 *
 * Verification:
 * Case 1-3: Secure sessions can be set up successfully.
 * Case 4: Secure session cannot be set up because the policy does not have any
 *         authorities who can verify the IC of the remote peer.
 */
TEST_F(SecurityAuthenticationTest, authenticate_test2_case1_ECDHE_NULL) {
    //---------------- Install Policy --------------
    {
        PermissionPolicy policy;
        SecurityAuthTestHelper::GeneratePermissivePolicyAnyTrusted(policy, 1);
        SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
        EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(policy));
        // Don't instantly call SecureConnection we want to control when SecureConnection is called.
    }
    {
        PermissionPolicy policy;
        SecurityAuthTestHelper::GeneratePermissivePolicyAnyTrusted(policy, 1);
        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
        EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(policy));
        // Don't instantly call SecureConnection we want to control when SecureConnection is called.
    }

    uint32_t sessionId;
    SessionOpts opts;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, sessionId));
    {
        ClearFlags();
        SCAuthListener.ClearFlags();
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL"));
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));

        EXPECT_TRUE(authenticationSuccessfull);

        EXPECT_TRUE(SCAuthListener.requestCredentialsCalled);
        EXPECT_FALSE(SCAuthListener.verifyCredentialsCalled);
        EXPECT_TRUE(SCAuthListener.authenticationSuccessfull);
        EXPECT_FALSE(SCAuthListener.securityViolationCalled);
    }
}

TEST_F(SecurityAuthenticationTest, authenticate_test2_case2_ECDHE_PSK) {
    //---------------- Install Policy --------------
    {
        PermissionPolicy policy;
        SecurityAuthTestHelper::GeneratePermissivePolicyAnyTrusted(policy, 1);
        SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
        EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(policy));
        // Don't instantly call SecureConnection we want to control when SecureConnection is called.
    }
    {
        PermissionPolicy policy;
        SecurityAuthTestHelper::GeneratePermissivePolicyAnyTrusted(policy, 1);
        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
        EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(policy));
        // Don't instantly call SecureConnection we want to control when SecureConnection is called.
    }

    uint32_t sessionId;
    SessionOpts opts;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, sessionId));
    {
        ClearFlags();
        SCAuthListener.ClearFlags();
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_PSK"));
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_PSK", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));

        EXPECT_TRUE(authenticationSuccessfull);

        EXPECT_TRUE(SCAuthListener.requestCredentialsCalled);
        EXPECT_FALSE(SCAuthListener.verifyCredentialsCalled);
        EXPECT_TRUE(SCAuthListener.authenticationSuccessfull);
        EXPECT_FALSE(SCAuthListener.securityViolationCalled);
    }
}

TEST_F(SecurityAuthenticationTest, authenticate_test2_case2_1_ECDHE_SPEKE) {
    //---------------- Install Policy --------------
    {
        PermissionPolicy policy;
        SecurityAuthTestHelper::GeneratePermissivePolicyAnyTrusted(policy, 1);
        SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
        EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(policy));
        // Don't instantly call SecureConnection we want to control when SecureConnection is called.
    }
    {
        PermissionPolicy policy;
        SecurityAuthTestHelper::GeneratePermissivePolicyAnyTrusted(policy, 1);
        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
        EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(policy));
        // Don't instantly call SecureConnection we want to control when SecureConnection is called.
    }

    uint32_t sessionId;
    SessionOpts opts;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, sessionId));
    {
        ClearFlags();
        SCAuthListener.ClearFlags();
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_SPEKE"));
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_SPEKE", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));

        EXPECT_TRUE(authenticationSuccessfull);

        EXPECT_TRUE(SCAuthListener.requestCredentialsCalled);
        EXPECT_FALSE(SCAuthListener.verifyCredentialsCalled);
        EXPECT_TRUE(SCAuthListener.authenticationSuccessfull);
        EXPECT_FALSE(SCAuthListener.securityViolationCalled);
    }
}

TEST_F(SecurityAuthenticationTest, authenticate_test2_case4_ECDHE_ECDSA) {
    //---------------- Install Policy --------------
    {
        PermissionPolicy policy;
        SecurityAuthTestHelper::GeneratePermissivePolicyAnyTrusted(policy, 1);
        SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
        EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(policy));
        // Don't instantly call SecureConnection we want to control when SecureConnection is called.
    }
    {
        PermissionPolicy policy;
        SecurityAuthTestHelper::GeneratePermissivePolicyAnyTrusted(policy, 1);
        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
        EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(policy));
        // Don't instantly call SecureConnection we want to control when SecureConnection is called.
    }

    uint32_t sessionId;
    SessionOpts opts;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, sessionId));
    {
        ClearFlags();
        SCAuthListener.ClearFlags();
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
        EXPECT_EQ(ER_AUTH_FAIL, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));

        EXPECT_FALSE(authenticationSuccessfull);

        EXPECT_FALSE(SCAuthListener.requestCredentialsCalled);
        EXPECT_TRUE(SCAuthListener.verifyCredentialsCalled);
        EXPECT_FALSE(SCAuthListener.authenticationSuccessfull);
        EXPECT_FALSE(SCAuthListener.securityViolationCalled);
    }
}

class SecurityAuthentication2AuthListener : public DefaultECDHEAuthListener {
  public:
    SecurityAuthentication2AuthListener() {
        SetPSK((uint8_t*) psk_char, strlen(psk_char));
        SetPassword((uint8_t*)ecspeke_password, strlen(ecspeke_password));
    }

    QStatus RequestCredentialsAsync(const char* authMechanism, const char* authPeer, uint16_t authCount, const char* userId, uint16_t credMask, void* context)
    {
        Credentials creds;
        if (strcmp(authMechanism, "ALLJOYN_SRP_KEYX") == 0) {
            if (credMask & AuthListener::CRED_PASSWORD) {
                creds.SetPassword("123456");
            }
            return RequestCredentialsResponse(context, true, creds);
        }

        return DefaultECDHEAuthListener::RequestCredentialsAsync(authMechanism, authPeer, authCount, userId, credMask, context);
    }
};

class SecurityAuthenticationTest2 : public testing::Test {
  public:
    SecurityAuthenticationTest2() :
        managerBus("SecurityAuthenticationManager", true),
        SCBus("SecurityAuthenticationSC", true),
        TCBus("SecurityAuthenticationTC"),

        busUsedAsCA("foo1"),
        busUsedAsCA1("foo2"),
        busUsedAsLivingRoom("foo3"),
        busUsedAsPeerC("foo4"),

        managerKeyStoreListener(),
        SCKeyStoreListener(),

        listener1(),
        listener2(),
        listener3(),
        listener4(),

        managerAuthListener(),
        SCAuthListener(),

        managerSessionPortListener(),
        SCSessionPortListener(),

        managerToSCSessionId(0),
        managerToTCSessionId(0),

        SCSessionPort(42),
        TCSessionPort(42),

        managerGuid(),
        caGuid(),
        livingRoomSGID(),

        manifestSize(1)
    {
    }

    virtual void SetUp() {
        EXPECT_EQ(ER_OK, managerBus.Start());
        EXPECT_EQ(ER_OK, managerBus.Connect());
        EXPECT_EQ(ER_OK, SCBus.Start());
        EXPECT_EQ(ER_OK, SCBus.Connect());

        // To avoid cross-talk, i.e. thin leaf node connect to unintended
        // routing nodes, generate and advertise a random routing node prefix.
        qcc::String routingNodePrefix = "test.rnPrefix.randhex" +
                                        qcc::RandHexString(64);
        qcc::String advertisingPrefix = "quiet@" + routingNodePrefix;
        ASSERT_EQ(ER_OK, managerBus.AdvertiseName(advertisingPrefix.c_str(), ajn::TRANSPORT_ANY));

        TCBus.Connect(routingNodePrefix.c_str());
        TCBus.Start();

        // Register in memory keystore listeners
        EXPECT_EQ(ER_OK, managerBus.RegisterKeyStoreListener(managerKeyStoreListener));
        EXPECT_EQ(ER_OK, SCBus.RegisterKeyStoreListener(SCKeyStoreListener));

        EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &managerAuthListener));
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA"));
        /* set claimable */
        TCBus.SetApplicationState(APP_STATE_CLAIMABLE);

        busUsedAsCA.Start();
        busUsedAsCA.Connect();
        busUsedAsCA1.Start();
        busUsedAsLivingRoom.Start();
        busUsedAsPeerC.Start();

        EXPECT_EQ(ER_OK, busUsedAsCA.RegisterKeyStoreListener(listener1));
        EXPECT_EQ(ER_OK, busUsedAsCA1.RegisterKeyStoreListener(listener2));
        EXPECT_EQ(ER_OK, busUsedAsLivingRoom.RegisterKeyStoreListener(listener3));
        EXPECT_EQ(ER_OK, busUsedAsPeerC.RegisterKeyStoreListener(listener4));

        EXPECT_EQ(ER_OK, busUsedAsCA.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", &managerAuthListener));
        EXPECT_EQ(ER_OK, busUsedAsCA1.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", &managerAuthListener));
        EXPECT_EQ(ER_OK, busUsedAsLivingRoom.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", &managerAuthListener));
        EXPECT_EQ(ER_OK, busUsedAsPeerC.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", &managerAuthListener));

        SessionOpts opts1;
        SessionId managerToManagerSessionId;
        SessionPort managerSessionPort = 42;
        EXPECT_EQ(ER_OK, managerBus.BindSessionPort(managerSessionPort, opts1, managerSessionPortListener));

        SessionOpts opts2;
        EXPECT_EQ(ER_OK, SCBus.BindSessionPort(SCSessionPort, opts2, SCSessionPortListener));

        SessionOpts opts3;
        EXPECT_EQ(ER_OK, TCBus.BindSessionPort(TCSessionPort));

        EXPECT_EQ(ER_OK, managerBus.JoinSession(managerBus.GetUniqueName().c_str(), managerSessionPort, NULL, managerToManagerSessionId, opts1));
        EXPECT_EQ(ER_OK, managerBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, NULL, managerToSCSessionId, opts2));
        EXPECT_EQ(ER_OK, managerBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, managerToTCSessionId, opts3));

        //-----------------------Claim each bus Attachments------------------
        SecurityApplicationProxy sapWithManager(managerBus, managerBus.GetUniqueName().c_str(), managerToManagerSessionId);
        SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);


        // All Inclusive manifest
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
        KeyInfoNISTP256 managerKey;
        PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(managerKey));

        //Get SC key
        KeyInfoNISTP256 SCKey;
        PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

        //Get TC key
        EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));
        TCKey.SetPublicKey(&TCPublicKey);

        //Get CA key
        KeyInfoNISTP256 caKey;
        PermissionConfigurator& pcCA = busUsedAsCA.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcCA.GetSigningPublicKey(caKey));

        //------------ Claim self(managerBus), SC, and TC --------
        uint8_t managerDigest[Crypto_SHA256::DIGEST_SIZE];
        EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(managerBus,
                                                                   manifest, manifestSize,
                                                                   managerDigest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

        EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(busUsedAsCA,
                                                                   manifest, manifestSize,
                                                                   caDigest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

        //Create identityCert
        const size_t certChainSize = 1;
        IdentityCertificate identityCertChainMaster[certChainSize];

        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(busUsedAsCA,
                                                                      "0",
                                                                      managerGuid.ToString(),
                                                                      managerKey.GetPublicKey(),
                                                                      "ManagerAlias",
                                                                      3600,
                                                                      identityCertChainMaster[0],
                                                                      managerDigest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

        /* set claimable */
        managerBus.GetPermissionConfigurator().SetApplicationState(PermissionConfigurator::CLAIMABLE);
        EXPECT_EQ(ER_OK, sapWithManager.Claim(caKey,
                                              managerGuid,
                                              managerKey,
                                              identityCertChainMaster, certChainSize,
                                              manifest, manifestSize));


        ECCPublicKey managerPublicKey;
        GetAppPublicKey(managerBus, managerPublicKey);
        ASSERT_EQ(*managerKey.GetPublicKey(), managerPublicKey);

        //Create SC identityCert
        IdentityCertificate identityCertChainSC[1];

        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(busUsedAsCA,
                                                                      "0",
                                                                      caGuid.ToString(),
                                                                      SCKey.GetPublicKey(),
                                                                      "SCAlias",
                                                                      3600,
                                                                      identityCertChainSC[0],
                                                                      caDigest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
        //Manager claims Peers
        /* set claimable */
        SCBus.GetPermissionConfigurator().SetApplicationState(PermissionConfigurator::CLAIMABLE);
        EXPECT_EQ(ER_OK, sapWithSC.Claim(caKey,
                                            managerGuid,
                                            caKey,
                                            identityCertChainSC, 1,
                                            manifest, manifestSize));

        //Create TC identityCert
        IdentityCertificate identityCertChainTC[certChainSize];

        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(busUsedAsCA,
                                                                      "0",
                                                                      caGuid.ToString(),
                                                                      TCKey.GetPublicKey(),
                                                                      "TCAlias",
                                                                      3600,
                                                                      identityCertChainTC[0],
                                                                      caDigest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

        EXPECT_EQ(ER_OK, sapWithTC.Claim(caKey,
                                            managerGuid,
                                            caKey,
                                            identityCertChainTC, certChainSize,
                                            manifest, manifestSize));

        EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &managerAuthListener));
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));

        //--------- InstallMembership certificates on self, SC, and TC

        String membershipSerial = "1";
        qcc::MembershipCertificate managerMembershipCertificate[1];
        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert(membershipSerial,
                                                                        busUsedAsCA,
                                                                        managerBus.GetUniqueName(),
                                                                        managerKey.GetPublicKey(),
                                                                        managerGuid,
                                                                        false,
                                                                        3600,
                                                                        managerMembershipCertificate[0]
                                                                        ));
        EXPECT_EQ(ER_OK, sapWithManager.InstallMembership(managerMembershipCertificate, 1));

        // Install Membership certificate
        qcc::MembershipCertificate SCMembershipCertificate[1];
        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("1",
                                                                        busUsedAsCA,
                                                                        SCBus.GetUniqueName(),
                                                                        SCKey.GetPublicKey(),
                                                                        managerGuid,
                                                                        false,
                                                                        3600,
                                                                        SCMembershipCertificate[0]
                                                                        ));

        EXPECT_EQ(ER_OK, sapWithSC.InstallMembership(SCMembershipCertificate, 1));

        qcc::MembershipCertificate TCMembershipCertificate[1];
        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert(membershipSerial,
                                                                        busUsedAsCA,
                                                                        TCBus.GetUniqueName(),
                                                                        TCKey.GetPublicKey(),
                                                                        managerGuid,
                                                                        false,
                                                                        3600,
                                                                        TCMembershipCertificate[0]
                                                                        ));
        EXPECT_EQ(ER_OK, sapWithTC.InstallMembership(TCMembershipCertificate, 1));
    }

    virtual void TearDown() {
        EXPECT_EQ(ER_OK, managerBus.Stop());
        EXPECT_EQ(ER_OK, managerBus.Join());
        EXPECT_EQ(ER_OK, SCBus.Stop());
        EXPECT_EQ(ER_OK, SCBus.Join());
        EXPECT_EQ(ER_OK, TCBus.Stop());
        EXPECT_EQ(ER_OK, TCBus.Join());
    }

    PermissionPolicy CreateSCPolicy(uint32_t version) {
        PermissionPolicy policy;
        policy.SetVersion(version);
        {
            PermissionPolicy::Acl acls[1];
            {
                PermissionPolicy::Peer peers[1];
                peers[0].SetType(PermissionPolicy::Peer::PEER_FROM_CERTIFICATE_AUTHORITY);
                PermissionConfigurator& pcCA = busUsedAsCA.GetPermissionConfigurator();
                KeyInfoNISTP256 caPublicKey;
                EXPECT_EQ(ER_OK, pcCA.GetSigningPublicKey(caPublicKey));
                peers[0].SetKeyInfo(&caPublicKey);
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
        return policy;
    }

    // ACL1: Peer type: WITH_MEMBERSHIP, SGID: Living Room
    // ACL2: Peer type: FROM_CERTIFICATE_AUTHORITY: CA1
    // ACL3: Peer Type: WITH_PUBLIC_KEY: Peer C
    PermissionPolicy CreateTCPolicyA(uint32_t version) {
        PermissionPolicy policy;
        policy.SetVersion(version);
        {
            PermissionPolicy::Acl acls[3];

            // All of the acls are using the same permissive rules
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

            // ACL0:  Peer type: WITH_MEMBERSHIP, SGID: Living Room
            {
                PermissionPolicy::Peer peers[1];
                peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);
                peers[0].SetSecurityGroupId(livingRoomSGID);
                ////Get manager key
                KeyInfoNISTP256 livingRoomKey;
                PermissionConfigurator& pcLivingRoom = busUsedAsLivingRoom.GetPermissionConfigurator();
                EXPECT_EQ(ER_OK, pcLivingRoom.GetSigningPublicKey(livingRoomKey));
                peers[0].SetKeyInfo(&livingRoomKey); //Is this the public key of TC???
                acls[0].SetPeers(1, peers);
                acls[0].SetRules(1, rules);
            }
            //ACL1: Peer type: FROM_CERTIFICATE_AUTHORITY: CA1
            {
                PermissionPolicy::Peer peers[1];
                peers[0].SetType(PermissionPolicy::Peer::PEER_FROM_CERTIFICATE_AUTHORITY);
                KeyInfoNISTP256 ca1Key;
                PermissionConfigurator& pcCA1 = busUsedAsCA1.GetPermissionConfigurator();
                EXPECT_EQ(ER_OK, pcCA1.GetSigningPublicKey(ca1Key));
                peers[0].SetKeyInfo(&ca1Key);
                acls[1].SetPeers(1, peers);
                acls[1].SetRules(1, rules);
            }
            //ACL2: Peer Type: WITH_PUBLIC_KEY: Peer C
            {
                PermissionPolicy::Peer peers[1];
                peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
                //Get manager key
                KeyInfoNISTP256 peerCKey;
                PermissionConfigurator& pcPeerC = busUsedAsPeerC.GetPermissionConfigurator();
                EXPECT_EQ(ER_OK, pcPeerC.GetSigningPublicKey(peerCKey));
                peers[0].SetKeyInfo(&peerCKey); //peerKey of peerC
                acls[2].SetPeers(1, peers);
                acls[2].SetRules(1, rules);
            }
            policy.SetAcls(3, acls);
        }
        return policy;
    }

    // Peer[0]: FROM_CERTIFICATE_AUTHORITY, Public key of CA1
    // Peer[1]: WITH_MEMBERSHIP, SGID: Living Room
    // Peer[2]: WITH_PUBLIC_KEY: Peer C's public key
    PermissionPolicy CreateTCPolicyB(uint32_t version) {
        PermissionPolicy policy;
        policy.SetVersion(version);
        {
            PermissionPolicy::Acl acls[1];

            // All of the acls are using the same permissive rules
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

            {
                PermissionPolicy::Peer peers[3];
                // Peer[0]: FROM_CERTIFICATE_AUTHORITY, Public key of CA1
                peers[0].SetType(PermissionPolicy::Peer::PEER_FROM_CERTIFICATE_AUTHORITY);
                KeyInfoNISTP256 ca1Key;
                PermissionConfigurator& pcCA1 = busUsedAsCA1.GetPermissionConfigurator();
                EXPECT_EQ(ER_OK, pcCA1.GetSigningPublicKey(ca1Key));
                peers[0].SetKeyInfo(&ca1Key);
                // Peer[1]: WITH_MEMBERSHIP, SGID: Living Room
                peers[1].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);
                peers[1].SetSecurityGroupId(livingRoomSGID);
                ////Get manager key
                KeyInfoNISTP256 livingRoomKey;
                PermissionConfigurator& pcLivingRoom = busUsedAsLivingRoom.GetPermissionConfigurator();
                EXPECT_EQ(ER_OK, pcLivingRoom.GetSigningPublicKey(livingRoomKey));
                peers[1].SetKeyInfo(&livingRoomKey);
                // Peer[2]: WITH_PUBLIC_KEY: Peer C's public key
                peers[2].SetType(PermissionPolicy::Peer::PEER_WITH_PUBLIC_KEY);
                //Get manager key
                KeyInfoNISTP256 peerCKey;
                PermissionConfigurator& pcPeerC = busUsedAsPeerC.GetPermissionConfigurator();
                EXPECT_EQ(ER_OK, pcPeerC.GetSigningPublicKey(peerCKey));
                peers[2].SetKeyInfo(&peerCKey); //peerKey of peerC

                acls[0].SetPeers(3, peers);
                acls[0].SetRules(1, rules);
            }
            policy.SetAcls(1, acls);
        }
        return policy;
    }

    /**
     * Base for test case 3.
     * Verify that, for authentication between two peers to succeed, identity trust
     * of the peer is matched against all the authorities as specified in the policy.
     *
     * Setup:
     * Peers A and app. bus are claimed
     * App. bus's IC is signed by the CA.
     *
     * Peer A has a policy with peer type: FROM_CERTIFICATE_AUTHORITY, Public key of CA.
     *
     * App. bus has the following ACLs.
     * ACL1:  Peer type: WITH_MEMBERSHIP, SGID: Living Room
     * ACL2: Peer type: FROM_CERTIFICATE_AUTHORITY: CA1
     * ACL3: Peer Type: WITH_PUBLIC_KEY: Peer C
     *
     * The ACLs does not have any rules.
     *
     *
     * SC == PeerA
     * TC == App. Bus
     */
    void BaseAuthenticationTest3(BusAttachment& identityIssuer, QStatus expectedStatus, const char* reference)
    {
        //Get SC key
        KeyInfoNISTP256 SCKey;
        PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

        //---------------- Install Policy --------------
        {
            PermissionPolicy policy = CreateSCPolicy(1);
            PermissionPolicy SCDefaultPolicy;

            SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
            EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
            /* SC will have new CA but managerBus still retains admin group privilege so it can install identity
             * cert to SC later */
            SecurityAuthTestHelper::UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, policy, false, true);
            EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(policy));
            EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));
        }
        {
            PermissionPolicy policy = CreateTCPolicyA(1);
            PermissionPolicy TCDefaultPolicy;

            SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
            EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(policy));
            /* From here on the managerBus has no access to TC anymore */
        }

        //Create SC identityCert

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

        GUID128 SCGuid;

        uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
        EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(busUsedAsCA1,
                                                                   manifest, manifestSize,
                                                                   digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

        IdentityCertificate identityCertChainSC[1];

        PermissionConfigurator& pcCA = SCBus.GetPermissionConfigurator();
        KeyInfoNISTP256 SCPublicKey;
        EXPECT_EQ(ER_OK, pcCA.GetSigningPublicKey(SCPublicKey));

        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(identityIssuer,
                                                                      "1",
                                                                      SCGuid.ToString(),
                                                                      SCPublicKey.GetPublicKey(),
                                                                      "SCAlias",
                                                                      3600,
                                                                      identityCertChainSC[0],
                                                                      digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
        EXPECT_EQ(ER_OK, sapWithSC.UpdateIdentity(identityCertChainSC, 1, manifest, manifestSize))
            << "Failed to update Identity cert or manifest ";
        uint32_t sessionId;
        SessionOpts opts;
        EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts));

        {
            EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
            EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
            SecurityApplicationProxy proxy(SCBus, TCBus.GetUniqueName().c_str(), sessionId);
            EXPECT_EQ(expectedStatus, proxy.SecureConnection(true)) << reference << " expects status " << QCC_StatusText(expectedStatus);
            //SecurityApplicationProxy proxy2(TCBus, SCBus.GetUniqueName().c_str(), sessionId);
            EXPECT_EQ(expectedStatus, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));
        }
    }

    /**
     * Base for test case 4.
     * Verify that, for authentication between two peers to succeed, identity
     * trust of the peer is matched against all the authorities as specified in
     * the policy. The policy has only one ACL but the ACL has several peers.
     *
     * Setup:
     * Peers A and app. bus are claimed
     * App. bus's IC is signed by the CA.
     *
     * Peer A has a policy with peer type: FROM_CERTIFICATE_AUTHORITY, Public key of CA.
     *
     * App. bus has the following ACLs.
     * ACL1:  Peer type: WITH_MEMBERSHIP, SGID: Living Room
     * ACL2: Peer type: FROM_CERTIFICATE_AUTHORITY: CA1
     * ACL3: Peer Type: WITH_PUBLIC_KEY: Peer C
     *
     * The ACLs does not have any rules.
     *
     *
     * SC == PeerA
     * TC == App. Bus
     */
    void BaseAuthenticationTest4(BusAttachment& identityIssuer)
    {
        //Get SC key
        KeyInfoNISTP256 SCKey;
        PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

        //---------------- Install Policy --------------
        {
            PermissionPolicy policy = CreateSCPolicy(1);
            PermissionPolicy SCDefaultPolicy;

            SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
            EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
            /* SC will have new CA but managerBus still retains admin group privilege so it can install identity
             * cert to SC later */
            SecurityAuthTestHelper::UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, policy, false, true);
            EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(policy));
            EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));
        }
        {
            PermissionPolicy policy = CreateTCPolicyB(1);
            PermissionPolicy TCDefaultPolicy;

            SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
            EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(policy));
            /* From here on the managerBus has no access to TC anymore */
        }

        //Create SC identityCert

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

        GUID128 SCGuid;

        uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
        EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(busUsedAsCA1,
                                                                   manifest, manifestSize,
                                                                   digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

        IdentityCertificate identityCertChainSC[1];

        PermissionConfigurator& pcCA = SCBus.GetPermissionConfigurator();
        KeyInfoNISTP256 SCPublicKey;
        EXPECT_EQ(ER_OK, pcCA.GetSigningPublicKey(SCPublicKey));

        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(identityIssuer,
                                                                      "1",
                                                                      SCGuid.ToString(),
                                                                      SCPublicKey.GetPublicKey(),
                                                                      "SCAlias",
                                                                      3600,
                                                                      identityCertChainSC[0],
                                                                      digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
        EXPECT_EQ(ER_OK, sapWithSC.UpdateIdentity(identityCertChainSC, 1, manifest, manifestSize))
            << "Failed to update Identity cert or manifest ";
    }

    /**
     * Base for test case 6.
     * Verify that under the default policy, authentication will succeed if the
     * IC is signed by either the CA or the ASGA.
     *
     * Both Peers use default policy
     */
    void BaseAuthenticationTest6(BusAttachment& identityIssuer, QStatus expectedStatus, const char* reference)
    {
        //Get SC key
        KeyInfoNISTP256 SCKey;
        PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

        //Create SC identityCert

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

        GUID128 SCGuid;

        uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
        EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(busUsedAsCA1,
                                                                   manifest, manifestSize,
                                                                   digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

        IdentityCertificate identityCertChainSC[1];

        PermissionConfigurator& pcCA = SCBus.GetPermissionConfigurator();
        KeyInfoNISTP256 SCPublicKey;
        EXPECT_EQ(ER_OK, pcCA.GetSigningPublicKey(SCPublicKey));

        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(identityIssuer,
                                                                      "1",
                                                                      SCGuid.ToString(),
                                                                      SCPublicKey.GetPublicKey(),
                                                                      "SCAlias",
                                                                      3600,
                                                                      identityCertChainSC[0],
                                                                      digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
        EXPECT_EQ(ER_OK, sapWithSC.UpdateIdentity(identityCertChainSC, 1, manifest, manifestSize))
            << "Failed to update Identity cert or manifest ";
        uint32_t sessionId;
        SessionOpts opts;
        EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts));

        {
            EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
            EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
            SecurityApplicationProxy proxy(SCBus, TCBus.GetUniqueName().c_str(), sessionId);
            EXPECT_EQ(expectedStatus, proxy.SecureConnection(true)) << reference << " expects status " << QCC_StatusText(expectedStatus);
            //SecurityApplicationProxy proxy2(TCBus, SCBus.GetUniqueName().c_str(), sessionId);
            EXPECT_EQ(expectedStatus, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));
        }
    }

    BusAttachment managerBus;
    BusAttachment SCBus;
    TCAuthenticationAttachment TCBus;

    BusAttachment busUsedAsCA;
    BusAttachment busUsedAsCA1;
    BusAttachment busUsedAsLivingRoom;
    BusAttachment busUsedAsPeerC;

    InMemoryKeyStoreListener managerKeyStoreListener;
    InMemoryKeyStoreListener SCKeyStoreListener;

    InMemoryKeyStoreListener listener1;
    InMemoryKeyStoreListener listener2;
    InMemoryKeyStoreListener listener3;
    InMemoryKeyStoreListener listener4;

    SecurityAuthentication2AuthListener managerAuthListener;
    SecurityAuthentication2AuthListener SCAuthListener;

    SecurityAuthenticationTestSessionPortListener managerSessionPortListener;
    SecurityAuthenticationTestSessionPortListener SCSessionPortListener;

    SessionId managerToSCSessionId;
    SessionId managerToTCSessionId;

    SessionPort SCSessionPort;
    SessionPort TCSessionPort;

    GUID128 managerGuid;
    GUID128 caGuid;
    qcc::GUID128 livingRoomSGID;

    const size_t manifestSize;
    PermissionPolicy::Rule manifest[1];
    uint8_t caDigest[Crypto_SHA256::DIGEST_SIZE];

    ECCPublicKey TCPublicKey;
    KeyInfoNISTP256 TCKey;
};

/*
 * Purpose:
 * Verify that, for authentication between two peers to succeed, identity trust
 * of the peer is matched against all the authorities as specified in the policy.
 *
 * Setup:
 * Peers A and app. bus are claimed
 * App. bus's IC is signed by the CA.
 *
 * Peer A has a policy with peer type: FROM_CERTIFICATE_AUTHORITY, Public key of CA.
 *
 * App. bus has the following ACLs.
 * ACL1:  Peer type: WITH_MEMBERSHIP, SGID: Living Room
 * ACL2: Peer type: FROM_CERTIFICATE_AUTHORITY: CA1
 * ACL3: Peer Type: WITH_PUBLIC_KEY: Peer C
 *
 * The ACLs does not have any rules.
 *
 * case A. Peer A has the IC signed by the CA and both peers specify the ECDHE_ECDSA auth. mechanism.
 * case B.  Peer A has the IC signed by the ASGA and both peers specify the ECDHE_ECDSA auth. mechanism.
 * case C. Peer A has the IC signed by the Living room authority  and both peers specify the ECDHE_ECDSA auth. mechanism.
 * case D. Peer A has the IC signed by the CA1 and both peers specify the ECDHE_ECDSA auth. mechanism.
 * case E.  Peer A has the IC signed by Peer C and both peers specify the ECDHE_ECDSA auth. mechanism.
 *
 * For each of the cases above, Peer A tries to establish a secure session with the app. bus.
 * For each of the cases above, the app. bus tries to establish a secure session with Peer A.
 *
 * Verification:
 * A. Verify that authentication between both peers is NOT successful.
 * B. Verify that authentication between both peers is  NOT successful.
 * C. Verify that authentication between both peers is successful.
 * D. Verify that authentication between both peers is successful.
 * E. Verify that authentication between both peers is not successful.
 *
 */
TEST_F(SecurityAuthenticationTest2, authenticate_test3_caseA) {
    BaseAuthenticationTest3(busUsedAsCA, ER_AUTH_FAIL, "authenticate_test3_caseA");
}

/*
 * Purpose:
 * Verify that, for authentication between two peers to succeed, identity trust
 * of the peer is matched against all the authorities as specified in the policy.
 *
 * Setup:
 * Peers A and app. bus are claimed
 * App. bus's IC is signed by the CA.
 *
 * Peer A has a policy with peer type: FROM_CERTIFICATE_AUTHORITY, Public key of CA.
 *
 * App. bus has the following ACLs.
 * ACL1:  Peer type: WITH_MEMBERSHIP, SGID: Living Room
 * ACL2: Peer type: FROM_CERTIFICATE_AUTHORITY: CA1
 * ACL3: Peer Type: WITH_PUBLIC_KEY: Peer C
 *
 * The ACLs does not have any rules.
 *
 * case A. Peer A has the IC signed by the CA and both peers specify the ECDHE_ECDSA auth. mechanism.
 * case B.  Peer A has the IC signed by the ASGA and both peers specify the ECDHE_ECDSA auth. mechanism.
 * case C. Peer A has the IC signed by the Living room authority  and both peers specify the ECDHE_ECDSA auth. mechanism.
 * case D. Peer A has the IC signed by the CA1 and both peers specify the ECDHE_ECDSA auth. mechanism.
 * case E.  Peer A has the IC signed by Peer C and both peers specify the ECDHE_ECDSA auth. mechanism.
 *
 * For each of the cases above, Peer A tries to establish a secure session with the app. bus.
 * For each of the cases above, the app. bus tries to establish a secure session with Peer A.
 *
 * Verification:
 * A. Verify that authentication between both peers is NOT successful.
 * B. Verify that authentication between both peers is  NOT successful.
 * C. Verify that authentication between both peers is successful.
 * D. Verify that authentication between both peers is successful.
 * E. Verify that authentication between both peers is not successful.
 *
 */
TEST_F(SecurityAuthenticationTest2, authenticate_test3_caseB) {
    BaseAuthenticationTest3(managerBus, ER_AUTH_FAIL, "authenticate_test3_caseB");
}

/*
 * Purpose:
 * Verify that, for authentication between two peers to succeed, identity trust
 * of the peer is matched against all the authorities as specified in the policy.
 *
 * Setup:
 * Peers A and app. bus are claimed
 * App. bus's IC is signed by the CA.
 *
 * Peer A has a policy with peer type: FROM_CERTIFICATE_AUTHORITY, Public key of CA.
 *
 * App. bus has the following ACLs.
 * ACL1:  Peer type: WITH_MEMBERSHIP, SGID: Living Room
 * ACL2: Peer type: FROM_CERTIFICATE_AUTHORITY: CA1
 * ACL3: Peer Type: WITH_PUBLIC_KEY: Peer C
 *
 * The ACLs does not have any rules.
 *
 * case A. Peer A has the IC signed by the CA and both peers specify the ECDHE_ECDSA auth. mechanism.
 * case B.  Peer A has the IC signed by the ASGA and both peers specify the ECDHE_ECDSA auth. mechanism.
 * case C. Peer A has the IC signed by the Living room authority  and both peers specify the ECDHE_ECDSA auth. mechanism.
 * case D. Peer A has the IC signed by the CA1 and both peers specify the ECDHE_ECDSA auth. mechanism.
 * case E.  Peer A has the IC signed by Peer C and both peers specify the ECDHE_ECDSA auth. mechanism.
 *
 * For each of the cases above, Peer A tries to establish a secure session with the app. bus.
 * For each of the cases above, the app. bus tries to establish a secure session with Peer A.
 *
 * Verification:
 * A. Verify that authentication between both peers is NOT successful.
 * B. Verify that authentication between both peers is  NOT successful.
 * C. Verify that authentication between both peers is successful.
 * D. Verify that authentication between both peers is successful.
 * E. Verify that authentication between both peers is not successful.
 *
 */
TEST_F(SecurityAuthenticationTest2, authenticate_test3_caseC) {
    BaseAuthenticationTest3(busUsedAsLivingRoom, ER_OK, "authenticate_test3_caseC");
}

/*
 * Purpose:
 * Verify that, for authentication between two peers to succeed, identity trust
 * of the peer is matched against all the authorities as specified in the policy.
 *
 * Setup:
 * Peers A and app. bus are claimed
 * App. bus's IC is signed by the CA.
 *
 * Peer A has a policy with peer type: FROM_CERTIFICATE_AUTHORITY, Public key of CA.
 *
 * App. bus has the following ACLs.
 * ACL1:  Peer type: WITH_MEMBERSHIP, SGID: Living Room
 * ACL2: Peer type: FROM_CERTIFICATE_AUTHORITY: CA1
 * ACL3: Peer Type: WITH_PUBLIC_KEY: Peer C
 *
 * The ACLs does not have any rules.
 *
 * case A. Peer A has the IC signed by the CA and both peers specify the ECDHE_ECDSA auth. mechanism.
 * case B.  Peer A has the IC signed by the ASGA and both peers specify the ECDHE_ECDSA auth. mechanism.
 * case C. Peer A has the IC signed by the Living room authority  and both peers specify the ECDHE_ECDSA auth. mechanism.
 * case D. Peer A has the IC signed by the CA1 and both peers specify the ECDHE_ECDSA auth. mechanism.
 * case E.  Peer A has the IC signed by Peer C and both peers specify the ECDHE_ECDSA auth. mechanism.
 *
 * For each of the cases above, Peer A tries to establish a secure session with the app. bus.
 * For each of the cases above, the app. bus tries to establish a secure session with Peer A.
 *
 * Verification:
 * A. Verify that authentication between both peers is NOT successful.
 * B. Verify that authentication between both peers is  NOT successful.
 * C. Verify that authentication between both peers is successful.
 * D. Verify that authentication between both peers is successful.
 * E. Verify that authentication between both peers is not successful.
 *
 */
TEST_F(SecurityAuthenticationTest2, authenticate_test3_caseD) {
    BaseAuthenticationTest3(busUsedAsCA1, ER_OK, "authenticate_test3_caseD");
}

/*
 * Purpose:
 * Verify that, for authentication between two peers to succeed, identity trust
 * of the peer is matched against all the authorities as specified in the policy.
 *
 * Setup:
 * Peers A and app. bus are claimed
 * App. bus's IC is signed by the CA.
 *
 * Peer A has a policy with peer type: FROM_CERTIFICATE_AUTHORITY, Public key of CA.
 *
 * App. bus has the following ACLs.
 * ACL1:  Peer type: WITH_MEMBERSHIP, SGID: Living Room
 * ACL2: Peer type: FROM_CERTIFICATE_AUTHORITY: CA1
 * ACL3: Peer Type: WITH_PUBLIC_KEY: Peer C
 *
 * The ACLs does not have any rules.
 *
 * case A. Peer A has the IC signed by the CA and both peers specify the ECDHE_ECDSA auth. mechanism.
 * case B.  Peer A has the IC signed by the ASGA and both peers specify the ECDHE_ECDSA auth. mechanism.
 * case C. Peer A has the IC signed by the Living room authority  and both peers specify the ECDHE_ECDSA auth. mechanism.
 * case D. Peer A has the IC signed by the CA1 and both peers specify the ECDHE_ECDSA auth. mechanism.
 * case E.  Peer A has the IC signed by Peer C and both peers specify the ECDHE_ECDSA auth. mechanism.
 *
 * For each of the cases above, Peer A tries to establish a secure session with the app. bus.
 * For each of the cases above, the app. bus tries to establish a secure session with Peer A.
 *
 * Verification:
 * A. Verify that authentication between both peers is NOT successful.
 * B. Verify that authentication between both peers is  NOT successful.
 * C. Verify that authentication between both peers is successful.
 * D. Verify that authentication between both peers is successful.
 * E. Verify that authentication between both peers is not successful.
 *
 */
TEST_F(SecurityAuthenticationTest2, authenticate_test3_caseE) {
    BaseAuthenticationTest3(busUsedAsPeerC, ER_AUTH_FAIL, "authenticate_test3_caseE");
}

/*
 * Purpose:
 * Verify that, for authentication between two peers to succeed, identity trust
 * of the peer is matched against all the authorities as specified in the policy.
 * The policy has only one ACL but the ACL has several peers.
 *
 * Setup:
 * Peer A and app. bus are claimed.
 * app bus's IC: signed by CA
 *
 * Peer A has a local policy with FROM_CERTIFICATE_AUTHORITY peer type, public key of CA
 *
 * app bus has the following policy:
 * ACL 1:
 * Peer[0]: FROM_CERTIFICATE_AUTHORITY, Public key of CA1
 * Peer[1]: WITH_MEMBERSHIP, SGID: Living Room
 * Peer[2]: WITH_PUBLIC_KEY: Peer C's public key
 *
 * Case 1: A and app. bus set up a ECDHE_NULL based session.
 * Case 2: A and app. bus set up a ECDHE_PSK based session.
 * Case 2.1: A and app. bus set up a ECDHE_SPEKE based session.
 * Case 3: A and app. bus set up a SRP based session.
 * Case 4: A and app. bus set up a ECDHE_ECDSA based session, IC of A is signed by CA1
 * Case 5: A and app. bus set up a ECDHE_ECDSA based session, IC of A is signed by Living room authority
 * Case 6: A and app. bus set up a ECDHE_ECDSA based session, IC of A is signed by Peer C
 * Case 7: A and app. bus set up a ECDHE_ECDSA based session, IC of A is signed by CA
 *
 * Verification:
 * Cases 1-5: Secure session can be set up successfully.
 * Cases 6-7: Secure session cannot be set up.
 *
 */
TEST_F(SecurityAuthenticationTest2, authenticate_test4_case1) {
    BaseAuthenticationTest4(busUsedAsCA);
    uint32_t sessionId;
    SessionOpts opts;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts));

    {
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL"));
        SecurityApplicationProxy proxy(SCBus, TCBus.GetUniqueName().c_str(), sessionId);
        EXPECT_EQ(ER_OK, proxy.SecureConnection(true));
        //SecurityApplicationProxy proxy2(TCBus, SCBus.GetUniqueName().c_str(), sessionId);
        EXPECT_EQ(ER_OK, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));
    }
}

/*
 * See authenticate_test4_case1 above for full test description
 */
TEST_F(SecurityAuthenticationTest2, authenticate_test4_case2) {
    BaseAuthenticationTest4(busUsedAsCA);
    uint32_t sessionId;
    SessionOpts opts;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts));

    {
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_PSK", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_PSK"));
        SecurityApplicationProxy proxy(SCBus, TCBus.GetUniqueName().c_str(), sessionId);
        EXPECT_EQ(ER_OK, proxy.SecureConnection(true));
        //SecurityApplicationProxy proxy2(TCBus, SCBus.GetUniqueName().c_str(), sessionId);
        EXPECT_EQ(ER_OK, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));
    }
}

/*
* See authenticate_test4_case1 above for full test description
*/
TEST_F(SecurityAuthenticationTest2, authenticate_test4_case2_1) {
    BaseAuthenticationTest4(busUsedAsCA);
    uint32_t sessionId;
    SessionOpts opts;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts));

    {
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_SPEKE", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_SPEKE"));
        SecurityApplicationProxy proxy(SCBus, TCBus.GetUniqueName().c_str(), sessionId);
        EXPECT_EQ(ER_OK, proxy.SecureConnection(true));
        EXPECT_EQ(ER_OK, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));
    }
}

/*
 * See authenticate_test4_case1 above for full test description
 */
TEST_F(SecurityAuthenticationTest2, DISABLED_authenticate_test4_case3) {
    BaseAuthenticationTest4(busUsedAsCA);
    uint32_t sessionId;
    SessionOpts opts;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts));

    {
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_SRP_KEYX", &SCAuthListener));
        /* TC does not support SRP - leave DISABLED */
        //EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_SRP_KEYX", &TCAuthListener));
        SecurityApplicationProxy proxy(SCBus, TCBus.GetUniqueName().c_str(), sessionId);
        EXPECT_EQ(ER_OK, proxy.SecureConnection(true));
        //SecurityApplicationProxy proxy2(TCBus, SCBus.GetUniqueName().c_str(), sessionId);
        EXPECT_EQ(ER_OK, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));
    }
}

/*
 * See authenticate_test4_case1 above for full test description
 */
TEST_F(SecurityAuthenticationTest2, authenticate_test4_case4) {
    BaseAuthenticationTest4(busUsedAsCA1);
    uint32_t sessionId;
    SessionOpts opts;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts));

    {
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
        SecurityApplicationProxy proxy(SCBus, TCBus.GetUniqueName().c_str(), sessionId);
        EXPECT_EQ(ER_OK, proxy.SecureConnection(true));
        //SecurityApplicationProxy proxy2(TCBus, SCBus.GetUniqueName().c_str(), sessionId);
        EXPECT_EQ(ER_OK, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));
    }
}

/*
 * See authenticate_test4_case1 above for full test description
 */
TEST_F(SecurityAuthenticationTest2, authenticate_test4_case5) {
    BaseAuthenticationTest4(busUsedAsLivingRoom);
    uint32_t sessionId;
    SessionOpts opts;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts));

    {
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
        SecurityApplicationProxy proxy(SCBus, TCBus.GetUniqueName().c_str(), sessionId);
        EXPECT_EQ(ER_OK, proxy.SecureConnection(true));
        //SecurityApplicationProxy proxy2(TCBus, SCBus.GetUniqueName().c_str(), sessionId);
        EXPECT_EQ(ER_OK, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));
    }
}

/*
 * See authenticate_test4_case1 above for full test description
 */
TEST_F(SecurityAuthenticationTest2, authenticate_test4_case6) {
    BaseAuthenticationTest4(busUsedAsPeerC);
    uint32_t sessionId;
    SessionOpts opts;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts));

    {
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
        SecurityApplicationProxy proxy(SCBus, TCBus.GetUniqueName().c_str(), sessionId);
        EXPECT_EQ(ER_AUTH_FAIL, proxy.SecureConnection(true));
        //SecurityApplicationProxy proxy2(TCBus, SCBus.GetUniqueName().c_str(), sessionId);
        EXPECT_EQ(ER_AUTH_FAIL, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));
    }
}

/*
 * See authenticate_test4_case1 above for full test description
 */
TEST_F(SecurityAuthenticationTest2, authenticate_test4_case7) {
    BaseAuthenticationTest4(busUsedAsCA);
    uint32_t sessionId;
    SessionOpts opts;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts));

    {
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
        SecurityApplicationProxy proxy(SCBus, TCBus.GetUniqueName().c_str(), sessionId);
        EXPECT_EQ(ER_AUTH_FAIL, proxy.SecureConnection(true));
        //SecurityApplicationProxy proxy2(TCBus, SCBus.GetUniqueName().c_str(), sessionId);
        EXPECT_EQ(ER_AUTH_FAIL, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));
    }
}

class SecurityAuthentication3AuthListener1 : public DefaultECDHEAuthListener {
  public:
    SecurityAuthentication3AuthListener1() {
        uint8_t incorrect_psk[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        uint8_t incorrect_password[16] = {0,0,0,0};
        SetPSK(incorrect_psk, sizeof(incorrect_psk));
        SetPassword(incorrect_password, sizeof(incorrect_password));
        calledAuthMechanisms.clear();
    }

    QStatus RequestCredentialsAsync(const char* authMechanism, const char* authPeer, uint16_t authCount, const char* userId, uint16_t credMask, void* context)
    {
        Credentials creds;
        if (strcmp(authMechanism, "ALLJOYN_SRP_KEYX") == 0) {
            if (credMask & AuthListener::CRED_PASSWORD) {
                creds.SetPassword("123456");
            }
            return RequestCredentialsResponse(context, true, creds);
        }
        return DefaultECDHEAuthListener::RequestCredentialsAsync(authMechanism, authPeer, authCount, userId, credMask, context);
    }
    void AuthenticationComplete(const char* authMechanism, const char* peerName, bool success) {
        calledAuthMechanisms.insert(authMechanism);
        DefaultECDHEAuthListener::AuthenticationComplete(authMechanism, peerName, success);
    }

    std::set<qcc::String> calledAuthMechanisms;
};

/*
 * This test class strongly resembles the SecurityAuthenticationTest2 class
 * except the AuthListeners used in the set up are different. As well as some
 * additional cleanup to remove unused variables.
 */
class SecurityAuthenticationTest3 : public testing::Test {
  public:
    SecurityAuthenticationTest3() :
        managerBus("SecurityAuthenticationManager", true),
        SCBus("SecuritAuthenticationSC", true),
        TCBus("SecurityAuthenticationTC"),

        busUsedAsCA("foo1"),
        busUsedAsLivingRoom("foo3"),

        managerKeyStoreListener(),
        SCKeyStoreListener(),

        listener1(),
        listener2(),

        managerAuthListener(),
        SCAuthListener(),

        managerSessionPortListener(),
        SCSessionPortListener(),

        managerToSCSessionId(0),
        managerToTCSessionId(0),

        SCSessionPort(42),
        TCSessionPort(42),

        managerGuid(),
        caGuid(),
        livingRoomSGID(),

        manifestSize(1)
    {
    }

    virtual void SetUp() {
        EXPECT_EQ(ER_OK, managerBus.Start());
        EXPECT_EQ(ER_OK, managerBus.Connect());
        EXPECT_EQ(ER_OK, SCBus.Start());
        EXPECT_EQ(ER_OK, SCBus.Connect());

        // To avoid cross-talk, i.e. thin leaf node connect to unintended
        // routing nodes, generate and advertise a random routing node prefix.
        qcc::String routingNodePrefix = "test.rnPrefix.randhex" +
                                        qcc::RandHexString(64);
        qcc::String advertisingPrefix = "quiet@" + routingNodePrefix;
        ASSERT_EQ(ER_OK, managerBus.AdvertiseName(advertisingPrefix.c_str(), ajn::TRANSPORT_ANY));

        TCBus.Connect(routingNodePrefix.c_str());
        TCBus.Start();

        // Register in memory keystore listeners
        EXPECT_EQ(ER_OK, managerBus.RegisterKeyStoreListener(managerKeyStoreListener));
        EXPECT_EQ(ER_OK, SCBus.RegisterKeyStoreListener(SCKeyStoreListener));

        EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &managerAuthListener));
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA"));
        /* set claimable */
        TCBus.SetApplicationState(APP_STATE_CLAIMABLE);

        busUsedAsCA.Start();
        busUsedAsCA.Connect();
        busUsedAsLivingRoom.Start();

        EXPECT_EQ(ER_OK, busUsedAsCA.RegisterKeyStoreListener(listener1));
        EXPECT_EQ(ER_OK, busUsedAsLivingRoom.RegisterKeyStoreListener(listener2));

        EXPECT_EQ(ER_OK, busUsedAsCA.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", &managerAuthListener));
        EXPECT_EQ(ER_OK, busUsedAsLivingRoom.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", &managerAuthListener));

        SessionOpts opts1;
        SessionId managerToManagerSessionId;
        SessionPort managerSessionPort = 42;
        EXPECT_EQ(ER_OK, managerBus.BindSessionPort(managerSessionPort, opts1, managerSessionPortListener));

        SessionOpts opts2;
        EXPECT_EQ(ER_OK, SCBus.BindSessionPort(SCSessionPort, opts2, SCSessionPortListener));

        SessionOpts opts3;
        EXPECT_EQ(ER_OK, TCBus.BindSessionPort(TCSessionPort));

        EXPECT_EQ(ER_OK, managerBus.JoinSession(managerBus.GetUniqueName().c_str(), managerSessionPort, NULL, managerToManagerSessionId, opts1));
        EXPECT_EQ(ER_OK, managerBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, NULL, managerToSCSessionId, opts2));
        EXPECT_EQ(ER_OK, managerBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, managerToTCSessionId, opts3));

        //-----------------------Claim each bus Attachments------------------
        SecurityApplicationProxy sapWithManager(managerBus, managerBus.GetUniqueName().c_str(), managerToManagerSessionId);
        SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);


        // All Inclusive manifest
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
        KeyInfoNISTP256 managerKey;
        PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(managerKey));

        //Get SC key
        KeyInfoNISTP256 SCKey;
        PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

        //Get TC key
        EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));
        TCKey.SetPublicKey(&TCPublicKey);

        //Get CA key
        KeyInfoNISTP256 caKey;
        PermissionConfigurator& pcCA = busUsedAsCA.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcCA.GetSigningPublicKey(caKey));

        //------------ Claim self(managerBus), SC, and TC --------
        uint8_t managerDigest[Crypto_SHA256::DIGEST_SIZE];
        EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(managerBus,
                                                                   manifest, manifestSize,
                                                                   managerDigest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

        EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(busUsedAsCA,
                                                                   manifest, manifestSize,
                                                                   caDigest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

        //Create identityCert
        const size_t certChainSize = 1;
        IdentityCertificate identityCertChainMaster[certChainSize];

        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(busUsedAsCA,
                                                                      "0",
                                                                      managerGuid.ToString(),
                                                                      managerKey.GetPublicKey(),
                                                                      "ManagerAlias",
                                                                      3600,
                                                                      identityCertChainMaster[0],
                                                                      managerDigest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

        /* set claimable */
        managerBus.GetPermissionConfigurator().SetApplicationState(PermissionConfigurator::CLAIMABLE);
        EXPECT_EQ(ER_OK, sapWithManager.Claim(caKey,
                                              managerGuid,
                                              managerKey,
                                              identityCertChainMaster, certChainSize,
                                              manifest, manifestSize));


        ECCPublicKey managerPublicKey;
        GetAppPublicKey(managerBus, managerPublicKey);
        ASSERT_EQ(*managerKey.GetPublicKey(), managerPublicKey);

        //Create SC identityCert
        IdentityCertificate identityCertChainSC[1];

        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(busUsedAsCA,
                                                                      "0",
                                                                      caGuid.ToString(),
                                                                      SCKey.GetPublicKey(),
                                                                      "SCAlias",
                                                                      3600,
                                                                      identityCertChainSC[0],
                                                                      caDigest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
        //Manager claims Peers
        /* set claimable */
        SCBus.GetPermissionConfigurator().SetApplicationState(PermissionConfigurator::CLAIMABLE);
        EXPECT_EQ(ER_OK, sapWithSC.Claim(caKey,
                                            managerGuid,
                                            caKey,
                                            identityCertChainSC, 1,
                                            manifest, manifestSize));

        //Create TC identityCert
        IdentityCertificate identityCertChainTC[certChainSize];

        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(busUsedAsCA,
                                                                      "0",
                                                                      caGuid.ToString(),
                                                                      TCKey.GetPublicKey(),
                                                                      "TCAlias",
                                                                      3600,
                                                                      identityCertChainTC[0],
                                                                      caDigest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

        EXPECT_EQ(ER_OK, sapWithTC.Claim(caKey,
                                            managerGuid,
                                            caKey,
                                            identityCertChainTC, certChainSize,
                                            manifest, manifestSize));

        EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &managerAuthListener));
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));

        //--------- InstallMembership certificates on self, SC, and TC

        String membershipSerial = "1";
        qcc::MembershipCertificate managerMembershipCertificate[1];
        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert(membershipSerial,
                                                                        busUsedAsCA,
                                                                        managerBus.GetUniqueName(),
                                                                        managerKey.GetPublicKey(),
                                                                        managerGuid,
                                                                        false,
                                                                        3600,
                                                                        managerMembershipCertificate[0]
                                                                        ));
        EXPECT_EQ(ER_OK, sapWithManager.InstallMembership(managerMembershipCertificate, 1));

        // Install Membership certificate
        qcc::MembershipCertificate SCMembershipCertificate[1];
        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("1",
                                                                        busUsedAsCA,
                                                                        SCBus.GetUniqueName(),
                                                                        SCKey.GetPublicKey(),
                                                                        managerGuid,
                                                                        false,
                                                                        3600,
                                                                        SCMembershipCertificate[0]
                                                                        ));

        EXPECT_EQ(ER_OK, sapWithSC.InstallMembership(SCMembershipCertificate, 1));

        qcc::MembershipCertificate TCMembershipCertificate[1];
        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert(membershipSerial,
                                                                        busUsedAsCA,
                                                                        TCBus.GetUniqueName(),
                                                                        TCKey.GetPublicKey(),
                                                                        managerGuid,
                                                                        false,
                                                                        3600,
                                                                        TCMembershipCertificate[0]
                                                                        ));
        EXPECT_EQ(ER_OK, sapWithTC.InstallMembership(TCMembershipCertificate, 1));
    }

    virtual void TearDown() {
        EXPECT_EQ(ER_OK, managerBus.Stop());
        EXPECT_EQ(ER_OK, managerBus.Join());
        EXPECT_EQ(ER_OK, SCBus.Stop());
        EXPECT_EQ(ER_OK, SCBus.Join());
        EXPECT_EQ(ER_OK, TCBus.Stop());
        EXPECT_EQ(ER_OK, TCBus.Join());
    }

    PermissionPolicy CreateSCPolicy(uint32_t version) {
        PermissionPolicy policy;
        policy.SetVersion(version);
        {
            PermissionPolicy::Acl acls[1];
            {
                PermissionPolicy::Peer peers[1];
                peers[0].SetType(PermissionPolicy::Peer::PEER_ALL);
                acls[0].SetPeers(1, peers);
            }
            policy.SetAcls(1, acls);
        }
        return policy;
    }

    //ACL0:  Peer type: WITH_MEMBERSHIP, SGID: Living Room;
    //ACL1:  Peer type: ALL, peer type
    //ACL2:  ANY_TRUSTED
    //(i.e app. bus has three ACLs.)
    //
    //The ACLs does not have any rules.
    PermissionPolicy CreateTCPolicy(uint32_t version) {
        PermissionPolicy policy;
        policy.SetVersion(version);
        {
            PermissionPolicy::Acl acls[3];
            // ACL0:  Peer type: WITH_MEMBERSHIP, SGID: Living Room
            {
                PermissionPolicy::Peer peers[1];
                peers[0].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);
                peers[0].SetSecurityGroupId(livingRoomSGID);
                ////Get manager key
                KeyInfoNISTP256 livingRoomKey;
                PermissionConfigurator& pcLivingRoom = busUsedAsLivingRoom.GetPermissionConfigurator();
                EXPECT_EQ(ER_OK, pcLivingRoom.GetSigningPublicKey(livingRoomKey));
                peers[0].SetKeyInfo(&livingRoomKey); //Is this the public key of TC???
                acls[0].SetPeers(1, peers);
            }
            //ACL1:  Peer type: ALL, peer type
            {
                PermissionPolicy::Peer peers[1];
                peers[0].SetType(PermissionPolicy::Peer::PEER_ALL);
                acls[1].SetPeers(1, peers);
            }
            //ACL2:  ANY_TRUSTED
            {
                PermissionPolicy::Peer peers[1];
                peers[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);
                acls[2].SetPeers(1, peers);
            }
            policy.SetAcls(3, acls);
        }
        return policy;
    }

    /**
     * base for test 5
     * Verify that peer should fallback to ECDHE_NULL based authentication in case of failure.
     *
     * Setup:
     * Peers A and app. bus are claimed.
     * App. bus's IC is signed by the CA.
     *
     * Peer A has a policy with ALL peer type.
     * App. bus has the following ACLs.
     * ACL1:  Peer type: WITH_MEMBERSHIP, SGID: Living Room;
     *
     * ACL2:  Peer type: ALL, peer type
     * ACL3:  ANY_TRUSTED
     * (i.e app. bus has three ACLs.)
     *
     * The ACLs does not have any rules.
     *
     * THe ECDHE_PSK key or the SRP key between two peers do not match. (This should cause the ECDHE_PSK and SRP auth. mechanisms to fail.)
     *
     * case A. Peer A has the IC signed by the CA' and both peers specify the ECDHE_ECDSA, ECDHE_PSK, SRP, ECDHE_NULL auth. mechanism.
     *
     * For each of the cases above, Peer A tries to establish a secure session with the app. bus.
     * For each of the cases above, the app. bus tries to establish a secure session with Peer A.
     *
     * SC == PeerA
     * TC == App. Bus
     */
    void BaseAuthenticationTest5(BusAttachment& identityIssuer)
    {
        //Get SC key
        KeyInfoNISTP256 SCKey;
        PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

        //---------------- Install Policy --------------
        {
            PermissionPolicy policy = CreateSCPolicy(1);
            PermissionPolicy SCDefaultPolicy;

            SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
            EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
            /* SC will have new CA but managerBus still retains admin group privilege so it can install identity
             * cert to SC later */
            SecurityAuthTestHelper::UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, policy, false, true);
            EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(policy));
            EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));
        }
        {
            PermissionPolicy policy = CreateTCPolicy(1);
            PermissionPolicy TCDefaultPolicy;

            SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
            EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(policy));
            /* From here on the managerBus has no access to TC anymore */
        }

        //Create SC identityCert

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

        GUID128 SCGuid;

        uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
        EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(busUsedAsCA,
                                                                   manifest, manifestSize,
                                                                   digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

        IdentityCertificate identityCertChainSC[1];

        PermissionConfigurator& pcCA = SCBus.GetPermissionConfigurator();
        KeyInfoNISTP256 SCPublicKey;
        EXPECT_EQ(ER_OK, pcCA.GetSigningPublicKey(SCPublicKey));

        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(identityIssuer,
                                                                      "1",
                                                                      SCGuid.ToString(),
                                                                      SCPublicKey.GetPublicKey(),
                                                                      "SCAlias",
                                                                      3600,
                                                                      identityCertChainSC[0],
                                                                      digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
        EXPECT_EQ(ER_OK, sapWithSC.UpdateIdentity(identityCertChainSC, 1, manifest, manifestSize))
            << "Failed to update Identity cert or manifest ";

        AJ_AlwaysPrintf(("BaseAuthenticationTest5 complete\n"));
    }

    BusAttachment managerBus;
    BusAttachment SCBus;
    TCAuthenticationAttachment TCBus;

    BusAttachment busUsedAsCA;
    BusAttachment busUsedAsLivingRoom;

    InMemoryKeyStoreListener managerKeyStoreListener;
    InMemoryKeyStoreListener SCKeyStoreListener;

    InMemoryKeyStoreListener listener1;
    InMemoryKeyStoreListener listener2;

    DefaultECDHEAuthListener managerAuthListener;
    SecurityAuthentication3AuthListener1 SCAuthListener;

    SecurityAuthenticationTestSessionPortListener managerSessionPortListener;
    SecurityAuthenticationTestSessionPortListener SCSessionPortListener;

    SessionId managerToSCSessionId;
    SessionId managerToTCSessionId;

    SessionPort SCSessionPort;
    SessionPort TCSessionPort;

    GUID128 managerGuid;
    GUID128 caGuid;
    qcc::GUID128 livingRoomSGID;

    const size_t manifestSize;
    PermissionPolicy::Rule manifest[1];
    uint8_t caDigest[Crypto_SHA256::DIGEST_SIZE];

    ECCPublicKey TCPublicKey;
    KeyInfoNISTP256 TCKey;
};

/**
 * purpose:
 * Verify that peer should fallback to ECDHE_NULL based authentication in case
 * of failure.
 *
 * Setup: (most of the setup done in the Setup and BaseAuthenticationTest5 methods)
 * Peers A and app. bus are claimed.
 * App. bus's IC is signed by the CA.
 *
 * Peer A has a policy with ALL peer type.
 * App. bus has the following ACLs.
 * ACL1:  Peer type: WITH_MEMBERSHIP, SGID: Living Room;
 *
 * ACL2:  Peer type: ALL, peer type
 * ACL3:  ANY_TRUSTED
 * (i.e app. bus has three ACLs.)
 *
 * The ACLs does not have any rules.
 *
 * The ECDHE_PSK key, the SRP key and the SPEKE password between two peers do not match.
 * (This should cause the ECDHE_PSK, SRP and SPEKE auth. mechanisms to fail.)
 *
 * case A. Peer A has the IC signed by the CA' and both peers specify the
 * ECDHE_ECDSA, ECDHE_PSK, ECDHE_SPEKE, SRP, ECDHE_NULL auth. mechanism.
 *
 * For each of the cases above, Peer A tries to establish a secure session with the app. bus.
 * For each of the cases above, the app. bus tries to establish a secure session with Peer A.
 *
 * Verify:
 * Verify that establishment of secure session fails with all authentication mechanisms
 * passed to EnablePeerSecurity, execpt ECDHE_NULL, where it succeeds.
 *
 * Peer A == Peer1
 * app. Bus == Peer2
 */
TEST_F(SecurityAuthenticationTest3, authenticate_test5_SC_tries_to_secure_session) {
    BaseAuthenticationTest5(busUsedAsCA);
    
    uint32_t sessionId;
    SessionOpts opts;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts));

    {
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA ALLJOYN_ECDHE_PSK ALLJOYN_ECDHE_SPEKE ALLJOYN_SRP_KEYX ALLJOYN_ECDHE_NULL", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA ALLJOYN_ECDHE_PSK ALLJOYN_ECDHE_SPEKE ALLJOYN_ECDHE_NULL"));

        SCAuthListener.calledAuthMechanisms.clear();

        SecurityApplicationProxy proxy1(SCBus, TCBus.GetUniqueName().c_str(), sessionId);
        EXPECT_EQ(ER_OK, proxy1.SecureConnection(true));

        EXPECT_TRUE(SCAuthListener.calledAuthMechanisms.find("ALLJOYN_ECDHE_NULL") != SCAuthListener.calledAuthMechanisms.end()) << "Expected ECDHE_NULL auth mechanism to be tried, but it wasn't.";
    }
}

/*
 * see description for authenticate_test5_peer1_tries_to_secure_session
 * This is the same test except peer2 is doing the authentications
 */
TEST_F(SecurityAuthenticationTest3, authenticate_test5_TC_tries_to_secure_session) {
    BaseAuthenticationTest5(busUsedAsCA);

    uint32_t sessionId;
    SessionOpts opts;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts));

    {
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA ALLJOYN_ECDHE_PSK ALLJOYN_ECDHE_SPEKE ALLJOYN_SRP_KEYX ALLJOYN_ECDHE_NULL", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA ALLJOYN_ECDHE_NULL"));

        SCAuthListener.calledAuthMechanisms.clear();

        EXPECT_EQ(ER_OK, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));
        
        EXPECT_TRUE(SCAuthListener.calledAuthMechanisms.find("ALLJOYN_ECDHE_ECDSA") != SCAuthListener.calledAuthMechanisms.end()) << "Expected ECDHE_ECDSA auth mechanism to be tried, but it wasn't.";
        EXPECT_TRUE(SCAuthListener.calledAuthMechanisms.find("ALLJOYN_ECDHE_NULL") != SCAuthListener.calledAuthMechanisms.end()) << "Expected ECDHE_NULL auth mechanism to be tried, but it wasn't.";
    }
}

/*
 * see description for authenticate_test5_peer1_tries_to_secure_session
 * This is the same test except the list of auth mechanisms is limited to ECDHE
 */
TEST_F(SecurityAuthenticationTest3, authenticate_test5_peer1_tries_to_secure_session_only_ECDHE) {
    BaseAuthenticationTest5(busUsedAsCA);
    uint32_t sessionId;
    SessionOpts opts;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts));

    {
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA ALLJOYN_ECDHE_PSK ALLJOYN_ECDHE_SPEKE ALLJOYN_ECDHE_NULL", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA ALLJOYN_ECDHE_PSK ALLJOYN_ECDHE_SPEKE ALLJOYN_ECDHE_NULL"));

        SCAuthListener.calledAuthMechanisms.clear();

        SecurityApplicationProxy proxy1(SCBus, TCBus.GetUniqueName().c_str(), sessionId);
        EXPECT_EQ(ER_OK, proxy1.SecureConnection(true));

        /*
        * All auth mechanisms with higher priority than ECDHE_NULL should have failed, and we check that authentication fell back on ECDHE_NULL.
        * Ideally we would check that each failed auth mechanism was called, and in the correct order, but the AuthenticationComplete
        * callback is not called reliably when authentication falls back to another mechanism.
        * The bug https://jira.allseenalliance.org/browse/ASACORE-2716 tracks this issue. 
        * By setting ER_DEBUG_AUTH_KEY_EXCHANGER=15 and viewing the tracing code, we can manually confirm that all mechanisms are being tried. 
        */
        EXPECT_TRUE(SCAuthListener.calledAuthMechanisms.find("ALLJOYN_ECDHE_NULL") != SCAuthListener.calledAuthMechanisms.end()) << "Expected ECDHE_NULL auth mechanism to be tried, but it wasn't.";
    }
}

/*
 * see description for authenticate_test5_peer1_tries_to_secure_session
 * This is the same test except the list of auth mechanisms is limited to ECDHE
 * and Peer2 is used for authentication instead of Peer1
 *
 * Disabled. See https://jira.allseenalliance.org/browse/ASACORE-2718 for details. 
 */
TEST_F(SecurityAuthenticationTest3, DISABLED_authenticate_test5_peer2_tries_to_secure_session_only_ECDHE) {
    BaseAuthenticationTest5(busUsedAsCA);
    uint32_t sessionId;
    SessionOpts opts;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts));

    {
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA ALLJOYN_ECDHE_SPEKE ALLJOYN_ECDHE_PSK ALLJOYN_ECDHE_NULL", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA ALLJOYN_ECDHE_SPEKE ALLJOYN_ECDHE_PSK ALLJOYN_ECDHE_NULL"));

        SCAuthListener.calledAuthMechanisms.clear();

        EXPECT_EQ(ER_OK, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));

        /*
         * This test fails because not all auth mechanisms get tried before falling back to ECDHE_NULL. The trace from the SC shows 
         * that ECDHE_SPEKE gets tried, then ECDHE_NULL gets tried. When ECDHE_SPEKE is not in the list, the trace shows that ECDSA
         * gets tried, then NULL.  So the behavior seems to be: try the mechanism with the higest integer value in PeerState.h, then
         * fall back to ECDHE_NULL. The test was broken before ECHDE_SPEKE was added (because ECDHE_PSK was not being attempted), but
         * showed up when a new auth mechanism with lower priority than ECDSA was added with a higher integer value in PeerState.h. 
         * Auth mechanism priority should be indpendent of the integer value, but previously the priority and integer values agreed 
         * (i.e., higher integer = higher priority). There are two issues here: 1. the order that auth mechanisms are tried is not as
         * expected, and 2. not all mechanisms getting tried before falling back to ECDHE_NULL. 
         * The bug https://jira.allseenalliance.org/browse/ASACORE-2718 tracks this issue. 
         */
        EXPECT_TRUE(SCAuthListener.calledAuthMechanisms.find("ALLJOYN_ECDHE_ECDSA") != SCAuthListener.calledAuthMechanisms.end()) << "Expected ECDHE_ECDSA auth mechanism to be tried, but it wasn't.";
        EXPECT_TRUE(SCAuthListener.calledAuthMechanisms.find("ALLJOYN_ECDHE_NULL") != SCAuthListener.calledAuthMechanisms.end()) << "Expected ECDHE_NULL auth mechanism to be tried, but it wasn't.";
    }
}

class SecurityAuthenticationTest4 : public testing::Test {
  public:
    SecurityAuthenticationTest4() :
        managerBus("SecurityAuthenticationManager", true),
        SCBus("SecurityAuthenticationSC", true),
        TCBus("SecurityAuthenticationTC"),

        busUsedAsCA("foo1"),
        busUsedAsCA1("foo2"),
        busUsedAsLivingRoom("foo3"),
        busUsedAsPeerC("foo4"),

        managerKeyStoreListener(),
        SCKeyStoreListener(),

        listener1(),
        listener2(),
        listener3(),
        listener4(),

        managerAuthListener(),
        SCAuthListener(),

        managerSessionPortListener(),
        SCSessionPortListener(),

        managerToSCSessionId(0),
        managerToTCSessionId(0),

        SCSessionPort(42),
        TCSessionPort(42),

        managerGuid(),
        caGuid(),
        livingRoomSGID(),

        manifestSize(1)
    {
    }

    virtual void SetUp() {
        EXPECT_EQ(ER_OK, managerBus.Start());
        EXPECT_EQ(ER_OK, managerBus.Connect());
        EXPECT_EQ(ER_OK, SCBus.Start());
        EXPECT_EQ(ER_OK, SCBus.Connect());

        // To avoid cross-talk, i.e. thin leaf node connect to unintended
        // routing nodes, generate and advertise a random routing node prefix.
        qcc::String routingNodePrefix = "test.rnPrefix.randhex" +
                                        qcc::RandHexString(64);
        qcc::String advertisingPrefix = "quiet@" + routingNodePrefix;
        ASSERT_EQ(ER_OK, managerBus.AdvertiseName(advertisingPrefix.c_str(), ajn::TRANSPORT_ANY));

        TCBus.Connect(routingNodePrefix.c_str());
        TCBus.Start();

        // Register in memory keystore listeners
        EXPECT_EQ(ER_OK, managerBus.RegisterKeyStoreListener(managerKeyStoreListener));
        EXPECT_EQ(ER_OK, SCBus.RegisterKeyStoreListener(SCKeyStoreListener));

        EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &managerAuthListener));
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA"));
        /* set claimable */
        TCBus.SetApplicationState(APP_STATE_CLAIMABLE);

        busUsedAsCA.Start();
        busUsedAsCA.Connect();
        busUsedAsCA1.Start();
        busUsedAsLivingRoom.Start();
        busUsedAsPeerC.Start();

        EXPECT_EQ(ER_OK, busUsedAsCA.RegisterKeyStoreListener(listener1));
        EXPECT_EQ(ER_OK, busUsedAsCA1.RegisterKeyStoreListener(listener2));
        EXPECT_EQ(ER_OK, busUsedAsLivingRoom.RegisterKeyStoreListener(listener3));
        EXPECT_EQ(ER_OK, busUsedAsPeerC.RegisterKeyStoreListener(listener4));

        EXPECT_EQ(ER_OK, busUsedAsCA.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", &managerAuthListener));
        EXPECT_EQ(ER_OK, busUsedAsCA1.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", &managerAuthListener));
        EXPECT_EQ(ER_OK, busUsedAsLivingRoom.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", &managerAuthListener));
        EXPECT_EQ(ER_OK, busUsedAsPeerC.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", &managerAuthListener));

        SessionOpts opts1;
        SessionId managerToManagerSessionId;
        SessionPort managerSessionPort = 42;
        EXPECT_EQ(ER_OK, managerBus.BindSessionPort(managerSessionPort, opts1, managerSessionPortListener));

        SessionOpts opts2;
        EXPECT_EQ(ER_OK, SCBus.BindSessionPort(SCSessionPort, opts2, SCSessionPortListener));

        SessionOpts opts3;
        EXPECT_EQ(ER_OK, TCBus.BindSessionPort(TCSessionPort));

        EXPECT_EQ(ER_OK, managerBus.JoinSession(managerBus.GetUniqueName().c_str(), managerSessionPort, NULL, managerToManagerSessionId, opts1));
        EXPECT_EQ(ER_OK, managerBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, NULL, managerToSCSessionId, opts2));
        EXPECT_EQ(ER_OK, managerBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, managerToTCSessionId, opts3));

        //-----------------------Claim each bus Attachments------------------
        SecurityApplicationProxy sapWithManager(managerBus, managerBus.GetUniqueName().c_str(), managerToManagerSessionId);
        SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);


        // All Inclusive manifest
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
        KeyInfoNISTP256 managerKey;
        PermissionConfigurator& pcManager = managerBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcManager.GetSigningPublicKey(managerKey));

        //Get SC key
        KeyInfoNISTP256 SCKey;
        PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

        //Get TC key
        EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));
        TCKey.SetPublicKey(&TCPublicKey);

        //Get CA key
        KeyInfoNISTP256 caKey;
        PermissionConfigurator& pcCA = busUsedAsCA.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcCA.GetSigningPublicKey(caKey));

        //------------ Claim self(managerBus), SC, and TC --------
        uint8_t managerDigest[Crypto_SHA256::DIGEST_SIZE];
        EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(managerBus,
                                                                   manifest, manifestSize,
                                                                   managerDigest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

        EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(busUsedAsCA,
                                                                   manifest, manifestSize,
                                                                   caDigest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

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
                                                                      managerDigest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

        /* set claimable */
        managerBus.GetPermissionConfigurator().SetApplicationState(PermissionConfigurator::CLAIMABLE);
        EXPECT_EQ(ER_OK, sapWithManager.Claim(caKey,
                                              managerGuid,
                                              managerKey,
                                              identityCertChainMaster, certChainSize,
                                              manifest, manifestSize));


        ECCPublicKey managerPublicKey;
        GetAppPublicKey(managerBus, managerPublicKey);
        ASSERT_EQ(*managerKey.GetPublicKey(), managerPublicKey);

        //Create SC identityCert
        IdentityCertificate identityCertChainSC[1];

        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(managerBus,
                                                                      "0",
                                                                      caGuid.ToString(),
                                                                      SCKey.GetPublicKey(),
                                                                      "SCAlias",
                                                                      3600,
                                                                      identityCertChainSC[0],
                                                                      caDigest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

        SCBus.GetPermissionConfigurator().SetApplicationState(PermissionConfigurator::CLAIMABLE);
        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
        //Manager claims Peers
        EXPECT_EQ(ER_OK, sapWithSC.Claim(caKey,
                                            managerGuid,
                                            managerKey,
                                            identityCertChainSC, 1,
                                            manifest, manifestSize));

        //Create TC identityCert
        IdentityCertificate identityCertChainTC[certChainSize];

        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(managerBus,
                                                                      "0",
                                                                      caGuid.ToString(),
                                                                      TCKey.GetPublicKey(),
                                                                      "TCAlias",
                                                                      3600,
                                                                      identityCertChainTC[0],
                                                                      caDigest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

        EXPECT_EQ(ER_OK, sapWithTC.Claim(caKey,
                                            managerGuid,
                                            managerKey,
                                            identityCertChainTC, certChainSize,
                                            manifest, manifestSize));

        EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &managerAuthListener));
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
        EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));

        //--------- InstallMembership certificates on self, SC, and TC

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

        // Install Membership certificate
        qcc::MembershipCertificate SCMembershipCertificate[1];
        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert("1",
                                                                        managerBus,
                                                                        SCBus.GetUniqueName(),
                                                                        SCKey.GetPublicKey(),
                                                                        managerGuid,
                                                                        false,
                                                                        3600,
                                                                        SCMembershipCertificate[0]
                                                                        ));

        EXPECT_EQ(ER_OK, sapWithSC.InstallMembership(SCMembershipCertificate, 1));

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
        EXPECT_EQ(ER_OK, sapWithTC.InstallMembership(TCMembershipCertificate, 1));
    }

    virtual void TearDown() {
        EXPECT_EQ(ER_OK, managerBus.Stop());
        EXPECT_EQ(ER_OK, managerBus.Join());
        EXPECT_EQ(ER_OK, SCBus.Stop());
        EXPECT_EQ(ER_OK, SCBus.Join());
        EXPECT_EQ(ER_OK, TCBus.Stop());
        EXPECT_EQ(ER_OK, TCBus.Join());
    }

    /**
     * Base for test case 6.
     * Verify that under the default policy, authentication will succeed if the
     * IC is signed by either the CA or the ASGA.
     *
     * Both Peers use default policy
     */
    void BaseAuthenticationTest6(BusAttachment& identityIssuer, QStatus expectedStatus, const char* reference)
    {
        //Get SC key
        KeyInfoNISTP256 SCKey;
        PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

        //Create SC identityCert

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

        GUID128 SCGuid;

        uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
        EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(busUsedAsCA1,
                                                                   manifest, manifestSize,
                                                                   digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

        IdentityCertificate identityCertChainSC[1];

        PermissionConfigurator& pcCA = SCBus.GetPermissionConfigurator();
        KeyInfoNISTP256 SCPublicKey;
        EXPECT_EQ(ER_OK, pcCA.GetSigningPublicKey(SCPublicKey));

        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(identityIssuer,
                                                                      "1",
                                                                      SCGuid.ToString(),
                                                                      SCPublicKey.GetPublicKey(),
                                                                      "SCAlias",
                                                                      3600,
                                                                      identityCertChainSC[0],
                                                                      digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
        EXPECT_EQ(ER_OK, sapWithSC.UpdateIdentity(identityCertChainSC, 1, manifest, manifestSize))
            << "Failed to update Identity cert or manifest ";
        uint32_t sessionId;
        SessionOpts opts;
        EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts));

        {
            EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
            EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
            SecurityApplicationProxy proxy(SCBus, TCBus.GetUniqueName().c_str(), sessionId);
            EXPECT_EQ(expectedStatus, proxy.SecureConnection(true)) << reference << " expects status " << QCC_StatusText(expectedStatus);
            EXPECT_EQ(expectedStatus, TCBus.AuthenticatePeer(SCBus.GetUniqueName().c_str()));
        }
    }

    BusAttachment managerBus;
    BusAttachment SCBus;
    TCAuthenticationAttachment TCBus;

    BusAttachment busUsedAsCA;
    BusAttachment busUsedAsCA1;
    BusAttachment busUsedAsLivingRoom;
    BusAttachment busUsedAsPeerC;

    InMemoryKeyStoreListener managerKeyStoreListener;
    InMemoryKeyStoreListener SCKeyStoreListener;

    InMemoryKeyStoreListener listener1;
    InMemoryKeyStoreListener listener2;
    InMemoryKeyStoreListener listener3;
    InMemoryKeyStoreListener listener4;

    SecurityAuthentication2AuthListener managerAuthListener;
    SecurityAuthentication2AuthListener SCAuthListener;

    SecurityAuthenticationTestSessionPortListener managerSessionPortListener;
    SecurityAuthenticationTestSessionPortListener SCSessionPortListener;

    SessionId managerToSCSessionId;
    SessionId managerToTCSessionId;

    SessionPort SCSessionPort;
    SessionPort TCSessionPort;

    GUID128 managerGuid;
    GUID128 caGuid;
    qcc::GUID128 livingRoomSGID;

    const size_t manifestSize;
    PermissionPolicy::Rule manifest[1];
    uint8_t caDigest[Crypto_SHA256::DIGEST_SIZE];

    ECCPublicKey TCPublicKey;
    KeyInfoNISTP256 TCKey;
};

/*
 * Purpose:
 * Verify that under the default policy, authentication will succeed if the IC
 * is signed by either the CA or the ASGA.
 *
 * Setup:
 * App. bus is claimed. The CA and ASGA public key are passed as arguments as a part of claim.
 *
 * (The app. bus has a default policy.)
 *
 * Case 1: A and app. bus  set up a ECDHE_ECDSA based session, IC of A is signed by CA.
 * Case 1: A and app. bus  set up a ECDHE_ECDSA based session, IC of A is signed by ASGA.
 *
 * Verification:
 * Cases 1-2: Secure sessions can be set up successfully.
 *
 */
TEST_F(SecurityAuthenticationTest4, authenticate_test6_case1) {
    BaseAuthenticationTest6(busUsedAsCA, ER_OK, "authenticate_test6_case1");
}
/*
 * See authenticate_test6_case1 above for full test description
 */
TEST_F(SecurityAuthenticationTest4, authenticate_test6_case2) {
    BaseAuthenticationTest6(managerBus, ER_OK, "authenticate_test6_case2");
}
