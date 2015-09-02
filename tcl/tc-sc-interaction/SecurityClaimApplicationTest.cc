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
#include <functional>
#include <mutex>
#include <future>

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
#define WAIT_MSECS  5
#define WAIT_SIGNAL 1000

static const char psk_hint[] = "<anonymous>";
static uint8_t psk[128];
static uint32_t len = 0;
static void SetPsk(const uint8_t* buffer, uint32_t bufLen)
{
    if (bufLen > sizeof (psk)) {
        bufLen = sizeof (psk);
    }
    memcpy(psk, buffer, bufLen);
    len = bufLen;
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

    case AUTH_SUITE_ECDHE_PSK:
        switch (command) {
        case AJ_CRED_PUB_KEY:
            cred->data = (uint8_t*) psk_hint;
            cred->len = strlen(psk_hint);
            cred->expiration = 1;
            status = AJ_OK;
            break;

        case AJ_CRED_PRV_KEY:
            cred->data = psk;
            cred->len = len;
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

class TCSecurityClaimThread : public Thread {

    typedef std::function<void (void)> Function;
    std::queue<Function> funcs;
    qcc::Mutex funcs_lock;


    void HandleQueuedMessages() {
        //std::lock_guard<std::mutex> guard(funcs_lock);
        funcs_lock.Lock();
        while (!funcs.empty()) {
            //printf("Got func\n");
            Function f = funcs.front();
            f();
            funcs.pop();
        }

        funcs_lock.Unlock();
    }

    void Enqueue(Function f) {
        //printf("Queueing\n");
        //std::lock_guard<std::mutex> guard(funcs_lock);
        funcs_lock.Lock();
        funcs.push(f);
        AJ_Net_Interrupt();
        funcs_lock.Unlock();
    }

    typedef std::map<int, Function> MsgHandlerMap;
    MsgHandlerMap message_handlers;

    void HandleMessage(AJ_Message* msg) {
        auto it = message_handlers.find(msg->msgId);

        if (it != message_handlers.end()) {
            Function handler = it->second;
            handler();
            message_handlers.erase(it);
        }
    }

  public:

    TCSecurityClaimThread() : qcc::Thread("TCSecurityClaimThread"), router() {
    }

    qcc::ThreadReturn Run(void* arg){
        QCC_UNUSED(arg);
        AJ_Status status;
        AJ_Message msg;

        printf("RUNNING!\n");

        AJ_AlwaysPrintf(("TC SetUp %s\n", router.c_str()));
        AJ_Initialize();
        // Ensure that a routing node is found as quickly as possible
        //AJ_SetSelectionTimeout(10);

        status = AJ_FindBusAndConnect(&bus, router.c_str(), TC_LEAFNODE_CONNECT_TIMEOUT);
        AJ_ASSERT(AJ_OK == status);

        //This resets the keystore
        AJ_ClearCredentials(0);
        AJ_BusSetAuthListenerCallback(&bus, AuthListenerCallback);

        running = TRUE;

        while (running) {
            HandleQueuedMessages();

            status = AJ_UnmarshalMsg(&bus, &msg, TC_UNMARSHAL_TIMEOUT);

            if (AJ_ERR_TIMEOUT == status && AJ_ERR_LINK_TIMEOUT == AJ_BusLinkStateProc(&bus)) {
                status = AJ_ERR_READ;
            }
            if (AJ_ERR_READ == status) {
                running = FALSE;
                break;
            } else if (AJ_OK == status) {
                /* Pass everything to the bus handler */
                AJ_BusHandleBusMessage(&msg);
            }
            AJ_CloseMsg(&msg);
        }

        AJ_Disconnect(&bus);
        return this;
    }

    QStatus Stop() {
        running = FALSE;
        AJ_Net_Interrupt();
        return Thread::Stop();
    }

    qcc::String GetUniqueName() {
        /* May have to wait for the hello message */
        for (int msec = 0; msec < 2000; msec += WAIT_MSECS) {
            if (bus.uniqueName[0] != '\0') {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }
        return qcc::String(bus.uniqueName);
    }

    QStatus EnablePeerSecurity(const char* mechanisms) {
        qcc::String str(mechanisms);

        std::promise<void> p;

        auto func = [this, &p, str] () {
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
            p.set_value();
        };

        Enqueue(func);
        p.get_future().wait();
        return ER_OK;
    }

    void SetApplicationState(uint16_t state) {
        AJ_SecuritySetClaimConfig(&bus, state, CLAIM_CAPABILITY_ECDHE_PSK | CLAIM_CAPABILITY_ECDHE_NULL, 0);
    }
    void SetPermissionManifest(AJ_Manifest* manifest) {
        uint16_t state;
        uint16_t cap;
        uint16_t info;
        AJ_SecurityGetClaimConfig(&state, &cap, &info);
        AJ_ManifestTemplateSet(manifest);
        AJ_SecuritySetClaimConfig(&bus, APP_STATE_NEED_UPDATE, cap, info);
    }

    qcc::String router;
    bool running;
    AJ_BusAttachment bus;
};

class StateNotification_ApplicationStateListener : public ApplicationStateListener {
  public:
    StateNotification_ApplicationStateListener() : busNames(), publicKeys(), states() {
        stateChanged = false;
    }

    virtual void State(const char* busName, const qcc::KeyInfoNISTP256& publicKeyInfo, PermissionConfigurator::ApplicationState state) {
        busNames.push(busName);
        publicKeys.push(publicKeyInfo);
        states.push(state);
        stateChanged = true;
    }

    queue<String> busNames;
    queue<KeyInfoNISTP256> publicKeys;
    queue<PermissionConfigurator::ApplicationState> states;
    bool stateChanged;
};
/*
class Claim_ApplicationStateListener : public ApplicationStateListener {
  public:
    Claim_ApplicationStateListener() {
        stateChanged = false;
    }

    virtual void State(const char* busName, const qcc::KeyInfoNISTP256& publicKeyInfo, PermissionConfigurator::ApplicationState state) {
        QCC_UNUSED(busName);
        QCC_UNUSED(publicKeyInfo);
        QCC_UNUSED(state);
        stateChanged = true;
    }

    bool stateChanged;
};*/

class SecurityClaimApplicationTest : public testing::Test {
  public:
    SecurityClaimApplicationTest() :
        securityManagerBus("SecurityClaimApplicationManager"),
        SCBus("SecurityClaimApplicationSC"),
        TCBus(),
        interfaceName("org.allseen.test.SecurityApplication.claim"),
        securityManagerKeyListener(NULL),
        SCKeyListener(NULL)
    {
        TCBus = new TCSecurityClaimThread();
    }

    void SetUp() {
        ASSERT_EQ(ER_OK, securityManagerBus.Start());
        ASSERT_EQ(ER_OK, securityManagerBus.Connect());
        ASSERT_EQ(ER_OK, SCBus.Start());
        ASSERT_EQ(ER_OK, SCBus.Connect());

        // Register in memory keystore listeners
        EXPECT_EQ(ER_OK, securityManagerBus.RegisterKeyStoreListener(securityManagerKeyStoreListener));
        EXPECT_EQ(ER_OK, SCBus.RegisterKeyStoreListener(SCKeyStoreListener));

        // To avoid cross-talk, i.e. thin leaf node connect to unintended
        // routing nodes, generate and advertise a random routing node prefix.
        qcc::String routingNodePrefix = "test.rnPrefix.randhex" +
                                        qcc::RandHexString(64);
        qcc::String advertisingPrefix = "quiet@" + routingNodePrefix;
        ASSERT_EQ(ER_OK, securityManagerBus.AdvertiseName(advertisingPrefix.c_str(), ajn::TRANSPORT_ANY));

        TCBus->router = routingNodePrefix.c_str();
        TCBus->Start();
        securityManagerBus.RegisterApplicationStateListener(appStateListener);
    }

    void TearDown() {
        securityManagerBus.UnregisterApplicationStateListener(appStateListener);
        TCBus->Stop();
        TCBus->Join();

        ASSERT_EQ(ER_OK, securityManagerBus.Disconnect());
        ASSERT_EQ(ER_OK, securityManagerBus.Stop());
        ASSERT_EQ(ER_OK, securityManagerBus.Join());
        ASSERT_EQ(ER_OK, SCBus.Disconnect());
        ASSERT_EQ(ER_OK, SCBus.Stop());
        ASSERT_EQ(ER_OK, SCBus.Join());

        delete securityManagerKeyListener;
        delete SCKeyListener;
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

    BusAttachment securityManagerBus;
    BusAttachment SCBus;
    TCSecurityClaimThread* TCBus;

    InMemoryKeyStoreListener securityManagerKeyStoreListener;
    InMemoryKeyStoreListener SCKeyStoreListener;

    String interface;
    const char* interfaceName;

    DefaultECDHEAuthListener* securityManagerKeyListener;
    DefaultECDHEAuthListener* SCKeyListener;

    int msec;

    StateNotification_ApplicationStateListener appStateListener;
};

TEST_F(SecurityClaimApplicationTest, IsClaimable)
{
    //EnablePeerSecurity
    securityManagerKeyListener = new DefaultECDHEAuthListener();
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", securityManagerKeyListener);

    SecurityApplicationProxy saWithSecurityManager(securityManagerBus, securityManagerBus.GetUniqueName().c_str());
    PermissionConfigurator::ApplicationState applicationStateSecurityManager;
    EXPECT_EQ(ER_OK, saWithSecurityManager.GetApplicationState(applicationStateSecurityManager));
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateSecurityManager);

    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL");
    SecurityApplicationProxy saWithTC(securityManagerBus, TCBus->GetUniqueName().c_str());
    PermissionConfigurator::ApplicationState applicationStateTC;
    EXPECT_EQ(ER_OK, saWithTC.GetApplicationState(applicationStateTC));
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateTC);
}



/*
 * Claim using ECDHE_NULL
 * Verify that claim is succesful using an ECDHE_NULL based session, where the
 * CA public key and the group public key are the same.
 *
 * Test Case:
 * Claim using ECDHE_NULL
 * caPublic key == adminGroupSecurityPublicKey
 * Identity = Single certificate signed by CA
 */
TEST_F(SecurityClaimApplicationTest, Claim_using_ECDHE_NULL_session_successful)
{
    securityManagerBus.AddApplicationStateRule();

    appStateListener.stateChanged = false;
    //EnablePeerSecurity
    securityManagerKeyListener = new DefaultECDHEAuthListener();
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", securityManagerKeyListener);

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(securityManagerBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    EXPECT_TRUE(appStateListener.stateChanged);

    appStateListener.stateChanged = false;
    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL");

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    ASSERT_TRUE(appStateListener.stateChanged);

    SecurityApplicationProxy sapWithTC(securityManagerBus, TCBus->GetUniqueName().c_str());
    PermissionConfigurator::ApplicationState applicationStateTC;
    EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
    ASSERT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateTC);

    //Create admin group key
    KeyInfoNISTP256 securityManagerKey;
    PermissionConfigurator& permissionConfigurator = securityManagerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(securityManagerKey));

    //Random GUID used for the SecurityManager
    GUID128 securityManagerGuid;

    //Create identityCertChain
    IdentityCertificate identityCertChain[1];

    // peer public key used to generate the identity certificate chain
    ECCPublicKey TCPublicKey;
    EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(securityManagerBus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(securityManagerBus,
                                                                  "0",
                                                                  securityManagerGuid.ToString(),
                                                                  &TCPublicKey,
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";

    appStateListener.stateChanged = false;
    /*
     * Claim TC
     * the certificate authority is self signed so the certificateAuthority
     * key is the same as the adminGroup key.
     * For this test the adminGroupId is a randomly generated GUID as long as the
     * GUID is consistent it's unimportant that the GUID is random.
     * Use generated identity certificate signed by the securityManager
     * Since we are only interested in claiming the peer we are using an all
     * inclusive manifest.
     */
    EXPECT_EQ(ER_OK, sapWithTC.Claim(securityManagerKey,
                                        securityManagerGuid,
                                        securityManagerKey,
                                        identityCertChain, 1,
                                        manifest, manifestSize));

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    ASSERT_TRUE(appStateListener.stateChanged);
    EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
    EXPECT_EQ(PermissionConfigurator::CLAIMED, applicationStateTC);
}

/*
 * Claim fails when using an empty public key identifier
 * Verify that claim fails.
 *
 * Test Case:
 * Claim using ECDHE_NULL
 * Claim using empty caPublicKeyIdentifier.
 * caPublic key == adminGroupSecurityPublicKey
 * Identity = Single certificate signed by CA
 */
TEST_F(SecurityClaimApplicationTest, claim_fails_using_empty_caPublicKeyIdentifier)
{
    //EnablePeerSecurity
    securityManagerKeyListener = new DefaultECDHEAuthListener();
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", securityManagerKeyListener);

    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL");

    SecurityApplicationProxy sapWithTC(securityManagerBus, TCBus->GetUniqueName().c_str());
    PermissionConfigurator::ApplicationState applicationStateTC;
    EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateTC);

    securityManagerBus.AddApplicationStateRule();

    //Create admin group key
    KeyInfoNISTP256 securityManagerKey;
    PermissionConfigurator& permissionConfigurator = securityManagerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(securityManagerKey));

    /*
     * For this test the authorityKeyIdentifier needs to be null
     * the rest of the information should be valid.
     */
    KeyInfoNISTP256 caKey;
    caKey = securityManagerKey;
    caKey.SetKeyId(NULL, 0);
    //Random GUID used for the SecurityManager
    GUID128 securityManagerGuid;

    //Create identityCertChain
    IdentityCertificate identityCertChain[1];

    // peer public key used to generate the identity certificate chain
    ECCPublicKey TCPublicKey;
    EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(securityManagerBus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(securityManagerBus,
                                                                  "1215",
                                                                  securityManagerGuid.ToString(),
                                                                  &TCPublicKey,
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";

    appStateListener.stateChanged = false;

    /*
     * Claim TC
     * the CA key is empty.
     * For this test the adminGroupId is a randomly generated GUID as long as the
     * GUID is consistent it's unimportant that the GUID is random.
     * Use generated identity certificate signed by the securityManager
     * Since we are only interested in claiming the peer we are using an all
     * inclusive manifest.
     */
    ASSERT_EQ(static_cast<size_t>(0), caKey.GetKeyIdLen());
    EXPECT_NE(ER_OK, sapWithTC.Claim(caKey,
                                        securityManagerGuid,
                                        securityManagerKey,
                                        identityCertChain, 1,
                                        manifest, manifestSize));

    EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateTC);
}

/*
 * Claim using ECDHE_NULL
 * Verify that claim is succesful using an ECDHE_NULL based session, where the
 * CA public key and the group public key are the same.
 *
 * Test Case:
 * Claim using ECDHE_NULL
 * Claim using empty adminGroupSecurityPublicKeyIdentifier.
 * caPublic key == adminGroupSecurityPublicKey
 * Identity = Single certificate signed by CA
 */
TEST_F(SecurityClaimApplicationTest, claim_fails_using_empty_adminGroupSecurityPublicKeyIdentifier)
{
    //EnablePeerSecurity
    securityManagerKeyListener = new DefaultECDHEAuthListener();
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", securityManagerKeyListener);

    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL");

    SecurityApplicationProxy sapWithTC(securityManagerBus, TCBus->GetUniqueName().c_str());
    PermissionConfigurator::ApplicationState applicationStateTC;
    EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateTC);

    securityManagerBus.AddApplicationStateRule();

    //Create admin group key
    KeyInfoNISTP256 securityManagerKey;
    PermissionConfigurator& permissionConfigurator = securityManagerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(securityManagerKey));

    KeyInfoNISTP256 caKey;
    caKey = securityManagerKey;

    /*
     * For this test the adminGroupAuthorityKeyIdentifier should be null
     * This is the KeyId of the securityManagerKey.
     */
    securityManagerKey.SetKeyId(NULL, 0);

    //Random GUID used for the SecurityManager
    GUID128 securityManagerGuid;

    //Create identityCertChain
    IdentityCertificate identityCertChain[1];

    // peer public key used to generate the identity certificate chain
    ECCPublicKey TCPublicKey;
    EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(securityManagerBus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(securityManagerBus,
                                                                  "1215",
                                                                  securityManagerGuid.ToString(),
                                                                  &TCPublicKey,
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";

    appStateListener.stateChanged = false;

    /*
     * Claim TC
     * the CA key is empty.
     * For this test the adminGroupId is a randomly generated GUID as long as the
     * GUID is consistent it's unimportant that the GUID is random.
     * Use generated identity certificate signed by the securityManager
     * Since we are only interested in claiming the peer we are using an all
     * inclusive manifest.
     */
    ASSERT_EQ(static_cast<size_t>(0), securityManagerKey.GetKeyIdLen());
    EXPECT_NE(ER_OK, sapWithTC.Claim(caKey,
                                        securityManagerGuid,
                                        securityManagerKey,
                                        identityCertChain, 1,
                                        manifest, manifestSize));

    EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateTC);
}

/*
 * Claim using ECDHE_NULL
 * Verify that Claim is successful using an ECDHE_NULL based session, where the
 * CA public key and the admin security group public key are different.
 *
 * Test Case:
 * caPublicKey != adminGroupSecurityPublicKey
 * Identity = Single certificate signed by CA
 */
TEST_F(SecurityClaimApplicationTest, Claim_using_ECDHE_NULL_caKey_not_same_as_adminGroupKey)
{
    securityManagerBus.AddApplicationStateRule();

    appStateListener.stateChanged = false;
    //EnablePeerSecurity
    securityManagerKeyListener = new DefaultECDHEAuthListener();
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", securityManagerKeyListener);

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(securityManagerBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    appStateListener.stateChanged = false;

    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL");

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    appStateListener.stateChanged = false;

    SCKeyListener = new DefaultECDHEAuthListener();
    SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", SCKeyListener);

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(SCBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    SecurityApplicationProxy sapWithTC(securityManagerBus, TCBus->GetUniqueName().c_str());
    PermissionConfigurator::ApplicationState applicationStateTC;
    EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateTC);

    //Create admin group key
    KeyInfoNISTP256 securityManagerKey;
    PermissionConfigurator& permissionConfigurator = securityManagerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(securityManagerKey));

    //Use SC key as the caKey
    KeyInfoNISTP256 caKey;
    PermissionConfigurator& permissionConfigurator2 = SCBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator2.GetSigningPublicKey(caKey));

    //Random GUID used for the SecurityManager
    GUID128 securityManagerGuid;
    GUID128 caGuid;

    //Create identityCertChain
    IdentityCertificate identityCertChain[1];

    // peer public key used to generate the identity certificate chain
    ECCPublicKey TCPublicKey;
    EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                  PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                  PermissionPolicy::Rule::Member::ACTION_MODIFY |
                  PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(SCBus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    // SC will become the the one signing the identity certificate.
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(SCBus,
                                                                  "1215",
                                                                  caGuid.ToString(),
                                                                  &TCPublicKey,
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";

    appStateListener.stateChanged = false;
    //Verify the caPublicKey != adminGroupSecurityPublicKey.
    EXPECT_NE(caKey, securityManagerKey);
    /*
     * Claim TC
     * the certificate authority is self signed by SC using the
     * CreateIdentityCert method
     *
     * For this test the adminGroupId is a randomly generated GUID as long as the
     * GUID is consistent it's unimportant that the GUID is random.
     * Use generated identity certificate signed by SC
     * Since we are only interested in claiming the peer we are using an all
     * inclusive manifest.
     */
    EXPECT_EQ(ER_OK, sapWithTC.Claim(caKey,
                                        securityManagerGuid,
                                        securityManagerKey,
                                        identityCertChain, 1,
                                        manifest, manifestSize));

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    EXPECT_TRUE(appStateListener.stateChanged);
    EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
    EXPECT_EQ(PermissionConfigurator::CLAIMED, applicationStateTC);
}

/*
 * Claim using ECDHE_PSK
 * Verify that Claim is successful using an ECDHE_PSK based session, where the
 * CA public key and the admin security group public key are the same.
 *
 * Test Case:
 * Claim using ECDHE_PSK
 * caPublic key == adminGroupSecurityPublicKey
 * Identity = Single certificate signed by CA
 */
TEST_F(SecurityClaimApplicationTest, Claim_using_ECDHE_PSK_session_successful)
{
    securityManagerBus.AddApplicationStateRule();

    appStateListener.stateChanged = false;
    //EnablePeerSecurity
    const uint8_t psk[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    securityManagerKeyListener = new DefaultECDHEAuthListener(psk, 16);
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_PSK", securityManagerKeyListener);

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(securityManagerBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    appStateListener.stateChanged = false;

    SetPsk(psk, 16);
    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_PSK");

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    SecurityApplicationProxy sapWithTC(securityManagerBus, TCBus->GetUniqueName().c_str());
    PermissionConfigurator::ApplicationState applicationStateTC;
    EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
    ASSERT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateTC);

    //Create admin group key
    KeyInfoNISTP256 securityManagerKey;
    PermissionConfigurator& permissionConfigurator = securityManagerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(securityManagerKey));

    //Random GUID used for the SecurityManager
    GUID128 securityManagerGuid;

    //Create identityCertChain
    IdentityCertificate identityCertChain[1];

    // peer public key used to generate the identity certificate chain
    ECCPublicKey TCPublicKey;
    EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(securityManagerBus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(securityManagerBus,
                                                                  "0",
                                                                  securityManagerGuid.ToString(),
                                                                  &TCPublicKey,
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";

    appStateListener.stateChanged = false;
    /*
     * Claim TC
     * the certificate authority is self signed so the certificateAuthority
     * key is the same as the adminGroup key.
     * For this test the adminGroupId is a randomly generated GUID as long as the
     * GUID is consistent it's unimportant that the GUID is random.
     * Use generated identity certificate signed by the securityManager
     * Since we are only interested in claiming the peer we are using an all
     * inclusive manifest.
     */
    EXPECT_EQ(ER_OK, sapWithTC.Claim(securityManagerKey,
                                        securityManagerGuid,
                                        securityManagerKey,
                                        identityCertChain, 1,
                                        manifest, manifestSize));

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    EXPECT_TRUE(appStateListener.stateChanged);
    EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
    EXPECT_EQ(PermissionConfigurator::CLAIMED, applicationStateTC);
}

/*
 * Verify that Calim fails when the digest in the Identity certificate does not
 * match the digest of the manifest.
 *
 * Test Case:
 * Claim
 * Manifest digest != digest in the identity certificate */
TEST_F(SecurityClaimApplicationTest, Claim_fails_if_identity_cert_digest_not_equal_claim_manifest)
{
    securityManagerBus.AddApplicationStateRule();

    appStateListener.stateChanged = false;
    //EnablePeerSecurity
    securityManagerKeyListener = new DefaultECDHEAuthListener();
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", securityManagerKeyListener);

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(securityManagerBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    appStateListener.stateChanged = false;

    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL");

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    SecurityApplicationProxy sapWithTC(securityManagerBus, TCBus->GetUniqueName().c_str());
    PermissionConfigurator::ApplicationState applicationStateTC;
    EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
    ASSERT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateTC);

    //Create admin group key
    KeyInfoNISTP256 securityManagerKey;
    PermissionConfigurator& permissionConfigurator = securityManagerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(securityManagerKey));

    //Random GUID used for the SecurityManager
    GUID128 securityManagerGuid;

    //Create identityCertChain
    IdentityCertificate identityCertChain[1];

    // peer public key used to generate the identity certificate chain
    ECCPublicKey TCPublicKey;
    EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(securityManagerBus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    // Manifest that is different then the All Inclusive manifest passed in as
    // the digest.
    PermissionPolicy::Rule::Member member2[1];
    member2[0].Set("*", PermissionPolicy::Rule::Member::METHOD_CALL, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    PermissionPolicy::Rule manifest2[manifestSize];
    manifest2[0].SetObjPath("*");
    manifest2[0].SetInterfaceName("*");
    manifest2[0].SetMembers(1, member2);

    uint8_t digest2[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(securityManagerBus,
                                                               manifest2, manifestSize,
                                                               digest2, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    EXPECT_TRUE(memcmp(digest, digest2, Crypto_SHA256::DIGEST_SIZE) != 0);

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(securityManagerBus,
                                                                  "0",
                                                                  securityManagerGuid.ToString(),
                                                                  &TCPublicKey,
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";

    /*
     * Claim TC
     * the certificate authority is self signed so the certificateAuthority
     * key is the same as the adminGroup key.
     * For this test the adminGroupId is a randomly generated GUID as long as the
     * GUID is consistent it's unimportant that the GUID is random.
     * Use generated identity certificate signed by the securityManager
     * Since we are only interested in claiming the peer we are using an all
     * inclusive manifest.
     */
    EXPECT_EQ(ER_DIGEST_MISMATCH, sapWithTC.Claim(securityManagerKey,
                                                     securityManagerGuid,
                                                     securityManagerKey,
                                                     identityCertChain, 1,
                                                     manifest2, manifestSize));
}

/*
 * Verify the Claim fails when you try to claim the app. bus again with the same
 * set of parameters.
 *
 * Test Case:
 * Try to claim an already claimed application with the same set of parameters
 * as before.
 *
 * We will make a successful ECDHE_NULL claim then claim again.
 */
TEST_F(SecurityClaimApplicationTest, fail_second_claim)
{
    securityManagerBus.AddApplicationStateRule();

    appStateListener.stateChanged = false;
    //EnablePeerSecurity
    securityManagerKeyListener = new DefaultECDHEAuthListener();
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", securityManagerKeyListener);

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(securityManagerBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    appStateListener.stateChanged = false;

    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL");

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    SecurityApplicationProxy sapWithTC(securityManagerBus, TCBus->GetUniqueName().c_str());
    PermissionConfigurator::ApplicationState applicationStateTC;
    EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
    ASSERT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateTC);

    //Create admin group key
    KeyInfoNISTP256 securityManagerKey;
    PermissionConfigurator& permissionConfigurator = securityManagerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(securityManagerKey));

    //Random GUID used for the SecurityManager
    GUID128 securityManagerGuid;

    //Create identityCertChain
    IdentityCertificate identityCertChain[1];

    // peer public key used to generate the identity certificate chain
    ECCPublicKey TCPublicKey;
    EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(securityManagerBus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(securityManagerBus,
                                                                  "0",
                                                                  securityManagerGuid.ToString(),
                                                                  &TCPublicKey,
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";

    appStateListener.stateChanged = false;
    /*
     * Claim TC
     * the certificate authority is self signed so the certificateAuthority
     * key is the same as the adminGroup key.
     * For this test the adminGroupId is a randomly generated GUID as long as the
     * GUID is consistent it's unimportant that the GUID is random.
     * Use generated identity certificate signed by the securityManager
     * Since we are only interested in claiming the peer we are using an all
     * inclusive manifest.
     */
    EXPECT_EQ(ER_OK, sapWithTC.Claim(securityManagerKey,
                                        securityManagerGuid,
                                        securityManagerKey,
                                        identityCertChain, 1,
                                        manifest, manifestSize));

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    EXPECT_TRUE(appStateListener.stateChanged);
    EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
    EXPECT_EQ(PermissionConfigurator::CLAIMED, applicationStateTC);

    appStateListener.stateChanged = false;
    EXPECT_EQ(ER_PERMISSION_DENIED, sapWithTC.Claim(securityManagerKey,
                                                       securityManagerGuid,
                                                       securityManagerKey,
                                                       identityCertChain, 1,
                                                       manifest, manifestSize));
}

/*
 * Verify the Claim fails when you try to claim the app. bus again with the
 * different  set of parameters.
 *
 * Test Case:
 * Try to claim an already claimed application with a different set of
 * parameters as before.
 *
 * We will make a successful ECDHE_NULL claim then claim again.
 */
TEST_F(SecurityClaimApplicationTest, fail_second_claim_with_different_parameters)
{
    securityManagerBus.AddApplicationStateRule();

    appStateListener.stateChanged = false;
    //EnablePeerSecurity
    securityManagerKeyListener = new DefaultECDHEAuthListener();
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", securityManagerKeyListener);

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(securityManagerBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    appStateListener.stateChanged = false;

    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL");

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    SecurityApplicationProxy sapWithTC(securityManagerBus, TCBus->GetUniqueName().c_str());
    PermissionConfigurator::ApplicationState applicationStateTC;
    EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
    ASSERT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateTC);

    //Create admin group key
    KeyInfoNISTP256 securityManagerKey;
    PermissionConfigurator& permissionConfigurator = securityManagerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(securityManagerKey));

    //Random GUID used for the SecurityManager
    GUID128 securityManagerGuid;

    //Create identityCertChain
    IdentityCertificate identityCertChain[1];

    // peer public key used to generate the identity certificate chain
    ECCPublicKey TCPublicKey;
    EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(securityManagerBus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(securityManagerBus,
                                                                  "0",
                                                                  securityManagerGuid.ToString(),
                                                                  &TCPublicKey,
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";

    appStateListener.stateChanged = false;
    /*
     * Claim TC
     * the certificate authority is self signed so the certificateAuthority
     * key is the same as the adminGroup key.
     * For this test the adminGroupId is a randomly generated GUID as long as the
     * GUID is consistent it's unimportant that the GUID is random.
     * Use generated identity certificate signed by the securityManager
     * Since we are only interested in claiming the peer we are using an all
     * inclusive manifest.
     */
    EXPECT_EQ(ER_OK, sapWithTC.Claim(securityManagerKey,
                                        securityManagerGuid,
                                        securityManagerKey,
                                        identityCertChain, 1,
                                        manifest, manifestSize));

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    EXPECT_TRUE(appStateListener.stateChanged);
    EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
    EXPECT_EQ(PermissionConfigurator::CLAIMED, applicationStateTC);


    //Create identityCertChain
    IdentityCertificate identityCertChain2[1];

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member2[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::METHOD_CALL,
                  PermissionPolicy::Rule::Member::ACTION_PROVIDE |
                  PermissionPolicy::Rule::Member::ACTION_MODIFY);
    PermissionPolicy::Rule manifest2[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member2);

    uint8_t digest2[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(securityManagerBus,
                                                               manifest2, manifestSize,
                                                               digest2, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(securityManagerBus,
                                                                  "0",
                                                                  securityManagerGuid.ToString(),
                                                                  &TCPublicKey,
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain2[0],
                                                                  digest2, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";

    EXPECT_EQ(ER_PERMISSION_DENIED, sapWithTC.Claim(securityManagerKey,
                                                       securityManagerGuid,
                                                       securityManagerKey,
                                                       identityCertChain2, 1,
                                                       manifest2, manifestSize));
}

/*
 * Verify that Claim fails when you try to Claim a "Non-Claimable" application.
 *
 * Test Case:
 * Try to claim a "Non-Claimable" application
 */
TEST_F(SecurityClaimApplicationTest, fail_when_claiming_non_claimable)
{
    securityManagerBus.AddApplicationStateRule();

    appStateListener.stateChanged = false;
    //EnablePeerSecurity
    securityManagerKeyListener = new DefaultECDHEAuthListener();
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", securityManagerKeyListener);

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(securityManagerBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    appStateListener.stateChanged = false;

    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL");

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    SecurityApplicationProxy sapWithTC(securityManagerBus, TCBus->GetUniqueName().c_str());
    PermissionConfigurator::ApplicationState applicationStateTC;
    EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
    ASSERT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateTC);
    TCBus->SetApplicationState(APP_STATE_NOT_CLAIMABLE);

    EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
    ASSERT_EQ(PermissionConfigurator::NOT_CLAIMABLE, applicationStateTC);

    //Create admin group key
    KeyInfoNISTP256 securityManagerKey;
    PermissionConfigurator& permissionConfigurator = securityManagerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(securityManagerKey));

    //Random GUID used for the SecurityManager
    GUID128 securityManagerGuid;

    //Create identityCertChain
    IdentityCertificate identityCertChain[1];

    // peer public key used to generate the identity certificate chain
    ECCPublicKey TCPublicKey;
    EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(securityManagerBus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(securityManagerBus,
                                                                  "0",
                                                                  securityManagerGuid.ToString(),
                                                                  &TCPublicKey,
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";

    appStateListener.stateChanged = false;
    /*
     * Claim TC
     * the certificate authority is self signed so the certificateAuthority
     * key is the same as the adminGroup key.
     * For this test the adminGroupId is a randomly generated GUID as long as the
     * GUID is consistent it's unimportant that the GUID is random.
     * Use generated identity certificate signed by the securityManager
     * Since we are only interested in claiming the peer we are using an all
     * inclusive manifest.
     */
    EXPECT_EQ(ER_PERMISSION_DENIED, sapWithTC.Claim(securityManagerKey,
                                                       securityManagerGuid,
                                                       securityManagerKey,
                                                       identityCertChain, 1,
                                                       manifest, manifestSize));
}

/*
 * Verify that Claim fails when the Claimer does not have security enabled.
 *
 * Test Case:
 * Claimer does not have security enabled.
 * Claimer makes a claim call.
 */
TEST_F(SecurityClaimApplicationTest, fail_claimer_security_not_enabled)
{
    securityManagerBus.AddApplicationStateRule();

    appStateListener.stateChanged = false;

    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL");

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    appStateListener.stateChanged = false;

    SCKeyListener = new DefaultECDHEAuthListener();
    SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", SCKeyListener);

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(SCBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    //Create admin group key
    KeyInfoNISTP256 caKey;
    PermissionConfigurator& permissionConfigurator = SCBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(caKey));

    //Random GUID used for the SecurityManager
    GUID128 securityManagerGuid;

    //Create identityCertChain
    IdentityCertificate identityCertChain[1];

    // peer public key used to generate the identity certificate chain
    ECCPublicKey TCPublicKey;
    SecurityApplicationProxy sapWithTC(securityManagerBus, TCBus->GetUniqueName().c_str());
    EXPECT_EQ(ER_BUS_SECURITY_NOT_ENABLED, sapWithTC.GetEccPublicKey(TCPublicKey));

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(SCBus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(SCBus,
                                                                  "0",
                                                                  securityManagerGuid.ToString(),
                                                                  &TCPublicKey,
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";

    EXPECT_EQ(ER_BUS_SECURITY_NOT_ENABLED, sapWithTC.Claim(caKey,
                                                              securityManagerGuid,
                                                              caKey,
                                                              identityCertChain, 1,
                                                              manifest, manifestSize));
}

/*
 * Verify that Claim fails when the Claimant does not have security enabled.
 *
 * Test Case:
 * Claimant does not have security enabled.
 * Claimer makes a claim call.
 */
TEST_F(SecurityClaimApplicationTest, fail_when_peer_being_claimed_is_not_security_enabled)
{
    securityManagerBus.AddApplicationStateRule();

    appStateListener.stateChanged = false;
    //EnablePeerSecurity
    securityManagerKeyListener = new DefaultECDHEAuthListener();
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", securityManagerKeyListener);

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(securityManagerBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    //Create admin group key
    KeyInfoNISTP256 securityManagerKey;
    PermissionConfigurator& permissionConfigurator = securityManagerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(securityManagerKey));

    //Random GUID used for the SecurityManager
    GUID128 securityManagerGuid;

    // Create identityCertChain CertChain is only valid for the SecurityManager
    // Not for TC.  Since TC has not enabled PeerSecurity it is unable to
    // provide a public key.  We use the securityManagersKey to create an
    // identity certificate.  We expect the resulting failure to be due to the
    // fact that TC has not enabled peer security not due to the publicKey
    // mismatch. Either way the result is the same, claim fails.
    IdentityCertificate identityCertChain[1];

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(securityManagerBus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(securityManagerBus,
                                                                  "0",
                                                                  securityManagerGuid.ToString(),
                                                                  securityManagerKey.GetPublicKey(),
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";

    appStateListener.stateChanged = false;
    printf("TC NAME %s\n", TCBus->GetUniqueName().c_str());
    SecurityApplicationProxy sapWithTC(securityManagerBus, TCBus->GetUniqueName().c_str());
    /*
     * Claim TC
     * the certificate authority is self signed so the certificateAuthority
     * key is the same as the adminGroup key.
     * For this test the adminGroupId is a randomly generated GUID as long as the
     * GUID is consistent it's unimportant that the GUID is random.
     * Use generated identity certificate signed by the securityManager
     * Since we are only interested in claiming the peer we are using an all
     * inclusive manifest.
     */
    EXPECT_EQ(ER_AUTH_FAIL, sapWithTC.Claim(securityManagerKey,
                                               securityManagerGuid,
                                               securityManagerKey,
                                               identityCertChain, 1,
                                               manifest, manifestSize));
}

class ClaimThread1 : public Thread {
  public:
    ClaimThread1() : status(ER_FAIL) { };
    QStatus status;
  protected:
    ThreadReturn STDCALL Run(void* arg) {
        SecurityClaimApplicationTest* thiz = (SecurityClaimApplicationTest*)arg;
        SecurityApplicationProxy sapWithTC(thiz->securityManagerBus, thiz->TCBus->GetUniqueName().c_str());

        //Create admin group key
        KeyInfoNISTP256 securityManagerKey;
        PermissionConfigurator& permissionConfigurator = thiz->securityManagerBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(securityManagerKey));

        //Random GUID used for the SecurityManager
        GUID128 securityManagerGuid;

        //Create identityCertChain
        IdentityCertificate identityCertChain[1];

        // peer public key used to generate the identity certificate chain
        ECCPublicKey TCPublicKey;
        EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));

        // All Inclusive manifest
        PermissionPolicy::Rule::Member member[1];
        member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        const size_t manifestSize = 1;
        PermissionPolicy::Rule manifest[manifestSize];
        manifest[0].SetObjPath("*");
        manifest[0].SetInterfaceName("*");
        manifest[0].SetMembers(1, member);

        uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
        EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(thiz->securityManagerBus,
                                                                   manifest, manifestSize,
                                                                   digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(thiz->securityManagerBus,
                                                                      "0",
                                                                      securityManagerGuid.ToString(),
                                                                      &TCPublicKey,
                                                                      "Alias",
                                                                      3600,
                                                                      identityCertChain[0],
                                                                      digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";

        status = sapWithTC.Claim(securityManagerKey,
                                    securityManagerGuid,
                                    securityManagerKey,
                                    identityCertChain, 1,
                                    manifest, manifestSize);

        return static_cast<ThreadReturn>(0);
    }
};

class ClaimThread2 : public Thread {
  public:
    ClaimThread2() : status(ER_FAIL) { };
    QStatus status;
  protected:
    ThreadReturn STDCALL Run(void* arg) {
        SecurityClaimApplicationTest* thiz = (SecurityClaimApplicationTest*)arg;
        SecurityApplicationProxy sapWithTC(thiz->securityManagerBus, thiz->TCBus->GetUniqueName().c_str());

        //Create admin group key
        KeyInfoNISTP256 securityManagerKey;
        PermissionConfigurator& permissionConfigurator = thiz->SCBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(securityManagerKey));

        //Random GUID used for the SecurityManager
        GUID128 securityManagerGuid;

        //Create identityCertChain
        IdentityCertificate identityCertChain[1];

        // peer public key used to generate the identity certificate chain
        ECCPublicKey TCPublicKey;
        EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));

        // All Inclusive manifest
        PermissionPolicy::Rule::Member member[1];
        member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        const size_t manifestSize = 1;
        PermissionPolicy::Rule manifest[manifestSize];
        manifest[0].SetObjPath("*");
        manifest[0].SetInterfaceName("*");
        manifest[0].SetMembers(1, member);

        uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
        EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(thiz->SCBus,
                                                                   manifest, manifestSize,
                                                                   digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

        EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(thiz->SCBus,
                                                                      "0",
                                                                      securityManagerGuid.ToString(),
                                                                      &TCPublicKey,
                                                                      "Alias",
                                                                      3600,
                                                                      identityCertChain[0],
                                                                      digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";

        status = sapWithTC.Claim(securityManagerKey,
                                    securityManagerGuid,
                                    securityManagerKey,
                                    identityCertChain, 1,
                                    manifest, manifestSize);
        return static_cast<ThreadReturn>(0);
    }
};

/*
 * Two buses try to claim an application simultaneously.
 *
 * Test Case:
 * Verify that one Claim call is successful and the other one fails.
 */
TEST_F(SecurityClaimApplicationTest, two_peers_claim_application_simultaneously)
{
    securityManagerBus.AddApplicationStateRule();

    appStateListener.stateChanged = false;
    //EnablePeerSecurity
    securityManagerKeyListener = new DefaultECDHEAuthListener();
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", securityManagerKeyListener);

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(securityManagerBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    appStateListener.stateChanged = false;

    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL");

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    appStateListener.stateChanged = false;

    SCKeyListener = new DefaultECDHEAuthListener();
    SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", SCKeyListener);

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(SCBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    SecurityApplicationProxy sapWithTC(securityManagerBus, TCBus->GetUniqueName().c_str());
    PermissionConfigurator::ApplicationState applicationStateTC;
    EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
    ASSERT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateTC);

    SecurityApplicationProxy SCSapWithTC(SCBus, TCBus->GetUniqueName().c_str());
    EXPECT_EQ(ER_OK, SCSapWithTC.GetApplicationState(applicationStateTC));
    ASSERT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateTC);

    appStateListener.stateChanged = false;

    ClaimThread1 claimThread1;
    ClaimThread2 claimThread2;

    claimThread1.Start(this, NULL);
    claimThread2.Start(this, NULL);

    claimThread1.Join();
    claimThread2.Join();

    //one of the claim threads must pass while the other must fail with Permission denied
    EXPECT_NE(claimThread1.status, claimThread2.status);
    EXPECT_TRUE(claimThread1.status == ER_OK || claimThread2.status == ER_OK);
    EXPECT_TRUE(claimThread1.status == ER_PERMISSION_DENIED || claimThread2.status == ER_PERMISSION_DENIED);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    EXPECT_TRUE(appStateListener.stateChanged);
    EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
    EXPECT_EQ(PermissionConfigurator::CLAIMED, applicationStateTC);
}

/*
 * Verify that Claim operation fails when the Claimer and Claimant have
 * different secirity mechanisms enabled.
 *
 * Test Case:
 * Claimer has security enabled for ECDHE_PSK
 * Claimant has security enabled for ECDHE_NULL
 */
TEST_F(SecurityClaimApplicationTest, fail_when_admin_and_peer_use_different_security_mechanisms)
{
    securityManagerBus.AddApplicationStateRule();

    appStateListener.stateChanged = false;
    //EnablePeerSecurity
    const uint8_t psk[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
    securityManagerKeyListener = new DefaultECDHEAuthListener(psk, 16);
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_PSK", securityManagerKeyListener);

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(securityManagerBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    appStateListener.stateChanged = false;

    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL");

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    SecurityApplicationProxy sapWithTC(securityManagerBus, TCBus->GetUniqueName().c_str());

    //Create admin group key
    KeyInfoNISTP256 securityManagerKey;
    PermissionConfigurator& permissionConfigurator = securityManagerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(securityManagerKey));

    //Random GUID used for the SecurityManager
    GUID128 securityManagerGuid;

    //Create identityCertChain
    IdentityCertificate identityCertChain[1];

    ECCPublicKey TCPublicKey;

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(securityManagerBus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(securityManagerBus,
                                                                  "0",
                                                                  securityManagerGuid.ToString(),
                                                                  &TCPublicKey,
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";

    appStateListener.stateChanged = false;

    EXPECT_EQ(ER_AUTH_FAIL, sapWithTC.Claim(securityManagerKey,
                                               securityManagerGuid,
                                               securityManagerKey,
                                               identityCertChain, 1,
                                               manifest, manifestSize));
}

/*
 * Verify that Claim fails when the identity certificate's subject is different
 * than the device's public key.
 *
 * Test Case:
 * Generate an identity certificate which has a different public key than that
 * of the device. The device's public key can be found from the Application
 * State notification signal.
 */
TEST_F(SecurityClaimApplicationTest, fail_if_incorrect_publickey_used_in_identity_cert)
{
    securityManagerBus.AddApplicationStateRule();

    appStateListener.stateChanged = false;
    //EnablePeerSecurity
    securityManagerKeyListener = new DefaultECDHEAuthListener();
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", securityManagerKeyListener);

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(securityManagerBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    appStateListener.stateChanged = false;

    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL");

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    SecurityApplicationProxy sapWithTC(securityManagerBus, TCBus->GetUniqueName().c_str());
    PermissionConfigurator::ApplicationState applicationStateTC;
    EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
    ASSERT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateTC);

    //Create admin group key
    KeyInfoNISTP256 securityManagerKey;
    PermissionConfigurator& permissionConfigurator = securityManagerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(securityManagerKey));

    //Random GUID used for the SecurityManager
    GUID128 securityManagerGuid;

    //Create identityCertChain
    IdentityCertificate identityCertChain[1];

    // peer public key used to generate the identity certificate chain
    ECCPublicKey TCPublicKey;
    EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(securityManagerBus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    // securityManagerKey used instead of TC key to make sure we create an
    // invalid cert.
    EXPECT_NE(TCPublicKey, *securityManagerKey.GetPublicKey());
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(securityManagerBus,
                                                                  "0",
                                                                  securityManagerGuid.ToString(),
                                                                  securityManagerKey.GetPublicKey(),
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";

    appStateListener.stateChanged = false;

    /* FAIL: SC error not correct */
    EXPECT_EQ(ER_UNKNOWN_CERTIFICATE, sapWithTC.Claim(securityManagerKey,
                                                         securityManagerGuid,
                                                         securityManagerKey,
                                                         identityCertChain, 1,
                                                         manifest, manifestSize));
}

/*
 * TestCase:
 * In factory reset mode, app should emit the state notification.
 *
 * Procedure:
 * Application does not have a keystore.
 * Application bus calls enable peer security with ECDHE_NULL authentication mechanism.
 * Bus does an add match rule for the state notification.
 * Verify that Bus gets the state notification.
 * The state should be "Claimable"
 * publickey algorithm should be equal to 0
 * publickey curveIdentifier should be equal to 0
 * publickey xCo-ordinate and yCo-ordinate are populated and are non-empty
 */
TEST_F(SecurityClaimApplicationTest, get_application_state_signal)
{
    //EnablePeerSecurity
    // the DSA Key Pair should be generated as soon as Enable PeerSecurity is
    // called.
    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL");

    EXPECT_FALSE(appStateListener.stateChanged);
    securityManagerBus.AddApplicationStateRule();

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    EXPECT_TRUE(appStateListener.stateChanged);
    EXPECT_EQ(TCBus->GetUniqueName(), appStateListener.busNames.front());
    appStateListener.busNames.pop();
    EXPECT_EQ(0, appStateListener.publicKeys.front().GetAlgorithm());
    EXPECT_EQ(0, appStateListener.publicKeys.front().GetCurve());
    EXPECT_TRUE(NULL != appStateListener.publicKeys.front().GetPublicKey()->GetX());
    EXPECT_TRUE(NULL != appStateListener.publicKeys.front().GetPublicKey()->GetY());
    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, appStateListener.states.front());
    appStateListener.states.pop();
}

/*
 * TestCase:
 * After Claim operation is successful, app should emit the state notification.
 *
 * Procedure:
 * Application does not have a keystore.
 * Application bus calls enable peer security with ECDHE_NULL authentication mechanism.
 *
 * Secondary bus does an add match rule for the state notification.
 *
 * Verify that Secondary bus gets the state notification.
 * The state should be "Claimable"
 * publickey algorithm = 0
 * publickey curveIdentifier = 0
 * publickey xCo-ordinate and yCo-ordinate are populated and are non-empty
 *
 * Standard bus claims application bus successfully.
 *
 * Verify that the Secondary bus gets the Sessionless signal.
 * The state should be "Claimed"
 * publickey algorithm = 0
 * publickey curveIdentifier = 0
 * publickey xCo-ordinate and yCo-ordinate are populated and are same as before.
 */
TEST_F(SecurityClaimApplicationTest, get_application_state_signal_for_claimed_peer)
{
    //EnablePeerSecurity
    // the DSA Key Pair should be generated as soon as Enable PeerSecurity is
    // called.
    securityManagerKeyListener = new DefaultECDHEAuthListener();
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", securityManagerKeyListener);

    EXPECT_FALSE(appStateListener.stateChanged);
    securityManagerBus.AddApplicationStateRule();

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(securityManagerBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    // fail if not true!
    ASSERT_TRUE(appStateListener.stateChanged);

    EXPECT_EQ(securityManagerBus.GetUniqueName(), appStateListener.busNames.front());
    appStateListener.busNames.pop();
    EXPECT_EQ(0, appStateListener.publicKeys.front().GetAlgorithm());
    EXPECT_EQ(0, appStateListener.publicKeys.front().GetCurve());
    EXPECT_TRUE(NULL != appStateListener.publicKeys.front().GetPublicKey()->GetX());
    EXPECT_TRUE(NULL != appStateListener.publicKeys.front().GetPublicKey()->GetY());
    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, appStateListener.states.front());
    appStateListener.states.pop();

    appStateListener.stateChanged = false;

    //verify we read all the signals
    EXPECT_TRUE(appStateListener.busNames.size() == 0 && appStateListener.publicKeys.size() == 0 && appStateListener.states.size() == 0);

    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL");

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    EXPECT_TRUE(appStateListener.stateChanged);

    SecurityApplicationProxy sapWithTC(securityManagerBus, TCBus->GetUniqueName().c_str());

    EXPECT_EQ(TCBus->GetUniqueName(), appStateListener.busNames.front());
    appStateListener.busNames.pop();
    EXPECT_EQ(0, appStateListener.publicKeys.front().GetAlgorithm());
    EXPECT_EQ(0, appStateListener.publicKeys.front().GetCurve());
    EXPECT_TRUE(NULL != appStateListener.publicKeys.front().GetPublicKey()->GetX());
    EXPECT_TRUE(NULL != appStateListener.publicKeys.front().GetPublicKey()->GetY());
    //EXPECT_EQ(TCPublicKey, publicKeys.front().GetPublicKey());
    ECCPublicKey TCPublicKey = *(appStateListener.publicKeys.front().GetPublicKey());
    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, appStateListener.states.front());
    appStateListener.states.pop();

    //verify we read all the signals
    EXPECT_TRUE(appStateListener.busNames.size() == 0 && appStateListener.publicKeys.size() == 0 && appStateListener.states.size() == 0);

    //Create admin group key
    KeyInfoNISTP256 securityManagerKey;
    PermissionConfigurator& permissionConfigurator = securityManagerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(securityManagerKey));

    //Random GUID used for the SecurityManager
    GUID128 securityManagerGuid;

    //Create identityCertChain
    IdentityCertificate identityCertChain[1];

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(securityManagerBus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(securityManagerBus,
                                                                  "0",
                                                                  securityManagerGuid.ToString(),
                                                                  &TCPublicKey,
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";

    appStateListener.stateChanged = false;

    EXPECT_TRUE(appStateListener.busNames.size() == 0 && appStateListener.publicKeys.size() == 0 && appStateListener.states.size() == 0);
//    SecurityApplicationProxy sapWithTC(securityManagerBus, TCBus->GetUniqueName().c_str().c_str());
    EXPECT_EQ(ER_OK, sapWithTC.Claim(securityManagerKey,
                                        securityManagerGuid,
                                        securityManagerKey,
                                        identityCertChain, 1,
                                        manifest, manifestSize));

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged && appStateListener.states.back() == PermissionConfigurator::CLAIMED) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    EXPECT_TRUE(appStateListener.stateChanged);

    EXPECT_EQ(TCBus->GetUniqueName(), appStateListener.busNames.front());
    appStateListener.busNames.pop();
    EXPECT_EQ(0, appStateListener.publicKeys.back().GetAlgorithm());
    EXPECT_EQ(0, appStateListener.publicKeys.back().GetCurve());
    EXPECT_TRUE(NULL != appStateListener.publicKeys.back().GetPublicKey()->GetX());
    EXPECT_TRUE(NULL != appStateListener.publicKeys.back().GetPublicKey()->GetY());

    EXPECT_TRUE(memcmp(TCPublicKey.GetX(), appStateListener.publicKeys.back().GetPublicKey()->GetX(), qcc::ECC_COORDINATE_SZ) == 0);
    EXPECT_TRUE(memcmp(TCPublicKey.GetY(), appStateListener.publicKeys.back().GetPublicKey()->GetY(), qcc::ECC_COORDINATE_SZ) == 0);

    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::CLAIMED, appStateListener.states.back());
    appStateListener.states.pop();

    //verify we read all the signals
    EXPECT_TRUE(appStateListener.busNames.size() == 0 && appStateListener.publicKeys.size() == 0 && appStateListener.states.size() == 0) << "The Notification State signal was sent more times than expected.";
}


/*
 * TestCase:
 * After Reset operation, app should emit the state notification and the public
 * key should be preserved.
 *
 * Procedure:
 * Verify that when admin resets the app. bus, the state notification is emitted
 *     and is received by the secondary bus.
 * Verify that Secondary bus gets the state notification.
 * The state should be "Claimable"
 * publickey algorithm = 0
 * publickey curveIdentifier = 0
 * publickey xCo-ordinate and yCo-ordinate are populated and are non-empty and
 *     are preserved and are same as before.
 */
TEST_F(SecurityClaimApplicationTest, get_application_state_signal_for_claimed_then_reset_peer)
{
    //EnablePeerSecurity
    // the DSA Key Pair should be generated as soon as Enable PeerSecurity is
    // called.
    appStateListener.stateChanged = false;
    securityManagerKeyListener = new DefaultECDHEAuthListener();
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", securityManagerKeyListener);
    printf("%d: %s\n", __LINE__, securityManagerBus.GetUniqueName().c_str());

    securityManagerBus.AddApplicationStateRule();

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(securityManagerBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    ASSERT_TRUE(appStateListener.stateChanged);
    EXPECT_EQ(securityManagerBus.GetUniqueName(), appStateListener.busNames.front());
    appStateListener.busNames.pop();
    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, appStateListener.states.front());
    appStateListener.states.pop();

    //verify we read all the signals
    EXPECT_TRUE(appStateListener.busNames.size() == 0 && appStateListener.publicKeys.size() == 0 && appStateListener.states.size() == 0);

    appStateListener.stateChanged = false;
    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL");
    printf("%d: %s\n", __LINE__, TCBus->GetUniqueName().c_str());

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    EXPECT_TRUE(appStateListener.stateChanged);

    EXPECT_EQ(TCBus->GetUniqueName(), appStateListener.busNames.front());
    appStateListener.busNames.pop();
    //EXPECT_EQ(TCPublicKey, publicKeys.front().GetPublicKey());
    ECCPublicKey TCPublicKey = *(appStateListener.publicKeys.front().GetPublicKey());
    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, appStateListener.states.front());
    appStateListener.states.pop();

    //verify we read all the signals
    EXPECT_TRUE(appStateListener.busNames.size() == 0 && appStateListener.publicKeys.size() == 0 && appStateListener.states.size() == 0);

    //Create admin group key
    KeyInfoNISTP256 securityManagerKey;
    PermissionConfigurator& permissionConfigurator = securityManagerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(securityManagerKey));

    //Random GUID used for the SecurityManager
    GUID128 securityManagerGuid;

    //Create identityCertChain
    IdentityCertificate identityCertChain[1];

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(securityManagerBus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(securityManagerBus,
                                                                  "0",
                                                                  securityManagerGuid.ToString(),
                                                                  &TCPublicKey,
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";

    appStateListener.stateChanged = false;
    SecurityApplicationProxy sapWithTC(securityManagerBus, TCBus->GetUniqueName().c_str());
    EXPECT_EQ(ER_OK, sapWithTC.Claim(securityManagerKey,
                                        securityManagerGuid,
                                        securityManagerKey,
                                        identityCertChain, 1,
                                        manifest, manifestSize));

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    ASSERT_TRUE(appStateListener.stateChanged);

    EXPECT_EQ(TCBus->GetUniqueName(), appStateListener.busNames.front());
    appStateListener.busNames.pop();
    EXPECT_EQ(0, appStateListener.publicKeys.back().GetAlgorithm());
    EXPECT_EQ(0, appStateListener.publicKeys.back().GetCurve());
    EXPECT_TRUE(NULL != appStateListener.publicKeys.back().GetPublicKey()->GetX());
    EXPECT_TRUE(NULL != appStateListener.publicKeys.back().GetPublicKey()->GetY());
    EXPECT_TRUE(memcmp(TCPublicKey.GetX(), appStateListener.publicKeys.back().GetPublicKey()->GetX(), qcc::ECC_COORDINATE_SZ) == 0);
    EXPECT_TRUE(memcmp(TCPublicKey.GetY(), appStateListener.publicKeys.back().GetPublicKey()->GetY(), qcc::ECC_COORDINATE_SZ) == 0);
    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::CLAIMED, appStateListener.states.back());
    appStateListener.states.pop();

    //verify we read all the signals
    EXPECT_TRUE(appStateListener.busNames.size() == 0 && appStateListener.publicKeys.size() == 0 && appStateListener.states.size() == 0) << "The Notification State signal was sent more times than expected.";

    appStateListener.stateChanged = false;
    // We first need a second bus attachment to claim the security manager bus
    BusAttachment managerClaimingBus("ManagerClaimingBus");
    EXPECT_EQ(ER_OK, managerClaimingBus.Start());
    EXPECT_EQ(ER_OK, managerClaimingBus.Connect());
    EXPECT_EQ(ER_OK, managerClaimingBus.RegisterKeyStoreListener(securityManagerKeyStoreListener));
    EXPECT_EQ(ER_OK, managerClaimingBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", securityManagerKeyListener, NULL, true));
    printf("%d: %s\n", __LINE__, managerClaimingBus.GetUniqueName().c_str());

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    ASSERT_TRUE(appStateListener.stateChanged);
    EXPECT_EQ(managerClaimingBus.GetUniqueName(), appStateListener.busNames.front());
    appStateListener.busNames.pop();
    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, appStateListener.states.front());
    appStateListener.states.pop();

    //verify we read all the signals
    EXPECT_TRUE(appStateListener.busNames.size() == 0 && appStateListener.publicKeys.size() == 0 && appStateListener.states.size() == 0);

    SecurityApplicationProxy sapWithManagerClaimingBus(managerClaimingBus, securityManagerBus.GetUniqueName().c_str());

    //Create identityCertChain for the secondary bus to claim the securityManagerBus
    IdentityCertificate identityCertChainToClaimAdmin[1];

    // All Inclusive manifest
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    //uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(managerClaimingBus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(managerClaimingBus,
                                                                  "0",
                                                                  securityManagerGuid.ToString(),
                                                                  securityManagerKey.GetPublicKey(),
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChainToClaimAdmin[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";



    appStateListener.stateChanged = false;
    EXPECT_EQ(ER_OK, sapWithManagerClaimingBus.Claim(securityManagerKey,
                                                     securityManagerGuid,
                                                     securityManagerKey,
                                                     identityCertChainToClaimAdmin, 1,
                                                     manifest, manifestSize));
    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    ASSERT_TRUE(appStateListener.stateChanged);
    EXPECT_EQ(securityManagerBus.GetUniqueName(), appStateListener.busNames.front());
    appStateListener.busNames.pop();
    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::CLAIMED, appStateListener.states.front());
    appStateListener.states.pop();

    //verify we read all the signals
    EXPECT_TRUE(appStateListener.busNames.size() == 0 && appStateListener.publicKeys.size() == 0 && appStateListener.states.size() == 0);

    PermissionConfigurator::ApplicationState applicationStateTC;
    EXPECT_EQ(ER_OK, sapWithManagerClaimingBus.GetApplicationState(applicationStateTC));
    EXPECT_EQ(PermissionConfigurator::CLAIMED, applicationStateTC);

    // After that we reload keystores
    managerClaimingBus.ReloadKeyStore();
    securityManagerBus.ReloadKeyStore();

    appStateListener.stateChanged = false;
    EXPECT_EQ(ER_OK, managerClaimingBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", securityManagerKeyListener, NULL, true));
    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);
    ASSERT_TRUE(appStateListener.stateChanged);
    EXPECT_EQ(managerClaimingBus.GetUniqueName(), appStateListener.busNames.front());
    appStateListener.busNames.pop();
    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::CLAIMED, appStateListener.states.front());
    appStateListener.states.pop();

    //verify we read all the signals
    EXPECT_TRUE(appStateListener.busNames.size() == 0 && appStateListener.publicKeys.size() == 0 && appStateListener.states.size() == 0);

    appStateListener.stateChanged = false;
    EXPECT_EQ(ER_OK, securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", securityManagerKeyListener, NULL, true));
    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);
    ASSERT_TRUE(appStateListener.stateChanged);
    EXPECT_EQ(securityManagerBus.GetUniqueName(), appStateListener.busNames.front());
    appStateListener.busNames.pop();
    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::CLAIMED, appStateListener.states.front());
    appStateListener.states.pop();

    //verify we read all the signals
    EXPECT_TRUE(appStateListener.busNames.size() == 0 && appStateListener.publicKeys.size() == 0 && appStateListener.states.size() == 0);

    // Create membership certificate
    String membershipSerial = "1";
    qcc::MembershipCertificate managerMembershipCertificate[1];
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert(membershipSerial,
                                                                    securityManagerBus,
                                                                    securityManagerBus.GetUniqueName(),
                                                                    securityManagerKey.GetPublicKey(),
                                                                    securityManagerGuid,
                                                                    false,
                                                                    3600,
                                                                    managerMembershipCertificate[0]));

    // Install membership certificate
    EXPECT_EQ(ER_OK, sapWithManagerClaimingBus.InstallMembership(managerMembershipCertificate, 1));

    appStateListener.stateChanged = false;
    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA");
    printf("%d: %s\n", __LINE__, TCBus->GetUniqueName().c_str());
    EXPECT_EQ(ER_OK, sapWithTC.Reset());

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged && appStateListener.states.back() == PermissionConfigurator::CLAIMABLE) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    ASSERT_TRUE(appStateListener.stateChanged);

    EXPECT_EQ(TCBus->GetUniqueName(), appStateListener.busNames.front());
    appStateListener.busNames.pop();
    EXPECT_EQ(0, appStateListener.publicKeys.back().GetAlgorithm());
    EXPECT_EQ(0, appStateListener.publicKeys.back().GetCurve());
    EXPECT_TRUE(NULL != appStateListener.publicKeys.back().GetPublicKey()->GetX());
    EXPECT_TRUE(NULL != appStateListener.publicKeys.back().GetPublicKey()->GetY());
    EXPECT_TRUE(memcmp(TCPublicKey.GetX(), appStateListener.publicKeys.back().GetPublicKey()->GetX(), qcc::ECC_COORDINATE_SZ) == 0);
    EXPECT_TRUE(memcmp(TCPublicKey.GetY(), appStateListener.publicKeys.back().GetPublicKey()->GetY(), qcc::ECC_COORDINATE_SZ) == 0);
    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, appStateListener.states.back());
    appStateListener.states.pop();

    //verify we read all the signals
    EXPECT_TRUE(appStateListener.busNames.size() == 0 && appStateListener.publicKeys.size() == 0 && appStateListener.states.size() == 0) << "The Notification State signal was sent more times than expected.";
}

/*
 * TestCase:
 * When admin calls UpdateIdentity() with a new manifest, the state notification should not be emitted
 *
 * Procedure:
 * Verify that when the admin calls UpdateIdentity() on the app. Bus with a new manifest, the state notification is NOT emitted.
 */
TEST_F(SecurityClaimApplicationTest, no_state_signal_after_update_identity)
{
    //EnablePeerSecurity
    // the DSA Key Pair should be generated as soon as Enable PeerSecurity is
    // called.
    securityManagerKeyListener = new DefaultECDHEAuthListener();
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", securityManagerKeyListener, NULL, true);

    securityManagerBus.AddApplicationStateRule();

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(securityManagerBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    ASSERT_TRUE(appStateListener.stateChanged);

    EXPECT_EQ(securityManagerBus.GetUniqueName(), appStateListener.busNames.front());
    appStateListener.busNames.pop();
    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, appStateListener.states.front());
    appStateListener.states.pop();

    appStateListener.stateChanged = false;

    //verify we read all the signals
    EXPECT_TRUE(appStateListener.busNames.size() == 0 && appStateListener.publicKeys.size() == 0 && appStateListener.states.size() == 0);

    // Setup the test peer
    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL");

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    ASSERT_TRUE(appStateListener.stateChanged);

    SecurityApplicationProxy sapWithTC(securityManagerBus, TCBus->GetUniqueName().c_str());

    EXPECT_EQ(TCBus->GetUniqueName(), appStateListener.busNames.front());
    appStateListener.busNames.pop();
    ECCPublicKey TCPublicKey = *(appStateListener.publicKeys.front().GetPublicKey());
    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, appStateListener.states.front());
    appStateListener.states.pop();

    //verify we read all the signals
    EXPECT_TRUE(appStateListener.busNames.size() == 0 && appStateListener.publicKeys.size() == 0 && appStateListener.states.size() == 0);

    //Create admin group key
    KeyInfoNISTP256 securityManagerKey;
    PermissionConfigurator& permissionConfigurator = securityManagerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(securityManagerKey));

    //Random GUID used for the SecurityManager
    GUID128 securityManagerGuid;

    //Create identityCertChain for the admin to claim the test peer
    IdentityCertificate identityCertChain[1];

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(securityManagerBus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(securityManagerBus,
                                                                  "0",
                                                                  securityManagerGuid.ToString(),
                                                                  &TCPublicKey,
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";

    appStateListener.stateChanged = false;

    EXPECT_TRUE(appStateListener.busNames.size() == 0 && appStateListener.publicKeys.size() == 0 && appStateListener.states.size() == 0);
    EXPECT_EQ(ER_OK, sapWithTC.Claim(securityManagerKey,
                                        securityManagerGuid,
                                        securityManagerKey,
                                        identityCertChain, 1,
                                        manifest, manifestSize));
    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged && appStateListener.states.back() == PermissionConfigurator::CLAIMED) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    ASSERT_TRUE(appStateListener.stateChanged);

    EXPECT_EQ(TCBus->GetUniqueName(), appStateListener.busNames.front());
    appStateListener.busNames.pop();
    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::CLAIMED, appStateListener.states.back());
    appStateListener.states.pop();

    appStateListener.stateChanged = false;

    // We first need a second bus attachment to claim the security manager bus
    BusAttachment managerClaimingBus("ManagerClaimingBus");
    EXPECT_EQ(ER_OK, managerClaimingBus.Start());
    EXPECT_EQ(ER_OK, managerClaimingBus.Connect());
    EXPECT_EQ(ER_OK, managerClaimingBus.RegisterKeyStoreListener(securityManagerKeyStoreListener));
    EXPECT_EQ(ER_OK, managerClaimingBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", securityManagerKeyListener, NULL, true));
    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(managerClaimingBus);

    SecurityApplicationProxy sapWithManagerClaimingBus(managerClaimingBus, securityManagerBus.GetUniqueName().c_str());

    //Create identityCertChain for the secondary bus to claim the securityManagerBus
    IdentityCertificate identityCertChainToClaimAdmin[1];

    // All Inclusive manifest
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    //uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(managerClaimingBus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(managerClaimingBus,
                                                                  "0",
                                                                  securityManagerGuid.ToString(),
                                                                  securityManagerKey.GetPublicKey(),
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChainToClaimAdmin[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";



    EXPECT_EQ(ER_OK, sapWithManagerClaimingBus.Claim(securityManagerKey,
                                                     securityManagerGuid,
                                                     securityManagerKey,
                                                     identityCertChainToClaimAdmin, 1,
                                                     manifest, manifestSize));
    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    ASSERT_TRUE(appStateListener.stateChanged);
    PermissionConfigurator::ApplicationState applicationStateTC;
    EXPECT_EQ(ER_OK, sapWithManagerClaimingBus.GetApplicationState(applicationStateTC));
    EXPECT_EQ(PermissionConfigurator::CLAIMED, applicationStateTC);

    // After that we reload keystores
    managerClaimingBus.ReloadKeyStore();
    securityManagerBus.ReloadKeyStore();
    EXPECT_EQ(ER_OK, managerClaimingBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", securityManagerKeyListener, NULL, true));
    EXPECT_EQ(ER_OK, securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", securityManagerKeyListener, NULL, true));

    // Create membership certificate
    String membershipSerial = "1";
    qcc::MembershipCertificate managerMembershipCertificate[1];
    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateMembershipCert(membershipSerial,
                                                                    securityManagerBus,
                                                                    securityManagerBus.GetUniqueName(),
                                                                    securityManagerKey.GetPublicKey(),
                                                                    securityManagerGuid,
                                                                    false,
                                                                    3600,
                                                                    managerMembershipCertificate[0]));

    // Install membership certificate
    EXPECT_EQ(ER_OK, sapWithManagerClaimingBus.InstallMembership(managerMembershipCertificate, 1));

    //Create identityCertChain
    IdentityCertificate identityCertChain1[1];

    // All Inclusive manifest
    PermissionPolicy::Rule::Member updatedMember[1];
    updatedMember[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED,  PermissionPolicy::Rule::Member::ACTION_PROVIDE);
    const size_t updatedManifestSize = 1;
    PermissionPolicy::Rule updatedManifest[updatedManifestSize];
    updatedManifest[0].SetObjPath("*");
    updatedManifest[0].SetInterfaceName("*");
    updatedManifest[0].SetMembers(1, updatedMember);

    uint8_t updatedDigest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(securityManagerBus,
                                                               updatedManifest, updatedManifestSize,
                                                               updatedDigest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(securityManagerBus,
                                                                  "1",
                                                                  securityManagerGuid.ToString(),
                                                                  &TCPublicKey,
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain1[0],
                                                                  updatedDigest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";

    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA");
    // Call updateIdentity
    EXPECT_EQ(ER_OK, sapWithTC.UpdateIdentity(identityCertChain1, 1,
                                                 updatedManifest, updatedManifestSize));

    appStateListener.stateChanged = false;

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    EXPECT_FALSE(appStateListener.stateChanged);
}

/*
 * TestCase:
 * When the manifest template changes in an app, the state notification will be emitted.
 *
 * Procedure:
 * Application changes the manifest template using the permission configurator.

 * The device needs to be Claimed first before changing the manifest template.

 * Verify that Secondary bus gets the state notification.
 * The state should be "Need update"
 * publickey algorithm = 0
 * publickey curveIdentifier = 0
 * publickey xCo-ordinate and yCo-ordinate are populated and are non-empty and are preserved and are same as before.
 */
TEST_F(SecurityClaimApplicationTest, get_state_signal_after_manifest_changes)
{
    //EnablePeerSecurity
    // the DSA Key Pair should be generated as soon as Enable PeerSecurity is
    // called.
    securityManagerKeyListener = new DefaultECDHEAuthListener();
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", securityManagerKeyListener, NULL, true);

    securityManagerBus.AddApplicationStateRule();

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(securityManagerBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    ASSERT_TRUE(appStateListener.stateChanged);

    EXPECT_EQ(securityManagerBus.GetUniqueName(), appStateListener.busNames.front());
    appStateListener.busNames.pop();
    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, appStateListener.states.front());
    appStateListener.states.pop();

    appStateListener.stateChanged = false;

    //verify we read all the signals
    EXPECT_TRUE(appStateListener.busNames.size() == 0 && appStateListener.publicKeys.size() == 0 && appStateListener.states.size() == 0);

    // Setup the test peer
    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL");

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    ASSERT_TRUE(appStateListener.stateChanged);

    SecurityApplicationProxy sapWithTC(securityManagerBus, TCBus->GetUniqueName().c_str());

    EXPECT_EQ(TCBus->GetUniqueName(), appStateListener.busNames.front());
    appStateListener.busNames.pop();
    ECCPublicKey TCPublicKey = *(appStateListener.publicKeys.front().GetPublicKey());
    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, appStateListener.states.front());
    appStateListener.states.pop();

    //verify we read all the signals
    EXPECT_TRUE(appStateListener.busNames.size() == 0 && appStateListener.publicKeys.size() == 0 && appStateListener.states.size() == 0);

    //Create admin group key
    KeyInfoNISTP256 securityManagerKey;
    PermissionConfigurator& permissionConfigurator = securityManagerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(securityManagerKey));

    //Random GUID used for the SecurityManager
    GUID128 securityManagerGuid;

    //Create identityCertChain for the admin to claim the test peer
    IdentityCertificate identityCertChain[1];

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(securityManagerBus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(securityManagerBus,
                                                                  "0",
                                                                  securityManagerGuid.ToString(),
                                                                  &TCPublicKey,
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";

    appStateListener.stateChanged = false;

    EXPECT_TRUE(appStateListener.busNames.size() == 0 && appStateListener.publicKeys.size() == 0 && appStateListener.states.size() == 0);
    EXPECT_EQ(ER_OK, sapWithTC.Claim(securityManagerKey,
                                        securityManagerGuid,
                                        securityManagerKey,
                                        identityCertChain, 1,
                                        manifest, manifestSize));
    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged && appStateListener.states.back() == PermissionConfigurator::CLAIMED) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    ASSERT_TRUE(appStateListener.stateChanged);

    EXPECT_EQ(TCBus->GetUniqueName(), appStateListener.busNames.front());
    appStateListener.busNames.pop();
    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::CLAIMED, appStateListener.states.back());
    appStateListener.states.pop();
    appStateListener.stateChanged = false;

    // Get the Permission configurator for the application
    //PermissionConfigurator& TCPermissionConfigurator = TCBus->GetPermissionConfigurator();

    // Change the manifest
    AJ_PermissionMember members[] = { { (char*) "*", AJ_MEMBER_TYPE_ANY, AJ_ACTION_PROVIDE, NULL } };
    AJ_PermissionRule rules[] = { { (char*) "*", (char*) "*", members, NULL } };
    AJ_Manifest updated = { rules };

    TCBus->SetPermissionManifest(&updated);
    // Verify that the security manager saw the "Needs Update" notification

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    ASSERT_TRUE(appStateListener.stateChanged);
    EXPECT_EQ(TCBus->GetUniqueName(), appStateListener.busNames.front());
    EXPECT_EQ(0, appStateListener.publicKeys.front().GetAlgorithm());
    EXPECT_EQ(0, appStateListener.publicKeys.front().GetCurve());
    EXPECT_TRUE(NULL != appStateListener.publicKeys.front().GetPublicKey()->GetX());
    EXPECT_TRUE(NULL != appStateListener.publicKeys.front().GetPublicKey()->GetY());
    appStateListener.busNames.pop();
    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::NEED_UPDATE, appStateListener.states.back());
    appStateListener.states.pop();

}

/*
 * TestCase:
 * When the manifest template changes in an app before claiming, the State notification is not emitted.
 *
 * Procedure:
 * Verify that when the manifest template changes before Claiming, the State Notification is not received.
 */
TEST_F(SecurityClaimApplicationTest, no_state_signal_before_claim_and_after_manifest_change)
{
    //EnablePeerSecurity
    // the DSA Key Pair should be generated as soon as Enable PeerSecurity is
    // called.
    securityManagerKeyListener = new DefaultECDHEAuthListener();
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", securityManagerKeyListener, NULL, true);

    securityManagerBus.AddApplicationStateRule();

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(securityManagerBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    ASSERT_TRUE(appStateListener.stateChanged);

    EXPECT_EQ(securityManagerBus.GetUniqueName(), appStateListener.busNames.front());
    appStateListener.busNames.pop();
    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, appStateListener.states.front());
    appStateListener.states.pop();

    appStateListener.stateChanged = false;

    //verify we read all the signals
    EXPECT_TRUE(appStateListener.busNames.size() == 0 && appStateListener.publicKeys.size() == 0 && appStateListener.states.size() == 0);

    // Setup the test peer
    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL");

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    ASSERT_TRUE(appStateListener.stateChanged);

    // Change the manifest
    AJ_PermissionMember members[] = { { (char*) "*", AJ_MEMBER_TYPE_ANY, AJ_ACTION_PROVIDE, NULL } };
    AJ_PermissionRule rules[] = { { (char*) "*", (char*) "*", members, NULL } };
    AJ_Manifest manifest = { rules };

    TCBus->SetPermissionManifest(&manifest);
    appStateListener.stateChanged = false;
    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    EXPECT_FALSE(appStateListener.stateChanged);
}

/*
 * Test Case:
 * When the claim operation fails, the state notification should not be emitted.
 *
 * Procedure:
 * Verify that when the claim operation fails, the state notification is not emitted.
 * Verify that the Secondary bus does not get the state notification.
 */
TEST_F(SecurityClaimApplicationTest, no_state_notification_on_claim_fail)
{
    securityManagerBus.AddApplicationStateRule();

    appStateListener.stateChanged = false;
    //EnablePeerSecurity
    securityManagerKeyListener = new DefaultECDHEAuthListener();
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", securityManagerKeyListener);

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(securityManagerBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    appStateListener.stateChanged = false;

    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL");

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    SecurityApplicationProxy sapWithTC(securityManagerBus, TCBus->GetUniqueName().c_str());
    PermissionConfigurator::ApplicationState applicationStateTC;
    EXPECT_EQ(ER_OK, sapWithTC.GetApplicationState(applicationStateTC));
    ASSERT_EQ(PermissionConfigurator::CLAIMABLE, applicationStateTC);

    //Create admin group key
    KeyInfoNISTP256 securityManagerKey;
    PermissionConfigurator& permissionConfigurator = securityManagerBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, permissionConfigurator.GetSigningPublicKey(securityManagerKey));

    //Random GUID used for the SecurityManager
    GUID128 securityManagerGuid;

    //Create identityCertChain
    IdentityCertificate identityCertChain[1];

    // peer public key used to generate the identity certificate chain
    ECCPublicKey TCPublicKey;
    EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));

    // All Inclusive manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    const size_t manifestSize = 1;
    PermissionPolicy::Rule manifest[manifestSize];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(securityManagerBus,
                                                               manifest, manifestSize,
                                                               digest, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    // Manifest that is different then the All Inclusive manifest passed in as the digest to make the claim call fail
    PermissionPolicy::Rule::Member member2[1];
    member2[0].Set("*", PermissionPolicy::Rule::Member::METHOD_CALL, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
    PermissionPolicy::Rule manifest2[manifestSize];
    manifest2[0].SetObjPath("*");
    manifest2[0].SetInterfaceName("*");
    manifest2[0].SetMembers(1, member2);

    uint8_t digest2[Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_OK, PermissionMgmtObj::GenerateManifestDigest(securityManagerBus,
                                                               manifest2, manifestSize,
                                                               digest2, Crypto_SHA256::DIGEST_SIZE)) << " GenerateManifestDigest failed.";

    EXPECT_TRUE(memcmp(digest, digest2, Crypto_SHA256::DIGEST_SIZE) != 0);


    EXPECT_EQ(ER_OK, PermissionMgmtTestHelper::CreateIdentityCert(securityManagerBus,
                                                                  "0",
                                                                  securityManagerGuid.ToString(),
                                                                  &TCPublicKey,
                                                                  "Alias",
                                                                  3600,
                                                                  identityCertChain[0],
                                                                  digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to creat identity certificate.";
    printf("\n Before calling claim");
    appStateListener.stateChanged = false;
    EXPECT_EQ(ER_DIGEST_MISMATCH, sapWithTC.Claim(securityManagerKey,
                                                     securityManagerGuid,
                                                     securityManagerKey,
                                                     identityCertChain, 1,
                                                     manifest2, manifestSize));

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    EXPECT_FALSE(appStateListener.stateChanged);
}

/*
 * TestCase:
 *  Using PermissionConfigurator, set the claimable field to "Not Claimable".
 *
 * Procedure:
 * Verify that the state notification is emitted with the state = "Not Claimable".
 */
TEST_F(SecurityClaimApplicationTest, not_claimable_state_signal)
{
    //EnablePeerSecurity
    // the DSA Key Pair should be generated as soon as Enable PeerSecurity is
    // called.
    securityManagerKeyListener = new DefaultECDHEAuthListener();
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", securityManagerKeyListener, NULL, true);

    securityManagerBus.AddApplicationStateRule();

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(securityManagerBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    ASSERT_TRUE(appStateListener.stateChanged);

    EXPECT_EQ(securityManagerBus.GetUniqueName(), appStateListener.busNames.front());
    appStateListener.busNames.pop();
    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, appStateListener.states.back());
    appStateListener.states.pop();

    appStateListener.stateChanged = false;

    //verify we read all the signals
    EXPECT_TRUE(appStateListener.busNames.size() == 0 && appStateListener.publicKeys.size() == 0 && appStateListener.states.size() == 0);

    // Setup the test peer
    TCBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL");

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    ASSERT_TRUE(appStateListener.stateChanged);
    EXPECT_EQ(TCBus->GetUniqueName(), appStateListener.busNames.front());
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, appStateListener.states.back());

    // Get the Permission configurator for the application
    appStateListener.stateChanged = false;
    TCBus->SetApplicationState(APP_STATE_NOT_CLAIMABLE);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    ASSERT_TRUE(appStateListener.stateChanged);

    SecurityApplicationProxy sapWithTC(securityManagerBus, TCBus->GetUniqueName().c_str());

    EXPECT_EQ(TCBus->GetUniqueName(), appStateListener.busNames.front());
    EXPECT_EQ(PermissionConfigurator::NOT_CLAIMABLE, appStateListener.states.back());
}


/*
 * TestCase:
 * State notification is not emitted when Security is not enabled on the app.

 * Procedure:
 * Application does not have a keystore.
 * Application does not enable security.
 * Secondary bus does an add match rule for the state notification.
 *
 * Verify that the Secondary bus does not get the state notification.
 */
TEST_F(SecurityClaimApplicationTest, no_state_notification_when_peer_security_off)
{
    //EnablePeerSecurity
    // the DSA Key Pair should be generated as soon as Enable PeerSecurity is
    // called.
    securityManagerKeyListener = new DefaultECDHEAuthListener();
    securityManagerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", securityManagerKeyListener, NULL, true);

    securityManagerBus.AddApplicationStateRule();

    /* The State signal is only emitted if manifest template is installed */
    SetManifestTemplate(securityManagerBus);

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    ASSERT_TRUE(appStateListener.stateChanged);

    EXPECT_EQ(securityManagerBus.GetUniqueName(), appStateListener.busNames.front());
    appStateListener.busNames.pop();
    appStateListener.publicKeys.pop();
    EXPECT_EQ(PermissionConfigurator::CLAIMABLE, appStateListener.states.back());
    appStateListener.states.pop();

    appStateListener.stateChanged = false;

    //verify we read all the signals
    EXPECT_TRUE(appStateListener.busNames.size() == 0 && appStateListener.publicKeys.size() == 0 && appStateListener.states.size() == 0);

    // Setup the test peer

    for (msec = 0; msec < WAIT_SIGNAL; msec += WAIT_MSECS) {
        if (appStateListener.stateChanged) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    printf("%d: Slept %d\n", __LINE__, msec);

    EXPECT_FALSE(appStateListener.stateChanged);
}
