/**
 * @file
 * Sample implementation of auth based test.
 * The auth client is the Admin app.
 * It is the ASGA i.e it has a membership certificate belonging to the ASG group. self signed by itself.)
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
#include <qcc/Log.h>
#include <qcc/Environ.h>
#include <qcc/Mutex.h>
#include <qcc/String.h>
#include <qcc/Thread.h>
#include <qcc/time.h>
#include <qcc/Util.h>

#include <alljoyn/AllJoynStd.h>
#include <alljoyn/BusAttachment.h>
#include <alljoyn/BusObject.h>
#include <alljoyn/DBusStd.h>
#include <alljoyn/Init.h>
#include <alljoyn/MsgArg.h>
#include <alljoyn/version.h>
#include <alljoyn/ApplicationStateListener.h>
#include <alljoyn/SecurityApplicationProxy.h>

#include <alljoyn/Status.h>
#include "PermissionMgmtObj.h"

#define QCC_MODULE "ALLJOYN"

using namespace std;
using namespace qcc;
using namespace ajn;


/* Static top level globals */
static BusAttachment* g_msgBus = NULL;
String g_appUniqueName;
static SessionId g_sessionId;
static qcc::KeyInfoNISTP256 g_publicKeyInfo;
static qcc::KeyInfoNISTP256 g_adminpublicKeyInfo;
static bool g_recd = false;

static KeyInfoNISTP256 g_cakeyInfo;
static ECCPrivateKey g_caPrivateKey;
static ECCPublicKey g_caPublicKey;

static const char* caPublicKeyPEM = {
    "-----BEGIN PUBLIC KEY-----"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE7MmnoBVWrArQosp1VvWwfWMsprlg"
    "fhVWyntQOeYPlTjzUdq1P3ETItAEQRpqsNasoC+p9yQv00kuGRkxalVuGQ=="
    "-----END PUBLIC KEY-----"
};

static const char* caPrivateKeyPEM = {
    "-----BEGIN EC PRIVATE KEY-----"
    "MHcCAQEEIBt/wyHHC+YUR8n7vwRqhltBGYMEyia5vAssQ98+w1+YoAoGCCqGSM49"
    "AwEHoUQDQgAE7MmnoBVWrArQosp1VvWwfWMsprlgfhVWyntQOeYPlTjzUdq1P3ET"
    "ItAEQRpqsNasoC+p9yQv00kuGRkxalVuGQ=="
    "-----END EC PRIVATE KEY-----"
};

void setcaKeyInfo(KeyInfoNISTP256& cakeyInfo) {

    uint8_t caAKI[] = { 1, 2 };
    cakeyInfo.SetKeyId(caAKI, 2);
    cakeyInfo.SetPublicKey(&g_caPublicKey);
}

void setCAKeys() {
    CertificateX509::DecodePrivateKeyPEM(caPrivateKeyPEM, &g_caPrivateKey);
    CertificateX509::DecodePublicKeyPEM(caPublicKeyPEM, &g_caPublicKey);
    setcaKeyInfo(g_cakeyInfo);
}

void createPermissionPolicy(PermissionPolicy& permissionPolicy) {

    //Set the version
    permissionPolicy.SetVersion(5555);
    {
        //Create an ACL[0].
        PermissionPolicy::Acl myAcl[1];
        //set two peers for acl[0]
        {
            PermissionPolicy::Peer peer[1];
            peer[0].SetType(PermissionPolicy::Peer::PEER_FROM_CERTIFICATE_AUTHORITY);
            peer[0].SetKeyInfo(&g_cakeyInfo);
            myAcl[0].SetPeers(1, peer);
        }
        permissionPolicy.SetAcls(1, myAcl);
    }
}


class MyBusListener : public BusListener, public SessionListener {
  public:

    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix)
    {
        printf("FoundAdvertisedName(name=%s, transport=0x%x, prefix=%s)\n", name, transport, namePrefix);

        /* We must enable concurrent callbacks since some of the calls below are blocking */
        g_msgBus->EnableConcurrentCallbacks();

        /* We found a remote bus that is advertising bbservice's well-known name so connect to it */
        SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
        QStatus status = ER_OK;
        SessionId sessionId;
        g_appUniqueName = name;
        status = g_msgBus->JoinSession(name, 101, this, sessionId, opts);
        if (ER_OK != status) {
            QCC_LogError(status, ("JoinSession(%s) failed", name));
        } else {
            printf("Join Session succeeded .. %u \n", sessionId);
            g_sessionId = sessionId;
        }

    }

    void LostAdvertisedName(const char* name, TransportMask transport, const char* prefix)
    {
        printf("LostAdvertisedName(name=%s, transport=0x%x, prefix=%s)\n", name, transport, prefix);
    }

    void SessionLost(SessionId sessionId, SessionLostReason reason) {
        printf("SessionLost(%08x) was called. Reason=%u.\n", sessionId, reason);
    }

};



class MyApplicationStateListener : public ApplicationStateListener {
  public:

    void State(const char* busName, const qcc::KeyInfoNISTP256& publicKeyInfo, PermissionConfigurator::ApplicationState state) {
        QCC_UNUSED(publicKeyInfo);
        if (strcmp(busName, g_msgBus->GetUniqueName().c_str()) != 0) { g_publicKeyInfo = publicKeyInfo; g_recd = true; }
        if (strcmp(busName, g_msgBus->GetUniqueName().c_str()) == 0) { g_adminpublicKeyInfo = publicKeyInfo; }
        String stateStr;
        switch (state) {
        case PermissionConfigurator::ApplicationState::CLAIMABLE:
            stateStr = "CLAIMABLE";
            break;

        case PermissionConfigurator::ApplicationState::CLAIMED:
            stateStr = "CLAIMED";
            break;

        case PermissionConfigurator::ApplicationState::NEED_UPDATE:
            stateStr = "NEED_UPDATE";
            break;

        case PermissionConfigurator::ApplicationState::NOT_CLAIMABLE:
            stateStr = "NOT_CLAIMABLE";
            break;

        default:
            stateStr = "<unknown>";
        }

        cout << "---------------------------------------------------------------------------" << endl;
        printf("My UniqueName is  %s  \n", g_msgBus->GetUniqueName().c_str());
        printf("Application state notification received: Bus %s, CurrentState %s\n", busName, stateStr.c_str());
        cout << "algorithm:   " << (int)publicKeyInfo.GetAlgorithm() << endl;
        cout << "curve:   "    << (int)publicKeyInfo.GetCurve() << endl;


        const uint8_t*x_co_ord = publicKeyInfo.GetPublicKey()->GetX();
        const uint8_t*y_co_ord = publicKeyInfo.GetPublicKey()->GetY();
        for (size_t i = 0; i < ECC_COORDINATE_SZ; i++) {
            cout << (int)x_co_ord[i] << " ";
        }
        cout << endl;

        for (size_t i = 0; i < ECC_COORDINATE_SZ; i++) {
            cout << (int)y_co_ord[i] << " ";
        }
        cout << endl;
        cout << "---------------------------------------------------------------------------" << endl;

    }

};
static MyApplicationStateListener appStateListener;

static const char ecdsaPrivateKeyPEM[] = {
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIAqN6AtyOAPxY5k7eFNXAwzkbsGMl4uqvPrYkIj0LNZBoAoGCCqGSM49\n"
    "AwEHoUQDQgAEvnRd4fX9opwgXX4Em2UiCMsBbfaqhB1U5PJCDZacz9HumDEzYdrS\n"
    "MymSxR34lL0GJVgEECvBTvpaHP2bpTIl6g==\n"
    "-----END EC PRIVATE KEY-----"
};

static const char ecdsaCertChainX509PEM[] = {
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBtDCCAVmgAwIBAgIJAMlyFqk69v+OMAoGCCqGSM49BAMCMFYxKTAnBgNVBAsM\n"
    "IDdhNDhhYTI2YmM0MzQyZjZhNjYyMDBmNzdhODlkZDAyMSkwJwYDVQQDDCA3YTQ4\n"
    "YWEyNmJjNDM0MmY2YTY2MjAwZjc3YTg5ZGQwMjAeFw0xNTAyMjYyMTUxMjVaFw0x\n"
    "NjAyMjYyMTUxMjVaMFYxKTAnBgNVBAsMIDZkODVjMjkyMjYxM2IzNmUyZWVlZjUy\n"
    "NzgwNDJjYzU2MSkwJwYDVQQDDCA2ZDg1YzI5MjI2MTNiMzZlMmVlZWY1Mjc4MDQy\n"
    "Y2M1NjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABL50XeH1/aKcIF1+BJtlIgjL\n"
    "AW32qoQdVOTyQg2WnM/R7pgxM2Ha0jMpksUd+JS9BiVYBBArwU76Whz9m6UyJeqj\n"
    "EDAOMAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDSQAwRgIhAKfmglMgl67L5ALF\n"
    "Z63haubkItTMACY1k4ROC2q7cnVmAiEArvAmcVInOq/U5C1y2XrvJQnAdwSl/Ogr\n"
    "IizUeK0oI5c=\n"
    "-----END CERTIFICATE-----"
    "\n"
    "-----BEGIN CERTIFICATE-----\n"
    "MIIBszCCAVmgAwIBAgIJAILNujb37gH2MAoGCCqGSM49BAMCMFYxKTAnBgNVBAsM\n"
    "IDdhNDhhYTI2YmM0MzQyZjZhNjYyMDBmNzdhODlkZDAyMSkwJwYDVQQDDCA3YTQ4\n"
    "YWEyNmJjNDM0MmY2YTY2MjAwZjc3YTg5ZGQwMjAeFw0xNTAyMjYyMTUxMjNaFw0x\n"
    "NjAyMjYyMTUxMjNaMFYxKTAnBgNVBAsMIDdhNDhhYTI2YmM0MzQyZjZhNjYyMDBm\n"
    "NzdhODlkZDAyMSkwJwYDVQQDDCA3YTQ4YWEyNmJjNDM0MmY2YTY2MjAwZjc3YTg5\n"
    "ZGQwMjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGEkAUATvOE4uYmt/10vkTcU\n"
    "SA0C+YqHQ+fjzRASOHWIXBvpPiKgHcINtNFQsyX92L2tMT2Kn53zu+3S6UAwy6yj\n"
    "EDAOMAwGA1UdEwQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgKit5yeq1uxTvdFmW\n"
    "LDeoxerqC1VqBrmyEvbp4oJfamsCIQDvMTmulW/Br/gY7GOP9H/4/BIEoR7UeAYS\n"
    "4xLyu+7OEA==\n"
    "-----END CERTIFICATE-----"
};


class MyAuthListener : public AuthListener {

    QStatus RequestCredentialsAsync(const char* authMechanism, const char* authPeer, uint16_t authCount, const char* userId, uint16_t credMask, void* context)
    {
        QCC_UNUSED(authCount);
        QCC_UNUSED(userId);
        Credentials creds;
        printf("RequestCredentials for authenticating %s using mechanism %s\n", authPeer, authMechanism);

        if (strcmp(authMechanism, "ALLJOYN_ECDHE_NULL") == 0) {
            printf("AuthListener::RequestCredentials for key exchange %s\n", authMechanism);
            return RequestCredentialsResponse(context, true, creds);
        }
        if (strcmp(authMechanism, "ALLJOYN_ECDHE_PSK") == 0) {
            if ((credMask& AuthListener::CRED_USER_NAME) == AuthListener::CRED_USER_NAME) {
                printf("AuthListener::RequestCredentials for key exchange %s received psk ID %s\n", authMechanism, creds.GetUserName().c_str());
            }
            creds.SetPassword("1234");
            return RequestCredentialsResponse(context, true, creds);
        }
        if (strcmp(authMechanism, "ALLJOYN_ECDHE_ECDSA") == 0) {
            printf("AuthListener::RequestCredentials for key exchange %s \n", authMechanism);
            if ((credMask& AuthListener::CRED_PRIVATE_KEY) == AuthListener::CRED_PRIVATE_KEY) {
                String pk(ecdsaPrivateKeyPEM);
                creds.SetPrivateKey(pk);
                printf("AuthListener::RequestCredentials for key exchange %s sends DSA private key \n%s\n", authMechanism, pk.c_str());
            }
            if ((credMask& AuthListener::CRED_CERT_CHAIN) == AuthListener::CRED_CERT_CHAIN) {
                String cert(ecdsaCertChainX509PEM, strlen(ecdsaCertChainX509PEM));
                creds.SetCertChain(cert);
                printf("AuthListener::RequestCredentials for key exchange %s sends DSA public cert \n%s\n", authMechanism, cert.c_str());
            }
            return RequestCredentialsResponse(context, true, creds);
        }
        printf("AuthListener::RequestCredentials for keyexchange returning false.. \n");
        return RequestCredentialsResponse(context, false, creds);
    }

    QStatus VerifyCredentialsAsync(const char* authMechanism, const char* authPeer, const Credentials& creds, void* context) {
        QCC_UNUSED(authPeer);
        if (strcmp(authMechanism, "ALLJOYN_ECDHE_ECDSA") == 0) {
            if (creds.IsSet(AuthListener::CRED_CERT_CHAIN)) {
                printf("AuthListener::VerifyCredentials for ECDSA auth. \n");
                return VerifyCredentialsResponse(context, true);
            }
        }
        return VerifyCredentialsResponse(context, false);
    }

    void AuthenticationComplete(const char* authMechanism, const char* authPeer, bool success) {
        QCC_UNUSED(authPeer);

        printf("Authentication %s %s\n", authMechanism, success ? "succesful" : "failed");
    }

    void SecurityViolation(QStatus status, const Message& msg) {
        QCC_UNUSED(msg);
        printf("Security violation %s\n", QCC_StatusText(status));
    }

};


int main() {

    QStatus status = ER_OK;
    setCAKeys();
    if (AllJoynInit() != ER_OK) {
        return 1;
    }
#ifdef ROUTER
    if (AllJoynRouterInit() != ER_OK) {
        AllJoynShutdown();
        return 1;
    }
#endif

    /* Create message bus */
    g_msgBus = new BusAttachment("authclienttest", true);
    status = g_msgBus->Start();
    assert(status == ER_OK);
    status = g_msgBus->Connect();
    assert(status == ER_OK);

    printf("Testing PermissionCOnfigurator functions.. \n");
    PermissionConfigurator& pc1 = g_msgBus->GetPermissionConfigurator();
    status = pc1.SetApplicationState(PermissionConfigurator::ApplicationState::CLAIMABLE);
    printf("Before calling EPS, calling SetApplicationState  %s \n", QCC_StatusText(status));

    PermissionConfigurator::ApplicationState state;
    printf("Application state is %s \n", PermissionConfigurator::ToString(state));
    status = pc1.GetApplicationState(state);
    printf("Before calling EPS, calling GetApplicationState  %s \n", QCC_StatusText(status));
    printf("Application state is %s \n", PermissionConfigurator::ToString(state));

    status = pc1.Reset();
    printf("Before calling EPS, calling Reset  %s \n", QCC_StatusText(status));

    status = pc1.GenerateSigningKeyPair();
    printf("Before calling EPS, calling GenerateSigningKeyPair()  %s \n", QCC_StatusText(status));

    KeyInfoNISTP256 keyInfo;
    status = pc1.GetSigningPublicKey(keyInfo);
    printf("Before calling EPS, calling GetSigningPublicKey  %s \n", QCC_StatusText(status));
    printf("End of testing PermissionConfigurator functions.. \n\n\n\n\n");

    g_msgBus->RegisterApplicationStateListener(appStateListener);
    g_msgBus->AddApplicationStateRule();


    //I have enabled peer security for NULL mechanism only. This is because, the master secret immediately expires after successful auth.
    status = g_msgBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL", new MyAuthListener(), "nara-client-test-keystore", false);
    assert(status == ER_OK);
    qcc::Sleep(2000);

    //status = pc1.GenerateSigningKeyPair();
    //printf("BUG after calling EPS, calling GetSigningPublicKey  %s \n",QCC_StatusText(status));


    //Self-Claim and install a membership for myself. I am the ASGA.

    //Create a CA key. This CA key is totally different.

    //Crypto_ECC caDsaKeyPair;
    //caDsaKeyPair.GenerateDSAKeyPair();
    //uint8_t caAKI[] = { 1, 2 };
    //
    //KeyInfoNISTP256 caKey;
    //caKey.SetKeyId(caAKI, 2);
    //caKey.SetPublicKey(caDsaKeyPair.GetDSAPublicKey());


    KeyInfoNISTP256 mycaKey;
    //mycaKey.SetKeyId(caAKI, 2);
    mycaKey.SetPublicKey(g_adminpublicKeyInfo.GetPublicKey());

    //Set the ASGA key as your public key.
    KeyInfoNISTP256 asgaKey;
    uint8_t asgAKI[] = { 3, 4, 5 };
    asgaKey.SetKeyId(asgAKI, 3);
    asgaKey.SetPublicKey(g_adminpublicKeyInfo.GetPublicKey());

    //GUID used by ASGA and this GUID should be persistent.
    GUID128 asgaGUID("123456785484");

    uint8_t adminSubjectCN[] = { 11, 22, 33, 44 };
    uint8_t adminIssuerCN[] = { 11, 22, 33, 44 };

    //Self Install membership certs on Admin
    qcc::MembershipCertificate memCert;
    memCert.SetSerial((uint8_t*)"1234", 4);
    memCert.SetIssuerCN(adminIssuerCN, 4);
    memCert.SetSubjectCN(adminSubjectCN, 4);
    CertificateX509::ValidPeriod validityMCert;
    validityMCert.validFrom = 1427404154;
    validityMCert.validTo = 1427404154 + 630720000;
    memCert.SetValidity(&validityMCert);
    memCert.SetSubjectPublicKey(g_adminpublicKeyInfo.GetPublicKey());
    memCert.SetGuild(asgaGUID);
    memCert.SetCA(true);
    //sign the leaf cert
    pc1.SignCertificate(memCert);

    //Create a security app proxy for yourself
    SecurityApplicationProxy mySecurityAppProxy(*g_msgBus, g_msgBus->GetUniqueName().c_str(), 0);

    //Claim yourself now.

    //Create my cert chain. I am self signed
    //Create a manifest
    PermissionPolicy::Rule::Member member[1];
    member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);

    PermissionPolicy::Rule manifest[1];
    manifest[0].SetObjPath("*");
    manifest[0].SetInterfaceName("*");
    manifest[0].SetMembers(1, member);

    uint8_t digest[Crypto_SHA256::DIGEST_SIZE];
    PermissionMgmtObj::GenerateManifestDigest(*g_msgBus, manifest, 1, digest, Crypto_SHA256::DIGEST_SIZE);

    qcc::IdentityCertificate adminCert;
    adminCert.SetSerial((uint8_t*)"admin", 6);
    adminCert.SetIssuerCN(adminIssuerCN, 4);
    adminCert.SetSubjectCN(adminSubjectCN, 4);
    CertificateX509::ValidPeriod validityICAdmin;
    validityICAdmin.validFrom = 1427404154;
    validityICAdmin.validTo = 1427404154 + 630720000;
    adminCert.SetValidity(&validityICAdmin);
    adminCert.SetSubjectPublicKey(g_adminpublicKeyInfo.GetPublicKey());
    adminCert.SetAlias("admin-leaf-cert-alias");
    adminCert.SetCA(true);
    adminCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);
    //sign the leaf cert
    pc1.SignCertificate(adminCert);

    printf("Claiming myself using Self signed IC, a new GUID128, a diff. ca pub key and an asga pub key (which is same as my pub key) \n");
    GUID128 myGUID;
    status = mySecurityAppProxy.Claim(g_cakeyInfo, myGUID, asgaKey, &adminCert, 1, manifest, 1);
    printf("Admin Claim status is %s \n", QCC_StatusText(status));


    printf("Installing a membership on myself. This is a self signed MC belonging to ASGA group. \n");
    if (status == ER_OK) {
        status = mySecurityAppProxy.InstallMembership(&memCert, 1);
        printf("Install Membership status is %s \n", QCC_StatusText(status));
    }
    //Lets focus attention on service side.
    MyBusListener busListener;
    g_msgBus->RegisterBusListener(busListener);
    status = g_msgBus->FindAdvertisedName("innocent.app");;
    assert(status == ER_OK);

    qcc::Sleep(2000);

    printf("Waiting for State notification from service.. \n");

    while (!g_recd)
        qcc::Sleep(200);

    //Create a security proxy for service side
    SecurityApplicationProxy securityAppProxy(*g_msgBus, g_appUniqueName.c_str(), g_sessionId);
    ECCPublicKey leafPublicKey;
    //const ECCPublicKey *leafPublicKey = g_publicKeyInfo.GetPublicKey();
    status =  securityAppProxy.GetEccPublicKey(leafPublicKey);
    assert(status == ER_OK);

    printf("-----------------------------------------------\n");
    printf("Printing the public key of service bus: \n");

    for (size_t i = 0; i < ECC_COORDINATE_SZ; i++) {
        cout << (int)leafPublicKey.GetX()[i] << " ";
    }
    cout << endl;

    for (size_t i = 0; i < ECC_COORDINATE_SZ; i++) {
        cout << (int)leafPublicKey.GetY()[i] << " ";
    }
    cout << endl;
    printf("-----------------------------------------------\n");


    //Create the ICC chain

    //Create the root DSA key Pair
    //Crypto_ECC rootDsaKeyPair;
    //status = rootDsaKeyPair.GenerateDSAKeyPair();


    uint8_t subjectCN[] = { 1, 2, 3, 4 };
    uint8_t issuerCN[] = { 11, 22, 33, 44 };

    qcc::IdentityCertificate leafCert;
    leafCert.SetSerial((uint8_t*)"1234", 5);
    leafCert.SetIssuerCN(issuerCN, 4);
    leafCert.SetSubjectCN(subjectCN, 4);
    CertificateX509::ValidPeriod validityLeaf;
    validityLeaf.validFrom = 1427404154;
    validityLeaf.validTo = 1427404154 + 630720000;
    //validityLeaf.validTo = 1427404154 + 630;
    leafCert.SetValidity(&validityLeaf);
    leafCert.SetDigest(digest, Crypto_SHA256::DIGEST_SIZE);
    leafCert.SetSubjectPublicKey(&leafPublicKey);
    //leafCert.SetAlias("leaf-cert-alias-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    leafCert.SetAlias("leaf-cert-alias-0123456789abcdef");
    leafCert.SetCA(true);

    //sign the leaf cert
    status = pc1.SignCertificate(leafCert);
    assert(status == ER_OK);


    qcc::IdentityCertificate certChain[2];
    certChain[0] = leafCert;
    certChain[1] = adminCert;


    String leafPEM, rootPEM;
    status = certChain[0].EncodeCertificatePEM(leafPEM);
    assert(status == ER_OK);
    status = certChain[1].EncodeCertificatePEM(rootPEM);
    assert(status == ER_OK);

    status = certChain[0].Verify(certChain[1].GetSubjectPublicKey());
    printf("Verify status is %s \n", QCC_StatusText(status));

    printf("leaf PEM \n");
    cout << leafPEM.c_str() << endl;
    printf("root PEM \n");
    cout << rootPEM.c_str() << endl;

    qcc::Sleep(2000);

    //status = securityAppProxy.Reset();
    //printf("BUG Reset status is %s  \n",QCC_StatusText(status));

    //All set to claim
    status = securityAppProxy.Claim(g_cakeyInfo, asgaGUID, asgaKey, certChain, 2, manifest, 1);
    printf("Service Claim status is %s \n", QCC_StatusText(status));

    qcc::Sleep(2000);

    //The problem is, the session between service and client could be NULL based or PASK baded during Claiming. However, that is not enough for doing management operations.
    // For management operations, you need a ECDSA based session. Hence, call EPS again with ECDSA enabled.
    status = g_msgBus->EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", new MyAuthListener(), "nara-client-test-keystore", false);
    assert(status == ER_OK);
    //Try to call Reset on service bus.
    status = securityAppProxy.Reset();
    printf("Service Reset status is %s \n", QCC_StatusText(status));

    while (true) {
        qcc::Sleep(500);
    }

#ifdef ROUTER
    AllJoynRouterShutdown();
#endif
    AllJoynShutdown();
    return (int) status;
}
