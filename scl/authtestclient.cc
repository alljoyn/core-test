/**
 * @file
 * Sample implementation of auth based test.
 * The authtestclient is the Admin app.
 */

/******************************************************************************
 * Copyright (c) 2016 Open Connectivity Foundation (OCF) and AllJoyn Open
 *    Source Project (AJOSP) Contributors and others.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Copyright 2016 Open Connectivity Foundation and Contributors to
 *    AllSeen Alliance. All rights reserved.
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
static SessionId g_sessionId = 0;
static qcc::KeyInfoNISTP256 g_publicKeyInfo;
static qcc::KeyInfoNISTP256 g_adminpublicKeyInfo;
static bool g_recd = false;
static bool peer1 = true;
static bool g_recvdAdminSLS = false;

static KeyInfoNISTP256 g_cakeyInfo;
static KeyInfoNISTP256 g_asgakeyInfo;
static ECCPrivateKey g_caPrivateKey;
static ECCPublicKey g_caPublicKey;
static GUID128 g_asgaGUID;
static String g_wellKnownName = "";
static qcc::CertificateX509 g_CACert;

/* The CA keys were generated using OpenSSL. The CA cert is self-signed.
 * It is of type CertificateX509 */
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

//Membership cert for SGID1
// 0 - sgid1.root
// 1 - ia.sgid1.root
static const char*membershipSGID2_privatekeys [2] = {
    "-----BEGIN EC PRIVATE KEY-----"
    "MHcCAQEEIMGf/sTLeCysCO7EGZn7S73u9CsW9apRyVqtUGk6Ie7UoAoGCCqGSM49"
    "AwEHoUQDQgAEYIdmiF+HO55YxCql9ltahRv6+034yMqAEhT64Y9fkui5+4OEQvXX"
    "IiEpw0/vcVCFNNfkgE7OBrOZVxxTDbtYcw=="
    "-----END EC PRIVATE KEY-----",

    "-----BEGIN EC PRIVATE KEY-----"
    "MHcCAQEEIIoIjuOhCMAmzn8NaVAGehlc3JpgYA1vJ7v7Dd8I/HHFoAoGCCqGSM49"
    "AwEHoUQDQgAEcQbvGPx97uKbZwaHPEgH8rOYvw7irwZ8GKqQIjqsLWQz1eFkTh1U"
    "GLmwyfISziAJPOspt2N/p6me6Vt0aNsSVA=="
    "-----END EC PRIVATE KEY-----"
};

static const char*membershipSGID2_publickeys [2] = {
    "-----BEGIN PUBLIC KEY-----"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEYIdmiF+HO55YxCql9ltahRv6+034"
    "yMqAEhT64Y9fkui5+4OEQvXXIiEpw0/vcVCFNNfkgE7OBrOZVxxTDbtYcw=="
    "-----END PUBLIC KEY-----",

    "-----BEGIN PUBLIC KEY-----"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcQbvGPx97uKbZwaHPEgH8rOYvw7i"
    "rwZ8GKqQIjqsLWQz1eFkTh1UGLmwyfISziAJPOspt2N/p6me6Vt0aNsSVA=="
    "-----END PUBLIC KEY-----"
};

//Membership cert for SGID2
// 0 - sgid2.root
// 1 - ia.sgid2.root

static const char*membershipSGID1_privatekeys [2] = {
    "-----BEGIN EC PRIVATE KEY-----"
    "MHcCAQEEIJqIVkLfJkWvvJH7/VgLDBYkjR7712YukKDES0HxG1/VoAoGCCqGSM49"
    "AwEHoUQDQgAECqxHZSuqHtujVD3zyb3RDAC38owRmeQC9XKBokzjtVp2DS7QcBSH"
    "/bobpagmJ2QSaBeFTbWTVxxbK5KeZgVynQ=="
    "-----END EC PRIVATE KEY-----",

    "-----BEGIN EC PRIVATE KEY-----"
    "MHcCAQEEIN4ZHjN0wcZPknLpCEZ8a/8dmAufB8CUragjP1CgjmpuoAoGCCqGSM49"
    "AwEHoUQDQgAEUxp9VHg/3z2jjguQ9nbTH1wS/aNaIYAiSWfICLThhFxalUm+o8kn"
    "2JkfVRkJs4/WdFm47uHkfptv05f8XZPh/w=="
    "-----END EC PRIVATE KEY-----"
};

static const char*membershipSGID1_publickeys [2] = {
    "-----BEGIN PUBLIC KEY-----"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECqxHZSuqHtujVD3zyb3RDAC38owR"
    "meQC9XKBokzjtVp2DS7QcBSH/bobpagmJ2QSaBeFTbWTVxxbK5KeZgVynQ=="
    "-----END PUBLIC KEY-----",

    "-----BEGIN PUBLIC KEY-----"
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUxp9VHg/3z2jjguQ9nbTH1wS/aNa"
    "IYAiSWfICLThhFxalUm+o8kn2JkfVRkJs4/WdFm47uHkfptv05f8XZPh/w=="
    "-----END PUBLIC KEY-----"
};

static ECCPrivateKey g_privateKey[4];
static ECCPublicKey g_publicKey[4];

void convertPEMtoDER() {

//populate the private keys
    CertificateX509::DecodePrivateKeyPEM(membershipSGID1_privatekeys[0], &g_privateKey[0]);
    CertificateX509::DecodePrivateKeyPEM(membershipSGID1_privatekeys[1], &g_privateKey[1]);
    CertificateX509::DecodePrivateKeyPEM(membershipSGID2_privatekeys[0], &g_privateKey[2]);
    CertificateX509::DecodePrivateKeyPEM(membershipSGID2_privatekeys[1], &g_privateKey[3]);

//populate the public keys
    CertificateX509::DecodePublicKeyPEM(membershipSGID1_publickeys[0], &g_publicKey[0]);
    CertificateX509::DecodePublicKeyPEM(membershipSGID1_publickeys[1], &g_publicKey[1]);
    CertificateX509::DecodePublicKeyPEM(membershipSGID2_publickeys[0], &g_publicKey[2]);
    CertificateX509::DecodePublicKeyPEM(membershipSGID2_publickeys[1], &g_publicKey[3]);

}

qcc::CertificateX509 SGID1Chain[3];
qcc::CertificateX509 SGID2Chain[3];


/* Membership certificate chain 1:  CA->SGA->leaf
   The Intermediate Cert is of type Membership Certificate which is the SG Authority which signs the Leaf Membership cert.
 */

void CreateMembershipCertChainPeer1() {

    CertificateX509::ValidPeriod validityMCert;
    validityMCert.validFrom = 1427404154;
    validityMCert.validTo = 1427404154 + 630720000;

    GUID128 SGID1("ALPHA");

    //The root is a self-signed CA, g_CACert, which is of CertificateX509Type
    SGID1Chain[2] = g_CACert;
    uint8_t rootIssuerCN[] = { 111, 222, 133, 144 };

    //SGID1 Chain root, self-signed
    //SGID1Chain[2].SetSerial((uint8_t*)"1111", 4);
    //uint8_t rootSubjectCN[] = { 1, 2, 3, 4 };
    //uint8_t rootIssuerCN[] = { 1, 2, 3, 4 };
    //SGID1Chain[2].SetIssuerCN(rootIssuerCN, 4);
    //SGID1Chain[2].SetSubjectCN(rootSubjectCN, 4);
    //SGID1Chain[2].SetValidity(&validityMCert);
    //SGID1Chain[2].SetSubjectPublicKey(&g_publicKey[0]);
    //SGID1Chain[2].SetGuild(SGID1);
    //SGID1Chain[2].SetCA(true);
    //QStatus status = SGID1Chain[2].Sign(&g_privateKey[0]);
    //assert(status == ER_OK);

    //SGID1 Chain, IA, signed by root
    qcc::MembershipCertificate tempIA;
    tempIA.SetSerial((uint8_t*)"2222", 4);
    uint8_t iaSubjectCN[] = { 5, 6, 7, 8 };
    tempIA.SetIssuerCN(rootIssuerCN, 4);
    tempIA.SetSubjectCN(iaSubjectCN, 4);
    tempIA.SetValidity(&validityMCert);
    tempIA.SetSubjectPublicKey(&g_publicKey[1]);
    tempIA.SetGuild(SGID1);
    tempIA.SetCA(true);
    QStatus status = tempIA.Sign(&g_caPrivateKey);
    assert(status == ER_OK);
    SGID1Chain[1] = tempIA;
    QCC_UNUSED(status);

    //SGID1 Chain, leaf, signed by IA
    qcc::MembershipCertificate leaf;
    leaf.SetSerial((uint8_t*)"3333", 4);
    uint8_t leafSubjectCN[] = { 9, 10, 11, 12 };
    leaf.SetIssuerCN(iaSubjectCN, 4);
    leaf.SetSubjectCN(leafSubjectCN, 4);
    leaf.SetValidity(&validityMCert);
    leaf.SetSubjectPublicKey(g_publicKeyInfo.GetPublicKey());
    leaf.SetGuild(SGID1);
    leaf.SetCA(true);
    status = leaf.Sign(&g_privateKey[1]);
    assert(status == ER_OK);
    SGID1Chain[0] = leaf;
}

/* Membership certificate chain 2:  CA->SGA->leaf
   The Intermediate Cert is of type Membership Certificate which is the SG Authority which signs the Leaf Membership cert.
 */

void CreateMembershipCertChainPeer2() {
    CertificateX509::ValidPeriod validityMCert;
    validityMCert.validFrom = 1427404154;
    validityMCert.validTo = 1427404154 + 630720000;

    GUID128 SGID2("BETA");

    //The root is a self-signed CA, g_CACert, which is of CertificateX509Type
    SGID2Chain[2] = g_CACert;
    uint8_t rootIssuerCN[] = { 111, 222, 133, 144 };

    //SGID2 Chain root, self-signed
    //SGID2Chain[2].SetSerial((uint8_t*)"4444", 4);
    //uint8_t rootSubjectCN[] = { 13, 14, 15, 16 };
    //SGID2Chain[2].SetIssuerCN(rootIssuerCN, 4);
    //SGID2Chain[2].SetSubjectCN(rootSubjectCN, 4);
    //SGID2Chain[2].SetValidity(&validityMCert);
    //SGID2Chain[2].SetSubjectPublicKey(&g_publicKey[2]);
    //SGID2Chain[2].SetGuild(SGID2);
    //SGID2Chain[2].SetCA(true);
    //QStatus status = SGID2Chain[2].Sign(&g_privateKey[2]);
    //assert(status == ER_OK);

    //SGID2 Chain, IA, signed by root
    qcc::MembershipCertificate tempIA;
    tempIA.SetSerial((uint8_t*)"5555", 4);
    uint8_t iaSubjectCN[] = { 17, 18, 19, 20 };
    tempIA.SetIssuerCN(rootIssuerCN, 4);
    tempIA.SetSubjectCN(iaSubjectCN, 4);
    tempIA.SetValidity(&validityMCert);
    tempIA.SetSubjectPublicKey(&g_publicKey[3]);
    tempIA.SetGuild(SGID2);
    tempIA.SetCA(true);
    QStatus status = tempIA.Sign(&g_caPrivateKey);
    assert(status == ER_OK);
    SGID2Chain[1] = tempIA;
    QCC_UNUSED(status);

    //SGID2 Chain, leaf, signed by IA
    qcc::MembershipCertificate leaf;
    leaf.SetSerial((uint8_t*)"6666", 4);
    uint8_t leafSubjectCN[] = { 21, 22, 23, 24 };
    leaf.SetIssuerCN(iaSubjectCN, 4);
    leaf.SetSubjectCN(leafSubjectCN, 4);
    leaf.SetValidity(&validityMCert);
    leaf.SetSubjectPublicKey(g_publicKeyInfo.GetPublicKey());
    leaf.SetGuild(SGID2);
    leaf.SetCA(true);
    status = leaf.Sign(&g_privateKey[3]);
    assert(status == ER_OK);
    SGID2Chain[0] = leaf;
}




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

void setASGAGUID(GUID128& guid) {
    g_asgaGUID = guid;
}

void setasgaKeyInfo(KeyInfoNISTP256& asgakeyInfo) {
    uint8_t asgaAKI[] = { 3, 4, 5 };
    asgakeyInfo.SetKeyId(asgaAKI, 3);
    asgakeyInfo.SetPublicKey(g_adminpublicKeyInfo.GetPublicKey());
}

void CreateCACert() {

    //Self signed CA certificate
    g_CACert.SetSerial((uint8_t*)"Certificate-authority", 22);
    uint8_t CN[] = { 111, 222, 133, 144 };
    g_CACert.SetIssuerCN(CN, 4);
    g_CACert.SetSubjectCN(CN, 4);
    CertificateX509::ValidPeriod validityICAdmin;
    validityICAdmin.validFrom = 1427404154;
    validityICAdmin.validTo = 1427404154 + 630720000;
    g_CACert.SetValidity(&validityICAdmin);
    g_CACert.SetSubjectPublicKey(&g_caPublicKey);
    g_CACert.SetCA(true);
    //sign the leaf cert
    g_CACert.Sign(&g_caPrivateKey);
}

void createPermissionPolicy(PermissionPolicy& permissionPolicy) {

    //Set the version
    permissionPolicy.SetVersion(5555);
    {
        //Create an ACL[0].
        PermissionPolicy::Acl myAcl[2];
        //set two peers for acl[0]
        {
            PermissionPolicy::Peer peer[2];
            peer[0].SetType(PermissionPolicy::Peer::PEER_FROM_CERTIFICATE_AUTHORITY);
            peer[0].SetKeyInfo(&g_cakeyInfo);

            peer[1].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);
            peer[1].SetKeyInfo(&g_asgakeyInfo);
            peer[1].SetSecurityGroupId(g_asgaGUID);

            PermissionPolicy::Rule::Member member[1];
            member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);

            PermissionPolicy::Rule rule[1];
            rule[0].SetObjPath("*");
            rule[0].SetInterfaceName("*");
            rule[0].SetMembers(1, member);

            myAcl[0].SetRules(1, rule);
            myAcl[0].SetPeers(2, peer);
        }
        {
            PermissionPolicy::Peer peer[1];
            peer[0].SetType(PermissionPolicy::Peer::PEER_ANY_TRUSTED);

            PermissionPolicy::Rule::Member member[1];
            member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);

            PermissionPolicy::Rule rule[1];
            rule[0].SetObjPath("*");
            rule[0].SetInterfaceName("*");
            rule[0].SetMembers(1, member);

            myAcl[1].SetRules(1, rule);
            myAcl[1].SetPeers(1, peer);
        }
        permissionPolicy.SetAcls(2, myAcl);
    }
}


void createPermissionPolicyForPeer1(PermissionPolicy& permissionPolicy) {

    GUID128 BETA("BETA");
    //Set the version
    permissionPolicy.SetVersion(5556);
    {
        //Create an ACL[0].
        PermissionPolicy::Acl myAcl[2];
        //set peer belonging to BETA membership group
        {
            PermissionPolicy::Peer peer[1];

            peer[0].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);

            //The public key is the root of the BETA certificate chain
            uint8_t AKI[] = { 3, 4, 5, 6, 7, 8 };
            KeyInfoNISTP256 keyInfo;
            keyInfo.SetKeyId(AKI, 6);
            keyInfo.SetPublicKey(&g_publicKey[3]);

            peer[0].SetKeyInfo(&keyInfo);
            peer[0].SetSecurityGroupId(BETA);

            PermissionPolicy::Rule::Member member[1];
            member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);

            PermissionPolicy::Rule rule[1];
            rule[0].SetObjPath("*");
            rule[0].SetInterfaceName("*");
            rule[0].SetMembers(1, member);

            myAcl[0].SetRules(1, rule);
            myAcl[0].SetPeers(1, peer);
        }
        {
            PermissionPolicy::Peer peer[1];
            peer[0].SetType(PermissionPolicy::Peer::PEER_FROM_CERTIFICATE_AUTHORITY);
            peer[0].SetKeyInfo(&g_cakeyInfo);
            myAcl[1].SetPeers(1, peer);
        }


        permissionPolicy.SetAcls(2, myAcl);
    }
}

void createPermissionPolicyForPeer2(PermissionPolicy& permissionPolicy) {

    GUID128 ALPHA("ALPHA");
    //Set the version
    permissionPolicy.SetVersion(5557);
    {
        //Create an ACL[0].
        PermissionPolicy::Acl myAcl[2];
        //set peer belonging to ALPHA membership group
        {
            PermissionPolicy::Peer peer[1];

            peer[0].SetType(PermissionPolicy::Peer::PEER_WITH_MEMBERSHIP);

            //The public key is the root of the ALPHA certificate chain
            uint8_t AKI[] = { 1, 2, 3, 4, 5, 6 };
            KeyInfoNISTP256 keyInfo;
            keyInfo.SetKeyId(AKI, 6);
            keyInfo.SetPublicKey(&g_publicKey[1]);

            peer[0].SetKeyInfo(&keyInfo);
            peer[0].SetSecurityGroupId(ALPHA);

            PermissionPolicy::Rule::Member member[1];
            member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);

            PermissionPolicy::Rule rule[1];
            rule[0].SetObjPath("*");
            rule[0].SetInterfaceName("*");
            rule[0].SetMembers(1, member);

            myAcl[0].SetRules(1, rule);
            myAcl[0].SetPeers(1, peer);
        }
        {
            PermissionPolicy::Peer peer[1];
            peer[0].SetType(PermissionPolicy::Peer::PEER_FROM_CERTIFICATE_AUTHORITY);
            peer[0].SetKeyInfo(&g_cakeyInfo);
            myAcl[1].SetPeers(1, peer);
        }


        permissionPolicy.SetAcls(2, myAcl);
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
        if (strcmp(busName, g_wellKnownName.c_str()) == 0) { g_publicKeyInfo = publicKeyInfo; g_recd = true; }
        if (strcmp(busName, g_msgBus->GetUniqueName().c_str()) == 0) { g_adminpublicKeyInfo = publicKeyInfo; g_recvdAdminSLS = true; }
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


int main(int argc, char*argv[]) {

    QStatus status = ER_OK;
    setCAKeys();
    //GUID used by ASGA and this GUID should be persistent.
    GUID128 asgaGUID("123456785484");
    setASGAGUID(asgaGUID);

    //Populate the CA Cert;
    CreateCACert();
    convertPEMtoDER();

    if (AllJoynInit() != ER_OK) {
        return 1;
    }
#ifdef ROUTER
    if (AllJoynRouterInit() != ER_OK) {
        AllJoynShutdown();
        return 1;
    }
#endif
    bool stressInstallPolicy = false;
    bool updateIdentity = false;
    bool reset = false;

    /* Parse command line args */
    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp("-n", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                exit(1);
            } else {
                g_wellKnownName = argv[i];
            }
        } else if (0 == strcmp("-sip", argv[i])) {
            stressInstallPolicy = true;
        } else if (0 == strcmp("-ui", argv[i])) {
            updateIdentity = true;
        } else if (0 == strcmp("-p2", argv[i])) {
            peer1 = false;
        } else if (0 == strcmp("-reset", argv[i])) {
            reset = true;
        }
    }

    /* Create message bus */
    g_msgBus = new BusAttachment("security-manager", true);
    status = g_msgBus->Start();
    assert(status == ER_OK);
    status = g_msgBus->Connect();
    assert(status == ER_OK);

    printf("Testing PermissionConfigurator functions.. \n");
    PermissionConfigurator& pc1 = g_msgBus->GetPermissionConfigurator();
    status = pc1.SetApplicationState(PermissionConfigurator::ApplicationState::CLAIMABLE);
    printf("Before calling EPS, calling SetApplicationState  %s \n", QCC_StatusText(status));

    PermissionConfigurator::ApplicationState state = PermissionConfigurator::NOT_CLAIMABLE;
    printf("Application state is %s \n", PermissionConfigurator::ToString(state));
    status = pc1.GetApplicationState(state);
    printf("Before calling EPS, calling GetApplicationState  %s \n", QCC_StatusText(status));
    printf("Application state is %s \n", PermissionConfigurator::ToString(state));

    status = pc1.Reset();
    printf("Before calling EPS, calling Reset  %s \n", QCC_StatusText(status));

    KeyInfoNISTP256 keyInfo;
    status = pc1.GetSigningPublicKey(keyInfo);
    printf("Before calling EPS, calling GetSigningPublicKey  %s \n", QCC_StatusText(status));
    printf("End of testing PermissionConfigurator functions.. \n\n\n\n\n");

    g_msgBus->RegisterApplicationStateListener(appStateListener);
    g_msgBus->AddApplicationStateRule();


    //I have enabled peer security for NULL mechanism only. This is because, the master secret immediately expires after successful auth.
    status = g_msgBus->EnablePeerSecurity("ALLJOYN_ECDHE_NULL", new MyAuthListener(), "security-manager-keystore", false);
    assert(status == ER_OK);

    //Set manifest template, ASACORE-2341 if no manifest template set, then no SLS emitted
    // All Inclusive manifest template
    {
        PermissionPolicy::Rule::Member member[1];
        member[0].Set("*", PermissionPolicy::Rule::Member::NOT_SPECIFIED, PermissionPolicy::Rule::Member::ACTION_PROVIDE | PermissionPolicy::Rule::Member::ACTION_MODIFY | PermissionPolicy::Rule::Member::ACTION_OBSERVE);
        const size_t manifestSize = 1;
        PermissionPolicy::Rule manifestTemplate[manifestSize];
        manifestTemplate[0].SetObjPath("*");
        manifestTemplate[0].SetInterfaceName("*");
        manifestTemplate[0].SetMembers(1, member);
        status = pc1.SetPermissionManifest(manifestTemplate, manifestSize);
    }

    //Self-Claim and install a membership for myself. I am the ASGA.

    //Create a CA key. This CA key is totally different.

    //Crypto_ECC caDsaKeyPair;
    //caDsaKeyPair.GenerateDSAKeyPair();
    //uint8_t caAKI[] = { 1, 2 };
    //
    //KeyInfoNISTP256 caKey;
    //caKey.SetKeyId(caAKI, 2);
    //caKey.SetPublicKey(caDsaKeyPair.GetDSAPublicKey());

    // Wait for SLS to be received from Admin
    while (!g_recvdAdminSLS) {
        // do nothing;
        qcc::Sleep(50);
    }

    //Set the ASGA KeyInfo
    setasgaKeyInfo(g_asgakeyInfo);

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

    //Self signed admin cert
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
    status = mySecurityAppProxy.Claim(g_cakeyInfo, myGUID, g_asgakeyInfo, &adminCert, 1, manifest, 1);
    printf("Admin Claim status is %s \n", QCC_StatusText(status));


    printf("Installing a membership on myself. This is a self signed MC belonging to ASGA group. \n");
    if (status == ER_OK) {
        status = mySecurityAppProxy.InstallMembership(&memCert, 1);
        printf("Install Membership status is %s \n", QCC_StatusText(status));
    }
    //Lets focus attention on service side.
    MyBusListener busListener;
    g_msgBus->RegisterBusListener(busListener);
    status = g_msgBus->FindAdvertisedName(g_wellKnownName.c_str());
    assert(status == ER_OK);
    printf("Waiting to JoinSession with %s \n", g_wellKnownName.c_str());
    while (g_sessionId == 0) {
        qcc::Sleep(200);
    }

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

    //CreateMembershipCertChain for peer 1
    CreateMembershipCertChainPeer1();
    //CreateMembershipCertChain for peer 2
    CreateMembershipCertChainPeer2();

    //Create the ICC chain
    //The CA cert is already created, it is stored in g_CACert
    // The admin cert is signed by CA
    qcc::CertificateX509 adminCertSignedByCA;
    adminCertSignedByCA.SetSerial((uint8_t*)"admin-cert-signed-by-ca", 24);
    uint8_t CN[] = { 111, 222, 133, 144 };
    adminCertSignedByCA.SetIssuerCN(CN, 4);
    adminCertSignedByCA.SetSubjectCN(adminSubjectCN, 4);
    CertificateX509::ValidPeriod validitytemp;
    validitytemp.validFrom = 1427404154;
    validitytemp.validTo = 1427404154 + 630720000;
    adminCertSignedByCA.SetValidity(&validitytemp);
    adminCertSignedByCA.SetSubjectPublicKey(g_adminpublicKeyInfo.GetPublicKey());
    adminCertSignedByCA.SetCA(true);
    adminCertSignedByCA.Sign(&g_caPrivateKey);

    uint8_t subjectCN[] = { 1, 2, 3, 4 };
    //uint8_t issuerCN[] = { 111, 222, 133, 144 };

    qcc::IdentityCertificate leafCert;
    leafCert.SetSerial((uint8_t*)"1234", 5);
    leafCert.SetIssuerCN(adminSubjectCN, 4);
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
    leafCert.SetCA(false);
    //sign the leaf cert using admin's private key
    pc1.SignCertificate(leafCert);

    //Form the Identity chain
    //qcc::IdentityCertificate certChain[2];
    qcc::CertificateX509 certChain[3];
    //This is the leaf cert, signed by the admin
    certChain[0] = leafCert;
    //This is the admin cert signed by CA
    certChain[1] = adminCertSignedByCA;
    //This CA cert is self signed
    certChain[2] = g_CACert;


    String leafPEM, adminPEM, rootPEM;
    status = certChain[0].EncodeCertificatePEM(leafPEM);
    assert(status == ER_OK);
    status = certChain[1].EncodeCertificatePEM(adminPEM);
    assert(status == ER_OK);
    status = certChain[2].EncodeCertificatePEM(rootPEM);
    assert(status == ER_OK);

    status = certChain[0].Verify(certChain[1].GetSubjectPublicKey());
    printf("Verify statu 0-1 s is %s \n", QCC_StatusText(status));
    status = certChain[1].Verify(certChain[2].GetSubjectPublicKey());
    printf("Verify statu 1-2 s is %s \n", QCC_StatusText(status));

    printf("leaf PEM \n");
    cout << leafPEM.c_str() << endl;
    printf("admin PEM \n");
    cout << adminPEM.c_str() << endl;
    printf("root PEM \n");
    cout << rootPEM.c_str() << endl;

    //status = securityAppProxy.Reset();
    //printf("BUG Reset status is %s  \n",QCC_StatusText(status));

    //All set to claim
    status = securityAppProxy.Claim(g_cakeyInfo, asgaGUID, g_asgakeyInfo, (qcc::IdentityCertificate*)certChain, 3, manifest, 1);
    printf("Service Claim status is %s \n", QCC_StatusText(status));

    //The problem is, the session between service and client could be NULL based or PASK baded during Claiming. However, that is not enough for doing management operations.
    // For management operations, you need a ECDSA based session. Hence, call EPS again with ECDSA enabled.
    status = g_msgBus->EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", new MyAuthListener(), "security-manager-keystore", false);
    assert(status == ER_OK);

    //Install a Policy
    PermissionPolicy myPolicy;
    createPermissionPolicy(myPolicy);

    if (stressInstallPolicy) {
        for (int i = 0; i < 1000; i++) {
            myPolicy.SetVersion(5555 + i);
            status = securityAppProxy.UpdatePolicy(myPolicy);
            printf("Service Update policy stress (%d)th time status is %s \n", i, QCC_StatusText(status));

            // ASACORE-2331 Dummy reset the policy. This call will fail.
            status = securityAppProxy.ResetPolicy();

            //Actual reset the policy.
            status = securityAppProxy.ResetPolicy();
            printf("Service Reset policy (%d)th time status is %s \n", i, QCC_StatusText(status));
        }
    }

    if (updateIdentity) {
        status = securityAppProxy.UpdateIdentity((qcc::IdentityCertificate*)certChain, 3, manifest, 1);
        printf("Service Update Identity status is %s \n", QCC_StatusText(status));
    }

    //Install Membership certificates
    if (peer1) {
        printf("Peer 1 \n");
        status = securityAppProxy.InstallMembership((qcc::MembershipCertificate*) SGID1Chain, 3);
        printf("Service InstallMembership status is %s \n", QCC_StatusText(status));
    } else {
        printf("Peer 2 \n");
        status =  securityAppProxy.InstallMembership((qcc::MembershipCertificate*) SGID2Chain, 3);
        printf("Service InstallMembership status is %s \n", QCC_StatusText(status));
    }

    //Verify the membership summaries
    MsgArg arg;
    status =  securityAppProxy.GetMembershipSummaries(arg);
    printf("Service GetMembership summaries status is %s \n", QCC_StatusText(status));
    size_t count = arg.v_array.GetNumElements();
    printf("Membership summaries returned %lu \n", count);

    KeyInfoNISTP256* keyInfos = new KeyInfoNISTP256[count];
    String* serials = new String[count];
    status = SecurityApplicationProxy::MsgArgToCertificateIds(arg, serials, keyInfos, count);
    for (size_t i = 0; i < count; i++) {
        printf("Serial %lu = %s \n", i, serials[i].c_str());
    }


    //Install the policy
    if (peer1) {
        PermissionPolicy myPolicyPeer1;
        createPermissionPolicyForPeer1(myPolicyPeer1);
        status = securityAppProxy.UpdatePolicy(myPolicyPeer1);
        printf("Service Update policy status is %s \n", QCC_StatusText(status));
        printf("Installed policy is \n %s \n", myPolicyPeer1.ToString().c_str());
    } else {
        PermissionPolicy myPolicyPeer2;
        createPermissionPolicyForPeer2(myPolicyPeer2);
        status = securityAppProxy.UpdatePolicy(myPolicyPeer2);
        printf("Service Update policy status is %s \n", QCC_StatusText(status));
        printf("Installed policy is \n %s \n", myPolicyPeer2.ToString().c_str());
    }


    //This is a dummy secure method call which we know will fail.
    //ECCPublicKey tempPublicKey;
    //status =  securityAppProxy.GetEccPublicKey(tempPublicKey);
    //printf("[We know this will fail] Service GetEccPublicKey status is %s \n", QCC_StatusText(status));


    if (reset) {
        //Try to call Reset on service bus.
        status = securityAppProxy.Reset();
        printf("Service Reset status is %s \n", QCC_StatusText(status));
    }
    while (true) {
        qcc::Sleep(500);
    }

#ifdef ROUTER
    AllJoynRouterShutdown();
#endif
    AllJoynShutdown();
    return (int) status;
}