/******************************************************************************
 *  * 
 *    Copyright (c) 2016 Open Connectivity Foundation and AllJoyn Open
 *    Source Project Contributors and others.
 *    
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0

 ******************************************************************************/
#include "ajtcscTestCommon.h"
#include <alljoyn/ApplicationStateListener.h>
#include <alljoyn/SecurityApplicationProxy.h>
#include <qcc/CertificateHelper.h>

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

/*
 * String constants used throughout this test file.
 */
static const char* ECHO_STRING = "String that should be Echoed back.";
static const char* CHIRP_STRING = "Chirp this string out in the signal.";
static const char* TEST_OBJ_PATH = "/test";

static const char* const secureInterface[] = {
    "org.allseen.test.security.other.secure",
    "?Echo <s >s",
    "!Chirp >s",
    "@Prop1=i",
    "@Prop2=i",
    NULL
};

static const char* const insecureInterface[] = {
    "org.allseen.test.security.other.insecure",
    "?Echo <s >s",
    "!Chirp >s",
    "@Prop1=i",
    "@Prop2=i",
    NULL
};

#define APP_SEC_GET_PROP        AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_GET)
#define APP_SEC_SET_PROP        AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_SET)
#define APP_SEC_ALL_PROP        AJ_APP_MESSAGE_ID(0, 0, AJ_PROP_GET_ALL)
#define APP_SEC_ECHO            AJ_APP_MESSAGE_ID(0, 1, 0)
#define APP_SEC_CHIRP           AJ_APP_MESSAGE_ID(0, 1, 1)
#define APP_SEC_PROP1           AJ_APP_PROPERTY_ID(0, 1, 2)
#define APP_SEC_PROP2           AJ_APP_PROPERTY_ID(0, 1, 3)

#define PRX_SEC_GET_PROP        AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_GET)
#define PRX_SEC_SET_PROP        AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_SET)
#define PRX_SEC_ALL_PROP        AJ_PRX_MESSAGE_ID(0, 0, AJ_PROP_GET_ALL)
#define PRX_SEC_ECHO            AJ_PRX_MESSAGE_ID(0, 1, 0)
#define PRX_SEC_CHIRP           AJ_PRX_MESSAGE_ID(0, 1, 1)
#define PRX_SEC_PROP1           AJ_PRX_PROPERTY_ID(0, 1, 2)
#define PRX_SEC_PROP2           AJ_PRX_PROPERTY_ID(0, 1, 3)

#define APP_INS_GET_PROP        AJ_APP_MESSAGE_ID(1, 0, AJ_PROP_GET)
#define APP_INS_SET_PROP        AJ_APP_MESSAGE_ID(1, 0, AJ_PROP_SET)
#define APP_INS_ALL_PROP        AJ_APP_MESSAGE_ID(1, 0, AJ_PROP_GET_ALL)
#define APP_INS_ECHO            AJ_APP_MESSAGE_ID(1, 1, 0)
#define APP_INS_CHIRP           AJ_APP_MESSAGE_ID(1, 1, 1)
#define APP_INS_PROP1           AJ_APP_PROPERTY_ID(1, 1, 2)
#define APP_INS_PROP2           AJ_APP_PROPERTY_ID(1, 1, 3)

#define PRX_INS_GET_PROP        AJ_PRX_MESSAGE_ID(1, 0, AJ_PROP_GET)
#define PRX_INS_SET_PROP        AJ_PRX_MESSAGE_ID(1, 0, AJ_PROP_SET)
#define PRX_INS_ALL_PROP        AJ_PRX_MESSAGE_ID(1, 0, AJ_PROP_GET_ALL)
#define PRX_INS_ECHO            AJ_PRX_MESSAGE_ID(1, 1, 0)
#define PRX_INS_CHIRP           AJ_PRX_MESSAGE_ID(1, 1, 1)
#define PRX_INS_PROP1           AJ_PRX_PROPERTY_ID(1, 1, 2)
#define PRX_INS_PROP2           AJ_PRX_PROPERTY_ID(1, 1, 3)

static const AJ_InterfaceDescription secureInterfaces[] = {
    AJ_PropertiesIface,
    secureInterface,
    NULL
};

static const AJ_InterfaceDescription insecureInterfaces[] = {
    AJ_PropertiesIface,
    insecureInterface,
    NULL
};

static AJ_Object AppObjects[] = {
    { "/test/secure", secureInterfaces, AJ_OBJ_FLAG_ANNOUNCED | AJ_OBJ_FLAG_SECURE },
    { "/test/insecure", insecureInterfaces, AJ_OBJ_FLAG_ANNOUNCED },
    { NULL }
};

static int32_t secprop1;
static int32_t secprop2;
static int32_t insprop1;
static int32_t insprop2;

static AJ_Status SecPropGetHandler(AJ_Message* msg, uint32_t id, void* context)
{
    QCC_UNUSED(context);
    switch (id) {
    case APP_SEC_PROP1:
        AJ_MarshalArgs(msg, "i", secprop1);
        return AJ_OK;

    case APP_SEC_PROP2:
        AJ_MarshalArgs(msg, "i", secprop2);
        return AJ_OK;

    default:
        return AJ_ERR_UNEXPECTED;
    }
}

static AJ_Status InsPropGetHandler(AJ_Message* msg, uint32_t id, void* context)
{
    QCC_UNUSED(context);
    switch (id) {
    case APP_INS_PROP1:
        AJ_MarshalArgs(msg, "i", insprop1);
        return AJ_OK;

    case APP_INS_PROP2:
        AJ_MarshalArgs(msg, "i", insprop2);
        return AJ_OK;

    default:
        return AJ_ERR_UNEXPECTED;
    }
}

static AJ_Status SecPropSetHandler(AJ_Message* msg, uint32_t id, void* context)
{
    QCC_UNUSED(context);
    switch (id) {
    case APP_SEC_PROP1:
        AJ_UnmarshalArgs(msg, "i", &secprop1);
        return AJ_OK;

    case APP_SEC_PROP2:
        AJ_UnmarshalArgs(msg, "i", &secprop2);
        return AJ_OK;

    default:
        return AJ_ERR_UNEXPECTED;
    }
}

static AJ_Status InsPropSetHandler(AJ_Message* msg, uint32_t id, void* context)
{
    QCC_UNUSED(context);
    switch (id) {
    case APP_INS_PROP1:
        AJ_UnmarshalArgs(msg, "i", &insprop1);
        return AJ_OK;

    case APP_INS_PROP2:
        AJ_UnmarshalArgs(msg, "i", &insprop2);
        return AJ_OK;

    default:
        return AJ_ERR_UNEXPECTED;
    }
}

static const char psk_hint[] = "<anonymous>";
static const char psk_char[] = "faaa0af3dd3f1e0379da046a3ab6ca44";
static uint32_t authenticationSuccessful = FALSE;
static AJ_ECCPrivateKey prv;
static Crypto_ECC ecc;
static IdentityCertificate idn;
static String pem;
static X509CertificateChain* root = NULL;
static AJ_Status TCAuthListener(uint32_t mechanism, uint32_t command, AJ_Credential* cred)
{
    AJ_Status status = AJ_ERR_INVALID;
    X509CertificateChain* node;

    AJ_AlwaysPrintf(("TCAuthListener mechanism %x command %x\n", mechanism, command));

    switch (mechanism) {
    case AUTH_SUITE_ECDHE_NULL:
        cred->expiration = 0;
        status = AJ_OK;
        break;

    case AUTH_SUITE_ECDHE_PSK:
        switch (command) {
        case AJ_CRED_PUB_KEY:
            cred->data = (uint8_t*) psk_hint;
            cred->len = strlen(psk_hint);
            cred->expiration = 0;
            status = AJ_OK;
            break;

        case AJ_CRED_PRV_KEY:
            cred->data = (uint8_t*) psk_char;
            cred->len = strlen(psk_char);
            cred->expiration = 0;
            status = AJ_OK;
            break;
        }
        break;

    case AUTH_SUITE_ECDHE_ECDSA:
        switch (command) {
        case AJ_CRED_PRV_KEY:
            AJ_ASSERT(sizeof (AJ_ECCPrivateKey) == cred->len);
            memcpy(cred->data, &prv, sizeof (AJ_ECCPrivateKey));
            cred->expiration = 0;
            status = AJ_OK;
            break;

        case AJ_CRED_CERT_CHAIN:
            switch (cred->direction) {
            case AJ_CRED_REQUEST:
                cred->data = (uint8_t*) root;
                cred->expiration = 0;
                status = AJ_OK;
                break;

            case AJ_CRED_RESPONSE:
                node = (X509CertificateChain*) cred->data;
                status = AJ_X509VerifyChain(node, NULL, AJ_CERTIFICATE_IDN_X509);
                while (node) {
                    printf("CERTIFICATE\n%s\n", BytesToHexString(node->certificate.der.data, node->certificate.der.size).c_str());
                    node = node->next;
                }
                cred->expiration = 0;
                break;
            }
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
        authenticationSuccessful = TRUE;
    }
    std::promise<AJ_Status>* p = (std::promise<AJ_Status>*) context;
    p->set_value(status);
}

static void ClearFlags() {
    authenticationSuccessful = FALSE;
}

static QStatus TCCreateCert(const qcc::String& serial,
                            const qcc::String& issuer,
                            const qcc::String& organization,
                            const ECCPrivateKey* issuerPrivateKey,
                            const ECCPublicKey* issuerPublicKey,
                            const qcc::String& subject,
                            const ECCPublicKey* subjectPubKey,
                            CertificateX509::ValidPeriod& validity,
                            bool isCA,
                            CertificateX509& cert)
{
    QStatus status = ER_CRYPTO_ERROR;

    cert.SetSerial((const uint8_t*)serial.data(), serial.size());
    cert.SetIssuerCN((const uint8_t*) issuer.c_str(), issuer.length());
    cert.SetSubjectCN((const uint8_t*) subject.c_str(), subject.length());
    if (!organization.empty()) {
        cert.SetIssuerOU((const uint8_t*) organization.c_str(), organization.length());
        cert.SetSubjectOU((const uint8_t*) organization.c_str(), organization.length());
    }
    cert.SetSubjectPublicKey(subjectPubKey);
    cert.SetCA(isCA);
    cert.SetValidity(&validity);
    status = cert.SignAndGenerateAuthorityKeyId(issuerPrivateKey, issuerPublicKey);
    return status;
}

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

class TCSecurityOtherAttachment : public TCBusAttachment {

  public:

    TCSecurityOtherAttachment(const char* name) : TCBusAttachment(name, TCAuthListener, TCAuthCallback) {
        sessionPort = 0;
        secprop1 = 42;
        secprop2 = 17;
        insprop1 = 42;
        insprop2 = 17;
        signalReceivedFlag = FALSE;
        AJ_RegisterObjects(AppObjects, AppObjects);

        ecc.GenerateDSAKeyPair();
        AJ_ASSERT(sizeof (prv.x) == ecc.GetDSAPrivateKey()->GetSize());
        prv.alg = 0;
        prv.crv = 0;
        memcpy(prv.x, ecc.GetDSAPrivateKey()->GetD(), sizeof (prv.x));
        CertificateX509::ValidPeriod validity;
        validity.validFrom = qcc::GetEpochTimestamp() / 1000;
        validity.validTo = validity.validFrom + 24 * 3600;
        TCCreateCert("1000",
                     "self",
                     "organization",
                     ecc.GetDSAPrivateKey(),
                     ecc.GetDSAPublicKey(),
                     "self",
                     ecc.GetDSAPublicKey(),
                     validity,
                     false,
                     idn);

        pem = idn.GetPEM();
        //Remove line breaks
        String tmp;
        String sub;
        size_t pos = 0;
        do {
            pos = pem.find_first_of('\n');
            sub = pem.substr(0, pos);
            tmp += sub;
            pem.erase(0, pos + 1);
        } while (pos != String::npos);

        root = AJ_X509DecodeCertificateChainPEM(tmp.c_str());
        AJ_ASSERT(root);
    }

    virtual ~TCSecurityOtherAttachment() {
        AJ_X509FreeDecodedCertificateChain(root);
    }

    void SetupTrustedCert(BusAttachment& issuerBus) {
        CredentialAccessor ca(issuerBus);
        ECCPrivateKey issuerPrivateKey;
        ECCPublicKey issuerPublicKey;

        ca.GetDSAPrivateKey(issuerPrivateKey);
        ca.GetDSAPublicKey(issuerPublicKey);

        ecc.GenerateDSAKeyPair();
        AJ_ASSERT(sizeof (prv.x) == ecc.GetDSAPrivateKey()->GetSize());
        prv.alg = 0;
        prv.crv = 0;
        memcpy(prv.x, ecc.GetDSAPrivateKey()->GetD(), sizeof (prv.x));
        CertificateX509::ValidPeriod validity;
        validity.validFrom = qcc::GetEpochTimestamp() / 1000;
        validity.validTo = validity.validFrom + 24 * 3600;
        TCCreateCert("1000",
                     "self",
                     "organization",
                     &issuerPrivateKey,
                     &issuerPublicKey,
                     "self",
                     ecc.GetDSAPublicKey(),
                     validity,
                     false,
                     idn);

        /* use the issuer bus to sign the cert */
        PermissionConfigurator& pc = issuerBus.GetPermissionConfigurator();
        EXPECT_EQ(ER_OK, pc.SignCertificate(idn));

        pem = idn.GetPEM();
        //Remove line breaks
        String tmp;
        String sub;
        size_t pos = 0;
        do {
            pos = pem.find_first_of('\n');
            sub = pem.substr(0, pos);
            tmp += sub;
            pem.erase(0, pos + 1);
        } while (pos != String::npos);

        if (NULL != root) {
            AJ_X509FreeDecodedCertificateChain(root);
        }

        root = AJ_X509DecodeCertificateChainPEM(tmp.c_str());
        AJ_ASSERT(root);
    }

    void RecvMessage(AJ_Message* msg) {
        AJ_Status status;
        AJ_Message reply;
        bool handled = TRUE;

        switch (msg->msgId) {
        case APP_SEC_ECHO:
        case APP_INS_ECHO:
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

        case APP_SEC_CHIRP:
        case APP_INS_CHIRP:
            status = AJ_UnmarshalArgs(msg, "s", &str);
            AJ_ASSERT(AJ_OK == status);
            printf("Chirp: %s\n", str);
            signalReceivedFlag = TRUE;
            break;

        case APP_SEC_GET_PROP:
            status = AJ_BusPropGet(msg, SecPropGetHandler, NULL);
            AJ_ASSERT(AJ_OK == status);
            break;

        case APP_INS_GET_PROP:
            status = AJ_BusPropGet(msg, InsPropGetHandler, NULL);
            AJ_ASSERT(AJ_OK == status);
            break;

        case APP_SEC_SET_PROP:
            status = AJ_BusPropSet(msg, SecPropSetHandler, NULL);
            AJ_ASSERT(AJ_OK == status);
            break;

        case APP_INS_SET_PROP:
            status = AJ_BusPropSet(msg, InsPropSetHandler, NULL);
            AJ_ASSERT(AJ_OK == status);
            break;

        case APP_SEC_ALL_PROP:
            status = AJ_BusPropGetAll(msg, SecPropGetHandler, NULL);
            AJ_ASSERT(AJ_OK == status);
            break;

        case APP_INS_ALL_PROP:
            status = AJ_BusPropGetAll(msg, InsPropGetHandler, NULL);
            AJ_ASSERT(AJ_OK == status);
            break;

        case AJ_REPLY_ID(PRX_SEC_ECHO):
        case AJ_REPLY_ID(PRX_INS_ECHO):
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

        case AJ_REPLY_ID(PRX_SEC_GET_PROP):
        case AJ_REPLY_ID(PRX_INS_GET_PROP):
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

        case AJ_REPLY_ID(PRX_SEC_SET_PROP):
        case AJ_REPLY_ID(PRX_INS_SET_PROP):
            if (AJ_MSG_ERROR == msg->hdr->msgType) {
                SCStatus = ER_BUS_REPLY_IS_ERROR_MESSAGE;
                response = msg->error;
            } else {
                SCStatus = ER_OK;
            }
            break;

        case AJ_REPLY_ID(PRX_SEC_ALL_PROP):
        case AJ_REPLY_ID(PRX_INS_ALL_PROP):
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

    int32_t ReadSecProp1() {
        return secprop1;
    }
    int32_t ReadSecProp2() {
        return secprop2;
    }
    int32_t ReadInsProp1() {
        return insprop1;
    }
    int32_t ReadInsProp2() {
        return insprop2;
    }

    void RegisterObjects(AJ_Object* objs, AJ_Object* prxs, uint8_t secure = true) {
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

        std::promise<void> p;

        auto func = [this, &p, objs, prxs] () {
            AJ_RegisterObjects(objs, prxs);
            AJ_VERIFY(AJ_OK == AJ_RegisterObjectsACL());
            p.set_value();
        };

        Enqueue(func);
        p.get_future().wait();
    }

    bool signalReceivedFlag;
};

/**
 * This is a collection of misc. test cases that did not fit into another
 * category but are still related to security2.0 feature.
 * most of the tests are related to backward compatibility.
 */

static void GetAppPublicKey(BusAttachment& bus, ECCPublicKey& publicKey)
{
    KeyInfoNISTP256 keyInfo;
    bus.GetPermissionConfigurator().GetSigningPublicKey(keyInfo);
    publicKey = *keyInfo.GetPublicKey();
}

class SecurityOtherTestSessionPortListener : public SessionPortListener {
  public:
    virtual bool AcceptSessionJoiner(SessionPort sessionPort, const char* joiner, const SessionOpts& opts) {
        QCC_UNUSED(sessionPort);
        QCC_UNUSED(joiner);
        QCC_UNUSED(opts);
        return true;
    }
};

class SecurityOtherTestBusObject : public BusObject {
  public:
    SecurityOtherTestBusObject(BusAttachment& bus, const char* path, const char* interfaceName, bool announce = true)
        : BusObject(path), isAnnounced(announce), prop1(42), prop2(17) {
        const InterfaceDescription* iface = bus.GetInterface(interfaceName);
        EXPECT_TRUE(iface != NULL) << "NULL InterfaceDescription* for " << interfaceName;
        if (iface == NULL) {
            return;
        }

        if (isAnnounced) {
            AddInterface(*iface, ANNOUNCED);
        } else {
            AddInterface(*iface, UNANNOUNCED);
        }

        /* Register the method handlers with the object */
        const MethodEntry methodEntries[] = {
            { iface->GetMember("Echo"), static_cast<MessageReceiver::MethodHandler>(&SecurityOtherTestBusObject::Echo) }
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

class SecurityOtherECDHE_ECDSAAuthListener : public AuthListener {
  public:
    SecurityOtherECDHE_ECDSAAuthListener() :
        requestCredentialsCalled(false),
        verifyCredentialsCalled(false),
        authenticationSuccessful(false),
        securityViolationCalled(false)
    {
        cryptoECC.GenerateDSAKeyPair();
        CertificateX509::ValidPeriod validity;
        validity.validFrom = qcc::GetEpochTimestamp() / 1000;
        validity.validTo = validity.validFrom + 24 * 3600;
        CreateCert("1000",
                   "self",
                   "organization",
                   cryptoECC.GetDSAPrivateKey(),
                   cryptoECC.GetDSAPublicKey(),
                   "self",
                   cryptoECC.GetDSAPublicKey(),
                   validity,
                   false,
                   identityCert);
    }

    QStatus RequestCredentialsAsync(const char* authMechanism, const char* authPeer, uint16_t authCount, const char* userId, uint16_t credMask, void* context)
    {
        QCC_UNUSED(authPeer);
        QCC_UNUSED(authCount);
        QCC_UNUSED(userId);
        QCC_UNUSED(credMask);
        requestCredentialsCalled = true;
        Credentials creds;
        if (strcmp(authMechanism, "ALLJOYN_ECDHE_ECDSA") == 0) {
            if ((credMask& AuthListener::CRED_PRIVATE_KEY) == AuthListener::CRED_PRIVATE_KEY) {
                String pk;
                CertificateX509::EncodePrivateKeyPEM(cryptoECC.GetDSAPrivateKey(), pk);
                creds.SetPrivateKey(pk);
            }
            if ((credMask& AuthListener::CRED_CERT_CHAIN) == AuthListener::CRED_CERT_CHAIN) {
                creds.SetCertChain(identityCert.GetPEM());
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
            authenticationSuccessful = true;
        }
    }

    void SecurityViolation(QStatus status, const Message& msg) {
        QCC_UNUSED(status);
        QCC_UNUSED(msg);
        securityViolationCalled = true;
    }

    QStatus CreateCert(const qcc::String& serial,
                       const qcc::String& issuer,
                       const qcc::String& organization,
                       const ECCPrivateKey* issuerPrivateKey,
                       const ECCPublicKey* issuerPublicKey,
                       const qcc::String& subject,
                       const ECCPublicKey* subjectPubKey,
                       CertificateX509::ValidPeriod& validity,
                       bool isCA,
                       CertificateX509& cert)
    {
        QStatus status = ER_CRYPTO_ERROR;

        cert.SetSerial((const uint8_t*)serial.data(), serial.size());
        cert.SetIssuerCN((const uint8_t*) issuer.c_str(), issuer.length());
        cert.SetSubjectCN((const uint8_t*) subject.c_str(), subject.length());
        if (!organization.empty()) {
            cert.SetIssuerOU((const uint8_t*) organization.c_str(), organization.length());
            cert.SetSubjectOU((const uint8_t*) organization.c_str(), organization.length());
        }
        cert.SetSubjectPublicKey(subjectPubKey);
        cert.SetCA(isCA);
        cert.SetValidity(&validity);
        status = cert.SignAndGenerateAuthorityKeyId(issuerPrivateKey, issuerPublicKey);
        return status;
    }

    bool requestCredentialsCalled;
    bool verifyCredentialsCalled;
    bool authenticationSuccessful;
    bool securityViolationCalled;

    Crypto_ECC cryptoECC;
    IdentityCertificate identityCert;
};

/*
 * Purpose:
 * Two peers are not claimed can make method call over a ECDHE_ECDSA session.
 *
 * Setup:
 * Two peers who are not claimed make method call over an ECDHE_ECDSA session.
 *
 * Verification:
 * Verify that method call is successful. Verify that application provides
 * credentials via RequestCredentials callback.
 *
 * This test helps verify backward compatibility since it is using ECDHE_ECDSA
 * over using Security1.0.
 */
TEST(SecurityOtherTest, methodCallOverECDHE_ECDSASession_SC) {
    BusAttachment SCBus("SecurityOtherSC", true);
    TCSecurityOtherAttachment TCBus("SecurityOtherTC");

    EXPECT_EQ(ER_OK, SCBus.Start());
    EXPECT_EQ(ER_OK, SCBus.Connect());
    // To avoid cross-talk, i.e. thin leaf node connect to unintended
    // routing nodes, generate and advertise a random routing node prefix.
    qcc::String routingNodePrefix = "test.rnPrefix.randhex" + qcc::RandHexString(64);
    qcc::String advertisingPrefix = "quiet@" + routingNodePrefix;
    ASSERT_EQ(ER_OK, SCBus.AdvertiseName(advertisingPrefix.c_str(), ajn::TRANSPORT_ANY));
    TCBus.Connect(routingNodePrefix.c_str());
    TCBus.Start();

    InMemoryKeyStoreListener SCKeyStoreListener;

    // Register in memory keystore listeners
    EXPECT_EQ(ER_OK, SCBus.RegisterKeyStoreListener(SCKeyStoreListener));

    SecurityOtherECDHE_ECDSAAuthListener SCAuthListener;

    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));

    qcc::String interface = "<node>"
                            "<interface name='org.allseen.test.security.other.secure'>"
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

    SessionOpts opts;
    SessionPort sessionPort = 42;
    SecurityOtherTestSessionPortListener sessionPortListener;
    EXPECT_EQ(ER_OK, TCBus.BindSessionPort(sessionPort));

    uint32_t sessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), sessionPort, NULL, sessionId, opts));

    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test/secure", sessionId, true);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface("org.allseen.test.security.other.secure")) << interface.c_str() << "\n";

    MsgArg arg("s", ECHO_STRING);
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_OK, proxy.MethodCall("org.allseen.test.security.other.secure", "Echo", &arg, static_cast<size_t>(1), replyMsg));

    char* echoReply;
    replyMsg->GetArg(0)->Get("s", &echoReply);
    EXPECT_STREQ(ECHO_STRING, echoReply);

    EXPECT_TRUE(SCAuthListener.requestCredentialsCalled);
    EXPECT_TRUE(SCAuthListener.verifyCredentialsCalled);
    EXPECT_TRUE(SCAuthListener.authenticationSuccessful);
    EXPECT_FALSE(SCAuthListener.securityViolationCalled);

}

TEST(SecurityOtherTest, methodCallOverECDHE_ECDSASession_TC) {
    BusAttachment SCBus("SecurityOtherSC", true);
    TCSecurityOtherAttachment TCBus("SecurityOtherTC");

    EXPECT_EQ(ER_OK, SCBus.Start());
    EXPECT_EQ(ER_OK, SCBus.Connect());
    // To avoid cross-talk, i.e. thin leaf node connect to unintended
    // routing nodes, generate and advertise a random routing node prefix.
    qcc::String routingNodePrefix = "test.rnPrefix.randhex" + qcc::RandHexString(64);
    qcc::String advertisingPrefix = "quiet@" + routingNodePrefix;
    ASSERT_EQ(ER_OK, SCBus.AdvertiseName(advertisingPrefix.c_str(), ajn::TRANSPORT_ANY));
    TCBus.Connect(routingNodePrefix.c_str());
    TCBus.Start();

    InMemoryKeyStoreListener SCKeyStoreListener;

    // Register in memory keystore listeners
    EXPECT_EQ(ER_OK, SCBus.RegisterKeyStoreListener(SCKeyStoreListener));

    SecurityOtherECDHE_ECDSAAuthListener SCAuthListener;

    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));

    qcc::String interface = "<node>"
                            "<interface name='org.allseen.test.security.other.secure'>"
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

    SecurityOtherTestBusObject SCSecureBusObject(SCBus, "/test/secure", "org.allseen.test.security.other.secure");
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCSecureBusObject, true));

    SessionOpts opts;
    SessionPort sessionPort = 42;
    SecurityOtherTestSessionPortListener sessionPortListener;
    EXPECT_EQ(ER_OK, SCBus.BindSessionPort(sessionPort, opts, sessionPortListener));

    uint32_t sessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), sessionPort, sessionId));

    const char* s = ECHO_STRING;
    QStatus status = TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_SEC_ECHO, s);
    ASSERT_EQ(ER_OK, status);
    EXPECT_STREQ(s, TCBus.GetResponse());

    EXPECT_TRUE(SCAuthListener.requestCredentialsCalled);
    EXPECT_TRUE(SCAuthListener.verifyCredentialsCalled);
    EXPECT_TRUE(SCAuthListener.authenticationSuccessful);
    EXPECT_FALSE(SCAuthListener.securityViolationCalled);

    EXPECT_TRUE(authenticationSuccessful);
    ClearFlags();
}

/*
 * Purpose:
 * Unsecure messages are not checked against rules. Test for Method calls,
 * get property calls, set property calls, sessionless signals.
 *
 * Setup:
 * Install policies on two peers that denies everything.
 *
 * Peer 1 makes a method call, get property, set property, get all properties call  to app. bus.
 * Peer 1 sends a signal to app. bus.
 * Peer 1 sends a store-and-forward signal to the app. bus
 *
 * Verification:
 * Verify that method call, get property, set property, get all properties call
 * to app. bus. are successful.
 * Verify that the signal is received by the app. bus.
 * Verify that the store-and-forward signal is received by the app. bus.
 */
TEST(SecurityOtherTest, unsecure_messages_not_blocked_by_policies_rules_SC) {
    BusAttachment managerBus("SecurityOtherManager", true);
    BusAttachment SCBus("SecurityOtherSC", true);
    TCSecurityOtherAttachment TCBus("SecurityOtherTC");

    EXPECT_EQ(ER_OK, managerBus.Start());
    EXPECT_EQ(ER_OK, managerBus.Connect());
    EXPECT_EQ(ER_OK, SCBus.Start());
    EXPECT_EQ(ER_OK, SCBus.Connect());

    // To avoid cross-talk, i.e. thin leaf node connect to unintended
    // routing nodes, generate and advertise a random routing node prefix.
    qcc::String routingNodePrefix = "test.rnPrefix.randhex" + qcc::RandHexString(64);
    qcc::String advertisingPrefix = "quiet@" + routingNodePrefix;
    ASSERT_EQ(ER_OK, managerBus.AdvertiseName(advertisingPrefix.c_str(), ajn::TRANSPORT_ANY));
    TCBus.Connect(routingNodePrefix.c_str());
    TCBus.Start();

    InMemoryKeyStoreListener managerKeyStoreListener;
    InMemoryKeyStoreListener SCKeyStoreListener;

    // Register in memory keystore listeners
    EXPECT_EQ(ER_OK, managerBus.RegisterKeyStoreListener(managerKeyStoreListener));
    EXPECT_EQ(ER_OK, SCBus.RegisterKeyStoreListener(SCKeyStoreListener));

    DefaultECDHEAuthListener managerAuthListener;
    DefaultECDHEAuthListener SCAuthListener;

    EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &managerAuthListener));
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA"));
    TCBus.SetApplicationState(APP_STATE_CLAIMABLE);

    qcc::String interface = "<node>"
                            "<interface name='org.allseen.test.security.other.secure'>"
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
                            "<interface name='org.allseen.test.security.other.insecure'>"
                            "<annotation name='org.alljoyn.Bus.Secure' value='false'/>"
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

    SecurityOtherTestBusObject SCSecureBusObject(SCBus, "/test/secure", "org.allseen.test.security.other.secure");
    SecurityOtherTestBusObject SCInsecureBusObject(SCBus, "/test/insecure", "org.allseen.test.security.other.insecure");
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCSecureBusObject, true));
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCInsecureBusObject));

    SessionOpts opts1;
    SessionId managerToManagerSessionId;
    SessionPort managerSessionPort = 42;
    SecurityOtherTestSessionPortListener managerSessionPortListener;
    EXPECT_EQ(ER_OK, managerBus.BindSessionPort(managerSessionPort, opts1, managerSessionPortListener));

    SessionOpts opts2;
    SessionId managerToSCSessionId;
    SessionPort SCSessionPort = 42;
    SecurityOtherTestSessionPortListener SCSessionPortListener;
    EXPECT_EQ(ER_OK, SCBus.BindSessionPort(SCSessionPort, opts2, SCSessionPortListener));

    SessionOpts opts3;
    SessionId managerToTCSessionId;
    SessionPort TCSessionPort = 42;
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
    KeyInfoNISTP256 TCKey;
    ECCPublicKey TCPublicKey;
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

    //Manager claims Peers
    /* set claimable */
    SCBus.GetPermissionConfigurator().SetApplicationState(PermissionConfigurator::CLAIMABLE);
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

    //----------------Install Policy that denies everything--------------
    // To deny everything we just install a policy that is identical to the
    // default policy but removes the AdminGroup entry and the InstallMembership
    // Entry.  This is a policy that will deny eveything.
    {
        PermissionPolicy policy;
        policy.SetVersion(1);
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, policy);
        EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(policy));
        EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));
    }
    {
        PermissionPolicy policy;
        policy.SetVersion(1);
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, policy);
        EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(policy));
        EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));
    }

    uint32_t sessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts2));
    {
        // secure methods should fail
        // Try to make method call, get/set properties and send a signal the
        // policy should deny all interaction with the secure interface.  This
        // is done to verify we have a policy that denies everything.
        ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test/secure", sessionId, true);
        EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
        EXPECT_TRUE(proxy.ImplementsInterface("org.allseen.test.security.other.secure")) << interface.c_str() << "\n";
        MsgArg arg("s", ECHO_STRING);
        Message replyMsg(SCBus);
        EXPECT_EQ(ER_PERMISSION_DENIED, proxy.MethodCall("org.allseen.test.security.other.secure", "Echo", &arg, static_cast<size_t>(1), replyMsg));

        MsgArg prop1Arg;
        EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
        EXPECT_EQ(ER_PERMISSION_DENIED, proxy.SetProperty("org.allseen.test.security.other.secure", "Prop1", prop1Arg));

        EXPECT_EQ(ER_PERMISSION_DENIED, proxy.GetProperty("org.allseen.test.security.other.secure", "Prop1", prop1Arg));

        MsgArg props;
        EXPECT_EQ(ER_PERMISSION_DENIED, proxy.GetAllProperties("org.allseen.test.security.other.secure", props));

        MsgArg signalArg("s", CHIRP_STRING);
        // Signals are send and forget.  They will always return ER_OK.
        EXPECT_EQ(ER_PERMISSION_DENIED, SCSecureBusObject.Signal(TCBus.GetUniqueName().c_str(),
                                                                    sessionId,
                                                                    *SCBus.GetInterface("org.allseen.test.security.other.secure")->GetMember("Chirp"),
                                                                    &signalArg, 1));
    }
    {
        // insecure methods should pass
        // Permission policies should no effect insecure interfaces.
        ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), "/test/insecure", sessionId);
        EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
        EXPECT_TRUE(proxy.ImplementsInterface("org.allseen.test.security.other.insecure")) << interface.c_str() << "\n";
        MsgArg arg("s", ECHO_STRING);
        Message replyMsg(SCBus);
        EXPECT_EQ(ER_OK, proxy.MethodCall("org.allseen.test.security.other.insecure", "Echo", &arg, static_cast<size_t>(1), replyMsg));

        char* echoReply;
        replyMsg->GetArg(0)->Get("s", &echoReply);
        EXPECT_STREQ(ECHO_STRING, echoReply);

        MsgArg prop1Arg;
        EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
        EXPECT_EQ(ER_OK, proxy.SetProperty("org.allseen.test.security.other.insecure", "Prop1", prop1Arg));

        EXPECT_EQ(513, TCBus.ReadInsProp1());

        EXPECT_EQ(ER_OK, proxy.GetProperty("org.allseen.test.security.other.insecure", "Prop1", prop1Arg));

        int32_t prop1;
        prop1Arg.Get("i", &prop1);
        EXPECT_EQ(513, prop1);

        MsgArg props;
        EXPECT_EQ(ER_OK, proxy.GetAllProperties("org.allseen.test.security.other.insecure", props));
        {
            int32_t prop1;
            MsgArg* propArg;
            EXPECT_EQ(ER_OK, props.GetElement("{sv}", "Prop1", &propArg)) << props.ToString().c_str();
            EXPECT_EQ(ER_OK, propArg->Get("i", &prop1)) << propArg->ToString().c_str();
            EXPECT_EQ(513, prop1);
        }
        {
            int32_t prop2;
            MsgArg* propArg;
            EXPECT_EQ(ER_OK, props.GetElement("{sv}", "Prop2", &propArg)) << props.ToString().c_str();
            EXPECT_EQ(ER_OK, propArg->Get("i", &prop2)) << propArg->ToString().c_str();
            EXPECT_EQ(17, prop2);
        }

        TCBus.signalReceivedFlag = FALSE;
        MsgArg signalArg("s", CHIRP_STRING);
        // Signals are send and forget.  They will always return ER_OK.
        EXPECT_EQ(ER_OK, SCInsecureBusObject.Signal(TCBus.GetUniqueName().c_str(),
                                                       sessionId,
                                                       *SCBus.GetInterface("org.allseen.test.security.other.insecure")->GetMember("Chirp"),
                                                       &signalArg, 1));

        //Wait for a maximum of 2 sec for the Chirp Signal.
        for (int msec = 0; msec < 2000; msec += WAIT_MSECS) {
            if (TCBus.signalReceivedFlag) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }

        EXPECT_TRUE(TCBus.signalReceivedFlag);
    }
}


TEST(SecurityOtherTest, unsecure_messages_not_blocked_by_policies_rules_TC) {
    BusAttachment managerBus("SecurityOtherManager", true);
    TCSecurityOtherAttachment TCBus("SecurityOtherTC");
    BusAttachment SCBus("SecurityOtherSC", true);

    EXPECT_EQ(ER_OK, managerBus.Start());
    EXPECT_EQ(ER_OK, managerBus.Connect());

    // To avoid cross-talk, i.e. thin leaf node connect to unintended
    // routing nodes, generate and advertise a random routing node prefix.
    qcc::String routingNodePrefix = "test.rnPrefix.randhex" + qcc::RandHexString(64);
    qcc::String advertisingPrefix = "quiet@" + routingNodePrefix;
    ASSERT_EQ(ER_OK, managerBus.AdvertiseName(advertisingPrefix.c_str(), ajn::TRANSPORT_ANY));
    TCBus.Connect(routingNodePrefix.c_str());
    TCBus.Start();

    EXPECT_EQ(ER_OK, SCBus.Start());
    EXPECT_EQ(ER_OK, SCBus.Connect());

    InMemoryKeyStoreListener managerKeyStoreListener;
    InMemoryKeyStoreListener SCKeyStoreListener;

    // Register in memory keystore listeners
    EXPECT_EQ(ER_OK, managerBus.RegisterKeyStoreListener(managerKeyStoreListener));
    EXPECT_EQ(ER_OK, SCBus.RegisterKeyStoreListener(SCKeyStoreListener));

    DefaultECDHEAuthListener managerAuthListener;
    DefaultECDHEAuthListener SCAuthListener;

    EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &managerAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA"));
    TCBus.SetApplicationState(APP_STATE_CLAIMABLE);
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &SCAuthListener));

    qcc::String interface = "<node>"
                            "<interface name='org.allseen.test.security.other.secure'>"
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
                            "<interface name='org.allseen.test.security.other.insecure'>"
                            "<annotation name='org.alljoyn.Bus.Secure' value='false'/>"
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

    SecurityOtherTestBusObject SCSecureBusObject(SCBus, "/test/secure", "org.allseen.test.security.other.secure");
    SecurityOtherTestBusObject SCInsecureBusObject(SCBus, "/test/insecure", "org.allseen.test.security.other.insecure");
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCSecureBusObject, true));
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCInsecureBusObject));

    SessionOpts opts1;
    SessionId managerToManagerSessionId;
    SessionPort managerSessionPort = 42;
    SecurityOtherTestSessionPortListener managerSessionPortListener;
    EXPECT_EQ(ER_OK, managerBus.BindSessionPort(managerSessionPort, opts1, managerSessionPortListener));

    SessionOpts opts2;
    SessionId managerToTCSessionId;
    SessionPort TCSessionPort = 42;
    SecurityOtherTestSessionPortListener TCSessionPortListener;
    EXPECT_EQ(ER_OK, TCBus.BindSessionPort(TCSessionPort));
    //EXPECT_EQ(ER_OK, TCBus.BindSessionPort(TCSessionPort, opts2, TCSessionPortListener));

    SessionOpts opts3;
    SessionId managerToSCSessionId;
    SessionPort SCSessionPort = 42;
    SecurityOtherTestSessionPortListener SCSessionPortListener;
    EXPECT_EQ(ER_OK, SCBus.BindSessionPort(SCSessionPort, opts3, SCSessionPortListener));

    EXPECT_EQ(ER_OK, managerBus.JoinSession(managerBus.GetUniqueName().c_str(), managerSessionPort, NULL, managerToManagerSessionId, opts1));
    EXPECT_EQ(ER_OK, managerBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, managerToTCSessionId, opts2));
    EXPECT_EQ(ER_OK, managerBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, NULL, managerToSCSessionId, opts3));

    //-----------------------Claim each bus Attachments------------------
    SecurityApplicationProxy sapWithManager(managerBus, managerBus.GetUniqueName().c_str(), managerToManagerSessionId);
    SecurityApplicationProxy sapWithTC(managerBus, TCBus.GetUniqueName().c_str(), managerToTCSessionId);
    SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);


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

    //Create TC key
    KeyInfoNISTP256 TCKey;
    ECCPublicKey TCPublicKey;
    EXPECT_EQ(ER_OK, sapWithTC.GetEccPublicKey(TCPublicKey));
    TCKey.SetPublicKey(&TCPublicKey);

    //Create SC key
    KeyInfoNISTP256 SCKey;
    PermissionConfigurator& pcSC = SCBus.GetPermissionConfigurator();
    EXPECT_EQ(ER_OK, pcSC.GetSigningPublicKey(SCKey));

    //------------ Claim self(managerBus), TC, and SC --------
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
    EXPECT_EQ(ER_OK, sapWithSC.Claim(managerKey,
                                        managerGuid,
                                        managerKey,
                                        identityCertChainSC, certChainSize,
                                        manifest, manifestSize));

    EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &managerAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &SCAuthListener));

    //--------- InstallMembership certificates on self, TC, and SC

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

    //----------------Install Policy that denies everything--------------
    // To deny everything we just install a policy that is identical to the
    // default policy but removes the AdminGroup entry and the InstallMembership
    // Entry.  This is a policy that will deny eveything.
    {
        PermissionPolicy policy;
        policy.SetVersion(1);
        PermissionPolicy TCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithTC.GetDefaultPolicy(TCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(TCDefaultPolicy, policy);
        EXPECT_EQ(ER_OK, sapWithTC.UpdatePolicy(policy));
        EXPECT_EQ(ER_OK, sapWithTC.SecureConnection(true));
    }
    {
        PermissionPolicy policy;
        policy.SetVersion(1);
        PermissionPolicy SCDefaultPolicy;
        EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
        UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, policy);
        EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(policy));
        EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));
    }

    uint32_t sessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, sessionId));
    {
        // secure methods should fail
        // Try to make method call, get/set properties and send a signal the
        // policy should deny all interaction with the secure interface.  This
        // is done to verify we have a policy that denies everything.
        const char* s = ECHO_STRING;
        QStatus status = TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_SEC_ECHO, s);
        ASSERT_EQ(ER_PERMISSION_DENIED, status);

        // Verify Set/Get Property and GetAll Properties
        int32_t prop = 513;
        status = TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_SEC_SET_PROP, PRX_SEC_PROP1, prop);
        EXPECT_EQ(ER_PERMISSION_DENIED, status);

        prop = 0;
        EXPECT_EQ(ER_PERMISSION_DENIED, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_SEC_GET_PROP, PRX_SEC_PROP1, prop));

        TCProperties tcprops;
        EXPECT_EQ(ER_PERMISSION_DENIED,TCBus.GetAllProperties(SCBus.GetUniqueName().c_str(), PRX_SEC_ALL_PROP, "org.allseen.test.security.other.secure", tcprops, true));

        const char* chirp = CHIRP_STRING;
        EXPECT_EQ(ER_PERMISSION_DENIED, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_SEC_CHIRP, chirp));
    }
    // insecure methods should pass
    // permission policies should have no effect on insecure interfaces
    {
        // Verify Method call
        const char* s = ECHO_STRING;
        ASSERT_EQ(ER_OK, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_INS_ECHO, s));
        EXPECT_STREQ(ECHO_STRING, TCBus.GetResponse());

        // Verify Set/Get Property
        EXPECT_EQ(ER_OK, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_INS_SET_PROP, PRX_INS_PROP1, 513));
        EXPECT_EQ(513, SCInsecureBusObject.ReadProp1());
        int32_t prop;
        EXPECT_EQ(ER_OK, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_INS_GET_PROP, PRX_INS_PROP1, prop));
        EXPECT_EQ(513, prop);

        // Send/Receive Signal
        ChirpSignalReceiver chirpSignalReceiver;
        EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver, static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler), SCBus.GetInterface("org.allseen.test.security.other.insecure")->GetMember("Chirp"), NULL));

        EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_INS_CHIRP, CHIRP_STRING));

        //Wait for a maximum of 2 sec for the Chirp Signal.
        for (int msec = 0; msec < 2000; msec += WAIT_MSECS) {
            if (chirpSignalReceiver.signalReceivedFlag) {
                break;
            }
            qcc::Sleep(WAIT_MSECS);
        }
        EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag);
    }
}


class SecurityOtherECDHE_NULLAuthListener : public AuthListener {
  public:
    SecurityOtherECDHE_NULLAuthListener() :
        requestCredentialsCalled(false),
        verifyCredentialsCalled(false),
        authenticationSuccessful(false),
        securityViolationCalled(false)
    {
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
        return RequestCredentialsResponse(context, false, creds);
    }
    QStatus VerifyCredentialsAsync(const char* authMechanism, const char* authPeer, const Credentials& creds, void* context) {
        QCC_UNUSED(authMechanism);
        QCC_UNUSED(authPeer);
        QCC_UNUSED(creds);
        verifyCredentialsCalled = true;
        return VerifyCredentialsResponse(context, false);
    }

    void AuthenticationComplete(const char* authMechanism, const char* authPeer, bool success) {
        QCC_UNUSED(authMechanism);
        QCC_UNUSED(authPeer);
        QCC_UNUSED(success);
        if (success) {
            authenticationSuccessful = true;
        }
    }

    void SecurityViolation(QStatus status, const Message& msg) {
        QCC_UNUSED(status);
        QCC_UNUSED(msg);
        securityViolationCalled = true;
    }
    bool requestCredentialsCalled;
    bool verifyCredentialsCalled;
    bool authenticationSuccessful;
    bool securityViolationCalled;

};

/*
 * Purpose:
 * Before Claiming, properties on org.alljoyn.Bus.Security.Application should be
 * accessible via ECDHE_NULL auth .mechanism.
 *
 * Setup:
 * DUT is not claimed.
 *
 * DUT and a peer bus establish an ECDHE_NULL based session.
 * A bus calls GetAll properties on org.alljoyn.Bus.Security.Application interface.
 *
 * Verification:
 * The following properties should be fetched:
 * "Version"  Expected value=1
 * "ApplicationState"  Expected value="Claimable"
 * "ManifestTemplateDigest"  Expected value=Unknown
 * "EccPublicKey"  Expected value=Public key of DUT
 * "ManufacturerCertificate"  Expected value=empty array
 * "ManifestTemplate"  Expected value=Unknown
 * "ClaimCapabilities"  Expected value=Unknown
 */
TEST(SecurityOtherTest, DISABLED_call_security_application_over_ECDHE_NULL) {
    BusAttachment SCBus("SecurityOtherSC", true);
    TCSecurityOtherAttachment TCBus("SecurityOtherTC");

    EXPECT_EQ(ER_OK, SCBus.Start());
    EXPECT_EQ(ER_OK, SCBus.Connect());

    // To avoid cross-talk, i.e. thin leaf node connect to unintended
    // routing nodes, generate and advertise a random routing node prefix.
    qcc::String routingNodePrefix = "test.rnPrefix.randhex" + qcc::RandHexString(64);
    qcc::String advertisingPrefix = "quiet@" + routingNodePrefix;
    ASSERT_EQ(ER_OK, SCBus.AdvertiseName(advertisingPrefix.c_str(), ajn::TRANSPORT_ANY));
    TCBus.Connect(routingNodePrefix.c_str());
    TCBus.Start();

    InMemoryKeyStoreListener SCKeyStoreListener;

    // Register in memory keystore listeners
    EXPECT_EQ(ER_OK, SCBus.RegisterKeyStoreListener(SCKeyStoreListener));

    SecurityOtherECDHE_NULLAuthListener SCAuthListener;
    SecurityOtherECDHE_NULLAuthListener TCAuthListener;

    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", &SCAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL"));

    SessionOpts opts;
    SessionPort sessionPort = 42;
    SecurityOtherTestSessionPortListener sessionPortListener;
    EXPECT_EQ(ER_OK, TCBus.BindSessionPort(sessionPort));

    uint32_t sessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), sessionPort, NULL, sessionId, opts));

    SecurityApplicationProxy proxy(SCBus, TCBus.GetUniqueName().c_str(), sessionId);

    // "Version"  Expected value=1
    uint16_t secuirtyApplicaitonVersion = 0;
    EXPECT_EQ(ER_OK, proxy.GetSecurityApplicationVersion(secuirtyApplicaitonVersion));
    EXPECT_EQ(1, secuirtyApplicaitonVersion);

    // "ApplicationState"  Expected value="Not Claimable"
    PermissionConfigurator::ApplicationState applicationState;
    EXPECT_EQ(ER_OK, proxy.GetApplicationState(applicationState));
    EXPECT_EQ(PermissionConfigurator::NOT_CLAIMABLE, applicationState);

    // "ManifestTemplateDigest"  Expected value=Unknown
    uint8_t manifestTemplateDigest[qcc::Crypto_SHA256::DIGEST_SIZE];
    EXPECT_EQ(ER_BAD_ARG_2, proxy.GetManifestTemplateDigest(manifestTemplateDigest, qcc::Crypto_SHA256::DIGEST_SIZE));

    // "EccPublicKey"  Expected value=Public key of DUT
    qcc::ECCPublicKey eccPublicKey;
    EXPECT_EQ(ER_OK, proxy.GetEccPublicKey(eccPublicKey));
    // TODO figure out how to get the TC public key to verify the return value
    //PermissionConfigurator& pcTC = TCBus.GetPermissionConfigurator();
    //KeyInfoNISTP256 TCKeyInfo;
    //EXPECT_EQ(ER_OK, pcTC.GetSigningPublicKey(TCKeyInfo));
    //EXPECT_EQ(*TCKeyInfo.GetPublicKey(), eccPublicKey);


    // "ManufacturerCertificate"  Expected value=empty array
    MsgArg manufacturerCertificate;
    EXPECT_EQ(ER_OK, proxy.GetManufacturerCertificate(manufacturerCertificate));
    EXPECT_EQ((size_t)0, manufacturerCertificate.v_array.GetNumElements());

    // "ManifestTemplate"  Expected value=Unknown
    MsgArg manifestTemplate;
    EXPECT_EQ(ER_OK, proxy.GetManifestTemplate(manifestTemplate));
    // manifestTemplate should be empty
    EXPECT_EQ((size_t)0, manifestTemplate.v_array.GetNumElements());

    // "ClaimCapabilities"  Expected value=Unknown
    PermissionConfigurator::ClaimCapabilities claimCapabilities;
    EXPECT_EQ(ER_OK, proxy.GetClaimCapabilities(claimCapabilities));
    EXPECT_EQ(PermissionConfigurator::CAPABLE_ECDHE_NULL, claimCapabilities);

    SCBus.Stop();
    SCBus.Join();
}

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

class SecurityOtherAuthListener : public AuthListener {
  public:
    SecurityOtherAuthListener() :
        requestCredentialsCalled(false),
        verifyCredentialsCalled(false),
        authenticationSuccessful(false),
        securityViolationCalled(false)
    {
    }

    void ClearFlags() {
        requestCredentialsCalled = false;
        verifyCredentialsCalled = false;
        authenticationSuccessful = false;
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
            creds.SetPassword("faaa0af3dd3f1e0379da046a3ab6ca44");
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
            authenticationSuccessful = true;
        }
    }

    void SecurityViolation(QStatus status, const Message& msg) {
        QCC_UNUSED(status);
        QCC_UNUSED(msg);
        securityViolationCalled = true;
    }
    bool requestCredentialsCalled;
    bool verifyCredentialsCalled;
    bool authenticationSuccessful;
    bool securityViolationCalled;

};

class SecurityOther2Test : public testing::Test {
  public:
    SecurityOther2Test() :
        managerBus("SecurityOtherManager", true),
        TCBus("SecurityOtherTC"),
        SCBus("SecurityOtherSC", true),
        managerKeyStoreListener(),
        SCKeyStoreListener(),
        managerAuthListener(),
        SCAuthListener(),
        interfaceName("org.allseen.test.security.other.secure"),
        interface(),
        managerSessionPort(42),
        TCSessionPort(42),
        SCSessionPort(42),
        opts1(),
        opts2(),
        opts3(),
        managerSessionPortListener(),
        TCSessionPortListener(),
        SCSessionPortListener(),
        managerToSCSessionId(),
        appStateListener()
    {

    }
    virtual void SetUp() {
        EXPECT_EQ(ER_OK, managerBus.Start());
        EXPECT_EQ(ER_OK, managerBus.Connect());

        // To avoid cross-talk, i.e. thin leaf node connect to unintended
        // routing nodes, generate and advertise a random routing node prefix.
        qcc::String routingNodePrefix = "test.rnPrefix.randhex" + qcc::RandHexString(64);
        qcc::String advertisingPrefix = "quiet@" + routingNodePrefix;
        ASSERT_EQ(ER_OK, managerBus.AdvertiseName(advertisingPrefix.c_str(), ajn::TRANSPORT_ANY));
        TCBus.Connect(routingNodePrefix.c_str());
        TCBus.Start();

        EXPECT_EQ(ER_OK, SCBus.Start());
        EXPECT_EQ(ER_OK, SCBus.Connect());


        // Register in memory keystore listeners
        EXPECT_EQ(ER_OK, managerBus.RegisterKeyStoreListener(managerKeyStoreListener));
        EXPECT_EQ(ER_OK, SCBus.RegisterKeyStoreListener(SCKeyStoreListener));

        EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &managerAuthListener));
        // Enable SC security here, TC security in individual test cases
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL ALLJOYN_ECDHE_ECDSA", &SCAuthListener));

        interface = "<node>"
                    "<interface name='" + interfaceName + "'>"
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

        SessionId managerToManagerSessionId;
        EXPECT_EQ(ER_OK, managerBus.BindSessionPort(managerSessionPort, opts1, managerSessionPortListener));

        // Bind SC sessionport here, TC in individual test cases after security enabled
        EXPECT_EQ(ER_OK, SCBus.BindSessionPort(SCSessionPort, opts2, SCSessionPortListener));

        EXPECT_EQ(ER_OK, managerBus.JoinSession(managerBus.GetUniqueName().c_str(), managerSessionPort, NULL, managerToManagerSessionId, opts1));
        EXPECT_EQ(ER_OK, managerBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, NULL, managerToSCSessionId, opts3));

        //-----------------------Claim manager and SC bus Attachments------------------
        SecurityApplicationProxy sapWithManager(managerBus, managerBus.GetUniqueName().c_str(), managerToManagerSessionId);
        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);

        managerBus.RegisterApplicationStateListener(appStateListener);
        managerBus.AddApplicationStateRule();

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

        //------------ Claim self(managerBus), SC --------
        GUID128 managerGuid;
        PermissionMgmtTestHelper::GetGUID(managerBus, managerGuid);

        GUID128 SCGuid;
        PermissionMgmtTestHelper::GetGUID(SCBus, SCGuid);

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
                                                                      SCGuid.ToString(),
                                                                      SCKey.GetPublicKey(),
                                                                      "SCAlias",
                                                                      3600,
                                                                      identityCertChainSC[0],
                                                                      digest, Crypto_SHA256::DIGEST_SIZE)) << "Failed to create identity certificate.";

        /* set claimable */
        EXPECT_EQ(ER_OK, SCBus.GetPermissionConfigurator().SetApplicationState(PermissionConfigurator::CLAIMABLE));
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

        EXPECT_EQ(ER_OK, managerBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &managerAuthListener));
        EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &SCAuthListener));

        //--------- InstallMembership certificates on self, and SC

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

        /* Reconfigure TC certificate so it has a trusted issuer */
        TCBus.SetupTrustedCert(managerBus);
    }

    void InstallAnyTrustedPolicy() {
        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
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

                rules[0].SetObjPath("*");
                rules[0].SetInterfaceName("*");
                {
                    PermissionPolicy::Rule::Member members[1];
                    members[0].Set("*",
                                   PermissionPolicy::Rule::Member::NOT_SPECIFIED,
                                   PermissionPolicy::Rule::Member::ACTION_MODIFY |
                                   PermissionPolicy::Rule::Member::ACTION_OBSERVE |
                                   PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                    rules[0].SetMembers(1, members);
                }
                acls[0].SetRules(1, rules);
            }
            SCPolicy.SetAcls(1, acls);
        }

        {
            PermissionPolicy SCDefaultPolicy;
            EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
            UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
            EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
            EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));
        }
    }

    void InstallFromCertificateAuthorityPolicy() {
        SecurityApplicationProxy sapWithSC(managerBus, SCBus.GetUniqueName().c_str(), managerToSCSessionId);
        // Permission policy that will be installed on TC
        PermissionPolicy SCPolicy;
        SCPolicy.SetVersion(1);
        {
            PermissionPolicy::Acl acls[1];
            {
                PermissionPolicy::Peer peers[1];
                peers[0].SetType(PermissionPolicy::Peer::PEER_FROM_CERTIFICATE_AUTHORITY);
                KeyInfoNISTP256 managerKey;
                EXPECT_EQ(ER_OK, managerBus.GetPermissionConfigurator().GetSigningPublicKey(managerKey));
                peers[0].SetKeyInfo(&managerKey);
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
                                   PermissionPolicy::Rule::Member::ACTION_MODIFY |
                                   PermissionPolicy::Rule::Member::ACTION_OBSERVE |
                                   PermissionPolicy::Rule::Member::ACTION_PROVIDE);
                    rules[0].SetMembers(1, members);
                }
                acls[0].SetRules(1, rules);
            }
            SCPolicy.SetAcls(1, acls);
        }

        {
            PermissionPolicy SCDefaultPolicy;
            EXPECT_EQ(ER_OK, sapWithSC.GetDefaultPolicy(SCDefaultPolicy));
            UpdatePolicyWithValuesFromDefaultPolicy(SCDefaultPolicy, SCPolicy);
            EXPECT_EQ(ER_OK, sapWithSC.UpdatePolicy(SCPolicy));
            EXPECT_EQ(ER_OK, sapWithSC.SecureConnection(true));
        }
    }

    virtual void TearDown() {
        EXPECT_EQ(ER_OK, managerBus.Stop());
        EXPECT_EQ(ER_OK, managerBus.Join());
        EXPECT_EQ(ER_OK, TCBus.Stop());
        EXPECT_EQ(ER_OK, TCBus.Join());
        EXPECT_EQ(ER_OK, SCBus.Stop());
        EXPECT_EQ(ER_OK, SCBus.Join());

    }
    BusAttachment managerBus;
    TCSecurityOtherAttachment TCBus;
    BusAttachment SCBus;

    InMemoryKeyStoreListener managerKeyStoreListener;
    InMemoryKeyStoreListener SCKeyStoreListener;

    SecurityOtherAuthListener managerAuthListener;
    SecurityOtherAuthListener SCAuthListener;

    qcc::String interfaceName;
    qcc::String interface;

    SessionPort managerSessionPort;
    SessionPort TCSessionPort;
    SessionPort SCSessionPort;

    SessionOpts opts1;
    SessionOpts opts2;
    SessionOpts opts3;

    SecurityOtherTestSessionPortListener managerSessionPortListener;
    SecurityOtherTestSessionPortListener TCSessionPortListener;
    SecurityOtherTestSessionPortListener SCSessionPortListener;

    SessionId managerToSCSessionId;

    SecurityManagement_ApplicationStateListener appStateListener;
};

static AJ_Object AppObjects2[] = {
    { "/test", secureInterfaces, AJ_OBJ_FLAG_ANNOUNCED | AJ_OBJ_FLAG_SECURE },
    { NULL }
};

/*
 * purpose:
 * Interaction between unclaimed app and claimed app: Security 1.0 peer must be
 * able to send/receive messages to/from Security 2.0 peer in a trusted manner,
 * Security 2.0 peer has an ACL with ANY_TRUSTED peer type.
 *
 * (Security 1.0 peer is an unclaimed application)
 * The DUT is Security 1.0 peer.
 *
 * Setup:
 * Security 2.0 peer is Claimed and has the following policy installed:
 * ACL: ANY_TRUSTED,
 * Rule:  Object path: *, Interface Name: *, Member Name: *,  Action: PROVIDE|MODIFY|OBSERVE
 *
 * Peers establish an ECDHE_NULL based session.
 * Security 1.0 peer makes a method call, get property call and set property call on Security 2.0 peer.
 * Security 1.0 peer sends a signal to Security 2.0 peer.
 * Security 2.0 peer makes a method call, get property call and set property call on Security 1.0 peer.
 * Security 2.0 peer sends a signal to Security 1.0 peer.
 * Method calls will not be received by Security 2.0.
 * Signal will not be received by Security 2.0 peer.
 * Method calls cannot be sent by Security 2.0 peer.
 * Signal will not be sent by Security 1.0 peer.
 * (This is because an ECDHE_NULL based session is not trusted.)
 *
 * Peers establish an ECDHE_PSK based session.
 * Security 1.0 peer makes a method call, get property call and set property call on Security 2.0 peer.
 * Security 1.0 peer sends a signal to Security 2.0 peer.
 * Security 2.0 peer makes a method call, get property call and set property call on Security 1.0 peer.
 * Security 2.0 peer sends a signal to Security 1.0 peer.
 * Method calls and signals will be successful.
 *
 * Peers establish an ECDHE_ECDSA based session.
 * Security 1.0 peer makes a method call, get property call and set property call on Security 2.0 peer.
 * Security 1.0 peer sends a signal to Security 2.0 peer.
 * Security 2.0 peer makes a method call, get property call and set property call on Security 1.0 peer.
 * Security 2.0 peer sends a signal to Security 1.0 peer.
 * Authentication between peers should be successful
 * Method calls and signals will not be successful since Security 1.0 peers can not exchange manifest.
 *
 * Verification:
 * Verification as mentioned in the set-up.
 */
TEST_F(SecurityOther2Test, security1_to_security2_over_ECDHE_NULL_acl_peer_ANY_TRUSTED) {
    InstallAnyTrustedPolicy();

    TCBus.RegisterObjects(AppObjects2, AppObjects2, true);

    SecurityOtherTestBusObject SCBusObject(SCBus, TEST_OBJ_PATH, interfaceName.c_str());
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject, true));

    //Peers establish an ECDHE_NULL based session.
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL"));
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", &SCAuthListener));
    EXPECT_EQ(ER_OK, TCBus.BindSessionPort(TCSessionPort));

    uint32_t sessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, sessionId));

    // Verify Method call
    const char* s = ECHO_STRING;
    ASSERT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_SEC_ECHO, s));
    EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());

    // Verify Set/Get Property
    EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_SEC_SET_PROP, PRX_SEC_PROP1, 513));
    EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());
    // Property should be unchanged.
    EXPECT_EQ(42, SCBusObject.ReadProp1());
    int32_t prop;
    EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_SEC_GET_PROP, PRX_SEC_PROP1, prop));
    EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());

    // Send/Receive Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver,
                                                  static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler),
                                                  SCBus.GetInterface(interfaceName.c_str())->GetMember("Chirp"),
                                                  NULL));

    EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_SEC_CHIRP, CHIRP_STRING));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < 2000; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_FALSE(chirpSignalReceiver.signalReceivedFlag);
}

/*
 * See SecurityOther2Test.security1_to_security2_over_ECDHE_NULL_acl_peer_ANY_TRUSTED
 * for full test description.
 */
TEST_F(SecurityOther2Test, security2_to_security1_over_ECDHE_NULL_acl_peer_ANY_TRUSTED) {
    InstallAnyTrustedPolicy();

    TCBus.RegisterObjects(AppObjects2, AppObjects2, true);

    SecurityOtherTestBusObject SCBusObject(SCBus, TEST_OBJ_PATH, interfaceName.c_str());
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject, true));

    //Peers establish an ECDHE_NULL based session.
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL"));
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", &SCAuthListener));
    EXPECT_EQ(ER_OK, TCBus.BindSessionPort(TCSessionPort));

    uint32_t sessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts1));

    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), TEST_OBJ_PATH, sessionId);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName.c_str())) << interface.c_str() << "\n";
    MsgArg arg("s", ECHO_STRING);
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.MethodCall(interfaceName.c_str(), "Echo", &arg, static_cast<size_t>(1), replyMsg));


    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.SetProperty(interfaceName.c_str(), "Prop1", prop1Arg));

    // Property should be unchanged.
    EXPECT_EQ(42, TCBus.ReadSecProp1());

    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.GetProperty(interfaceName.c_str(), "Prop1", prop1Arg));

    int32_t prop1;
    prop1Arg.Get("i", &prop1);
    EXPECT_EQ(513, prop1);

    TCBus.signalReceivedFlag = FALSE;

    MsgArg signalArg("s", CHIRP_STRING);
    EXPECT_EQ(ER_PERMISSION_DENIED, SCBusObject.Signal(TCBus.GetUniqueName().c_str(),
                                                       sessionId,
                                                       *SCBus.GetInterface(interfaceName.c_str())->GetMember("Chirp"),
                                                       &signalArg, 1));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    // for (int msec = 0; msec < 2000; msec += WAIT_MSECS) {
    //     if (TCBus.signalReceivedFlag) {
    //         break;
    //     }
    //     qcc::Sleep(WAIT_MSECS);
    // }
    // EXPECT_FALSE(TCBus.signalReceivedFlag);
}

/*
 * See SecurityOther2Test.security1_to_security2_over_ECDHE_NULL_acl_peer_ANY_TRUSTED
 * for full test description.
 */
TEST_F(SecurityOther2Test, security1_to_security2_over_ECDHE_PSK_acl_peer_ANY_TRUSTED) {
    InstallAnyTrustedPolicy();

    TCBus.RegisterObjects(AppObjects2, AppObjects2, true);

    SecurityOtherTestBusObject SCBusObject(SCBus, TEST_OBJ_PATH, interfaceName.c_str());
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject, true));

    //Peers establish an ECDHE_PSK based session.
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_PSK", &SCAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_PSK"));
    EXPECT_EQ(ER_OK, TCBus.BindSessionPort(TCSessionPort));

    uint32_t sessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, sessionId));

    // Verify Method call
    const char* s = ECHO_STRING;
    ASSERT_EQ(ER_OK, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_SEC_ECHO, s));
    EXPECT_STREQ(ECHO_STRING, TCBus.GetResponse());

    // Verify Set/Get Property
    EXPECT_EQ(ER_OK, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_SEC_SET_PROP, PRX_SEC_PROP1, 513));
    EXPECT_EQ(513, SCBusObject.ReadProp1());
    int32_t prop;
    EXPECT_EQ(ER_OK, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_SEC_GET_PROP, PRX_SEC_PROP1, prop));
    EXPECT_EQ(513, prop);

    // Send/Receive Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver,
                                                 static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler),
                                                 SCBus.GetInterface(interfaceName.c_str())->GetMember("Chirp"),
                                                 NULL));

    EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_SEC_CHIRP, CHIRP_STRING));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < 2000; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag);
}

/*
 * See SecurityOther2Test.security1_to_security2_over_ECDHE_NULL_acl_peer_ANY_TRUSTED
 * for full test description.
 */
TEST_F(SecurityOther2Test, security2_to_security1_over_ECDHE_PSK_acl_peer_ANY_TRUSTED) {
    InstallAnyTrustedPolicy();

    TCBus.RegisterObjects(AppObjects2, AppObjects2, true);

    SecurityOtherTestBusObject SCBusObject(SCBus, TEST_OBJ_PATH, interfaceName.c_str());
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject, true));

    //Peers establish an ECDHE_NULL based session.
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_PSK"));
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_PSK", &SCAuthListener));
    EXPECT_EQ(ER_OK, TCBus.BindSessionPort(TCSessionPort));

    uint32_t sessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts1));

    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), TEST_OBJ_PATH, sessionId);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName.c_str())) << interface.c_str() << "\n";
    MsgArg arg("s", ECHO_STRING);
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_OK, proxy.MethodCall(interfaceName.c_str(), "Echo", &arg, static_cast<size_t>(1), replyMsg));

    char* echoReply;
    EXPECT_EQ(ER_OK, replyMsg->GetArg(0)->Get("s", &echoReply));
    EXPECT_STREQ(ECHO_STRING, echoReply);

    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_OK, proxy.SetProperty(interfaceName.c_str(), "Prop1", prop1Arg));

    EXPECT_EQ(513, TCBus.ReadSecProp1());

    EXPECT_EQ(ER_OK, proxy.GetProperty(interfaceName.c_str(), "Prop1", prop1Arg));

    int32_t prop1;
    EXPECT_EQ(ER_OK, prop1Arg.Get("i", &prop1));
    EXPECT_EQ(513, prop1);


    TCBus.signalReceivedFlag = FALSE;

   MsgArg signalArg("s", CHIRP_STRING);
   EXPECT_EQ(ER_OK, SCBusObject.Signal(TCBus.GetUniqueName().c_str(),
                                       sessionId,
                                       *SCBus.GetInterface(interfaceName.c_str())->GetMember("Chirp"),
                                       &signalArg, 1));

   //Wait for a maximum of 2 sec for the Chirp Signal.
   for (int msec = 0; msec < 2000; msec += WAIT_MSECS) {
       if (TCBus.signalReceivedFlag) {
           break;
       }
       qcc::Sleep(WAIT_MSECS);
   }
   EXPECT_TRUE(TCBus.signalReceivedFlag);
}

/*
 * See SecurityOther2Test.security1_to_security2_over_ECDHE_NULL_acl_peer_ANY_TRUSTED
 * for full test description.
 */
TEST_F(SecurityOther2Test, security1_to_security2_over_ECDHE_ECDSA_acl_peer_ANY_TRUSTED) {
    InstallAnyTrustedPolicy();

    TCBus.RegisterObjects(AppObjects2, AppObjects2, true);

    SecurityOtherTestBusObject SCBusObject(SCBus, TEST_OBJ_PATH, interfaceName.c_str());
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject, true));

    //Peers establish an ECDHE_ECDSA based session.
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
    EXPECT_EQ(ER_OK, TCBus.BindSessionPort(TCSessionPort));

    uint32_t sessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, sessionId));


    // Verify Method call
    const char* s = ECHO_STRING;
    ASSERT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_SEC_ECHO, s));
    EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());

    // Verify Set/Get Property
    EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_SEC_SET_PROP, PRX_SEC_PROP1, 513));
    EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());
    // Property should be unchanged.
    EXPECT_EQ(42, SCBusObject.ReadProp1());
    int32_t prop;
    EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_SEC_GET_PROP, PRX_SEC_PROP1, prop));
    EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());

    // Send/Receive Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver,
                                                  static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler),
                                                  SCBus.GetInterface(interfaceName.c_str())->GetMember("Chirp"),
                                                  NULL));

    EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_SEC_CHIRP, CHIRP_STRING));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < 2000; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_FALSE(chirpSignalReceiver.signalReceivedFlag);
}

/*
 * See SecurityOther2Test.security1_to_security2_over_ECDHE_NULL_acl_peer_ANY_TRUSTED
 * for full test description.
 */
TEST_F(SecurityOther2Test, security2_to_security1_over_ECDHE_ECDSA_acl_peer_ANY_TRUSTED) {
    InstallAnyTrustedPolicy();

    TCBus.RegisterObjects(AppObjects2, AppObjects2, true);

    SecurityOtherTestBusObject SCBusObject(SCBus, TEST_OBJ_PATH, interfaceName.c_str());
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject, true));

    //Peers establish an ECDHE_NULL based session.
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
    EXPECT_EQ(ER_OK, TCBus.BindSessionPort(TCSessionPort));

    uint32_t sessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts1));

    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), TEST_OBJ_PATH, sessionId);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName.c_str())) << interface.c_str() << "\n";
    MsgArg arg("s", ECHO_STRING);
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.MethodCall(interfaceName.c_str(), "Echo", &arg, static_cast<size_t>(1), replyMsg));
    //EXPECT_STREQ("", replyMsg->GetErrorName());
    //EXPECT_EQ(ER_FAIL, (QStatus)replyMsg->GetArg(1)->v_uint16);

    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.SetProperty(interfaceName.c_str(), "Prop1", prop1Arg));

    // Property should be unchanged.
    EXPECT_EQ(42, TCBus.ReadSecProp1());

    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.GetProperty(interfaceName.c_str(), "Prop1", prop1Arg));

    TCBus.signalReceivedFlag = FALSE;

    MsgArg signalArg("s", CHIRP_STRING);
    EXPECT_EQ(ER_PERMISSION_DENIED, SCBusObject.Signal(TCBus.GetUniqueName().c_str(),
                                        sessionId,
                                        *SCBus.GetInterface(interfaceName.c_str())->GetMember("Chirp"),
                                        &signalArg, 1));
}

/*
 * purpose:
 * Interaction between unclaimed app and claimed app: Security 1.0 peer must be
 * able to send/receive messages to/from Security 2.0 peer in a trusted manner,
 * Security 2.0 peer has an ACL with FROM_CERTIFICATE_AUTHORITY peer type.
 *
 * (Security 1.0 peer is an unclaimed application.)
 * The DUT is Security 1.0 peer.
 *
 * Setup:
 * Security 2.0 peer is Claimed and has the following policy installed:
 * ACL: WITH_CERTIFICATE_AUTHORITY, Public key: CA public key
 * Rule:  Object path: *, Interface Name: *, Member Name: *,  Action: PROVIDE|MODIFY|OBSERVE
 *
 * Peers establish an ECDHE_NULL based session.
 * Security 1.0 peer makes a method call, get property call and set property call on Security 2.0 peer.
 * Security 1.0 peer sends a signal to Security 2.0 peer.
 * Security 2.0 peer makes a method call, get property call and set property call on Security 1.0 peer.
 * Security 2.0 peer sends a signal to Security 1.0 peer.
 * Messages cannot be sent or received by Security 2.0 peer.
 *
 * Peers establish an ECDHE_PSK based session.
 * Security 1.0 peer makes a method call, get property call and set property call on Security 2.0 peer.
 * Security 1.0 peer sends a signal to Security 2.0 peer.
 * Security 2.0 peer makes a method call, get property call and set property call on Security 1.0 peer.
 * Security 2.0 peer sends a signal to Security 1.0 peer.
 * Messages cannot be sent or received by Security 2.0 peer.
 *
 * Peers establish an ECDHE_ECDSA based session.
 * Security 1.0 peer makes a method call, get property call and set property call on Security 2.0 peer.
 * Security 1.0 peer sends a signal to Security 2.0 peer.
 * Security 2.0 peer makes a method call, get property call and set property call on Security 1.0 peer.
 * Security 2.0 peer sends a signal to Security 1.0 peer.
 * Authentication between peers should be successful
 * Method calls and signals will not be successful since Security 1.0 peers can not exchange manifest.
 *
 * Verification:
 * Verification as mentioned in the set-up.
 */
TEST_F(SecurityOther2Test, security1_to_security2_over_ECDHE_NULL_acl_peer_FROM_CERTIFICATE_AUTHORITY) {
    InstallFromCertificateAuthorityPolicy();

    TCBus.RegisterObjects(AppObjects2, AppObjects2, true);

    SecurityOtherTestBusObject SCBusObject(SCBus, TEST_OBJ_PATH, interfaceName.c_str());
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject, true));

    //Peers establish an ECDHE_NULL based session.
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL"));
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", &SCAuthListener));
    EXPECT_EQ(ER_OK, TCBus.BindSessionPort(TCSessionPort));

    uint32_t sessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, sessionId));

    // Verify Method call
    const char* s = ECHO_STRING;
    ASSERT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_SEC_ECHO, s));
    EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());

    // Verify Set/Get Property
    EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_SEC_SET_PROP, PRX_SEC_PROP1, 513));
    EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());
    // Property should be unchanged.
    EXPECT_EQ(42, SCBusObject.ReadProp1());
    int32_t prop;
    EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_SEC_GET_PROP, PRX_SEC_PROP1, prop));
    EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());

    // Send/Receive Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver,
                                                  static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler),
                                                  SCBus.GetInterface(interfaceName.c_str())->GetMember("Chirp"),
                                                  NULL));

    EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_SEC_CHIRP, CHIRP_STRING));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < 2000; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_FALSE(chirpSignalReceiver.signalReceivedFlag);
}

/*
 * See SecurityOther2Test.security1_to_security2_over_ECDHE_NULL_acl_peer_FROM_CERTIFICATE_AUTHORITY
 * for full test description.
 */
TEST_F(SecurityOther2Test, security2_to_security1_over_ECDHE_NULL_acl_peer_FROM_CERTIFICATE_AUTHORITY) {
    InstallFromCertificateAuthorityPolicy();

    TCBus.RegisterObjects(AppObjects2, AppObjects2, true);

    SecurityOtherTestBusObject SCBusObject(SCBus, TEST_OBJ_PATH, interfaceName.c_str());
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject, true));

    //Peers establish an ECDHE_NULL based session.
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL"));
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_NULL", &SCAuthListener));
    EXPECT_EQ(ER_OK, TCBus.BindSessionPort(TCSessionPort));

    uint32_t sessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts1));

    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), TEST_OBJ_PATH, sessionId);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName.c_str())) << interface.c_str() << "\n";
    MsgArg arg("s", ECHO_STRING);
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.MethodCall(interfaceName.c_str(), "Echo", &arg, static_cast<size_t>(1), replyMsg));


    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.SetProperty(interfaceName.c_str(), "Prop1", prop1Arg));

    // Property should be unchanged.
    EXPECT_EQ(42, TCBus.ReadSecProp1());

    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.GetProperty(interfaceName.c_str(), "Prop1", prop1Arg));

    int32_t prop1;
    prop1Arg.Get("i", &prop1);
    EXPECT_EQ(513, prop1);

    TCBus.signalReceivedFlag = FALSE;

    MsgArg signalArg("s", CHIRP_STRING);
    EXPECT_EQ(ER_PERMISSION_DENIED, SCBusObject.Signal(TCBus.GetUniqueName().c_str(),
                                        sessionId,
                                        *SCBus.GetInterface(interfaceName.c_str())->GetMember("Chirp"),
                                        &signalArg, 1));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    // for (int msec = 0; msec < 2000; msec += WAIT_MSECS) {
    //     if (chirpSignalReceiver.signalReceivedFlag) {
    //         break;
    //     }
    //     qcc::Sleep(WAIT_MSECS);
    // }
    // EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag);
}

/*
 * See SecurityOther2Test.security1_to_security2_over_ECDHE_NULL_acl_peer_FROM_CERTIFICATE_AUTHORITY
 * for full test description.
 */
TEST_F(SecurityOther2Test, security1_to_security2_over_ECDHE_PSK_acl_peer_FROM_CERTIFICATE_AUTHORITY) {
    InstallFromCertificateAuthorityPolicy();
    TCBus.RegisterObjects(AppObjects2, AppObjects2, true);

    SecurityOtherTestBusObject SCBusObject(SCBus, TEST_OBJ_PATH, interfaceName.c_str());
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject, true));

    //Peers establish an ECDHE_PSK based session.
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_PSK", &SCAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_PSK"));
    EXPECT_EQ(ER_OK, TCBus.BindSessionPort(TCSessionPort));

    uint32_t sessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, sessionId));

    // Verify Method call
    const char* s = ECHO_STRING;
    ASSERT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_SEC_ECHO, s));
    EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());

    // Verify Set/Get Property
    EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_SEC_SET_PROP, PRX_SEC_PROP1, 513));
    EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());
    EXPECT_EQ(42, SCBusObject.ReadProp1());
    int32_t prop;
    EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_SEC_GET_PROP, PRX_SEC_PROP1, prop));
    EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());

    // Send/Receive Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver,
                                                 static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler),
                                                 SCBus.GetInterface(interfaceName.c_str())->GetMember("Chirp"),
                                                 NULL));

    EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_SEC_CHIRP, CHIRP_STRING));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < 2000; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_FALSE(chirpSignalReceiver.signalReceivedFlag);
}

/*
 * See SecurityOther2Test.security1_to_security2_over_ECDHE_NULL_acl_peer_FROM_CERTIFICATE_AUTHORITY
 * for full test description.
 */
TEST_F(SecurityOther2Test, security2_to_security1_over_ECDHE_PSK_acl_peer_FROM_CERTIFICATE_AUTHORITY) {
    InstallFromCertificateAuthorityPolicy();

    TCBus.RegisterObjects(AppObjects2, AppObjects2, true);

    SecurityOtherTestBusObject SCBusObject(SCBus, TEST_OBJ_PATH, interfaceName.c_str());
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject, true));

    //Peers establish an ECDHE_NULL based session.
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_PSK"));
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_PSK", &SCAuthListener));
    EXPECT_EQ(ER_OK, TCBus.BindSessionPort(TCSessionPort));

    uint32_t sessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts1));

    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), TEST_OBJ_PATH, sessionId);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName.c_str())) << interface.c_str() << "\n";
    MsgArg arg("s", ECHO_STRING);
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.MethodCall(interfaceName.c_str(), "Echo", &arg, static_cast<size_t>(1), replyMsg));


    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.SetProperty(interfaceName.c_str(), "Prop1", prop1Arg));

    // Property should be unchanged.
    EXPECT_EQ(42, TCBus.ReadSecProp1());

    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.GetProperty(interfaceName.c_str(), "Prop1", prop1Arg));

    int32_t prop1;
    prop1Arg.Get("i", &prop1);
    EXPECT_EQ(513, prop1);

    TCBus.signalReceivedFlag = FALSE;

    MsgArg signalArg("s", CHIRP_STRING);
    EXPECT_EQ(ER_PERMISSION_DENIED, SCBusObject.Signal(TCBus.GetUniqueName().c_str(),
                                        sessionId,
                                        *SCBus.GetInterface(interfaceName.c_str())->GetMember("Chirp"),
                                        &signalArg, 1));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    // for (int msec = 0; msec < 2000; msec += WAIT_MSECS) {
    //     if (chirpSignalReceiver.signalReceivedFlag) {
    //         break;
    //     }
    //     qcc::Sleep(WAIT_MSECS);
    // }
    // EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag);
}

/*
 * See SecurityOther2Test.security1_to_security2_over_ECDHE_NULL_acl_peer_FROM_CERTIFICATE_AUTHORITY
 * for full test description.
 */
TEST_F(SecurityOther2Test, security1_to_security2_over_ECDHE_ECDSA_acl_peer_FROM_CERTIFICATE_AUTHORITY) {
    InstallFromCertificateAuthorityPolicy();
    TCBus.RegisterObjects(AppObjects2, AppObjects2, true);

    SecurityOtherTestBusObject SCBusObject(SCBus, TEST_OBJ_PATH, interfaceName.c_str());
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject, true));

    //Peers establish an ECDHE_ECDSA based session.
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
    EXPECT_EQ(ER_OK, TCBus.BindSessionPort(TCSessionPort));

    uint32_t sessionId;
    EXPECT_EQ(ER_OK, TCBus.JoinSession(SCBus.GetUniqueName().c_str(), SCSessionPort, sessionId));

    // Verify Method call
    const char* s = ECHO_STRING;
    ASSERT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, TCBus.MethodCall(SCBus.GetUniqueName().c_str(), PRX_SEC_ECHO, s));
    EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());

    // Verify Set/Get Property
    EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, TCBus.SetProperty(SCBus.GetUniqueName().c_str(), PRX_SEC_SET_PROP, PRX_SEC_PROP1, 513));
    EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());
    EXPECT_EQ(42, SCBusObject.ReadProp1());
    int32_t prop;
    EXPECT_EQ(ER_BUS_REPLY_IS_ERROR_MESSAGE, TCBus.GetProperty(SCBus.GetUniqueName().c_str(), PRX_SEC_GET_PROP, PRX_SEC_PROP1, prop));
    EXPECT_STREQ("org.alljoyn.Bus.Security.Error.PermissionDenied", TCBus.GetErrorName());

    // Send/Receive Signal
    ChirpSignalReceiver chirpSignalReceiver;
    EXPECT_EQ(ER_OK, SCBus.RegisterSignalHandler(&chirpSignalReceiver,
                                                 static_cast<MessageReceiver::SignalHandler>(&ChirpSignalReceiver::ChirpSignalHandler),
                                                 SCBus.GetInterface(interfaceName.c_str())->GetMember("Chirp"),
                                                 NULL));

    EXPECT_EQ(ER_OK, TCBus.Signal(SCBus.GetUniqueName().c_str(), PRX_SEC_CHIRP, CHIRP_STRING));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    for (int msec = 0; msec < 2000; msec += WAIT_MSECS) {
        if (chirpSignalReceiver.signalReceivedFlag) {
            break;
        }
        qcc::Sleep(WAIT_MSECS);
    }
    EXPECT_FALSE(chirpSignalReceiver.signalReceivedFlag);
}

/*
 * See SecurityOther2Test.security1_to_security2_over_ECDHE_NULL_acl_peer_FROM_CERTIFICATE_AUTHORITY
 * for full test description.
 */
TEST_F(SecurityOther2Test, security2_to_security1_over_ECDHE_ECDSA_acl_peer_FROM_CERTIFICATE_AUTHORITY) {
    InstallFromCertificateAuthorityPolicy();

    TCBus.RegisterObjects(AppObjects2, AppObjects2, true);

    SecurityOtherTestBusObject SCBusObject(SCBus, TEST_OBJ_PATH, interfaceName.c_str());
    EXPECT_EQ(ER_OK, SCBus.RegisterBusObject(SCBusObject, true));

    //Peers establish an ECDHE_NULL based session.
    EXPECT_EQ(ER_OK, TCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA"));
    EXPECT_EQ(ER_OK, SCBus.EnablePeerSecurity("ALLJOYN_ECDHE_ECDSA", &SCAuthListener));
    EXPECT_EQ(ER_OK, TCBus.BindSessionPort(TCSessionPort));

    uint32_t sessionId;
    EXPECT_EQ(ER_OK, SCBus.JoinSession(TCBus.GetUniqueName().c_str(), TCSessionPort, NULL, sessionId, opts1));

    ProxyBusObject proxy(SCBus, TCBus.GetUniqueName().c_str(), TEST_OBJ_PATH, sessionId);
    EXPECT_EQ(ER_OK, proxy.ParseXml(interface.c_str()));
    EXPECT_TRUE(proxy.ImplementsInterface(interfaceName.c_str())) << interface.c_str() << "\n";
    MsgArg arg("s", ECHO_STRING);
    Message replyMsg(SCBus);
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.MethodCall(interfaceName.c_str(), "Echo", &arg, static_cast<size_t>(1), replyMsg));


    MsgArg prop1Arg;
    EXPECT_EQ(ER_OK, prop1Arg.Set("i", 513));
    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.SetProperty(interfaceName.c_str(), "Prop1", prop1Arg));

    // Property should be unchanged.
    EXPECT_EQ(42, TCBus.ReadSecProp1());

    EXPECT_EQ(ER_PERMISSION_DENIED, proxy.GetProperty(interfaceName.c_str(), "Prop1", prop1Arg));

    int32_t prop1;
    prop1Arg.Get("i", &prop1);
    EXPECT_EQ(513, prop1);

    TCBus.signalReceivedFlag = FALSE;

    MsgArg signalArg("s", CHIRP_STRING);
    EXPECT_EQ(ER_PERMISSION_DENIED, SCBusObject.Signal(TCBus.GetUniqueName().c_str(),
                                        sessionId,
                                        *SCBus.GetInterface(interfaceName.c_str())->GetMember("Chirp"),
                                        &signalArg, 1));

    //Wait for a maximum of 2 sec for the Chirp Signal.
    // for (int msec = 0; msec < 2000; msec += WAIT_MSECS) {
    //     if (chirpSignalReceiver.signalReceivedFlag) {
    //         break;
    //     }
    //     qcc::Sleep(WAIT_MSECS);
    // }
    // EXPECT_TRUE(chirpSignalReceiver.signalReceivedFlag);
}