/**
 * @file

   signal
   join
   advertise
   canceladvertise
   exit
   requestname
   releasename
   bind
   unbind
   hasowner
   leave
   find
   cancelfind
   enablenoc
   disablenoc
   joinasync
   methodasync
   methodsync
   createproxybusobject
   destroyproxybusobject

   addmatch
   removematch

 * Sample implementation of an AllJoyn service.
 * It has one interface :- "org.alljoyn.signals.Interface"
 * It emits two signals :- "my_signal1" and "my_signal2"
 * exit
   & signal

 *  ./bbtest -n com.cool
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
#include <qcc/Environ.h>
#include <qcc/Mutex.h>
#include <qcc/String.h>
#include <qcc/Thread.h>
#include <qcc/time.h>
#include <qcc/GUID.h>
#include <qcc/Util.h>
#include <qcc/StringUtil.h>

#include <alljoyn/BusAttachment.h>
#include <alljoyn/Init.h>
#include <alljoyn/BusObject.h>
#include <alljoyn/DBusStd.h>
#include <alljoyn/AllJoynStd.h>
#include <alljoyn/MsgArg.h>
#include <alljoyn/version.h>

#include <Status.h>


#define QCC_MODULE "BBTEST PROGRAM"

using namespace std;
using namespace qcc;
using namespace ajn;

namespace org {
namespace alljoyn {
namespace alljoyn_test {
const char* InterfaceName1 = "org.alljoyn.Interface";
const char* DefaultWellKnownName = "org.alljoyn.signals";
const char* ObjectPath = "/bbtest";
}
}
}

/** Static top level message bus object */
static BusAttachment* g_msgBus = NULL;
static String g_wellKnownName = ::org::alljoyn::alljoyn_test::DefaultWellKnownName;
static Mutex passwordLock;
static bool maskNOC = true;


/* Predefined session ports. */
SessionPort SESSION_PORT_MESSAGES_PP1 = 23;
SessionPort SESSION_PORT_MESSAGES_PP2 = 24;
SessionPort SESSION_PORT_MESSAGES_PP3 = 25;
SessionPort SESSION_PORT_MESSAGES_MP1 = 26;
SessionPort SESSION_PORT_MESSAGES_MP2 = 27;
SessionPort SESSION_PORT_MESSAGES_MP3 = 28;
SessionPort SESSION_PORT_RAW_PP1      = 29;
SessionPort SESSION_PORT_RAW_PP2      = 30;
SessionPort SESSION_PORT_RAW_PP3      = 31;

/* Fetch data from console */
char* get_data(char*inpbuf)
{
    char*p = NULL;
    fd_set rfds;
    struct timeval tv;
    int retval;

    FD_ZERO(&rfds);
    FD_SET(0, &rfds);
    //wait for 1 sec
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    retval = select(1, &rfds, NULL, NULL, &tv);
    if (retval) {
        p = fgets(inpbuf, 512, stdin);
        inpbuf[strlen(inpbuf) - 1] = '\0';
        FD_CLR(0, &rfds);
        return p;
    }

    FD_CLR(0, &rfds);

    return p;

}

static volatile bool g_interrupt = false;
/** Signal handler */
static void CDECL_CALL SigIntHandler(int sig)
{
    QCC_UNUSED(sig);
    g_interrupt = true;
}

/* Call back for Async Method Calls */
class MyMessageReceiver : public MessageReceiver {
  public:
    void MyResponseHandler(Message& message, void* context)
    {
        QCC_UNUSED(context);
        if (message->GetType() == MESSAGE_METHOD_RET) {
            QCC_SyncPrintf("Method Call successfull. \n");
            fflush(stdout);
        } else {
            // must be an error
            qcc::String errMsg;
            const char* errName = message->GetErrorName(&errMsg);
            QCC_SyncPrintf("Method call returned error %s: %s\n", errName, errMsg.c_str()); \
            fflush(stdout);
        }
    }
};

class MyAuthListener : public AuthListener {
  public:

    MyAuthListener() : AuthListener() { }

  private:

    bool RequestCredentials(const char* authMechanism, const char* authPeer, uint16_t authCount, const char* userId, uint16_t credMask, Credentials& creds) {
        QCC_UNUSED(userId);

        printf("Started authentication process for peer  [%s]\n", authPeer);
        if (authCount > 1) { return false; }

        if (strcmp(authMechanism, "ALLJOYN_SRP_KEYX") == 0) {
            if (credMask & AuthListener::CRED_PASSWORD) {
                passwordLock.Lock();
                printf("Enter password :");
                fflush(stdout);
                char pwd[10];
                if (scanf("%s", pwd) != 1) {
                    printf("Expect string for password \n");
                    fflush(stdout);
                    return false;
                }
                creds.SetPassword(pwd);
                printf("AuthListener returning fixed pin \"%s\" for %s\n", creds.GetPassword().c_str(), authMechanism);
                fflush(stdout);
                passwordLock.Unlock();
            }
            return true;
        }

        if (strcmp(authMechanism, "ALLJOYN_SRP_LOGON") == 0) {
            passwordLock.Lock();
            if (credMask & AuthListener::CRED_USER_NAME) {
                printf("Enter username :");
                fflush(stdout);
                char username[20];
                if (scanf("%s", username) != 1) {
                    printf("Expect string for username \n");
                    fflush(stdout);
                    return false;
                }
                creds.SetUserName(username);
            }
            if (credMask & AuthListener::CRED_PASSWORD) {
                printf("Enter password :");
                fflush(stdout);
                char password[20];
                if (scanf("%s", password) != 1) {
                    printf("Expect string for password \n");
                    fflush(stdout);
                    return false;
                }
                creds.SetPassword(password);
            }
            passwordLock.Unlock();
            return true;
        }
        return false;
    }

    bool VerifyCredentials(const char* authMechanism, const char* authPeer, const Credentials& creds) {
        QCC_UNUSED(authMechanism);
        QCC_UNUSED(authPeer);
        QCC_UNUSED(creds);
        return false;
    }

    void AuthenticationComplete(const char* authMechanism, const char* authPeer, bool success) {
        QCC_UNUSED(authPeer);
        printf("Authentication %s %s\n", authMechanism, success ? "succesful" : "failed");
        fflush(stdout);
    }

    void SecurityViolation(const char* error) {
        printf("Security violation %s\n", error);
        fflush(stdout);
    }

};
static MyAuthListener myAuthListener1;

class MyBusListener : public BusListener {

  public:
    MyBusListener() : BusListener() { }

    void ListenerRegistered(BusAttachment* bus) {
        QCC_UNUSED(bus);
        printf("BusListener registered  %p", this);
        fflush(stdout);
    }

    void ListenerUnregistered() {
        printf("BusListener unregistered %p", this);
        fflush(stdout);
    }

    void BusStopping() {
        printf("From bus Listener - Bus is stopping. \n");
        fflush(stdout);
    }

    void BusDisconnected() {
        printf("From bus Listener - Bus is disconnected. \n");
        fflush(stdout);
    }

    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix) {
        printf("FoundAdvertisedName(name=%s, transport=0x%x, prefix=%s)\n", name, transport, namePrefix);
        fflush(stdout);
    }

    void LostAdvertisedName(const char* name, TransportMask transport, const char* prefix) {
        printf("LostAdvertisedName(name=%s, transport=0x%x,  prefix=%s)\n", name, transport, prefix);
        fflush(stdout);
    }

    void NameOwnerChanged(const char* name, const char* previousOwner, const char* newOwner) {
        if (!maskNOC) {
            printf("NameOwnerChanged(%s, %s, %s)\n", name,
                   previousOwner ? previousOwner : "null",
                   newOwner ? newOwner : "null");
            fflush(stdout);
        }
    }

};
static MyBusListener myBusListener1;

class MySessionPortListener : public SessionPortListener {

    bool AcceptSessionJoiner(SessionPort sessionPort, const char* joiner, const SessionOpts& opts) {
        QCC_UNUSED(sessionPort);
        QCC_UNUSED(joiner);
        QCC_UNUSED(opts);
        return true;
    }

    void SessionJoined(SessionPort sessionPort, SessionId sessionId, const char* joiner) {
        QCC_UNUSED(sessionPort);
        printf("Session Established: joiner=%s, sessionId=%u\n", joiner, sessionId);
        fflush(stdout);
    }

};
static MySessionPortListener mySessionPortListener1;



class MySessionPortListenerWithPrompt : public SessionPortListener {

    bool AcceptSessionJoiner(SessionPort sessionPort, const char* joiner, const SessionOpts& opts) {
        QCC_UNUSED(sessionPort);
        QCC_UNUSED(opts);
        g_msgBus->EnableConcurrentCallbacks();
        printf("Joiner  [%s] wants to join on %d transport: y/n ?  ", joiner, opts.transports);
        fflush(stdout);
        char option;
        if (scanf("%c", &option) != 1) {
            printf("Expect y/n for answer \n");
            fflush(stdout);
            return false;
        }
        getchar();
        if (option == 'y') { return true; }
        return false;
    }

    void SessionJoined(SessionPort sessionPort, SessionId sessionId, const char* joiner)
    {
        QCC_UNUSED(sessionPort);
        printf("Session Established: joiner=%s, sessionId=%u\n", joiner, sessionId);
        fflush(stdout);
    }

};
static MySessionPortListenerWithPrompt mySessionPortListenerWithPrompt;



class MySessionListener : public SessionListener {

    void SessionLost(SessionId sessid, SessionListener::SessionLostReason reason)
    {
        QCC_UNUSED(reason);
        QCC_SyncPrintf("Session Lost  %u \n", sessid);
    }

    void SessionMemberAdded(SessionId sessionId, const char* uniqueName) {
        QCC_SyncPrintf("Member(%s) JOINED in %u \n", uniqueName, sessionId);
    }

    void SessionMemberRemoved(SessionId sessionId, const char* uniqueName) {
        QCC_SyncPrintf("Member(%s) LEFT from %u \n", uniqueName, sessionId);
    }
};
static MySessionListener mySessionListener1;

class JoinCB : public BusAttachment::JoinSessionAsyncCB {
  public:
    void JoinSessionCB(QStatus status, SessionId id, const SessionOpts& opts, void* context)
    {
        QCC_UNUSED(opts);
        QCC_UNUSED(context);

        if (ER_OK != status) {
            QCC_LogError(status, ("JoinSessionCB(%s) failed ", (char*)context));
            fflush(stdout);
        } else {
            printf("JoinedSessionCB with session id  %u \n", id);
            fflush(stdout);
        }

    }
};


class LocalTestObject : public BusObject {

  public:

    LocalTestObject(BusAttachment& bus, const char* path)
        : BusObject(path),
        my_signal_member1(NULL),
        my_signal_member2(NULL),
        my_signal_member3(NULL),
        bus(bus)
    {
        /* Add the test interface to this object */
        const InterfaceDescription* regTestIntf = bus.GetInterface(::org::alljoyn::alljoyn_test::InterfaceName1);
        assert(regTestIntf);
        AddInterface(*regTestIntf);

        my_signal_member1 = regTestIntf->GetMember("my_signal1");
        assert(my_signal_member1);
        my_signal_member2 =  regTestIntf->GetMember("my_signal2");
        assert(my_signal_member2);
        my_signal_member3 =  regTestIntf->GetMember("my_signal3");
        assert(my_signal_member3);

        const MethodEntry methodEntries[] = {
            { regTestIntf->GetMember("authinit"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::AuthInit) }
        };
        QStatus status = AddMethodHandlers(methodEntries, ArraySize(methodEntries));

        if (ER_OK != status) {
            QCC_LogError(status, ("Failed to register method handlers for LocalTestObject"));
        }

    }

    void ObjectRegistered(void)
    {
        BusObject::ObjectRegistered();
        QCC_SyncPrintf("Object Registered \n");
    }

    void AuthInit(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);

        /* Reply with same string that was sent to us */
        MsgArg arg(*(msg->GetArg(0)));
        QCC_SyncPrintf("Pinged with: %s\n", msg->GetArg(0)->ToString().c_str());
        if (msg->IsEncrypted()) {
            QCC_SyncPrintf("Authenticated using %s\n", msg->GetAuthMechanism().c_str());
        }
        QStatus status = MethodReply(msg, &arg, 1);
        if (ER_OK != status) {
            QCC_LogError(status, ("Ping: Error sending reply"));
        }
    }


    QStatus EmitSignal()
    {
        QStatus status = ER_OK;

        char tempDest[20];
        char tempflags[20];
        char option[2];

        SessionId sessionid, tsessionid = 0;
        char*dest = NULL;
        uint8_t flags = 0, tflags = 0;
        uint16_t ttl = 0;

        printf("Enter the session id: ");
        fflush(stdout);
        if (scanf("%u", &sessionid) != 1) {
            status = ER_FAIL;
            printf("Expect integer for sessionId\n");
            fflush(stdout);
            return status;
        }
        tsessionid = sessionid;
        getchar();

        printf("Done ? else press 'm' [enter]: ");
        fflush(stdout);

        while (get_data(option) == NULL);

        if (option[0] == 'm') {
            printf("Enter the destination id [NULL] :");
            fflush(stdout);
            while (get_data(tempDest) == NULL);
            if (tempDest[0] != '\0') { dest = tempDest; }

            printf("Enter flags - encryption (E), sessionless (S), broadcast (G): ESG [0] :");
            fflush(stdout);
            while (get_data(tempflags) == NULL);
            if (tempflags[0] != '\0') {
                String tstr(tempflags);
                size_t temp = tstr.find_first_of("E");
                if (temp != String::npos) { flags |= ALLJOYN_FLAG_ENCRYPTED; }
                temp = tstr.find_first_of("S");
                if (temp != String::npos) { flags |= ALLJOYN_FLAG_SESSIONLESS; }
                temp = tstr.find_first_of("G");
                if (temp != String::npos) { flags |= ALLJOYN_FLAG_GLOBAL_BROADCAST; }
            }
            printf("Done ? else press 'm' [enter]: ");
            fflush(stdout);
            while (get_data(option) == NULL);

            tflags = flags;

            if (option[0] == 'm') {
                printf("Enter the ttl [0] :");
                fflush(stdout);
                if (scanf("%hu", &ttl) != 1) {
                    status = ER_FAIL;
                    printf("Expect integer for ttl\n");
                    fflush(stdout);
                    return status;
                }
                getchar();
            }
        }

        printf("\nSignal params: \nSession id=%u\nDestination=%s\nflags=%c %c %c \nttl=%u \n", tsessionid, dest,
               (tflags & ALLJOYN_FLAG_ENCRYPTED)  ? 'E' : '.',
               (tflags & ALLJOYN_FLAG_SESSIONLESS) ? 'S' : '.',
               (tflags & ALLJOYN_FLAG_GLOBAL_BROADCAST) ? 'G' : '.', ttl);
        fflush(stdout);

        MsgArg arg;
        arg.Set("s", "Hello");

        /* Emitting Interface1.Signal1 */
        status = Signal(dest, tsessionid, *my_signal_member1, &arg, 1, ttl, tflags);
        if (ER_OK != status) {
            QCC_LogError(status, ("Ping: Error sending Interface.my_signal1"));
        }

        /* Emitting Interface.signal2 */
        status = Signal(dest, tsessionid, *my_signal_member2, &arg, 1, ttl, tflags);
        if (ER_OK != status) {
            QCC_LogError(status, ("Ping: Error sending Interface.my_signal2"));
        }

        /* Emitting Interface.signal3 */
        status = Signal(dest, tsessionid, *my_signal_member3, &arg, 1, ttl, tflags);
        if (ER_OK != status) {
            QCC_LogError(status, ("Ping: Error sending Interface.my_signal3"));
        }

        return status;
    }

    /* Most Probably you wont need it */
    QStatus IntrospectObject(SessionId sessionid) {
        QStatus status = ER_OK;
        char t_path[50]; printf("\n Enter the path ");
        if (scanf("%s", t_path) != 1) {
            status = ER_FAIL;
            printf("Expect string for object path\n");
            fflush(stdout);
            return status;
        }
        char t_name[50]; printf("\n Enter the name ");
        if (scanf("%s", t_name) != 1) {
            status = ER_FAIL;
            printf("Expect string for name\n");
            fflush(stdout);
            return status;
        }

        ProxyBusObject remoteObj = ProxyBusObject(bus, t_name, t_path, sessionid);
        status = remoteObj.IntrospectRemoteObject();
        if (ER_OK != status) {
            QCC_LogError(status, ("Introspection of %s (path=%s) failed\n", g_wellKnownName.c_str(), ::org::alljoyn::alljoyn_test::ObjectPath));
        }
        return status;
    }


    QStatus SubscribeNameChangedSignal(void) {


        QStatus status;
        const InterfaceDescription* intf = bus.GetInterface(::org::alljoyn::alljoyn_test::InterfaceName1);
        assert(intf);
        const InterfaceDescription::Member* mysignal1  = intf->GetMember("my_signal1");
        assert("mysignal1");

        const InterfaceDescription::Member* mysignal2  = intf->GetMember("my_signal2");
        assert("mysignal2");

        const InterfaceDescription::Member* mysignal3  = intf->GetMember("my_signal3");
        assert("mysignal3");

        /* register the signal handler for Interface.my_signal1 */
        status =  bus.RegisterSignalHandler(this,
                                            static_cast<MessageReceiver::SignalHandler>(&LocalTestObject::SignalHandler1),
                                            mysignal1,
                                            NULL);
        if (status != ER_OK) {
            printf("Failed to register signal handler for mysignal1");
        }

        /* register the signal handler for Interface.my_signal1 */
        status =  bus.RegisterSignalHandler(this,
                                            static_cast<MessageReceiver::SignalHandler>(&LocalTestObject::SignalHandler12),
                                            mysignal1,
                                            NULL);
        if (status != ER_OK) {
            printf("Failed to register signal handler12 for mysignal1");
        }


        /* register the signal handler for Interface.my_signal1 */
        status =  bus.RegisterSignalHandler(this,
                                            static_cast<MessageReceiver::SignalHandler>(&LocalTestObject::SignalHandler13),
                                            mysignal1,
                                            NULL);
        if (status != ER_OK) {
            printf("Failed to register signal handler13 for mysignal1");
        }

        /* register the signal handler for Interface.my_signal2 */
        status =  bus.RegisterSignalHandler(this,
                                            static_cast<MessageReceiver::SignalHandler>(&LocalTestObject::SignalHandler2),
                                            mysignal2,
                                            NULL);
        if (status != ER_OK) {
            printf("Failed to register signal handler for mysignal2");
        }

        /* register the signal handler 3 for signal3 */
        status =  bus.RegisterSignalHandler(this,
                                            static_cast<MessageReceiver::SignalHandler>(&LocalTestObject::SignalHandler3),
                                            mysignal3,
                                            NULL);
        if (status != ER_OK) {
            printf("Failed to register signal handler for mysignal3");
        }



        return status;

    }

    QStatus UnRegisterSignalHandlers() {

        /* register the signal handler for Interface.my_signal1 */
        QStatus status =  bus.UnregisterSignalHandler(this,
                                                      static_cast<MessageReceiver::SignalHandler>(&LocalTestObject::SignalHandler12),
                                                      my_signal_member1,
                                                      NULL);
        if (status != ER_OK) {
            printf("Failed to register signal handler12 for mysignal1");
        }
        return status;
    }

    QStatus AddMatchRule(void) {
        /* add the match rules */
        QStatus status = ER_OK;
        status = bus.AddMatch("type='signal',interface='org.alljoyn.Interface',member='my_signal1'");
        if (status != ER_OK) {
            QCC_LogError(status, ("Failed to register Match rule for 'org.alljoyn.signals.Interface.my_signal1'\n"));
        }

        status = bus.AddMatch("type='signal',interface='org.alljoyn.Interface',member='my_signal2'");
        if (status != ER_OK) {
            QCC_LogError(status, ("Failed to register Match rule for 'org.alljoyn.signals.Interface.my_signal2'\n"));
        }

        status = bus.AddMatch("type='signal',interface='org.alljoyn.Interface',member='my_signal3'");
        if (status != ER_OK) {
            QCC_LogError(status, ("Failed to register Match rule for 'org.alljoyn.signals.Interface.my_signal3'\n"));
        }

        return status;
    }


    void SignalHandler1(const InterfaceDescription::Member*member,
                        const char* sourcePath,
                        Message& msg)
    {
        QCC_UNUSED(member);
        QCC_UNUSED(sourcePath);
        printf("[SIGNAL1] ++==## signalConsumer: Signal Received [%s] - \"%s\" session id  is [%u] ##==--\n", msg->GetInterface(), msg->GetArg(0)->v_string.str, msg->GetSessionId());
    }

    void SignalHandler2(const InterfaceDescription::Member*member,
                        const char* sourcePath,
                        Message& msg)
    {
        QCC_UNUSED(member);
        QCC_UNUSED(sourcePath);
        printf("[SIGNAL2] ++==## signalConsumer: Signal Received [%s] - \"%s\" session id is [%u] ##==--\n", msg->GetInterface(), msg->GetArg(0)->v_string.str, msg->GetSessionId());
    }

    void SignalHandler3(const InterfaceDescription::Member*member,
                        const char* sourcePath,
                        Message& msg)
    {
        QCC_UNUSED(member);
        QCC_UNUSED(sourcePath);
        printf("[SIGNAL3] ++==## signalConsumer: Signal Received [%s] - \"%s\" session id is [%u] ##==--\n", msg->GetInterface(), msg->GetArg(0)->v_string.str, msg->GetSessionId());
    }


    void SignalHandler12(const InterfaceDescription::Member*member,
                         const char* sourcePath,
                         Message& msg)
    {
        QCC_UNUSED(member);
        QCC_UNUSED(sourcePath);
        printf("[SIGNAL12] ++==## signalConsumer: Signal Received [%s] - \"%s\" session id  is [%u] ##==--\n", msg->GetInterface(), msg->GetArg(0)->v_string.str, msg->GetSessionId());
    }
    void SignalHandler13(const InterfaceDescription::Member*member,
                         const char* sourcePath,
                         Message& msg)
    {
        QCC_UNUSED(member);
        QCC_UNUSED(sourcePath);
        printf("[SIGNAL13] ++==## signalConsumer: Signal Received [%s] - \"%s\" session id  is [%u] ##==--\n", msg->GetInterface(), msg->GetArg(0)->v_string.str, msg->GetSessionId());
    }


    const InterfaceDescription::Member* my_signal_member1;
    const InterfaceDescription::Member* my_signal_member2;
    const InterfaceDescription::Member* my_signal_member3;
    BusAttachment& bus;
};

QStatus  CreateSession(SessionPort sessport, SessionOpts& options)
{
    /* Create a session for incoming client connections */
    QStatus status = ER_OK;
    if ((sessport == 25) || (sessport == 28) || (sessport == 31)) {
        status = g_msgBus->BindSessionPort(sessport, options, mySessionPortListenerWithPrompt);
    } else {
        status = g_msgBus->BindSessionPort(sessport, options, mySessionPortListener1);
    }
    if (status != ER_OK) {
        QCC_LogError(status, ("BindSessionPort failed for [%u]", sessport));
    }
    return status;
}

static void usage(void)
{
    printf("Usage: bbtest \n\n");
    printf("Options:\n");
    printf("   -h         = Print this help message\n");
    printf("   -n <name>  = Well-known name to advertise\n");
}

int TestAppMain(int argc, char** argv)
{
    QStatus status = ER_OK;
    MyMessageReceiver msgReceiver;
    ProxyBusObject*proxyBusObject = NULL;

    /* Install SIGINT handler */
    signal(SIGINT, SigIntHandler);

    /* Parse command line args
     * -h usage
     * -n well known name */

    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp("-h", argv[i])) {
            usage();
            exit(0);
        } else if (0 == strcmp("-n", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_wellKnownName = argv[i];
            }
        } else {
            status = ER_FAIL;
            printf("Unknown option %s\n", argv[i]);
            usage();
            exit(1);
        }
    }

    /* Create message bus */
    g_msgBus = new BusAttachment("bbtest", true);

    /* Add org.alljoyn.alljoyn_test interface */
    InterfaceDescription* testIntf = NULL;
    status = g_msgBus->CreateInterface(::org::alljoyn::alljoyn_test::InterfaceName1, testIntf);
    if (ER_OK == status) {
        testIntf->AddMethod("authinit",  "s", "s", "inStr,outStr", 0);
        testIntf->AddSignal("my_signal1", "s", NULL, 0);
        testIntf->AddSignal("my_signal2", "s", NULL, 0);
        testIntf->AddSignal("my_signal3", "s", NULL, 0);
        testIntf->Activate();
    } else {
        QCC_LogError(status, ("Failed to create interface %s", ::org::alljoyn::alljoyn_test::InterfaceName1));
    }


    /* Start the msg bus */
    if (ER_OK == status) {
        status = g_msgBus->Start();
    } else {
        QCC_LogError(status, ("BusAttachment::Start failed"));
    }

    /* Connect to the daemon */
    status = g_msgBus->Connect();
    if (status !=  ER_OK) {
        QCC_LogError(status, ("Bus connect faiiled. "));
        return status;
    }

    g_msgBus->RegisterBusListener(myBusListener1);

    /* Register local objects and connect to the daemon */
    if (ER_OK == status) {
        LocalTestObject testObj(*g_msgBus, ::org::alljoyn::alljoyn_test::ObjectPath);
        g_msgBus->RegisterBusObject(testObj);
        status = testObj.SubscribeNameChangedSignal();
        status = testObj.AddMatchRule();

        /* Create session opts */
        SessionOpts optspp(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
        SessionOpts optsmp(SessionOpts::TRAFFIC_MESSAGES, true,  SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
        SessionOpts optsppr(SessionOpts::TRAFFIC_RAW_RELIABLE, false,  SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);

        /* Create a session for incoming client connections */
        status = CreateSession(SESSION_PORT_MESSAGES_PP1, optspp);
        status = CreateSession(SESSION_PORT_MESSAGES_PP2, optspp);
        status = CreateSession(SESSION_PORT_MESSAGES_PP3, optspp);
        status = CreateSession(SESSION_PORT_MESSAGES_MP1, optsmp);
        status = CreateSession(SESSION_PORT_MESSAGES_MP2, optsmp);
        status = CreateSession(SESSION_PORT_MESSAGES_MP3, optsmp);
        status = CreateSession(SESSION_PORT_RAW_PP1, optsppr);
        status = CreateSession(SESSION_PORT_RAW_PP2, optsppr);
        status = CreateSession(SESSION_PORT_RAW_PP3, optsppr);

        /* Request a well-known name */
        QStatus status = g_msgBus->RequestName(g_wellKnownName.c_str(), DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE);
        if (status != ER_OK) {
            QCC_LogError(status, ("RequestName(%s) failed. ", g_wellKnownName.c_str()));
            return status;
        }

        /* Begin Advertising the well-known name */
        uint16_t trans = 0;
        printf("Which transport: local, tcp, udp, ip ? \n");
        printf("For local- Type 1, tcp- Type 4, udp- Type 256, ip- Type 261, all- 65535 \n");
        cin >> trans;

        getchar();
        status = g_msgBus->AdvertiseName(g_wellKnownName.c_str(), trans);
        if (ER_OK != status) {
            QCC_LogError(status, ("Sending org.alljoyn.Bus.Advertise failed "));
            return status;
        }


        status = ER_OK;

        if (ER_OK == status) {
            char option[512];
            while (1) {

                if (get_data(option) == NULL) {
                    continue;
                }
                char*temp = NULL;
                temp = strtok(option, " ");
                if (!temp) {
                    continue;
                }

// SIGNAL
                if (strcmp(temp, "signal") == 0) {
                    testObj.EmitSignal();
                } else if (strcmp(temp, "exit") == 0) {
//EXIT
                    break;
                } else if (strcmp(temp, "join") == 0) {
//JOINSESSION
                    /* join name port isMultipoint traffic transport noSessionListener*/
                    char joinName[100];
                    SessionPort sessionPort = 0;
                    SessionOpts opts;
                    bool noBusListener = false;
                    QStatus status = ER_OK;

                    opts.isMultipoint = false;
                    opts.traffic = static_cast<SessionOpts::TrafficType>(1);
                    opts.transports = TRANSPORT_ANY;

                    temp = strtok(NULL, " ");
                    if (!temp) {
                        printf("ERROR - join wkn port isMultipoint traffic proximity transport noSessionListener. \n");
                        fflush(stdout);
                        status = ER_FAIL;
                    } else {
                        strcpy(joinName, temp);
                        status = ER_OK;
                    }

                    if (status == ER_OK) {
                        temp = strtok(NULL, " ");
                        if (!temp) {
                            printf("ERROR - join wkn port isMultipoint traffic proximity transport noSessionListener. \n");
                            fflush(stdout);
                            status = ER_FAIL;
                        } else {
                            sessionPort = static_cast<SessionPort>(StringToU32(temp, 0, 0));
                            status = ER_OK;
                        }
                    }

                    if (status == ER_OK) {
                        temp = strtok(NULL, " ");
                        if (temp) {
                            opts.isMultipoint =  (strcmp(temp, "true") == 0) ? true : false;
                        }
                        temp = strtok(NULL, " ");
                        if (temp) {
                            opts.traffic = static_cast<SessionOpts::TrafficType>(StringToU32(temp, 0, 0x1));
                        }
                        temp = strtok(NULL, " ");
                        if (temp) {
                            opts.proximity = static_cast<SessionOpts::Proximity>(StringToU32(temp, 0, 0xFF));
                        }
                        temp = strtok(NULL, " ");
                        if (temp) {
                            opts.transports = static_cast<TransportMask>(StringToU32(temp, 0, TRANSPORT_ANY));
                        }
                        temp = strtok(NULL, " ");
                        if (temp) {
                            noBusListener =  (strcmp(temp, "true") == 0) ? true : false;
                        }
                    }

                    if (status == ER_OK) {
                        SessionId sessionId;
                        if (noBusListener == false) {
                            status = g_msgBus->JoinSession(joinName, sessionPort, &mySessionListener1, sessionId, opts);
                        } else {
                            status = g_msgBus->JoinSession(joinName, sessionPort, NULL, sessionId, opts);
                        }

                        if (ER_OK != status) {
                            QCC_LogError(status, ("JoinSession(%s) failed ", joinName));
                            fflush(stdout);
                        } else {
                            printf("Joined session with session id  %u \n", sessionId);
                            fflush(stdout);
                        }
                    }
                } else if (strcmp(temp, "joinasync") == 0) {
//JOINSESSIONASYNC
                    /* joinasync name port isMultipoint traffic transport noSessionListener*/
                    char joinName[100];
                    SessionPort sessionPort = 0;
                    SessionOpts opts;
                    bool noBusListener = false;
                    QStatus status = ER_OK;

                    opts.isMultipoint = false;
                    opts.traffic = static_cast<SessionOpts::TrafficType>(1);
                    opts.transports = TRANSPORT_ANY;

                    temp = strtok(NULL, " ");
                    if (!temp) {
                        printf("ERROR - joinasync wkn port isMultipoint traffic transport noSessionListener. \n");
                        fflush(stdout);
                        status = ER_FAIL;
                    } else {
                        strcpy(joinName, temp);
                        status = ER_OK;
                    }

                    if (status == ER_OK) {
                        temp = strtok(NULL, " ");
                        if (!temp) {
                            printf("ERROR - joinasync wkn port isMultipoint traffic transport noSessionListener. \n");
                            fflush(stdout);
                            status = ER_FAIL;
                        } else {
                            sessionPort = static_cast<SessionPort>(StringToU32(temp, 0, 0));
                            status = ER_OK;
                        }
                    }

                    if (status == ER_OK) {
                        temp = strtok(NULL, " ");
                        if (temp) {
                            opts.isMultipoint =  (strcmp(temp, "true") == 0) ? true : false;
                        }
                        temp = strtok(NULL, " ");
                        if (temp) {
                            opts.traffic = static_cast<SessionOpts::TrafficType>(StringToU32(temp, 0, 0x1));
                        }
                        temp = strtok(NULL, " ");
                        if (temp) {
                            opts.proximity = static_cast<SessionOpts::Proximity>(StringToU32(temp, 0, 0xFF));
                        }
                        temp = strtok(NULL, " ");
                        if (temp) {
                            opts.transports = static_cast<TransportMask>(StringToU32(temp, 0, TRANSPORT_ANY));
                        }
                        temp = strtok(NULL, " ");
                        if (temp) {
                            noBusListener =  (strcmp(temp, "true") == 0) ? true : false;
                        }
                    }

                    if (status == ER_OK) {
                        JoinCB callback;
                        if (noBusListener == false) {
                            status = g_msgBus->JoinSessionAsync(joinName, sessionPort, &mySessionListener1, opts, &callback, (char*)joinName);
                        } else {
                            status = g_msgBus->JoinSessionAsync(joinName, sessionPort, NULL, opts, &callback, (char*)joinName);
                        }

                        if (ER_OK != status) {
                            QCC_LogError(status, ("JoinSessionAsync(%s) failed ", joinName));
                            fflush(stdout);
                        }
                    }

                } else if (strcmp(temp, "advertise") == 0) {
//ADVERTISE
                    /* advertise name transport */
                    char advertiseName[100];
                    TransportMask transport = 65535;
                    temp = strtok(NULL, " ");
                    if (!temp) {
                        printf("ERROR - advertise name transport \n");
                        fflush(stdout);
                        status = ER_FAIL;
                    } else {
                        strcpy(advertiseName, temp);
                        status = ER_OK;
                    }
                    if (status == ER_OK) {
                        temp = strtok(NULL, " ");
                        if (temp) {
                            transport = static_cast<TransportMask>(StringToU32(temp, 0, 0xFFFF));
                        }
                    }
                    if (status == ER_OK) {
                        status = g_msgBus->AdvertiseName(advertiseName, transport);
                        if (ER_OK != status) {
                            QCC_LogError(status, ("AdvertiseName(%s) failed ", advertiseName));
                            fflush(stdout);
                        }
                    }
                } else if (strcmp(temp, "canceladvertise") == 0) {
//CANCELADVERTISE
                    /* canceladvertise name transport */
                    char canceladvertiseName[100];
                    TransportMask transport = 65535;
                    temp = strtok(NULL, " ");
                    if (!temp) {
                        printf("ERROR - canceladvertise name transport \n");
                        fflush(stdout);
                        status = ER_FAIL;
                    } else {
                        strcpy(canceladvertiseName, temp);
                        status = ER_OK;
                    }
                    if (status == ER_OK) {
                        temp = strtok(NULL, " ");
                        if (temp) {
                            transport = static_cast<TransportMask>(StringToU32(temp, 0, 0xFFFF));
                        }
                    }
                    if (status == ER_OK) {
                        status = g_msgBus->CancelAdvertiseName(canceladvertiseName, transport);
                        if (ER_OK != status) {
                            QCC_LogError(status, ("CancelAdvertiseName(%s) failed ", canceladvertiseName));
                            fflush(stdout);
                        }
                    }
                } else if (strcmp(temp, "requestname") == 0) {
//REQUESTNAME
                    /* requestname name */
                    char requestname[100];
                    temp = strtok(NULL, " ");
                    if (!temp) {
                        printf("ERROR - requestname name \n");
                        fflush(stdout);
                        status = ER_FAIL;
                    } else {
                        strcpy(requestname, temp);
                        status = ER_OK;
                    }
                    if (status == ER_OK) {
                        status = g_msgBus->RequestName(requestname, DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE);
                        if (ER_OK != status) {
                            QCC_LogError(status, ("RequestName(%s) failed ", requestname));
                            fflush(stdout);
                        }
                    }
                } else if (strcmp(temp, "releasename") == 0) {
//RELEASENAME
                    /* releasename name */
                    char releasename[100];
                    temp = strtok(NULL, " ");
                    if (!temp) {
                        printf("ERROR - releasename name \n");
                        fflush(stdout);
                        status = ER_FAIL;
                    } else {
                        strcpy(releasename, temp);
                        status = ER_OK;
                    }
                    if (status == ER_OK) {
                        status = g_msgBus->ReleaseName(releasename);
                        if (ER_OK != status) {
                            QCC_LogError(status, ("ReleaseName(%s) failed ", releasename));
                            fflush(stdout);
                        }
                    }
                } else if (strcmp(temp, "nameonbus") == 0) {
//NAMEHASOWNER
                    /* nameonbus name */
                    bool hasOwner = false;
                    char nametobechecked[50];
                    temp = strtok(NULL, " ");
                    if (!temp) {
                        printf("ERROR - nametobechecked name \n");
                        fflush(stdout);
                        status = ER_FAIL;
                    } else {
                        strcpy(nametobechecked, temp);
                        status = ER_OK;
                    }
                    if (status == ER_OK) {
                        status = g_msgBus->NameHasOwner(nametobechecked, hasOwner);
                        if (ER_OK != status) {
                            QCC_LogError(status, ("NamehasOwner on (%s) failed ", nametobechecked));
                            fflush(stdout);
                        } else if (!hasOwner) {
                            printf("Name[%s] is not on the bus. \n", nametobechecked);
                            fflush(stdout);
                        }
                    }
                } else if (strcmp(temp, "leave") == 0) {
//LEAVESESSION
                    /* leave sessionid */
                    SessionId sessionId = 0;
                    temp = strtok(NULL, " ");
                    if (!temp) {
                        printf("ERROR - leave sessionid \n");
                        fflush(stdout);
                        status = ER_FAIL;
                    } else {
                        sessionId = static_cast<SessionId>(StringToU32(temp, 0, 0));
                        status = ER_OK;
                    }
                    if (status == ER_OK) {
                        status = g_msgBus->LeaveSession(sessionId);
                        if (ER_OK != status) {
                            QCC_LogError(status, ("LeaveSession (%u) failed ", sessionId));
                            fflush(stdout);
                        }
                    }
                } else if (strcmp(temp, "bind") == 0) {
//BINDSESSIONPORT
                    /* bind port isMultipoint traffic transport*/
                    SessionPort sessionPort = 0;
                    SessionOpts opts;
                    status = ER_OK;

                    opts.isMultipoint = false;
                    opts.traffic = static_cast<SessionOpts::TrafficType>(1);
                    opts.transports = TRANSPORT_ANY;

                    temp = strtok(NULL, " ");
                    if (!temp) {
                        printf("ERROR - bind port isMultipoint traffic transport \n");
                        fflush(stdout);
                        status = ER_FAIL;
                    } else {
                        sessionPort = static_cast<SessionPort>(StringToU32(temp, 0, 0));
                        status = ER_OK;
                    }

                    if (status == ER_OK) {
                        temp = strtok(NULL, " ");
                        if (temp) {
                            opts.isMultipoint =  (strcmp(temp, "true") == 0) ? true : false;
                        }
                        temp = strtok(NULL, " ");
                        if (temp) {
                            opts.traffic = static_cast<SessionOpts::TrafficType>(StringToU32(temp, 0, 0x1));
                        }
                        temp = strtok(NULL, " ");
                        if (temp) {
                            opts.transports = static_cast<TransportMask>(StringToU32(temp, 0, 0xFFFF));
                        }
                        temp = strtok(NULL, " ");
                    }
                    if (status == ER_OK) {
                        status = g_msgBus->BindSessionPort(sessionPort, opts, mySessionPortListener1);
                        if (ER_OK != status) {
                            QCC_LogError(status, ("BindSessionPort failed on [%u]", sessionPort));
                            fflush(stdout);
                        } else {
                            printf("Sessionport (%d) bound.\n", sessionPort);
                            fflush(stdout);
                        }
                    }
                } else if (strcmp(temp, "unbind") == 0) {
//UNBINDSESSIONPORT
                    /* unbind sessionport*/
                    SessionPort sessionPort = 0;
                    temp = strtok(NULL, " ");
                    if (!temp) {
                        printf("ERROR - unbind sessionport. \n");
                        fflush(stdout);
                        status = ER_FAIL;
                    } else {
                        sessionPort = static_cast<SessionPort>(StringToU32(temp, 0, 0));
                        status = ER_OK;
                    }
                    if (status == ER_OK) {
                        status = g_msgBus->UnbindSessionPort(sessionPort);
                        if (ER_OK != status) {
                            QCC_LogError(status, ("UnbindSessionPort(%u) failed ", sessionPort));
                            fflush(stdout);
                        }
                    }
                } else if (strcmp(temp, "find") == 0) {
//FINDADVERTISEDNAME
                    /* find prefix */
                    char prefix[50];
                    status = ER_OK;
                    temp = strtok(NULL, " ");
                    if (!temp) {
                        strcpy(prefix, "");
                    } else {
                        strcpy(prefix, temp);
                    }
                    if (status == ER_OK) {
                        status = g_msgBus->FindAdvertisedName(prefix);
                        if (ER_OK != status) {
                            QCC_LogError(status, ("FindAdvertisedName(%s) failed ", prefix));
                            fflush(stdout);
                        }
                    }
                } else if (strcmp(temp, "cancelfind") == 0) {
//CANCELFIND
                    /* cancelfind prefix */
                    char prefix[50];
                    status = ER_OK;
                    temp = strtok(NULL, " ");
                    if (!temp) {
                        strcpy(prefix, "");
                    } else {
                        strcpy(prefix, temp);
                    }
                    if (status == ER_OK) {
                        status = g_msgBus->CancelFindAdvertisedName(prefix);
                        if (ER_OK != status) {
                            QCC_LogError(status, ("CancelFindAdvertisedName(%s) failed ", prefix));
                            fflush(stdout);
                        }
                    }
                } else if (strcmp(temp, "enablenoc") == 0) {
//ENABLENOC
                    printf("Enabling NOC signals. \n");
                    fflush(stdout);
                    maskNOC = false;
                } else if (strcmp(temp, "disablenoc") == 0) {
//DISABLENOC
                    printf("Disabling NOC signals. \n");
                    fflush(stdout);
                    maskNOC = true;
                } else if ((strcmp(temp, "methodasync") == 0)  || (strcmp(temp, "methodsync") == 0)) {
//METHODCALL or METHODCALLASYNC
                    bool methodasync = false;
                    if (strcmp(temp, "methodasync") == 0) {
                        methodasync = true;
                    }

                    /* method interface methodname m*/
                    /* m -> timeout, flags */
                    char interfaceName[50];
                    char methodName[50];
                    uint8_t ttl = 0, flags = 0;
                    QStatus status = ER_OK;

                    temp = strtok(NULL, " ");
                    if (!temp) {
                        printf("ERROR - method interface methodname m \n");
                        fflush(stdout);
                        status = ER_FAIL;
                    } else {
                        strcpy(interfaceName, temp);
                        status = ER_OK;
                    }

                    if (status == ER_OK) {
                        temp = strtok(NULL, " ");
                        if (!temp) {
                            printf("ERROR - method interface methodname m \n");
                            fflush(stdout);
                            status = ER_FAIL;
                        } else {
                            strcpy(methodName, temp);
                            status = ER_OK;
                        }
                    }

                    if (status == ER_OK) {
                        temp = strtok(NULL, " ");
                        if (temp && (temp[0] == 'm')) {
                            printf("Enter flags(HESN) ttl  :");
                            fflush(stdout);
                            char tempOptions[50];
                            while (get_data(tempOptions) == NULL);
                            temp = strtok(tempOptions, " ");
                            if (temp) {
                                String tstr(temp);
                                size_t temp = tstr.find_first_of("E");
                                if (temp != String::npos) {
                                    flags |= ALLJOYN_FLAG_ENCRYPTED;
                                }
                                temp = tstr.find_first_of("S");
                                if (temp != String::npos) {
                                    flags |= ALLJOYN_FLAG_SESSIONLESS;
                                }
                                temp = tstr.find_first_of("N");
                                if (temp != String::npos) {
                                    flags |= ALLJOYN_FLAG_NO_REPLY_EXPECTED;
                                }
                            }
                            temp = strtok(NULL, " ");
                            if (temp) {
                                ttl = static_cast<uint8_t>(StringToU32(temp, 0, 0));
                            }
                        }
                    }

                    if ((!proxyBusObject) && (status == ER_OK)) {
                        printf("ERROR - ProxyBusObject is not defined. \n");
                        fflush(stdout);
                        status = ER_FAIL;
                    }

                    if (status == ER_OK) {

                        Message reply(*g_msgBus);

                        /* Set the arguments */
                        MsgArg msgArgs;
                        msgArgs.Set("s", "This is a method call");

                        /* Now make the method call */
                        if (status == ER_OK) {

                            if (methodasync) {
                                status = proxyBusObject->MethodCallAsync(interfaceName, methodName, &msgReceiver,
                                                                         static_cast<MessageReceiver::ReplyHandler>(&MyMessageReceiver::MyResponseHandler),
                                                                         &msgArgs, 1, NULL,
                                                                         ttl, flags);
                                if (status != ER_OK) {
                                    QCC_LogError(status, ("MethodCallAsync on %s.%s failed", interfaceName, methodName));
                                    fflush(stdout);
                                }
                                qcc::Sleep(ttl + 10);
                            } else {

                                status = proxyBusObject->MethodCall(interfaceName, methodName,
                                                                    &msgArgs, 1, reply, ttl, flags);
                                if (status != ER_OK) {
                                    printf("ERROR - MethodCall failed with  %s ", QCC_StatusText(status));
                                    fflush(stdout);
                                } else {
                                    printf("MethodCall succeeded. \n");
                                    fflush(stdout);
                                }
                            }
                        }
                    }

                } else if ((strcmp(temp, "introspectasync") == 0)  || (strcmp(temp, "introspect") == 0)) {
//INTROSPECT or INTROSPECTASYNC
                    //bool introspectasync=false;
                    //if(strcmp(temp, "introspectasync") == 0) introspectasync=true;

                    /* introspect wkn objectpath sessionid m*/
                    //char wkn[50];
                    //SessionId sessionId=0;
                    //char objectPath[50];
                    //QStatus status = ER_OK;
                    //ProxyBusObject *remoteObj = NULL;

                    //temp = strtok(NULL, " ");
                    //if(!temp) {
                    //     printf("ERROR - intospect wkn objectpath sessionid m \n");
                    //     fflush(stdout);
                    //     status = ER_FAIL;
                    //} else {
                    //   strcpy(wkn, temp);
                    //   status = ER_OK;
                    //}

                    //if(status == ER_OK) {
                    //     temp = strtok(NULL, " ");
                    //     if(!temp) {
                    //       printf("ERROR - introspect wkn objectpath sessionid m \n");
                    //       fflush(stdout);
                    //       status = ER_FAIL;
                    //     } else {
                    //       strcpy(objectPath, temp);
                    //       status = ER_OK;
                    //     }
                    //}
                    //if(status  == ER_OK) {
                    //     temp = strtok(NULL, " ");
                    //     if(temp) sessionId = static_cast<SessionId>(StringToU32(temp, 0, 0));
                    // }

                } else if ((strcmp(temp, "createproxy") == 0)) {
                    /* createproxy wellknownname objectpath sessionid */
//CREATE PROXY BUS OBJECT
                    char wkn[50];
                    SessionId sessionId = 0;
                    char objectPath[50];
                    QStatus status = ER_OK;

                    temp = strtok(NULL, " ");
                    if (!temp) {
                        printf("ERROR - createproxy wellknownname objectpath sessionid  \n");
                        fflush(stdout);
                        status = ER_FAIL;
                    } else {
                        strcpy(wkn, temp);
                        status = ER_OK;
                    }

                    if (status == ER_OK) {
                        temp = strtok(NULL, " ");
                        if (!temp) {
                            printf("ERROR - createproxy wellknownname objectpath sessionid  \n");
                            fflush(stdout);
                            status = ER_FAIL;
                        } else {
                            strcpy(objectPath, temp);
                            status = ER_OK;
                        }
                    }

                    if (status == ER_OK) {
                        temp = strtok(NULL, " ");
                        if (!temp) {
                            printf("ERROR - createproxy wellknownname objectpath sessionid  \n");
                            fflush(stdout);
                            status = ER_FAIL;
                        } else {
                            sessionId = static_cast<SessionId>(StringToU32(temp, 0, 0));
                            status = ER_OK;
                        }
                    }

                    if (status == ER_OK) {
                        if ((!proxyBusObject)) {
                            proxyBusObject = new ProxyBusObject(*g_msgBus, wkn, objectPath, sessionId);
                            status = proxyBusObject->IntrospectRemoteObject();
                            if (status == ER_OK) {
                                printf("Successfully introspected proxy bus object. \n");
                                fflush(stdout);
                            } else {
                                QCC_LogError(status, ("Introspection of proxybusobject failed. "));
                                fflush(stdout);
                            }
                        } else {
                            printf("proxyBusObject already exists. \n");
                            fflush(stdout);
                        }
                    }

                } else if ((strcmp(temp, "destroyproxy") == 0)) {
//DESTROY PROXY
                    if (proxyBusObject) {
                        delete proxyBusObject;
                        proxyBusObject = NULL;
                        printf("Destroyed proxyBusObject. \n");
                        fflush(stdout);
                    } else {
                        printf("proxyBusObject is already NULL. \n");
                        fflush(stdout);
                    }

                } else if ((strcmp(temp, "getversion") == 0)) {
//GET VERSION
                    printf("AllJoyn Library version: %s\n", ajn::GetVersion());
                    printf("AllJoyn Library build info: %s\n", ajn::GetBuildInfo());
                    fflush(stdout);
                } else if ((strcmp(temp, "help") == 0)) {
//HELP
                    printf("getversion\n");
                    printf("destroyproxy \n");
                    printf("createproxy   wellknownname objectpath sessionid \n");
                    printf("methodasync interface methodname  m (HESN) \n");
                    printf("methodsync  interface methodname  m (HESN) \n");
                    printf("diasablenoc \n");
                    printf("enablenoc \n");
                    printf("cancelfind \n");
                    printf("find \n");
                    printf("unbind sessionport \n");
                    printf("bind port isMultipoint traffic transport \n");
                    printf("leave sessionid \n");
                    printf("nameonbus name\n");
                    printf("releasename name\n");
                    printf("requestname name\n");
                    printf("canceladvertise name transport\n");
                    printf("advertise name transport\n");
                    printf("joinasync name port isMultipoint traffic proximity transport noSessionListener\n");
                    printf("join name port isMultipoint traffic proximity transport noSessionListener\n");
                    printf("exit\n");
                    printf("signal\n");
                    printf("help\n");
                    fflush(stdout);
                }


            } //End of while loop

        } else {
            QCC_LogError(status, ("Failed to connect to bus"));
        }
    }

    /* Clean up msg bus */
    if (g_msgBus) {
        delete g_msgBus;
    }

    printf("\n %s exiting with status %d (%s)\n", argv[0], status, QCC_StatusText(status));

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
