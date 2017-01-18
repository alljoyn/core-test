/**
 * Sample implementation of an AllJoyn c++ application that does a file transfer.
 * This app can also be used to test throughput for any transport.
 * Default file size is 130000 bytes.
 * Point-to-Point session used, Port NO 550
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

#include <signal.h>
#include <stdlib.h>
#include <qcc/Util.h>
#include <qcc/StringUtil.h>
#include <qcc/ThreadPool.h>
#include <alljoyn/BusAttachment.h>
#include <alljoyn/Init.h>
#include <qcc/Thread.h>

#define QCC_MODULE "ALLJOYN"

using namespace std;
using namespace qcc;
using namespace ajn;

/** Static top level message bus object */
static BusAttachment* g_msgBus = nullptr;
static ThreadPool* threadPool = nullptr;
static Event* g_discoverEvent = nullptr;
static volatile bool g_interrupt = false;

static bool UDP = false;
static bool TCP = false;
static bool LOCAL = false;
static bool THROUGHPUT = false;
static uint32_t g_payload = 130000;
static uint32_t g_no_signals = 100000;
static uint32_t g_startTime = 0;
static uint32_t g_endTime = 0;
static bool g_random = false;
static bool g_ttl = false;
static uint32_t g_rate = 0;
static bool g_server_complete = false;
static bool g_client_complete = false;

/** Signal handler */
static void CDECL_CALL SigIntHandler(int sig)
{
    QCC_UNUSED(sig);
    g_interrupt = true;
}

namespace org {
namespace alljoyn {
namespace file_transfer {
const char* WellKnownName = "org.alljoyn.file_transfer";
const char* InterfaceName = "org.alljoyn.file_transfer.Interface";
const char* ObjectPath = "/org/alljoyn/file_transfer";
}
}
}

static String g_WellKnownName = ::org::alljoyn::file_transfer::WellKnownName;
static String g_FileName = "";

/** This is for the client AllJoynListener receives discovery events from AllJoyn */
class MyBusListener : public BusListener, public SessionPortListener, public SessionListener {
  public:
    MyBusListener() : BusListener(), SessionPortListener() { }

    bool AcceptSessionJoiner(SessionPort sessionPort, const char* joiner, const SessionOpts& opts)
    {
        QCC_UNUSED(opts);
        QCC_UNUSED(sessionPort);
        printf("Session Joined with: joiner=%s\n", joiner);
        return true;
    }

    void SessionJoined(SessionPort sessionPort, SessionId sessionId, const char* joiner)
    {
        QCC_UNUSED(sessionPort);
        printf("Session Established: joiner=%s, sessionId=%u\n", joiner, sessionId);
        QStatus status = g_msgBus->SetSessionListener(sessionId, this);
        if (status != ER_OK) {
            QCC_LogError(status, ("SetSessionListener failed"));
            return;
        }

    }

    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix)
    {
        printf("FoundAdvertisedName(name=%s, transport=0x%x, prefix=%s)\n", name, transport, namePrefix);
        if (0 == strcmp(name, g_WellKnownName.c_str())) {
            if ((TCP && (transport == 4)) || (UDP && (transport == 256)) || (LOCAL && (transport == 1))) {
                g_discoverEvent->SetEvent();
            }
        }
    }

    void LostAdvertisedName(const char* name, TransportMask transport, const char* prefix)
    {
        printf("LostAdvertisedName(name=%s, transport=0x%x,  prefix=%s)\n", name, transport, prefix);
    }

    void SessionLost(SessionId sessionId, SessionListener::SessionLostReason reason) {
        QCC_UNUSED(reason);
        printf("\n SessionLost(%08x) \n", sessionId);
        g_server_complete = true;
    }
};

/** Static bus listener */
static MyBusListener g_busListener;

class FileTransfer : public Runnable, public BusObject {

  public:

    FileTransfer(const InterfaceDescription::Member* my_signal_member, const InterfaceDescription::Member* my_ftp_over_member, SessionId sessionId, String fileName) :
        BusObject("/a/b"),
        my_signal_member(my_signal_member),
        my_ftp_over_member(my_ftp_over_member),
        sessionId(sessionId),
        fileName(fileName)   { }

    virtual void Run(void) {

        QStatus status = ER_OK;
        uint8_t* buf = new uint8_t[g_payload];

        uint8_t flags = 0;
        srand(1);
        /* Transfer the file. */
        if (strcmp(fileName.c_str(), "throughput") != 0) {

            MsgArg msgbuf;
            FILE* inpf = nullptr;
            inpf = fopen(g_FileName.c_str(), "rb");
            int num;

            if (inpf == nullptr) {
                QCC_LogError(ER_FAIL, ("Cannot open File - %s ", g_FileName.c_str()));
                status = ER_FAIL;
            }

            if (status == ER_OK) {
                printf("\nStarting file transfer using signals..\n");
                uint32_t t_payload = g_payload;
                while (!feof(inpf)) {
                    if (g_random) {
                        t_payload = 1 + (rand() % g_payload);
                    }
                    num = fread(buf, 1, t_payload, inpf);
                    msgbuf.Set("ay", num, buf);
                    status = Signal(nullptr, sessionId, *my_signal_member, &msgbuf, 1, 0, flags);
                    if (ER_OK != status) {
                        QCC_LogError(status, ("Error sending signal. File transfer aborted."));
                        break;
                    }
                }
                fclose(inpf);

                //Send the my_ftp_over  signal
                status = Signal(nullptr, sessionId, *my_ftp_over_member, nullptr, 0, 0, 0);
                if (ER_OK != status) {
                    QCC_LogError(status, ("Error sending my_ftp_over signal. DISASTER!"));
                }
            }
        } else if (strcmp(fileName.c_str(), "throughput") == 0) {
            /* Throughput check. */

            for (uint32_t i = 0; i < g_no_signals; i++) {
                MsgArg arg[2];
                uint32_t t_payload = g_payload;
                if (g_random) {
                    t_payload = 1 + (rand() % g_payload);
                }
                arg[1].Set("ay", t_payload, buf);

                arg[0].Set("i", i);
                status = Signal(nullptr, sessionId, *my_signal_member, arg, 2, g_rate, flags);
                if (ER_OK != status) {
                    QCC_LogError(status, ("Error sending signal. Throughput check aborted."));
                    break;
                }
                if (g_rate) {
                    printf("Sending signal with %u ttl %u \n", g_rate, i);
                    qcc::Sleep(g_rate);
                }
            }
            //Send the my_ftp_over  signal
            status = Signal(nullptr, sessionId, *my_ftp_over_member, nullptr, 0, 0, 0);
            if (ER_OK != status) {
                QCC_LogError(status, ("Error sending my_ftp_over signal. DISASTER!"));
            }
        }
        delete buf;
    }

  private:
    const InterfaceDescription::Member* my_signal_member;
    const InterfaceDescription::Member* my_ftp_over_member;
    SessionId sessionId;
    String fileName;
};


/* For the service */
class LocalTestObject : public BusObject {
  public:

    LocalTestObject(const char*path) : BusObject(path)
    {
        QStatus status = ER_OK;

        const InterfaceDescription* Intf = g_msgBus->GetInterface(::org::alljoyn::file_transfer::InterfaceName);
        QCC_ASSERT(Intf);
        AddInterface(*Intf);

        my_signal_member = Intf->GetMember("my_ftp_signal");
        QCC_ASSERT(my_signal_member);
        my_throughput_signal_member = Intf->GetMember("my_throughput_signal");
        QCC_ASSERT(my_throughput_signal_member);
        my_ftp_over_member = Intf->GetMember("my_ftp_over");
        QCC_ASSERT(my_ftp_over_member);
        my_sender_ok_member = Intf->GetMember("my_sender_ok");
        QCC_ASSERT(my_sender_ok_member);

        /* Register the method handlers with the object */
        const MethodEntry methodEntries[] = {
            { Intf->GetMember("my_ftp_start"), static_cast<MessageReceiver::MethodHandler>(&LocalTestObject::TransferFile) }
        };

        /* Add the method handlers */
        status = AddMethodHandlers(methodEntries, ArraySize(methodEntries));
        if (ER_OK != status) {
            QCC_LogError(status, ("Failed to register method handlers for LocalTestObject."));
        }
    }

    void ObjectRegistered(void)
    {
        printf("Object registered \n");
    }

    void TransferFile(const InterfaceDescription::Member* member, Message& msg)
    {
        QCC_UNUSED(member);
        /* Enabling concurrent callbacks. */
        g_msgBus->EnableConcurrentCallbacks();

        QStatus status = ER_OK;
        fileName = msg->GetArg(0)->v_string.str;

        /* Check if the file exists. */
        if (strcmp(fileName.c_str(), "throughput") != 0) {
            FILE* tmp = nullptr;
            tmp = fopen(g_FileName.c_str(), "rb");
            if (tmp == nullptr) {
                status = ER_NONE;
                QCC_LogError(status, ("TransferFile: file '%s' could not be opened.", fileName.c_str()));
            } else {
                fclose(tmp);
            }
        }

        MsgArg arg;
        if (ER_OK == status) {
            arg.Set("s", "ER_OK");
        }  else if (ER_NONE == status) {
            arg.Set("s", "ER_CANNOT_OPEN_FILE");
        } else {
            arg.Set("s", "ER_FAIL");
        }

        //Send the MethodReply first, so that the client will start its timer before the first signal arrives.
        QStatus status1 = MethodReply(msg, &arg, 1);
        if (ER_OK != status1) {
            QCC_LogError(status, ("TransferFile: Error sending reply."));
        }
        qcc::Sleep(10);

        /* If everything is ok, spawn a new thread here. */
        if (status == ER_OK) {
            Ptr<FileTransfer> runnable = nullptr;
            if (strcmp(fileName.c_str(), "throughput") != 0) {
                /* Spawn the file transfer thread. */
                runnable = NewPtr<FileTransfer>(my_signal_member, my_ftp_over_member, msg->GetSessionId(), fileName);
                g_msgBus->RegisterBusObject(*runnable);
            } else if (strcmp(fileName.c_str(), "throughput") == 0) {
                /* Spawn the throughput transfer thread. */
                runnable = NewPtr<FileTransfer>(my_throughput_signal_member, my_ftp_over_member, msg->GetSessionId(), fileName);
                g_msgBus->RegisterBusObject(*runnable);
            }
            status = threadPool->Execute(runnable);
        }
    }

  private:
    const InterfaceDescription::Member* my_signal_member;
    const InterfaceDescription::Member* my_throughput_signal_member;
    const InterfaceDescription::Member* my_ftp_over_member;
    const InterfaceDescription::Member* my_sender_ok_member;
    String fileName;
};

/* For the client */
class ClientObject : public MessageReceiver {

  public:
    QStatus SubscribeNameChangedSignal(bool throughput) {

        QStatus status = ER_OK;

        const InterfaceDescription* Intf = g_msgBus->GetInterface(::org::alljoyn::file_transfer::InterfaceName);
        QCC_ASSERT(Intf);
        /* Register the signal handler with the bus */

        my_signal_member = Intf->GetMember("my_ftp_signal");
        QCC_ASSERT(my_signal_member);
        my_throughput_signal_member = Intf->GetMember("my_throughput_signal");
        QCC_ASSERT(my_throughput_signal_member);
        my_ftp_over_member = Intf->GetMember("my_ftp_over");
        QCC_ASSERT(my_ftp_over_member);


        if (!throughput) {
            printf("Registering signal handler for my_ftp_signal. \n");
            status =  g_msgBus->RegisterSignalHandler(this,
                                                      static_cast<MessageReceiver::SignalHandler>(&ClientObject::FileSignalHandler),
                                                      my_signal_member,
                                                      nullptr);
        } else {
            printf("Registering signal handler for my_throughput_signal. \n");
            status =  g_msgBus->RegisterSignalHandler(this,
                                                      static_cast<MessageReceiver::SignalHandler>(&ClientObject::ThroughputSignalHandler),
                                                      my_throughput_signal_member,
                                                      nullptr);
        }

        status =  g_msgBus->RegisterSignalHandler(this,
                                                  static_cast<MessageReceiver::SignalHandler>(&ClientObject::FTPOverSignalHandler),
                                                  my_ftp_over_member,
                                                  nullptr);

        if (status != ER_OK) {
            QCC_LogError(status, ("Failed to register signal handler for %s.name", ::org::alljoyn::file_transfer::InterfaceName));
            return status;
        }

        return status;
    }

    void FileSignalHandler(const InterfaceDescription::Member*member,
                           const char* sourcePath,
                           Message& msg)
    {
        QCC_UNUSED(member);
        QCC_UNUSED(sourcePath);
        /* File write operations at the client */
        if (opf != (FILE*)0) {
            size_t num_bytes_to_write = msg->GetArg(0)->v_string.len;
            size_t i = fwrite(msg->GetArg(0)->v_string.str, 1, num_bytes_to_write, opf);

            std::cout << "bytes written = " << i << std::endl;
            fflush(opf);
        }
        printf(".");
    }

    void ThroughputSignalHandler(const InterfaceDescription::Member*member,
                                 const char* sourcePath,
                                 Message& msg)
    {
        QCC_UNUSED(member);
        QCC_UNUSED(sourcePath);
        static uint32_t count = 0;

        uint32_t i(msg->GetArg(0)->v_int32);
        uint32_t length = msg->GetArg(1)->v_scalarArray.numElements;

        if (!g_ttl) {
            if (count != i) {
                printf("Missing signal and infinite ttl. Danger !  expected: %u, got  %u\n", count, i);
                QCC_ASSERT(false);
            }
            count++;
            printf("Throughput Signal Received. %d %u bytes\n", i, length);
            if (i == (g_no_signals - 1)) {
                printf("THROUGHPUT TEST COMPLETE \n");
            }
        } else if (g_ttl) {

            if (i > count) {
                for (uint32_t j = count; j < i; j++) {
                    printf("Missed Signal %u \n", j);
                }
            }
            count = i + 1;
        }
    }

    void FTPOverSignalHandler(const InterfaceDescription::Member*member,
                              const char* sourcePath,
                              Message& msg)
    {
        QCC_UNUSED(member);
        QCC_UNUSED(sourcePath);
        printf("\n FTP over signal received \n");
        g_endTime = GetTimestamp();
        printf("\n\n Time taken is %u ms \n\n", (g_endTime - g_startTime));
        g_client_complete = true;

        QStatus status = g_msgBus->LeaveSession(msg->GetSessionId());
        if (status == ER_OK) {
            printf("Session Terminated \n");
        }
    }

  public:
    FILE* opf;
    const InterfaceDescription::Member* my_signal_member;
    const InterfaceDescription::Member* my_throughput_signal_member;
    const InterfaceDescription::Member* my_ftp_over_member;
};


static void usage(void)
{
    printf("[SERVER MODE] ./bbftp s  -payload #  -signals #s  -n [wkn] -random -ttl -rate #  -f <name_of_file> \n");
    printf("[CLIENT MODE] ./bbftp c -/t/-u/-l -r  -n [wkn] -ttl \n");
    printf("The output file will be named download* \n");
}

/** Main entry point */
int CDECL_CALL main(int argc, char**argv)
{
    QStatus status = ER_OK;
    status = AllJoynInit();
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

    g_discoverEvent = new Event();
    bool server = false;

    /* Install SIGINT handler */
    signal(SIGINT, SigIntHandler);

    /* Parse command line args */
    if (argc < 2) {
        usage();
        exit(-1);
    }
    if ((argv[1][0] != 's') && (argv[1][0] != 'c')) {
        usage();
        exit(-1);
    }

    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp("-h", argv[i])) {
            usage();
            exit(0);
        } else if (0 == strcmp("s", argv[i])) {
            server = true;
        } else if (0 == strcmp("c", argv[i])) {
            server = false;
        } else if (0 == strcmp("-t", argv[i])) {
            TCP = true;
        } else if (0 == strcmp("-u", argv[i])) {
            UDP = true;
        } else if (0 == strcmp("-l", argv[i])) {
            LOCAL = true;
        } else if (0 == strcmp("-r", argv[i])) {
            THROUGHPUT = true;
        } else if (0 == strcmp("-random", argv[i])) {
            g_random = true;
        } else if (0 == strcmp("-ttl", argv[i])) {
            g_ttl = true;
        } else if (0 == strcmp("-rate", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_rate = StringToU32(argv[i], 0, 30);
            }
        } else if (0 == strcmp("-payload", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_payload = StringToU32(argv[i], 0, 130000);
            }
        } else if (0 == strcmp("-n", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_WellKnownName = argv[i];
            }
        } else if (0 == strcmp("-signals", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_no_signals = StringToU32(argv[i], 0, 100000);
            }
        } else if (0 == strcmp("-f", argv[i])) {
            ++i;
            if (i == argc) {
                printf("option %s requires a parameter\n", argv[i - 1]);
                usage();
                exit(1);
            } else {
                g_FileName = argv[i];
            }
        } else {
            printf("Invalid option. \n");
            usage();
            exit(-1);
        }
    }

    if ((server) && (g_FileName.empty())) {
        printf("Server should specify the name of the file it wants to send \n");
        usage();
        exit(-1);
    }

    if ((server) && ((TCP) || (UDP) || (LOCAL))) {
        printf("Don't set transport for server. \n");
        usage();
        exit(-1);
    }

    if ((!server) && (!TCP) && (!UDP) && (!LOCAL)) {
        printf("Set some transport for the client. \n");
        usage();
        exit(-1);
    }

    if (server) {
        printf("Server mode \n");
        printf("Payload length = %u  \n", g_payload);
        printf("No of signals = %u  \n", g_no_signals);
        if (g_random) {
            printf("Data is random from 0 - %u \n", g_payload);
        }
    } else {
        printf("Client mode  \n");
        if (THROUGHPUT) {
            printf("Throughput mode  \n");
        } else {
            printf("FTP mode \n");
        }
    }

    /* Create message bus */
    g_msgBus = new BusAttachment("bbftp", true);

    /* Start the msg bus */
    status = g_msgBus->Start();
    if (ER_OK != status) {
        QCC_LogError(status, ("BusAttachment::Start failed."));
        return status;
    }

    status = g_msgBus->Connect();
    if (ER_OK != status) {
        QCC_LogError(status, ("BusAttachment::Connect failed."));
        return status;
    }

    g_msgBus->RegisterBusListener(g_busListener);

    InterfaceDescription* Intf = nullptr;
    status = g_msgBus->CreateInterface(::org::alljoyn::file_transfer::InterfaceName, Intf);
    if (ER_OK != status) {
        QCC_LogError(status, ("Cannot create interface on bus attachment."));
        return status;
    }

    Intf->AddSignal("my_ftp_signal", "ay", nullptr, 0);
    Intf->AddSignal("my_throughput_signal", "iay", nullptr, 0);
    Intf->AddSignal("my_ftp_over", nullptr, nullptr, 0);
    Intf->AddSignal("my_sender_ok", nullptr, nullptr, 0);
    Intf->AddMethod("my_ftp_start", "s", "s", "i,o", 0);
    Intf->Activate();

    LocalTestObject* testObj = nullptr;
    if (server) {
        /* Start the thread pool. */
        threadPool = new ThreadPool("FTPSERVERTHREAD", 2);

        testObj = new LocalTestObject(::org::alljoyn::file_transfer::ObjectPath);
        g_msgBus->RegisterBusObject(*testObj);

        /* If service - request name, advertise it and create session */
        status = g_msgBus->RequestName(g_WellKnownName.c_str(), DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE);
        if (ER_OK != status) {
            QCC_LogError(status, ("Request Name failed for [%s].", g_WellKnownName.c_str()));
            return status;
        }

        /* Begin Advertising the well-known name */
        status = g_msgBus->AdvertiseName(g_WellKnownName.c_str(), TRANSPORT_ANY | TRANSPORT_UDP);
        if (ER_OK != status) {
            QCC_LogError(status, ("Advertising failed."));
            return status;
        }

        /* Create a session for incoming client connections */
        SessionOpts optspp(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY | TRANSPORT_UDP);
        SessionPort sessport = 550;
        status = g_msgBus->BindSessionPort(sessport, optspp, g_busListener);
        if (status != ER_OK) {
            QCC_LogError(status, ("BindSessionPort failed."));
            return status;
        }
    }
    /* client side */
    else {
        ClientObject clObj;
        status = g_msgBus->FindAdvertisedName(g_WellKnownName.c_str());
        if (status != ER_OK) {
            QCC_LogError(status, ("FindAdvertisedName failed."));
            return status;
        }

        /* Wait till discovery happens. */
        status = Event::Wait(*g_discoverEvent, 120000);
        if ((status == ER_TIMEOUT) || (status == ER_ALERTED_THREAD)) {
            QCC_LogError(status, ("Discovery times out. Did not get any advertisement."));
            return status;
        }

        /* Join the session */
        SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
        if (LOCAL) {
            opts.transports = TRANSPORT_LOCAL;
        } else if (TCP) {
            opts.transports = TRANSPORT_TCP;
        } else if (UDP) {
            opts.transports = TRANSPORT_UDP;
        }

        SessionId sessionid;
        status = g_msgBus->JoinSession(g_WellKnownName.c_str(), 550, &g_busListener, sessionid, opts);
        if (ER_OK != status) {
            QCC_LogError(status, ("Join Session failed."));
            return status;
        }

        bool hasOwner = false;
        status = g_msgBus->NameHasOwner(g_WellKnownName.c_str(), hasOwner);
        if (hasOwner == false) {
            status = ER_NONE;
            QCC_LogError(ER_FAIL, ("Name has not appeared on the bus."));
            return status;
        }

        //Client all set to receive the signals by subscribing to it
        status = clObj.SubscribeNameChangedSignal(THROUGHPUT);
        if (ER_OK != status) {
            QCC_LogError(status, ("Could not Subscribe any signal."));
            return status;
        }

        /* Make a method call and get the name of the file you want */
        ProxyBusObject remoteObj;
        remoteObj = ProxyBusObject(*g_msgBus, g_WellKnownName.c_str(), ::org::alljoyn::file_transfer::ObjectPath, sessionid);
        remoteObj.IntrospectRemoteObject();

        char name[50];
        if (!THROUGHPUT) {
            sprintf(name, "download.%u", qcc::Rand32());
            clObj.opf = fopen(name, "wb");
        } else {
            strcpy(name, "throughput");
        }

        Message reply(*g_msgBus);
        MsgArg fileName("s", name);
        status = remoteObj.MethodCall(::org::alljoyn::file_transfer::InterfaceName, "my_ftp_start", &fileName, 1, reply);
        if (ER_OK != status) {
            QCC_LogError(status, ("Error talking to the service."));
        } else if (ER_OK == status) {

            char* value = nullptr;
            const MsgArg* arg((reply->GetArg(0)));
            arg->Get("s", &value);

            if (strcmp(value, "ER_OK") == 0) {
                printf("Wait, Operation  %s in progress..\n", (THROUGHPUT) ? "throughput measurement" : "file transfer");
                g_startTime = GetTimestamp();
            } else if (strcmp(value, "ER_THREADPOOL_EXHAUSTED") == 0) {
                printf("Server is busy. Cannot respond now. \n");
            } else if (strcmp(value, "ER_CANNOT_OPEN_FILE") == 0) {
                printf("Invalid file. \n");
            } else {
                printf("Error talking to the service. \n");
            }
        }

        while ((!g_interrupt) && (!g_client_complete)) {
            qcc::Sleep(2000);
        }

        printf("\nOPERATION OVER. CHECK DATA\n");
        if (!THROUGHPUT) {
            int c = fclose(clObj.opf);
            printf("Status of fclose is %d \n", c);
        }

    }  //End of client


    while (server && !g_interrupt && !g_server_complete) {
        qcc::Sleep(2000);
    }

    /* Clean up msg bus */
    if (g_msgBus) {
        delete g_msgBus;
    }

    if (testObj) {
        delete testObj;
    }

    /* Clean up the thread pool. */
    if (threadPool) {
        delete threadPool;
    }
    delete g_discoverEvent;

#ifdef ROUTER
    AllJoynRouterShutdown();
#endif
    AllJoynShutdown();

    return (int) status;
}
