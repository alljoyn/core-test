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

// These are a set of tests which involve RouterNode-to-RouterNode scenarios
// launch alljoyn-daemon before running tests

#include <qcc/platform.h>

#include <alljoyn/BusAttachment.h>
#include <alljoyn/Init.h>
#include <qcc/Thread.h>
#include <qcc/time.h>
#include <qcc/Util.h>

/* Header files included for Google Test Framework */
#include <gtest/gtest.h>

using namespace std;
using namespace qcc;
using namespace ajn;

/** Main entry point */
int main(int argc, char**argv, char**envArg)
{
    int status = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    QStatus ajInitStatus = AllJoynInit();
    if (ER_OK != ajInitStatus) {
        return 1;
    }
    status = AllJoynRouterInit();
    if (ER_OK != ajInitStatus) {
        AllJoynShutdown();
        return 1;
    }

    std::cout << "\n Running common unit test " << std::endl;
    testing::InitGoogleTest(&argc, argv);
    status = RUN_ALL_TESTS();

    AllJoynRouterShutdown();
    AllJoynShutdown();

    std::cout << argv[0] << " exiting with status " << status << std::endl;
    return (int) status;
}

static const uint32_t waitTimeoutMs = 4000;
static const SessionPort sessionPort = 80;

class OtherBusListener : public BusListener, public SessionPortListener {
  public:
    volatile bool found;

    OtherBusListener() : found(false) { }

    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix) {
        found = true;
    }

    bool AcceptSessionJoiner(SessionPort sessionPort, const char* joiner, const SessionOpts& opts) {
        return true;
    }
};

class NameOwnerChangedTest : public testing::Test, public BusListener, public SessionPortListener {
  public:
    BusAttachment* bus;
    String alias, oldOwner, newOwner;
    volatile unsigned int signalled;
    volatile bool found;
    SessionId sid;

    BusAttachment* otherBus;
    OtherBusListener* otherBusListener;

    virtual void SetUp() {
        alias.clear(); oldOwner.clear(); newOwner.clear();
        signalled = 0;
        found = false;
        sid = 0;
        bus = new BusAttachment("NameOwnerChangedTest", true);
        bus->RegisterBusListener(*this);
        EXPECT_EQ(ER_OK, bus->Start());
        EXPECT_EQ(ER_OK, bus->Connect("null:"));
        SessionPort port = sessionPort;
        SessionOpts opts;
        EXPECT_EQ(ER_OK, bus->BindSessionPort(port, opts, *this));
        EXPECT_EQ(ER_OK, bus->RequestName("bus.alias", DBUS_NAME_FLAG_DO_NOT_QUEUE));
        EXPECT_EQ(ER_OK, bus->AdvertiseName("bus.alias", TRANSPORT_ANY));
        FlushNameOwnerChangedSignals();

        otherBus = new BusAttachment("NameOwnerChangedTestOther", true);
        otherBusListener = new OtherBusListener();
        otherBus->RegisterBusListener(*otherBusListener);
    }

    virtual void TearDown() {
        otherBus->UnregisterBusListener(*otherBusListener);
        bus->UnregisterBusListener(*this);
        delete otherBusListener;
        delete otherBus;
        delete bus;
    }

    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix) {
        found = true;
    }

    void NameOwnerChanged(const char* name, const char* oldOwner, const char* newOwner) {
        printf("NameOwnerChanged(name=%s,oldOwner=%s,newOwner=%s)\n", name, oldOwner, newOwner);
        this->alias = name;
        this->oldOwner = oldOwner;
        this->newOwner = newOwner;
        ++signalled;
    }

    QStatus WaitForNameOwnerChanged(uint32_t msecs = waitTimeoutMs) {
        for (uint32_t i = 0; !signalled && (i < msecs); i += 100) {
            qcc::Sleep(100);
        }
        if (signalled) {
            --signalled;
            return ER_OK;
        } else {
            return ER_TIMEOUT;
        }
    }

    void FlushNameOwnerChangedSignals() {
        while (WaitForNameOwnerChanged(500) != ER_TIMEOUT)
            ;
        alias.clear(); oldOwner.clear(); newOwner.clear();
        printf("NameOwnerChanged flushed\n");
    }

    QStatus ConnectOtherBus(const char* connectSpec = "null:") {
        QStatus status = otherBus->Start();
        if (ER_OK == status) {
            status = otherBus->Connect(connectSpec);
        }
        if (ER_OK == status) {
            SessionPort port = sessionPort;
            SessionOpts opts;
            status = otherBus->BindSessionPort(port, opts, *otherBusListener);
        }
        if (ER_OK == status) {
            status = otherBus->RequestName("other.bus.alias", DBUS_NAME_FLAG_DO_NOT_QUEUE);
        }
        if (ER_OK == status) {
            status = otherBus->AdvertiseName("other.bus.alias", TRANSPORT_ANY);
        }
        return status;
    }

    QStatus JoinSession(SessionOpts::NameTransferType nameTransfer = SessionOpts::ALL_NAMES) {
        QStatus status = bus->FindAdvertisedName("other.bus.alias");
        if (ER_OK == status || ER_ALLJOYN_FINDADVERTISEDNAME_REPLY_ALREADY_DISCOVERING == status) {
            for (uint32_t i = 0; !found && (i < waitTimeoutMs); i += 100) {
                qcc::Sleep(100);
            }
            status = found ? ER_OK : ER_TIMEOUT;
        }
        if (ER_OK == status) {
            SessionPort port = sessionPort;
            SessionOpts opts;
            opts.nameTransfer = nameTransfer;
            printf("JoinSession(name=%s,opts={nameTransfer=%s,...})\n", otherBus->GetUniqueName().c_str(),
                   (opts.nameTransfer == SessionOpts::ALL_NAMES) ? "ALL_NAMES" : "DAEMON_NAMES");
            status = bus->JoinSession("other.bus.alias", port, NULL, sid, opts);
        }
        return status;
    }

    bool AcceptSessionJoiner(SessionPort sessionPort, const char* joiner, const SessionOpts& opts) {
        printf("AcceptSession(name=%s,opts={nameTransfer=%s,...})\n", joiner,
               (opts.nameTransfer == SessionOpts::ALL_NAMES) ? "ALL_NAMES" : "DAEMON_NAMES");
        return true;
    }

    void SessionJoined(SessionPort sessionPort, SessionId id, const char* joiner) {
        sid = id;
        printf("SessionJoined(name=%s,...)\n", joiner);
    }

    QStatus AcceptSession(SessionOpts::NameTransferType nameTransfer = SessionOpts::ALL_NAMES) {
        QStatus status = otherBus->FindAdvertisedName("bus.alias");
        if (ER_OK == status) {
            for (uint32_t i = 0; !otherBusListener->found && (i < waitTimeoutMs); i += 100) {
                qcc::Sleep(100);
            }
            status = otherBusListener->found ? ER_OK : ER_TIMEOUT;
        }
        if (ER_OK == status) {
            SessionPort port = sessionPort;
            SessionId id;
            SessionOpts opts;
            opts.nameTransfer = nameTransfer;
            status = otherBus->JoinSession("bus.alias", port, NULL, id, opts);
        }
        return status;
    }

    QStatus LeaveSession() {
        printf("LeaveSession\n");
        return bus->LeaveSession(sid);
    }
};

TEST_F(NameOwnerChangedTest, LocalConnectTriggersNOC)
{
    EXPECT_EQ(ER_OK, ConnectOtherBus());
    EXPECT_EQ(ER_OK, WaitForNameOwnerChanged());
}

TEST_F(NameOwnerChangedTest, LocalRequestNameTriggersNOC)
{
    EXPECT_EQ(ER_OK, ConnectOtherBus());
    FlushNameOwnerChangedSignals();
    EXPECT_EQ(ER_OK, otherBus->RequestName("other.bus.name", DBUS_NAME_FLAG_DO_NOT_QUEUE));
    EXPECT_EQ(ER_OK, WaitForNameOwnerChanged());
}

TEST_F(NameOwnerChangedTest, LocalReleaseNameTriggersNOC)
{
    EXPECT_EQ(ER_OK, ConnectOtherBus());
    EXPECT_EQ(ER_OK, otherBus->RequestName("other.bus.name", DBUS_NAME_FLAG_DO_NOT_QUEUE));
    FlushNameOwnerChangedSignals();
    EXPECT_EQ(ER_OK, otherBus->ReleaseName("other.bus.name"));
    EXPECT_EQ(ER_OK, WaitForNameOwnerChanged());
}

TEST_F(NameOwnerChangedTest, AllNames_LocalJoinSessionDoesNotTriggerNOC)
{
    EXPECT_EQ(ER_OK, ConnectOtherBus());
    FlushNameOwnerChangedSignals();
    EXPECT_EQ(ER_OK, JoinSession());
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged(500));
    EXPECT_EQ(ER_OK, LeaveSession());
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged(500));
}

TEST_F(NameOwnerChangedTest, AllNames_LocalAcceptSessionDoesNotTriggerNOC)
{
    EXPECT_EQ(ER_OK, ConnectOtherBus());
    FlushNameOwnerChangedSignals();
    EXPECT_EQ(ER_OK, AcceptSession());
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged(500));
    EXPECT_EQ(ER_OK, LeaveSession());
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged(500));
}

TEST_F(NameOwnerChangedTest, DaemonNames_LocalJoinSessionDoesNotTriggerNOC)
{
    EXPECT_EQ(ER_OK, ConnectOtherBus());
    FlushNameOwnerChangedSignals();
    EXPECT_EQ(ER_OK, JoinSession(SessionOpts::DAEMON_NAMES));
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged(500));
    EXPECT_EQ(ER_OK, LeaveSession());
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged(500));
}

TEST_F(NameOwnerChangedTest, DaemonNames_LocalAcceptSessionDoesNotTriggerNOC)
{
    EXPECT_EQ(ER_OK, ConnectOtherBus());
    FlushNameOwnerChangedSignals();
    EXPECT_EQ(ER_OK, AcceptSession(SessionOpts::DAEMON_NAMES));
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged(500));
    EXPECT_EQ(ER_OK, LeaveSession());
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged(500));
}

TEST_F(NameOwnerChangedTest, AllNames_RemoteConnectTriggersNOC)
{
    EXPECT_EQ(ER_OK, ConnectOtherBus("unix:abstract=alljoyn"));
    EXPECT_EQ(ER_OK, JoinSession());
    FlushNameOwnerChangedSignals();
    BusAttachment* remoteOtherBus = new BusAttachment("NameOwnerChangedTestRemoteOther", true);
    EXPECT_EQ(ER_OK, remoteOtherBus->Start());
    EXPECT_EQ(ER_OK, remoteOtherBus->Connect("unix:abstract=alljoyn"));
    EXPECT_EQ(ER_OK, WaitForNameOwnerChanged());
    delete remoteOtherBus;
}

TEST_F(NameOwnerChangedTest, AllNames_RemoteRequestNameTriggersNOC)
{
    EXPECT_EQ(ER_OK, ConnectOtherBus("unix:abstract=alljoyn"));
    EXPECT_EQ(ER_OK, JoinSession());
    FlushNameOwnerChangedSignals();
    EXPECT_EQ(ER_OK, otherBus->RequestName("other.bus.name", DBUS_NAME_FLAG_DO_NOT_QUEUE));
    EXPECT_EQ(ER_OK, WaitForNameOwnerChanged());
}

TEST_F(NameOwnerChangedTest, AllNames_RemoteReleaseNameTriggersNOC)
{
    EXPECT_EQ(ER_OK, ConnectOtherBus("unix:abstract=alljoyn"));
    EXPECT_EQ(ER_OK, JoinSession());
    EXPECT_EQ(ER_OK, otherBus->RequestName("other.bus.name", DBUS_NAME_FLAG_DO_NOT_QUEUE));
    FlushNameOwnerChangedSignals();
    EXPECT_EQ(ER_OK, otherBus->ReleaseName("other.bus.name"));
    EXPECT_EQ(ER_OK, WaitForNameOwnerChanged());
}

TEST_F(NameOwnerChangedTest, AllNames_RemoteJoinSessionTriggersNOC)
{
    EXPECT_EQ(ER_OK, ConnectOtherBus("unix:abstract=alljoyn"));
    FlushNameOwnerChangedSignals();
    EXPECT_EQ(ER_OK, JoinSession());
    EXPECT_EQ(ER_OK, WaitForNameOwnerChanged(500));
    EXPECT_EQ(ER_OK, LeaveSession());
    EXPECT_EQ(ER_OK, WaitForNameOwnerChanged(500));
}

TEST_F(NameOwnerChangedTest, AllNames_RemoteAcceptSessionTriggersNOC)
{
    EXPECT_EQ(ER_OK, ConnectOtherBus("unix:abstract=alljoyn"));
    FlushNameOwnerChangedSignals();
    EXPECT_EQ(ER_OK, AcceptSession());
    EXPECT_EQ(ER_OK, WaitForNameOwnerChanged(500));
    EXPECT_EQ(ER_OK, LeaveSession());
    EXPECT_EQ(ER_OK, WaitForNameOwnerChanged(500));
}

TEST_F(NameOwnerChangedTest, DaemonNames_RemoteConnectDoesNotTriggerNOC)
{
    EXPECT_EQ(ER_OK, ConnectOtherBus("unix:abstract=alljoyn"));
    EXPECT_EQ(ER_OK, JoinSession(SessionOpts::DAEMON_NAMES));
    FlushNameOwnerChangedSignals();
    BusAttachment* remoteOtherBus = new BusAttachment("NameOwnerChangedTestRemoteOther", true);
    EXPECT_EQ(ER_OK, remoteOtherBus->Start());
    EXPECT_EQ(ER_OK, remoteOtherBus->Connect("unix:abstract=alljoyn"));
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged());
    delete remoteOtherBus;
}

TEST_F(NameOwnerChangedTest, DaemonNames_RemoteRequestNameDoesNotTriggerNOC)
{
    EXPECT_EQ(ER_OK, ConnectOtherBus("unix:abstract=alljoyn"));
    EXPECT_EQ(ER_OK, JoinSession(SessionOpts::DAEMON_NAMES));
    FlushNameOwnerChangedSignals();
    EXPECT_EQ(ER_OK, otherBus->RequestName("other.bus.name", DBUS_NAME_FLAG_DO_NOT_QUEUE));
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged());
}

TEST_F(NameOwnerChangedTest, DaemonNames_RemoteReleaseNameDoesNotTriggerNOC)
{
    EXPECT_EQ(ER_OK, ConnectOtherBus("unix:abstract=alljoyn"));
    EXPECT_EQ(ER_OK, JoinSession(SessionOpts::DAEMON_NAMES));
    EXPECT_EQ(ER_OK, otherBus->RequestName("other.bus.name", DBUS_NAME_FLAG_DO_NOT_QUEUE));
    FlushNameOwnerChangedSignals();
    EXPECT_EQ(ER_OK, otherBus->ReleaseName("other.bus.name"));
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged());
}

TEST_F(NameOwnerChangedTest, DaemonNames_RemoteJoinSessionDoesNotTriggerNOC)
{
    EXPECT_EQ(ER_OK, ConnectOtherBus("unix:abstract=alljoyn"));
    FlushNameOwnerChangedSignals();
    EXPECT_EQ(ER_OK, JoinSession(SessionOpts::DAEMON_NAMES));
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged(500));
    EXPECT_EQ(ER_OK, LeaveSession());
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged(500));
}

TEST_F(NameOwnerChangedTest, DaemonNames_RemoteAcceptSessionDoesNotTriggerNOC)
{
    EXPECT_EQ(ER_OK, ConnectOtherBus("unix:abstract=alljoyn"));
    FlushNameOwnerChangedSignals();
    EXPECT_EQ(ER_OK, AcceptSession(SessionOpts::DAEMON_NAMES));
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged(500));
    EXPECT_EQ(ER_OK, LeaveSession());
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged(500));
}

/* This is to test part of the ASACORE-713 fix.  It's disabled due to needing manual setup and verification. */
TEST_F(NameOwnerChangedTest, DISABLED_DaemonNames_DoesNotExchangeRemoteNames)
{
    EXPECT_EQ(ER_OK, ConnectOtherBus("unix:abstract=alljoyn"));

    BusAttachment* remoteOtherBus = new BusAttachment("NameOwnerChangedTestRemoteOther", true);
    OtherBusListener* remoteOtherBusListener = new OtherBusListener();
    remoteOtherBus->RegisterBusListener(*remoteOtherBusListener);
    EXPECT_EQ(ER_OK, remoteOtherBus->Start());
    EXPECT_EQ(ER_OK, remoteOtherBus->Connect("unix:abstract=alljoyn1"));
    EXPECT_EQ(ER_OK, remoteOtherBus->FindAdvertisedName("other.bus.alias"));
    for (uint32_t i = 0; !remoteOtherBusListener->found && (i < waitTimeoutMs); i += 100) qcc::Sleep(100);
    EXPECT_EQ(true, remoteOtherBusListener->found);
    SessionPort port = sessionPort; SessionOpts opts;
    EXPECT_EQ(ER_OK, remoteOtherBus->JoinSession("other.bus.alias", port, NULL, sid, opts));

    EXPECT_EQ(ER_OK, JoinSession(SessionOpts::DAEMON_NAMES));
    EXPECT_EQ(ER_OK, LeaveSession());

    remoteOtherBus->UnregisterBusListener(*remoteOtherBusListener);
    delete remoteOtherBusListener;
    delete remoteOtherBus;
}

TEST_F(NameOwnerChangedTest, DaemonNames_LocalOldOwnerIsAllNewOwnerIsDaemon) {
    EXPECT_EQ(ER_OK, ConnectOtherBus("unix:abstract=alljoyn"));
    /* The bus.alias remote owner is masked by the local owner */
    EXPECT_EQ(ER_OK, otherBus->RequestName("bus.alias", DBUS_NAME_FLAG_DO_NOT_QUEUE));
    EXPECT_EQ(ER_OK, JoinSession(SessionOpts::DAEMON_NAMES));
    FlushNameOwnerChangedSignals();
    /* Unmask the remote owner */
    EXPECT_EQ(ER_OK, bus->ReleaseName("bus.alias"));
    /*
     * Since newOwner is DAEMON_NAMES, then we should not see it in the
     * NameOwnerChanged signal.
     */
    EXPECT_EQ(ER_OK, WaitForNameOwnerChanged());
    EXPECT_STREQ("bus.alias", alias.c_str());
    EXPECT_STREQ(bus->GetUniqueName().c_str(), oldOwner.c_str());
    EXPECT_STREQ("", newOwner.c_str());
}

TEST_F(NameOwnerChangedTest, DaemonNames_RemoteOldOwnerIsAllNewOwnerIsDaemon) {
    /* Request remote name, twice (second one is queued) */
    EXPECT_EQ(ER_OK, ConnectOtherBus("unix:abstract=alljoyn"));
    EXPECT_EQ(ER_OK, otherBus->RequestName("other.bus.name", 0));
    BusAttachment* remoteOtherBus = new BusAttachment("NameOwnerChangedTestRemoteOther", true);
    EXPECT_EQ(ER_OK, remoteOtherBus->Start());
    EXPECT_EQ(ER_OK, remoteOtherBus->Connect("unix:abstract=alljoyn"));
    EXPECT_EQ(ER_DBUS_REQUEST_NAME_REPLY_IN_QUEUE, remoteOtherBus->RequestName("other.bus.name", 0));
    FlushNameOwnerChangedSignals();
    /* Join remote session ALL, newOwner of other.bus.name is otherBus */
    EXPECT_EQ(ER_OK, JoinSession());
    SessionId a = sid;
    EXPECT_EQ(ER_OK, WaitForNameOwnerChanged()); // TODO check explicitly for other.bus.name alias
    FlushNameOwnerChangedSignals();
    /* Join remote session DAEMON and leave remote session ALL */
    EXPECT_EQ(ER_OK, JoinSession(SessionOpts::DAEMON_NAMES));
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged());
    EXPECT_EQ(ER_OK, bus->LeaveSession(a));
    EXPECT_EQ(ER_OK, WaitForNameOwnerChanged());
    FlushNameOwnerChangedSignals();
    /*
     * Since newOwner is DAEMON_NAMES, then we should not see it in the
     * NameOwnerChanged signal.
     */
    EXPECT_EQ(ER_OK, otherBus->ReleaseName("other.bus.name"));
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged());
    delete remoteOtherBus;
}

TEST_F(NameOwnerChangedTest, DaemonNames_RemoteOldOwnerIsDaemonLocalNewOwnerIsAll) {
    EXPECT_EQ(ER_OK, ConnectOtherBus("unix:abstract=alljoyn"));
    EXPECT_EQ(ER_OK, otherBus->RequestName("other.bus.name", 0));
    EXPECT_EQ(ER_OK, JoinSession(SessionOpts::DAEMON_NAMES));
    FlushNameOwnerChangedSignals();
    EXPECT_EQ(ER_OK, bus->RequestName("other.bus.name", 0));
    /*
     * Since oldOwner is DAEMON_NAMES, then we should not it in the
     * NameOwnerChanged signal.
     */
    EXPECT_EQ(ER_OK, WaitForNameOwnerChanged());
    EXPECT_STREQ("other.bus.name", alias.c_str());
    EXPECT_STREQ("", oldOwner.c_str());
    EXPECT_STREQ(bus->GetUniqueName().c_str(), newOwner.c_str());
}

// TODO Don't how to test this permutation, so test is DISABLED
TEST_F(NameOwnerChangedTest, DISABLED_DaemonNames_RemoteOldOwnerIsDaemonRemoteNewOwnerIsAll) {
}

TEST_F(NameOwnerChangedTest, DaemonNames_MultipleDaemonAndAllSessions) {
    EXPECT_EQ(ER_OK, ConnectOtherBus("unix:abstract=alljoyn"));
    FlushNameOwnerChangedSignals();

    EXPECT_EQ(ER_OK, JoinSession(SessionOpts::DAEMON_NAMES));
    SessionId a = sid;
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged(500));

    EXPECT_EQ(ER_OK, JoinSession());
    SessionId b = sid;
    /*
     * Since oldOwner is DAEMON_NAMES, then we should not it in the
     * NameOwnerChanged signal.
     */
    EXPECT_EQ(ER_OK, WaitForNameOwnerChanged());
    EXPECT_STREQ("other.bus.alias", alias.c_str());
    EXPECT_STREQ("", oldOwner.c_str());
    EXPECT_STREQ(otherBus->GetUniqueName().c_str(), newOwner.c_str());
    FlushNameOwnerChangedSignals();

    EXPECT_EQ(ER_OK, JoinSession());
    SessionId c = sid;
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged(500));

    EXPECT_EQ(ER_OK, JoinSession(SessionOpts::DAEMON_NAMES));
    SessionId d = sid;
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged(500));

    printf("LeaveSession()\n");
    EXPECT_EQ(ER_OK, bus->LeaveSession(d));
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged(500));

    printf("LeaveSession()\n");
    EXPECT_EQ(ER_OK, bus->LeaveSession(c));
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged(500));

    printf("LeaveSession()\n");
    EXPECT_EQ(ER_OK, bus->LeaveSession(b));
    EXPECT_EQ(ER_OK, WaitForNameOwnerChanged());
    FlushNameOwnerChangedSignals();

    /* Join an ALL_NAMES again and see what happens */
    EXPECT_EQ(ER_OK, JoinSession());
    b = sid;
    /*
     * Since oldOwner is DAEMON_NAMES, then we should not get it in the
     * NameOwnerChanged signal.
     */
    EXPECT_EQ(ER_OK, WaitForNameOwnerChanged());
    EXPECT_STREQ("other.bus.alias", alias.c_str());
    EXPECT_STREQ("", oldOwner.c_str());
    EXPECT_STREQ(otherBus->GetUniqueName().c_str(), newOwner.c_str());
    FlushNameOwnerChangedSignals();

    printf("LeaveSession()\n");
    EXPECT_EQ(ER_OK, bus->LeaveSession(b));
    EXPECT_EQ(ER_OK, WaitForNameOwnerChanged());
    FlushNameOwnerChangedSignals();

    printf("LeaveSession()\n");
    EXPECT_EQ(ER_OK, bus->LeaveSession(a));
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged(500));
}

TEST_F(NameOwnerChangedTest, DaemonNames_RemoteDaemonChangeOwner) {
    EXPECT_EQ(ER_OK, ConnectOtherBus("unix:abstract=alljoyn"));
    EXPECT_EQ(ER_OK, otherBus->RequestName("other.bus.name", 0));
    BusAttachment* remoteOtherBus = new BusAttachment("NameOwnerChangedTestRemoteOther", true);
    EXPECT_EQ(ER_OK, remoteOtherBus->Start());
    EXPECT_EQ(ER_OK, remoteOtherBus->Connect("unix:abstract=alljoyn"));
    EXPECT_EQ(ER_DBUS_REQUEST_NAME_REPLY_IN_QUEUE, remoteOtherBus->RequestName("other.bus.name", 0));
    FlushNameOwnerChangedSignals();

    EXPECT_EQ(ER_OK, JoinSession(SessionOpts::DAEMON_NAMES));
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged(500));
    EXPECT_EQ(ER_OK, otherBus->ReleaseName("other.bus.name"));
    EXPECT_EQ(ER_TIMEOUT, WaitForNameOwnerChanged(500));

    delete remoteOtherBus;
}

TEST_F(NameOwnerChangedTest, DaemonNames_RemoteAllChangeOwner) {
    EXPECT_EQ(ER_OK, ConnectOtherBus("unix:abstract=alljoyn"));
    EXPECT_EQ(ER_OK, otherBus->RequestName("other.bus.name", 0));
    BusAttachment* remoteOtherBus = new BusAttachment("NameOwnerChangedTestRemoteOther", true);
    EXPECT_EQ(ER_OK, remoteOtherBus->Start());
    EXPECT_EQ(ER_OK, remoteOtherBus->Connect("unix:abstract=alljoyn"));
    EXPECT_EQ(ER_DBUS_REQUEST_NAME_REPLY_IN_QUEUE, remoteOtherBus->RequestName("other.bus.name", 0));
    FlushNameOwnerChangedSignals();

    EXPECT_EQ(ER_OK, JoinSession());
    EXPECT_EQ(ER_OK, WaitForNameOwnerChanged());
    FlushNameOwnerChangedSignals();
    EXPECT_EQ(ER_OK, otherBus->ReleaseName("other.bus.name"));
    EXPECT_EQ(ER_OK, WaitForNameOwnerChanged());

    delete remoteOtherBus;
}
