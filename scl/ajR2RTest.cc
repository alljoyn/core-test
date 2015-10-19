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

#include <gtest/gtest.h>

#include <signal.h>
#include <stdio.h>
#include <vector>

#include <qcc/platform.h>
#include <qcc/Thread.h>
#include <qcc/Util.h>
#include <qcc/String.h>

#include <alljoyn/BusAttachment.h>
#include <alljoyn/Init.h>
#include <alljoyn/BusObject.h>
#include <alljoyn/DBusStd.h>
#include <alljoyn/AllJoynStd.h>
#include <alljoyn/BusObject.h>
#include <alljoyn/MsgArg.h>
#include <alljoyn/version.h>
#include <alljoyn/Status.h>

static const uint8_t WAIT_TIME = 5;
static const uint32_t PING_DELAY_TIME = 6000;
static const uint32_t FIND_NAME_TIME = 5000;

using namespace std;
using namespace qcc;
using namespace ajn;

/** Main entry point */
int main(int argc, char**argv, char**envArg)
{
    QCC_UNUSED(envArg);

    int status = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    QStatus ajInitStatus = AllJoynInit();
    if (ER_OK != ajInitStatus) {
        return 1;
    }
    ajInitStatus = AllJoynRouterInit();
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

// routing to routing node test class
class R2RTest : public testing::Test {
  public:
    BusAttachment* BusPtrA;
    BusAttachment* BusPtrB;

    virtual void SetUp() {
        QStatus status = ER_OK;

        BusPtrA = new BusAttachment("busAttachmentA", true);
        BusPtrB = new BusAttachment("busAttachmentB", true);

        // start second bus attachmetn on unix abstract first so local bus
        // attachement does not bind port 9955

        // start busB connection external sample daemon
        status = BusPtrB->Start();
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
        status = BusPtrB->Connect("unix:abstract=alljoyn");
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

        // advertise quiet name to open port on Andriod OS,
        status = BusPtrB->AdvertiseName("quiet@R2Rtest.randomNameB", TRANSPORT_ANY);
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

        // start busA connection internal
        status = BusPtrA->Start();
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
        status = BusPtrA->Connect("null:");
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

        status = BusPtrA->AdvertiseName("quiet@R2Rtest.randomNameA", TRANSPORT_ANY);
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
        // validate the alljoyn-daemon is running before running the tests
        size_t first = (BusPtrB->GetUniqueName()).find_first_of(":");
        size_t last = (BusPtrB->GetUniqueName()).find_last_of(".");
        size_t npos = (last - first) - 1;
        qcc::String strTestA = (BusPtrA->GetUniqueName()).substr(1, npos);
        qcc::String strTestB = (BusPtrB->GetUniqueName()).substr(1, npos);
        ASSERT_STRNE(strTestA.c_str(), strTestB.c_str()) << "  alljoyn-daemon not active! Ending test... ";
    }

    virtual void TearDown() {
        QStatus status = ER_OK;
        status = BusPtrA->Disconnect();
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
        BusPtrA->Stop();
        BusPtrA->Join();
        delete BusPtrA;

        status = BusPtrB->Disconnect();
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
        BusPtrB->Stop();
        BusPtrB->Join();
        delete BusPtrB;
    }

};

// callback bus listener
class R2RTestFindNameListener : public BusListener {
  public:

    R2RTestFindNameListener() : nameFound(0), nameMatched(0) { }

    int nameFound;
    bool nameMatched;
    String NameToMatch;

    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix) {
        QCC_UNUSED(transport);
        QCC_UNUSED(namePrefix);

        nameFound++;
        if (strcmp(name, NameToMatch.c_str()) == 0) {
            nameMatched = true;
        }
    }
    void LostAdvertisedName(const char* name, TransportMask transport, const char* namePrefix) {
        QCC_UNUSED(transport);
        QCC_UNUSED(namePrefix);

        if (strcmp(name, NameToMatch.c_str()) == 0) {
            nameFound--;
        }
    }
};

// Verify that Presence detection works between two devices after discovery is done
TEST_F(R2RTest, Presence_DetectionAfterDiscovery) {
    QStatus status = ER_OK;

    // initialize listener callback
    R2RTestFindNameListener listener;

    // set unique name
    listener.NameToMatch = "org.test.A" + BusPtrA->GetGlobalGUIDShortString();

    // request name
    status = BusPtrA->RequestName(listener.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // advertise name
    status = BusPtrA->AdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_ANY);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // register second bus listener for 2nd bus attachment
    BusPtrB->RegisterBusListener(listener);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // find advertised name
    status = BusPtrB->FindAdvertisedName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // wait for to find name
    for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
        if ((listener.nameFound) && (listener.nameMatched)) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }
    ASSERT_TRUE(listener.nameFound) << "failed to find advertised name: " << listener.NameToMatch.c_str();
    ASSERT_TRUE(listener.nameMatched) << "failed to find advertised name: " << listener.NameToMatch.c_str();

    // ping the well known name
    status = BusPtrB->Ping(listener.NameToMatch.c_str(), PING_DELAY_TIME);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // ping the unique name
    status = BusPtrB->Ping(BusPtrA->GetUniqueName().c_str(), PING_DELAY_TIME);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // cancel find
    status = BusPtrB->CancelFindAdvertisedName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // unregister
    BusPtrB->UnregisterBusListener(listener);

    // cancel advertise
    status = BusPtrA->CancelAdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_ANY);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // release name
    status = BusPtrA->ReleaseName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
}

// Negative test - Verify that Presence detection does not work if the advertisement is cancelled
TEST_F(R2RTest, Presence_NegativeDetectionAdvertiseCancel) {
    QStatus status = ER_OK;

    // initialize listener callback
    R2RTestFindNameListener listener;

    // set unique name
    listener.NameToMatch = "org.test.A" + BusPtrA->GetGlobalGUIDShortString();

    // request name
    status = BusPtrA->RequestName(listener.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // advertise name
    status = BusPtrA->AdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_ANY);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // register second bus listener for 2nd bus attachment
    BusPtrB->RegisterBusListener(listener);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // find advertised name
    status = BusPtrB->FindAdvertisedName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // wait for to find name
    for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
        if ((listener.nameFound) && (listener.nameMatched)) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }
    ASSERT_TRUE(listener.nameFound) << "failed to find advertised name: " << listener.NameToMatch.c_str();
    ASSERT_TRUE(listener.nameMatched) << "failed to find advertised name: " << listener.NameToMatch.c_str();

    // Stop advertising the name
    status = BusPtrA->CancelAdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_ANY);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // wait for advertised name to go away
    for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
        if (!listener.nameFound) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }
    ASSERT_FALSE(listener.nameFound) << "failed to cancel advertised name: " << listener.NameToMatch.c_str();

    // ping the name
    status = BusPtrB->Ping(listener.NameToMatch.c_str(), PING_DELAY_TIME);
    EXPECT_EQ(ER_ALLJOYN_PING_REPLY_UNKNOWN_NAME, status) << "  Actual Status: " << QCC_StatusText(status);

    // cancel find
    status = BusPtrB->CancelFindAdvertisedName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // unregister
    BusPtrB->UnregisterBusListener(listener);

    // release name
    status = BusPtrA->ReleaseName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
}

// Negative test - Verify presence detection returns unreachable if name had not been requested
TEST_F(R2RTest, Presence_NegativeDetectionNameRequested) {
    QStatus status = ER_OK;

    // initialize listener callback
    R2RTestFindNameListener listener;

    // set unique name
    listener.NameToMatch = "org.test.A" + BusPtrA->GetGlobalGUIDShortString();

    // advertise name
    status = BusPtrA->AdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_ANY);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // register second bus listener for 2nd bus attachment
    BusPtrB->RegisterBusListener(listener);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // find advertised name
    status = BusPtrB->FindAdvertisedName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // wait for to find name
    for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
        if ((listener.nameFound) && (listener.nameMatched)) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }
    ASSERT_TRUE(listener.nameFound) << "failed to find advertised name: " << listener.NameToMatch.c_str();
    ASSERT_TRUE(listener.nameMatched) << "failed to find advertised name: " << listener.NameToMatch.c_str();

    // ping the name
    status = BusPtrB->Ping(listener.NameToMatch.c_str(), PING_DELAY_TIME);
    EXPECT_EQ(ER_ALLJOYN_PING_REPLY_UNREACHABLE, status) << "  Actual Status: " << QCC_StatusText(status);

    // cancel find
    status = BusPtrB->CancelFindAdvertisedName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // unregister
    BusPtrB->UnregisterBusListener(listener);

    // Stop advertising the name
    status = BusPtrA->CancelAdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_ANY);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
}

// session join listener class
class R2RTestSessionListener : public SessionPortListener, SessionListener {
  public:

    R2RTestSessionListener(BusAttachment* bus = NULL) : bus(bus),
        sessionAccepted(0), sessionJoined(0),
        sessionLost(0), busSessionId(0) {
        // set random 16-bit port number on construction
        port = qcc::Rand16();
    }
    BusAttachment* bus;

    SessionPort port;
    bool sessionAccepted;
    bool sessionJoined;
    bool sessionLost;
    SessionId busSessionId;

    bool AcceptSessionJoiner(SessionPort sessionPort, const char* joiner, const SessionOpts& opts) {
        QCC_UNUSED(joiner);
        QCC_UNUSED(opts);

        if (sessionPort == port) {
            sessionAccepted = true;
            return true;
        } else {
            sessionAccepted = false;
            return false;
        }
    }

    void SessionLost(SessionId id, SessionListener::SessionLostReason reason) {
        QCC_UNUSED(id);
        QCC_UNUSED(reason);

        sessionLost = true;
    }

    void SessionJoined(SessionPort sessionPort, SessionId id, const char* joiner) {
        QCC_UNUSED(joiner);

        if (sessionPort == port) {
            busSessionId = id;
            sessionJoined = true;
            if (bus) {
                bus->SetSessionListener(id, this);
            }
        } else {
            sessionJoined = false;
        }
    }
};

// callback bus listener
class R2RTestFindNameListener2 : public BusListener {
  public:

    R2RTestFindNameListener2() : nameFound(0), nameLost(0), nameMatched(0) { }

    int nameFound;
    int nameLost;
    bool nameMatched;
    String NameToMatch;

    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix) {
        QCC_UNUSED(transport);
        QCC_UNUSED(namePrefix);
        nameFound++;
        if (strcmp(name, NameToMatch.c_str()) == 0) {
            printf("Found %s %x\n", name, transport);
            EXPECT_FALSE(nameLost);
            nameMatched = true;
        }
    }
    void LostAdvertisedName(const char* name, TransportMask transport, const char* namePrefix) {
        QCC_UNUSED(transport);
        QCC_UNUSED(namePrefix);

        if (strcmp(name, NameToMatch.c_str()) == 0) {
            printf("Lost %s %x\n", name, transport);
            nameFound--;
            nameLost = 1;
        }
    }
};

// Verify that the FoundName for a name is not received after the LostAdvertisedName
TEST_F(R2RTest, Advertisement_NoFoundNameAfterLost) {
    QStatus status = ER_OK;

    // initialize listener callback
    R2RTestFindNameListener2 listener;

    // set unique name
    listener.NameToMatch = "org.test.A" + BusPtrA->GetGlobalGUIDShortString();

    // Set up SessionOpts
    SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_TCP);

    // bind port
    R2RTestSessionListener sessionPortListenerA;
    sessionPortListenerA.port = sessionPortListenerA.port;

    status = BusPtrA->BindSessionPort(sessionPortListenerA.port, opts, sessionPortListenerA);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // request name
    status = BusPtrA->RequestName(listener.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // advertise name
    status = BusPtrA->AdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_TCP);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // register second bus listener for 2nd routing node
    BusPtrB->RegisterBusListener(listener);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // find advertised name
    status = BusPtrB->FindAdvertisedName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // wait for to find name
    for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
        if ((listener.nameFound) && (listener.nameMatched)) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }
    ASSERT_TRUE(listener.nameFound) << "failed to find advertised name: " << listener.NameToMatch.c_str();
    ASSERT_TRUE(listener.nameMatched) << "failed to find advertised name: " << listener.NameToMatch.c_str();

    // join session with second bus
    SessionId sessionId = 0;
    status = BusPtrB->JoinSession(listener.NameToMatch.c_str(), sessionPortListenerA.port, NULL, sessionId, opts);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
    // wait for to find name, 5 second max
    for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
        if (sessionPortListenerA.sessionJoined) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }

    EXPECT_NE(static_cast<SessionId>(0), sessionId) << "  SessionID should not be '0'";
    EXPECT_EQ(sessionPortListenerA.busSessionId, sessionId) << "  session ID's do not match";

    // stop advertising the name
    BusPtrA->CancelAdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_TCP);

    // wait for the found name signal to complete
    for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
        if (!listener.nameFound) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }
    EXPECT_FALSE(listener.nameFound);

    //Leave Session
    status = BusPtrB->LeaveSession(sessionId);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    qcc::Sleep(1000);

    // cancel find
    status = BusPtrB->CancelFindAdvertisedName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // unregister
    BusPtrB->UnregisterBusListener(listener);

    // release name
    status = BusPtrA->ReleaseName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // unbind port
    status = BusPtrA->UnbindSessionPort(sessionPortListenerA.port);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    //No FoundName after LostName
    EXPECT_TRUE(listener.nameLost);
    EXPECT_FALSE(listener.nameFound);

}
// Verify that Presence detection works between two routing nodes when they are in a session
TEST_F(R2RTest, Presence_DetectionTwoNodesDurringSession) {
    QStatus status = ER_OK;

    // initialize listener callback
    R2RTestFindNameListener listener;

    // set unique name
    listener.NameToMatch = "org.test.A" + BusPtrA->GetGlobalGUIDShortString();

    // Set up SessionOpts
    SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);

    // bind port
    R2RTestSessionListener sessionPortListenerA;
    sessionPortListenerA.port = sessionPortListenerA.port;

    status = BusPtrA->BindSessionPort(sessionPortListenerA.port, opts, sessionPortListenerA);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // request name
    status = BusPtrA->RequestName(listener.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // advertise name
    status = BusPtrA->AdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_ANY);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // register second bus listener for 2nd routing node
    BusPtrB->RegisterBusListener(listener);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // find advertised name
    status = BusPtrB->FindAdvertisedName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // wait for to find name
    for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
        if ((listener.nameFound) && (listener.nameMatched)) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }
    ASSERT_TRUE(listener.nameFound) << "failed to find advertised name: " << listener.NameToMatch.c_str();
    ASSERT_TRUE(listener.nameMatched) << "failed to find advertised name: " << listener.NameToMatch.c_str();

    // join session with second bus
    SessionId sessionId = 0;
    status = BusPtrB->JoinSession(listener.NameToMatch.c_str(), sessionPortListenerA.port, NULL, sessionId, opts);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
    // wait for to find name, 5 second max
    for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
        if (sessionPortListenerA.sessionJoined) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }

    EXPECT_NE(static_cast<SessionId>(0), sessionId) << "  SessionID should not be '0'";
    EXPECT_EQ(sessionPortListenerA.busSessionId, sessionId) << "  session ID's do not match";

    // stop advertising the name
    BusPtrA->CancelAdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_ANY);

    // wait for the found name signal to complete
    for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
        if (!listener.nameFound) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }
    EXPECT_FALSE(listener.nameFound);

    // ping name with second bus
    status = BusPtrB->Ping(listener.NameToMatch.c_str(), PING_DELAY_TIME);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // ping unique name with second bus
    status = BusPtrB->Ping(BusPtrA->GetUniqueName().c_str(), PING_DELAY_TIME);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // ping unique name with first bus
    status = BusPtrA->Ping(BusPtrB->GetUniqueName().c_str(), PING_DELAY_TIME);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // explicitly leave session to release resources for transports viz. UDP
    status = BusPtrB->LeaveSession(sessionId);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // cancel find
    status = BusPtrB->CancelFindAdvertisedName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // unregister
    BusPtrB->UnregisterBusListener(listener);

    // release name
    status = BusPtrA->ReleaseName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // unbind port
    status = BusPtrA->UnbindSessionPort(sessionPortListenerA.port);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
}
//Negative Verify that Presence detection does not work between two routing nodes after leaving session
TEST_F(R2RTest, Presence_DetectionTwoNodesAfterLeaveSession) {
    QStatus status = ER_OK;

    // initialize listener callback
    R2RTestFindNameListener listener;

    // set unique name
    listener.NameToMatch = "org.test.A" + BusPtrA->GetGlobalGUIDShortString();

    // Set up SessionOpts
    SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);

    // bind port
    R2RTestSessionListener sessionPortListenerA;
    sessionPortListenerA.port = sessionPortListenerA.port;

    status = BusPtrA->BindSessionPort(sessionPortListenerA.port, opts, sessionPortListenerA);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // request name
    status = BusPtrA->RequestName(listener.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // advertise name
    status = BusPtrA->AdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_ANY);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // register second bus listener for 2nd routing node
    BusPtrB->RegisterBusListener(listener);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // find advertised name
    status = BusPtrB->FindAdvertisedName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // wait for to find name
    for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
        if ((listener.nameFound) && (listener.nameMatched)) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }
    ASSERT_TRUE(listener.nameFound) << "failed to find advertised name: " << listener.NameToMatch.c_str();
    ASSERT_TRUE(listener.nameMatched) << "failed to find advertised name: " << listener.NameToMatch.c_str();

    // join session with second bus
    SessionId sessionId = 0;
    status = BusPtrB->JoinSession(listener.NameToMatch.c_str(), sessionPortListenerA.port, NULL, sessionId, opts);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
    // wait for to find name, 5 second max
    for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
        if (sessionPortListenerA.sessionJoined) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }

    EXPECT_NE(static_cast<SessionId>(0), sessionId) << "  SessionID should not be '0'";
    EXPECT_EQ(sessionPortListenerA.busSessionId, sessionId) << "  session ID's do not match";

    // stop advertising the name
    BusPtrA->CancelAdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_ANY);

    // wait for the found name signal to complete
    for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
        if (!listener.nameFound) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }
    EXPECT_FALSE(listener.nameFound);

    //Leave Session
    status = BusPtrB->LeaveSession(sessionId);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    qcc::Sleep(1000);

    // ping unique name with second bus
    status = BusPtrB->Ping(BusPtrA->GetUniqueName().c_str(), PING_DELAY_TIME);
    EXPECT_EQ(ER_ALLJOYN_PING_REPLY_UNKNOWN_NAME, status) << "  Actual Status: " << QCC_StatusText(status);

    // ping unique name with first bus
    status = BusPtrA->Ping(BusPtrB->GetUniqueName().c_str(), PING_DELAY_TIME);
    EXPECT_EQ(ER_ALLJOYN_PING_REPLY_UNKNOWN_NAME, status) << "  Actual Status: " << QCC_StatusText(status);

    // cancel find
    status = BusPtrB->CancelFindAdvertisedName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // unregister
    BusPtrB->UnregisterBusListener(listener);

    // release name
    status = BusPtrA->ReleaseName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // unbind port
    status = BusPtrA->UnbindSessionPort(sessionPortListenerA.port);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
}

TEST_F(R2RTest, Presence_DetectionTwoNodesAfterExit) {
    QStatus status = ER_OK;

    BusAttachment* BusPtrC = new BusAttachment("busAttachmentC", true);


    // start busC connection external sample daemon
    status = BusPtrC->Start();
    ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
    status = BusPtrC->Connect("unix:abstract=alljoyn");
    ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);


    // initialize listener callback
    R2RTestFindNameListener listener;

    // set unique name
    listener.NameToMatch = "org.test.A" + BusPtrA->GetGlobalGUIDShortString();

    // Set up SessionOpts
    SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);

    // bind port
    R2RTestSessionListener sessionPortListenerA(BusPtrA);
    sessionPortListenerA.port = sessionPortListenerA.port;

    status = BusPtrA->BindSessionPort(sessionPortListenerA.port, opts, sessionPortListenerA);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // request name
    status = BusPtrA->RequestName(listener.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // advertise name
    status = BusPtrA->AdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_ANY);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // register second bus listener for 2nd routing node
    BusPtrB->RegisterBusListener(listener);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // find advertised name
    status = BusPtrB->FindAdvertisedName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // wait for to find name
    for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
        if ((listener.nameFound) && (listener.nameMatched)) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }
    ASSERT_TRUE(listener.nameFound) << "failed to find advertised name: " << listener.NameToMatch.c_str();
    ASSERT_TRUE(listener.nameMatched) << "failed to find advertised name: " << listener.NameToMatch.c_str();

    // join session with second bus
    SessionId sessionId = 0;
    status = BusPtrB->JoinSession(listener.NameToMatch.c_str(), sessionPortListenerA.port, NULL, sessionId, opts);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
    // wait for to find name, 5 second max
    for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
        if (sessionPortListenerA.sessionJoined) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }

    EXPECT_NE(static_cast<SessionId>(0), sessionId) << "  SessionID should not be '0'";
    EXPECT_EQ(sessionPortListenerA.busSessionId, sessionId) << "  session ID's do not match";

    // join session from C to A.
    sessionId = 0;
    sessionPortListenerA.sessionJoined = false;
    status = BusPtrC->JoinSession(listener.NameToMatch.c_str(), sessionPortListenerA.port, NULL, sessionId, opts);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
    // wait for to find name, 5 second max
    for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
        if (sessionPortListenerA.sessionJoined) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }

    EXPECT_NE(static_cast<SessionId>(0), sessionId) << "  SessionID should not be '0'";
    EXPECT_EQ(sessionPortListenerA.busSessionId, sessionId) << "  session ID's do not match";

    // stop advertising the name
    BusPtrA->CancelAdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_ANY);

    // wait for the found name signal to complete
    for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
        if (!listener.nameFound) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }
    EXPECT_FALSE(listener.nameFound);

    String uqnC = BusPtrC->GetUniqueName();

    BusPtrC->Stop();
    BusPtrC->Join();
    delete BusPtrC;

    //Wait for SessionLost on A
    for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
        if (sessionPortListenerA.sessionLost) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }

    status = BusPtrA->Ping(BusPtrB->GetUniqueName().c_str(), PING_DELAY_TIME);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // ping unique name for BusPtrC ASACORE-1628
    status = BusPtrA->Ping(uqnC.c_str(), PING_DELAY_TIME);
    EXPECT_EQ(ER_ALLJOYN_PING_REPLY_UNKNOWN_NAME, status) << "  Actual Status: " << QCC_StatusText(status);

    // cancel find
    status = BusPtrB->CancelFindAdvertisedName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // unregister
    BusPtrB->UnregisterBusListener(listener);

    // release name
    status = BusPtrA->ReleaseName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // unbind port
    status = BusPtrA->UnbindSessionPort(sessionPortListenerA.port);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
}

// Ping should work after discovery if the name was selectively discovered over one transport
// advertise with all transports and find TCP
TEST_F(R2RTest, Presence_DiscoveryAdvertiseAllFindByTCP) {
    QStatus status = ER_OK;

    // initialize listener callback
    R2RTestFindNameListener listener;

    // set unique name
    listener.NameToMatch = "org.test.A" + BusPtrA->GetGlobalGUIDShortString();

    // request name
    status = BusPtrA->RequestName(listener.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // advertise name over all transports
    status = BusPtrA->AdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_ANY);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // register second bus listener for 2nd routing node
    BusPtrB->RegisterBusListener(listener);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // find advertised name (TCP transport)
    status = BusPtrB->FindAdvertisedNameByTransport(listener.NameToMatch.c_str(), TRANSPORT_TCP);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // wait for to find name
    for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
        if ((listener.nameFound) && (listener.nameMatched)) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }
    ASSERT_TRUE(listener.nameFound) << "failed to find advertised name via TCP transport: " << listener.NameToMatch.c_str();
    ASSERT_TRUE(listener.nameMatched) << "failed to find advertised name via TCP transport: " << listener.NameToMatch.c_str();

    // ping
    status = BusPtrB->Ping(listener.NameToMatch.c_str(), PING_DELAY_TIME);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // cancel find
    status = BusPtrB->CancelFindAdvertisedNameByTransport(listener.NameToMatch.c_str(), TRANSPORT_TCP);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // unregister
    BusPtrB->UnregisterBusListener(listener);

    // cancel advertise
    status = BusPtrA->CancelAdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_ANY);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // release name
    status = BusPtrA->ReleaseName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
}

// Ping should work after discovery if the name was selectively discovered over one transport
// advertise with all transports and find UDP
// disable until 14.10 when TRANSPORT_ALL includes UDP
TEST_F(R2RTest, DISABLED_Presence_DiscoveryAdvertiseAllFindByUDP) {
    QStatus status = ER_OK;

    // initialize listener callback
    R2RTestFindNameListener listener;

    // set unique name
    listener.NameToMatch = "org.test.A" + BusPtrA->GetGlobalGUIDShortString();

    // request name
    status = BusPtrA->RequestName(listener.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // advertise name over all transports
    status = BusPtrA->AdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_ANY);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // register second bus listener for 2nd routing node
    BusPtrB->RegisterBusListener(listener);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // find UDP transport
    status = BusPtrB->FindAdvertisedNameByTransport(listener.NameToMatch.c_str(), TRANSPORT_UDP);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // wait for to find name
    for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
        if ((listener.nameFound) && (listener.nameMatched)) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }
    ASSERT_TRUE(listener.nameFound) << "failed to find advertised name via UDP transport: " << listener.NameToMatch.c_str();
    ASSERT_TRUE(listener.nameMatched) << "failed to find advertised name via UDP transport: " << listener.NameToMatch.c_str();

    // ping
    status = BusPtrB->Ping(listener.NameToMatch.c_str(), PING_DELAY_TIME);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // cancel find
    status = BusPtrB->CancelFindAdvertisedNameByTransport(listener.NameToMatch.c_str(), TRANSPORT_UDP);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // unregister
    BusPtrB->UnregisterBusListener(listener);

    // cancel advertise
    status = BusPtrA->CancelAdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_ANY);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // release name
    status = BusPtrA->ReleaseName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
}

// advertise by transport TCP find by all
TEST_F(R2RTest, Presence_DiscoveryAdvertiseTCPFindByAll) {
    QStatus status = ER_OK;

    // set unique name
    R2RTestFindNameListener listener;
    listener.NameToMatch = "org.test.TCP.E" + BusPtrA->GetGlobalGUIDShortString();

    // request name
    status = BusPtrA->RequestName(listener.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // advertise name over TCP transport from local bus
    status = BusPtrA->AdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_TCP);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // register listener on second routing node
    BusPtrB->RegisterBusListener(listener);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // find advertised name (local transport any)
    status = BusPtrB->FindAdvertisedNameByTransport(listener.NameToMatch.c_str(), TRANSPORT_ANY);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // wait for to find name
    for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
        if ((listener.nameFound) && (listener.nameMatched)) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }
    ASSERT_TRUE(listener.nameFound) << "failed to find advertised name: " << listener.NameToMatch.c_str();
    ASSERT_TRUE(listener.nameMatched) << "failed to find advertised name via TCP transport: " << listener.NameToMatch.c_str();

    // ping
    status = BusPtrB->Ping(listener.NameToMatch.c_str(), PING_DELAY_TIME);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // cancel find
    status = BusPtrB->CancelFindAdvertisedNameByTransport(listener.NameToMatch.c_str(), TRANSPORT_TCP);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // unregister
    BusPtrB->UnregisterBusListener(listener);

    // cancel advertise
    status = BusPtrA->CancelAdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_ANY);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // relase name
    status = BusPtrA->ReleaseName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
}

// advertise by transport UDP find by all, Note TRANSPORT_ANY has UDP bit disabled wait for 14.10
TEST_F(R2RTest, DISABLED_Presence_DiscoveryAdvertiseUDPFindByAll) {
    QStatus status = ER_OK;

    // set unique name
    R2RTestFindNameListener listener;
    listener.NameToMatch = "org.test.UDP.F" + BusPtrA->GetGlobalGUIDShortString();

    // request name
    status = BusPtrA->RequestName(listener.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // advertise name over UDP transport from local bus
    status = BusPtrA->AdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_UDP);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // register listener on second routing node
    BusPtrB->RegisterBusListener(listener);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // find advertised name (local transport any)
    status = BusPtrB->FindAdvertisedNameByTransport(listener.NameToMatch.c_str(), TRANSPORT_ANY);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // wait for to find name
    for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
        if ((listener.nameFound) && (listener.nameMatched)) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }
    ASSERT_TRUE(listener.nameFound) << "failed to find advertised name: " << listener.NameToMatch.c_str();
    ASSERT_TRUE(listener.nameMatched) << "failed to find advertised name via UDP transport: " << listener.NameToMatch.c_str();

    // ping
    status = BusPtrB->Ping(listener.NameToMatch.c_str(), PING_DELAY_TIME);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // cancel find
    status = BusPtrB->CancelFindAdvertisedNameByTransport(listener.NameToMatch.c_str(), TRANSPORT_TCP);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // unregister
    BusPtrB->UnregisterBusListener(listener);

    // cancel advetise
    status = BusPtrA->CancelAdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_ANY);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // release name
    status = BusPtrA->ReleaseName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
}
//Negative test Verify that bogus unique names return failure
TEST_F(R2RTest, Presence_BogusUniqueName) {
    QStatus status = ER_OK;

    // initialize listener callback
    R2RTestFindNameListener listener;

    // set bogus unique name
    listener.NameToMatch = BusPtrA->GetUniqueName() + ".1";

    // advertise name
    status = BusPtrA->AdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_ANY);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // register second bus listener for 2nd bus attachment
    BusPtrB->RegisterBusListener(listener);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // find advertised name
    status = BusPtrB->FindAdvertisedName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // wait for to find name
    for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
        if ((listener.nameFound) && (listener.nameMatched)) {
            break;
        }
        qcc::Sleep(WAIT_TIME);
    }
    ASSERT_TRUE(listener.nameFound) << "failed to find advertised name: " << listener.NameToMatch.c_str();
    ASSERT_TRUE(listener.nameMatched) << "failed to find advertised name: " << listener.NameToMatch.c_str();

    // ping bogus unique names on remote router test 16
    status = BusPtrB->Ping(listener.NameToMatch.c_str(), PING_DELAY_TIME);
    EXPECT_EQ(ER_ALLJOYN_PING_REPLY_UNKNOWN_NAME, status) << "  Actual Status: " << QCC_StatusText(status);

    status = BusPtrB->Ping(String(BusPtrA->GetUniqueName() + "0").c_str(), PING_DELAY_TIME);
    EXPECT_EQ(ER_ALLJOYN_PING_REPLY_UNKNOWN_NAME, status) << "  Actual Status: " << QCC_StatusText(status);

    // test 16
    status = BusPtrB->Ping(String(BusPtrA->GetUniqueName() + ".lo").c_str(), PING_DELAY_TIME);
    EXPECT_EQ(ER_ALLJOYN_PING_REPLY_UNKNOWN_NAME, status) << "  Actual Status: " << QCC_StatusText(status);

    // cancel find
    status = BusPtrB->CancelFindAdvertisedName(listener.NameToMatch.c_str());
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

    // unregister
    BusPtrB->UnregisterBusListener(listener);

    // cancel advertise
    status = BusPtrA->CancelAdvertiseName(listener.NameToMatch.c_str(), TRANSPORT_ANY);
    EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

}


