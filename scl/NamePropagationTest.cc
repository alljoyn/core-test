/******************************************************************************
 * Copyright (c) 2015, AllSeen Alliance. All rights reserved.
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
// Note that two routing nodes need to be started before running these tests:
// One using the default routing node config
// and another using a different port number and listening on unix-abstract=alljoyn2.


#include <gtest/gtest.h>

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <vector>

#include <qcc/platform.h>
#include <qcc/Thread.h>
#include <qcc/Util.h>
#include <qcc/String.h>
#include <qcc/time.h>

#include <alljoyn/BusAttachment.h>
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
    int status = 0;
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);

    std::cout << "\n Running common unit test " << std::endl;
    testing::InitGoogleTest(&argc, argv);
    status = RUN_ALL_TESTS();

    std::cout << argv[0] << " exiting with status " << status << std::endl;
    return (int) status;
}

// Name propagation test class
class NamePropagationTest : public testing::Test {
  public:
    BusAttachment* BusPtrA;
    BusAttachment* BusPtrB;
    BusAttachment* BusPtrC;
    BusAttachment* BusPtrD;
    BusAttachment* BusPtrE;

    virtual void SetUp() {
        QStatus status = ER_OK;

        BusPtrA = new BusAttachment("busAttachmentA", true);
        BusPtrB = new BusAttachment("busAttachmentB", true);
        BusPtrC = new BusAttachment("busAttachmentC", true);
        BusPtrD = new BusAttachment("busAttachmentD", true);
        BusPtrE = new BusAttachment("busAttachmentE", true);

        // start second bus attachmetn on unix abstract first so local bus
        // attachement does not bind port 9955

        // start busB connection external sample daemon
        status = BusPtrB->Start();
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
        status = BusPtrB->Connect("unix:abstract=alljoyn");
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

        // start busC connection external sample daemon
        status = BusPtrC->Start();
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
        status = BusPtrC->Connect("unix:abstract=alljoyn");
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

        // start busD connection using second external sample daemon
        status = BusPtrD->Start();
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
        status = BusPtrD->Connect("unix:abstract=alljoyn2");
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

        // start busE connection using second external sample daemon
        status = BusPtrE->Start();
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
        status = BusPtrE->Connect("unix:abstract=alljoyn2");
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

        // advertise quiet name to open port on Andriod OS,
        status = BusPtrB->AdvertiseName("quiet@NamePropTest.randomNameB", TRANSPORT_ANY);
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

        // advertise quiet name to open port on Andriod OS,
        status = BusPtrD->AdvertiseName("quiet@NamePropTest.randomNameD", TRANSPORT_ANY);
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

        // start busA connection internal
        status = BusPtrA->Start();
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
        status = BusPtrA->Connect("null:");
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

        status = BusPtrA->AdvertiseName("quiet@NamePropTest.randomNameA", TRANSPORT_ANY);
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
        // validate that both alljoyn-daemons are running before running the tests
        size_t first = (BusPtrB->GetUniqueName()).find_first_of(":");
        size_t last = (BusPtrB->GetUniqueName()).find_last_of(".");
        size_t npos = (last - first) - 1;
        qcc::String strTestA = (BusPtrA->GetUniqueName()).substr(1, npos);
        qcc::String strTestB = (BusPtrB->GetUniqueName()).substr(1, npos);
        ASSERT_STRNE(strTestA.c_str(), strTestB.c_str()) << " first alljoyn-daemon not active! Ending test... ";

        qcc::String strTestD = (BusPtrD->GetUniqueName()).substr(1, npos);
        ASSERT_STRNE(strTestA.c_str(), strTestD.c_str()) << " second alljoyn-daemon not active! Ending test... ";
        ASSERT_STRNE(strTestB.c_str(), strTestD.c_str()) << " second alljoyn-daemon not active! Ending test... ";
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

        status = BusPtrC->Disconnect();
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
        BusPtrC->Stop();
        BusPtrC->Join();
        delete BusPtrC;

        status = BusPtrD->Disconnect();
        ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
        BusPtrD->Stop();
        BusPtrD->Join();
        delete BusPtrD;

    }

};

// callback bus listener
class NamePropTestFindNameListener : public BusListener {
  public:

    NamePropTestFindNameListener(String busAttachmentName = "") : nameFound(0), nameMatched(0), busAttachmentName(busAttachmentName) { }

    bool nameFound;
    bool nameMatched;
    String NameToMatch;
    String busAttachmentName;

    set<String> presenceNOCS;
    set<String> absenceNOCS;
    void FoundAdvertisedName(const char* name, TransportMask transport, const char* namePrefix) {
        nameFound = true;
        if (strcmp(name, NameToMatch.c_str()) == 0) {
            nameMatched = true;
        }
    }
    void LostAdvertisedName(const char* name, TransportMask transport, const char* namePrefix) {
        if (strcmp(name, NameToMatch.c_str()) == 0) {
            nameFound = false;
        }
    }
    void NameOwnerChanged(const char* busName, const char* previousOwner, const char* newOwner) {
        if (previousOwner == NULL) {
            presenceNOCS.insert(busName);
        } else {
            absenceNOCS.insert(busName);
        }

    }

    bool GotPresenceNOCFor(String name) {
        return (presenceNOCS.find(name) != presenceNOCS.end());
    }

    bool GotAbsenceNOCFor(String name) {
        return (absenceNOCS.find(name) != absenceNOCS.end());
    }

};

// session join listener class
class NamePropTestSessionListener : public SessionPortListener, SessionListener {
  public:

    NamePropTestSessionListener(BusAttachment* bus = NULL) : bus(bus), sessionAccepted(0), sessionJoined(0),
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
        if (sessionPort == port) {
            sessionAccepted = true;
            return true;
        } else {
            sessionAccepted = false;
            return false;
        }
    }

    void SessionLost(SessionId id, SessionListener::SessionLostReason reason) {
        sessionLost = true;
    }

    void SessionJoined(SessionPort sessionPort, SessionId id, const char* joiner) {
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

TransportMask transportMasks[2] = { TRANSPORT_TCP, TRANSPORT_TCP };
#define EXCHANGE_ALL_NAMES 0
#if (ALLJOYN_PROTOCOL_VERSION < 12)

int nameTransferTypes[1] = { -1 };
#else

#define EXCHANGE_SESSION_NAMES 1
int nameTransferTypes[3] = { -1, EXCHANGE_ALL_NAMES, EXCHANGE_SESSION_NAMES };
#endif
/* TwoRoutingNodeP2PSessionTest1:
 * Perform test for UDP and TCP and for nameTransferType EXCHANGE_SESSION_NAMES and EXCHANGE_ALL_NAMES
 * P2P session
 * (B)-(SR)         (BR)-(A)
 *      |
 *     (C)
 * SR = standalone RN
 * BR = bundled RN
 * B requests, advertises a name and binds a P2P session.
 * A finds and joins the session.
 * Check session IDs match.
 * Expected: A gets Presence NOC for B and the SR.
 *           A gets Presence NOC for C only if this is an EXCHANGE_ALL_NAMES session.
 *               B gets Presence NOC for A and BR.
 *               C gets Presence NOC for A and BR.
 * C finds and joins the session.
 * C leaves session
 * A leaves session
 * Expected: A gets Absence NOC for B and the SR. A gets Absence NOC for C only if this is an EXCHANGE_ALL_NAMES session.
 *               C gets Absence NOC for A and BR.
 *               C does not get Absence NOC for B.
 */
TEST_F(NamePropagationTest, TwoRoutingNodeP2PSessionTest1) {
    QStatus status = ER_OK;

    for (size_t i = 0; i < sizeof(transportMasks) / sizeof(TransportMask); i++) {

        TransportMask tm = transportMasks[i];


        for (size_t j = 0; j < sizeof(nameTransferTypes) / sizeof(SessionOpts::NameTransferType); j++) {
            SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
            int nm = nameTransferTypes[j];
#if (ALLJOYN_PROTOCOL_VERSION < 12)
            if (nm != -1) {
                /* Only run test once for lower protocol versions */
                break;
            }
#else
            switch (nm) {
            case EXCHANGE_ALL_NAMES:
                opts.SetAllNames();
                break;

            case EXCHANGE_SESSION_NAMES:
                opts.SetSessionNames();
                break;

            default:
                break;
            }
#endif

            /* Set up bus listeners */
            NamePropTestFindNameListener listenerA("busAttachmentA");
            listenerA.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();

            BusPtrA->RegisterBusListener(listenerA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerB("busAttachmentB");
            listenerB.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();

            BusPtrB->RegisterBusListener(listenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerC("busAttachmentC");
            listenerC.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();

            BusPtrC->RegisterBusListener(listenerC);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Request name, advertise, bind session */
            status = BusPtrB->RequestName(listenerA.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->AdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestSessionListener sessionPortListenerB(BusPtrB);
            status = BusPtrB->BindSessionPort(sessionPortListenerB.port, opts, sessionPortListenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Find Name */
            status = BusPtrA->FindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerA.nameFound) && (listenerA.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerA.nameFound) << "failed to find advertised name: " << listenerA.NameToMatch.c_str();
            ASSERT_TRUE(listenerA.nameMatched) << "failed to find advertised name via UDP transport: " << listenerA.NameToMatch.c_str();

            /* BusAttachment A: JoinSession */
            SessionId sessionIdA = 0;
            status = BusPtrA->JoinSession(listenerA.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdA, opts);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerB.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session IDs are matching */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdA) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdA) << "  session ID's do not match";

            String bundledRouter = BusPtrA->GetUniqueName().substr(0, BusPtrA->GetUniqueName().find('.')) + ".1";
            String standAloneRouter = BusPtrB->GetUniqueName().substr(0, BusPtrB->GetUniqueName().find('.')) + ".1";

            /* BusAttachment A: Gets Presence NOC for B, SR.
             * Gets Presence NOC for C if protocol version <12 or EXCHANGE_ALL_NAMES nameTransfer was used.
             * BusAttachment B: Gets Presence NOC for A, BR.
             * BusAttachment C: Gets Presence NOC for A, BR.
             * No Absence NOCs must be received at this point.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerB.GotPresenceNOCFor(bundledRouter) &&
                    listenerC.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerC.GotPresenceNOCFor(bundledRouter) &&
                    listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerA.GotPresenceNOCFor(standAloneRouter) &&
                    ((ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) ||
                     listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()))) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }


            EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotPresenceNOCFor(standAloneRouter));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));
            } else {
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));
            }
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));

            EXPECT_TRUE(listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(bundledRouter));
            EXPECT_FALSE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_FALSE(listenerB.GotAbsenceNOCFor(bundledRouter));

            EXPECT_TRUE(listenerC.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerC.GotPresenceNOCFor(bundledRouter));
            EXPECT_FALSE(listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_FALSE(listenerC.GotAbsenceNOCFor(bundledRouter));

            /* BusAttachment C: find advertised name */
            status = BusPtrC->FindAdvertisedNameByTransport(listenerC.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment C: Wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerC.nameFound) && (listenerC.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerC.nameFound) << "failed to find advertised name: " << listenerC.NameToMatch.c_str();
            ASSERT_TRUE(listenerC.nameMatched) << "failed to find advertised name via UDP transport: " << listenerC.NameToMatch.c_str();

            /* BusAttachment C: JoinSession */
            sessionPortListenerB.sessionJoined = false;
            SessionId sessionIdC = 0;
            status = BusPtrC->JoinSession(listenerC.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdC, opts);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerB.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session IDs are matching */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdC) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdC) << "  session ID's do not match";

            /* CancelFindAdvertisedName */
            status = BusPtrA->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrC->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Leave session */
            status = BusPtrA->LeaveSession(sessionIdA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Gets Absence NOC for B, SR.
             * Gets Absence NOC for C if protocol version <12 or EXCHANGE_ALL_NAMES nameTransfer was used.
             * BusAttachment B: Gets Absence NOC for A, BR.
             * BusAttachment C: Gets Absence NOC for A, BR.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerA.GotAbsenceNOCFor(standAloneRouter) &&
                    ((ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) ||
                     listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName())) &&
                    listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerB.GotAbsenceNOCFor(bundledRouter) &&
                    listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerC.GotAbsenceNOCFor(bundledRouter)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(standAloneRouter));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));
            } else {
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));
            }

            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(bundledRouter));
            EXPECT_TRUE(listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerC.GotAbsenceNOCFor(bundledRouter));

            /* BusAttachment C: Leave session */
            status = BusPtrC->LeaveSession(sessionIdC);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachments B and C must not receive Absence NOCs for each other since
             * these are connected to the same Routing node.
             */
            EXPECT_FALSE(listenerB.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));
            EXPECT_FALSE(listenerC.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));

            /* Unregister Bus Listeners */
            BusPtrA->UnregisterBusListener(listenerA);
            BusPtrB->UnregisterBusListener(listenerB);
            BusPtrC->UnregisterBusListener(listenerC);

            /* BusAttachment B: CancelAdvertiseName and ReleaseName */
            status = BusPtrB->CancelAdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->ReleaseName(listenerA.NameToMatch.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
        }
    }
}

/* TwoRoutingNodeP2PSessionTest2:
 * Difference is in the order of JoinSessions.
 * Perform test for UDP and TCP and for nameTransferType EXCHANGE_SESSION_NAMES and EXCHANGE_ALL_NAMES
 * (B)-(SR)         (BR)-(A)
 *      |
 *     (C)
 * SR = standalone RN
 * BR = bundled RN
 * B requests, advertises a name and binds a P2P session.
 * C finds and joins the session.
 * Check session IDs match.
 * A finds and joins the session.
 * Check session IDs match.
 * Expected: A gets Presence NOC for B and the SR.
 *           A gets Presence NOC for C only if this is an EXCHANGE_ALL_NAMES session.
 *               B gets Presence NOC for A and BR.
 *               C gets Presence NOC for A and BR.
 * C leaves session
 * A leaves session
 * Expected: A gets Absence NOC for B and the SR. A gets Absence NOC for C only if this is an EXCHANGE_ALL_NAMES session.
 *               B gets Absence NOC for A and BR.
 *               C gets Absence NOC for A and BR.
 *               C does not get Absence NOC for B.
 */
TEST_F(NamePropagationTest, TwoRoutingNodeP2PSessionTest2) {
    QStatus status = ER_OK;

    for (size_t i = 0; i < sizeof(transportMasks) / sizeof(TransportMask); i++) {
        TransportMask tm = transportMasks[i];
        for (size_t j = 0; j < sizeof(nameTransferTypes) / sizeof(SessionOpts::NameTransferType); j++) {
            SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
            int nm = nameTransferTypes[j];
#if (ALLJOYN_PROTOCOL_VERSION < 12)
            if (nm != -1) {
                /* Only run test once for lower protocol versions */
                break;
            }
#else
            switch (nm) {
            case EXCHANGE_ALL_NAMES:
                opts.SetAllNames();
                break;

            case EXCHANGE_SESSION_NAMES:
                opts.SetSessionNames();
                break;

            default:
                break;
            }
#endif
            /* Set up bus listeners */
            NamePropTestFindNameListener listenerA("busAttachmentA");
            listenerA.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrA->RegisterBusListener(listenerA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerB("busAttachmentB");
            listenerB.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrB->RegisterBusListener(listenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerC("busAttachmentC");
            listenerC.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrC->RegisterBusListener(listenerC);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Request name, advertise, bind session */
            status = BusPtrB->RequestName(listenerA.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->AdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestSessionListener sessionPortListenerB(BusPtrB);
            status = BusPtrB->BindSessionPort(sessionPortListenerB.port, opts, sessionPortListenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Find name */
            status = BusPtrA->FindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerA.nameFound) && (listenerA.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerA.nameFound) << "failed to find advertised name: " << listenerA.NameToMatch.c_str();
            ASSERT_TRUE(listenerA.nameMatched) << "failed to find advertised name via UDP transport: " << listenerA.NameToMatch.c_str();

            /* BusAttachment C: Find name */
            status = BusPtrC->FindAdvertisedNameByTransport(listenerC.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment C: Wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerC.nameFound) && (listenerC.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerC.nameFound) << "failed to find advertised name: " << listenerC.NameToMatch.c_str();
            ASSERT_TRUE(listenerC.nameMatched) << "failed to find advertised name via UDP transport: " << listenerC.NameToMatch.c_str();

            /* BusAttachment C: JoinSession */
            SessionId sessionIdC = 0;
            status = BusPtrC->JoinSession(listenerC.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdC, opts);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerB.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session IDs */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdC) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdC) << "  session ID's do not match";

            sessionPortListenerB.sessionJoined = false;

            /* BusAttachment A: JoinSession */
            SessionId sessionIdA = 0;
            status = BusPtrA->JoinSession(listenerA.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdA, opts);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerB.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session IDs */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdA) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdA) << "  session ID's do not match";


            String bundledRouter = BusPtrA->GetUniqueName().substr(0, BusPtrA->GetUniqueName().find('.')) + ".1";
            String standaloneRouter = BusPtrB->GetUniqueName().substr(0, BusPtrB->GetUniqueName().find('.')) + ".1";

            /* BusAttachment A: Gets Presence NOC for B, SR.
             * Gets Presence NOC for C if protocol version <12 or EXCHANGE_ALL_NAMES nameTransfer was used.
             * BusAttachment B: Gets Presence NOC for A, BR.
             * BusAttachment C: Gets Presence NOC for A, BR.
             * No Absence NOCs must be received at this point.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerB.GotPresenceNOCFor(bundledRouter) &&
                    listenerC.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerC.GotPresenceNOCFor(bundledRouter) &&
                    listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerA.GotPresenceNOCFor(standaloneRouter) &&
                    ((ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) ||
                     listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()))) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotPresenceNOCFor(standaloneRouter));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));
            } else {
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));
            }
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));

            EXPECT_TRUE(listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(bundledRouter));
            EXPECT_FALSE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_FALSE(listenerB.GotAbsenceNOCFor(bundledRouter));

            EXPECT_TRUE(listenerC.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerC.GotPresenceNOCFor(bundledRouter));
            EXPECT_FALSE(listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_FALSE(listenerC.GotAbsenceNOCFor(bundledRouter));

            /* Cancel findAdvertisedName */
            status = BusPtrA->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrC->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* Leave sessions */
            status = BusPtrA->LeaveSession(sessionIdA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrC->LeaveSession(sessionIdC);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Gets Absence NOC for B, SR.
             * Gets Absence NOC for C if protocol version <12 or EXCHANGE_ALL_NAMES nameTransfer was used.
             * BusAttachment B: Gets Absence NOC for A, BR.
             * BusAttachment C: Gets Absence NOC for A, BR.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (((ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) ||
                     listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()))  &&
                    listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerB.GotAbsenceNOCFor(bundledRouter) &&
                    listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerC.GotAbsenceNOCFor(bundledRouter)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));
            } else {
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));

            }

            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(bundledRouter));
            EXPECT_TRUE(listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerC.GotAbsenceNOCFor(bundledRouter));

            EXPECT_FALSE(listenerC.GotPresenceNOCFor(BusPtrB->GetUniqueName()));

            /* Unregister Bus Listeners */
            BusPtrA->UnregisterBusListener(listenerA);
            BusPtrB->UnregisterBusListener(listenerB);
            BusPtrC->UnregisterBusListener(listenerC);

            /* BusAttachment B: CancelAdvertiseName, ReleaseName */
            status = BusPtrB->CancelAdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->ReleaseName(listenerA.NameToMatch.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
        }
    }
}

/*
 * TwoRoutingNodeP2PSessionTest3:
 * Difference is in the direction of JoinSession.
 * Perform test for UDP and TCP and for nameTransferType EXCHANGE_SESSION_NAMES and EXCHANGE_ALL_NAMES
 * (B)-(SR)         (BR)-(A)
 *      |
 *     (C)
 * SR = standalone RN
 * BR = bundled RN
 * A requests, advertises a name and binds a P2P session.
 * B finds and joins the session.
 * Check session IDs match.
 * Expected: A gets Presence NOC for B and the SR.
 *           A gets Presence NOC for C only if this is an EXCHANGE_ALL_NAMES session.
 *               B gets Presence NOC for A and BR.
 *               C gets Presence NOC for A and BR.
 * A leaves session
 * Expected: A gets Absence NOC for B and the SR. A gets Absence NOC for C only if this is an EXCHANGE_ALL_NAMES session.
 *               B gets Absence NOC for A and BR.
 *               C gets Absence NOC for A and BR.
 *               C does not get Absence NOC for B.
 */
TEST_F(NamePropagationTest, TwoRoutingNodeP2PSessionTest3) {
    QStatus status = ER_OK;

    for (size_t i = 0; i < sizeof(transportMasks) / sizeof(TransportMask); i++) {

        TransportMask tm = transportMasks[i];
        for (size_t j = 0; j < sizeof(nameTransferTypes) / sizeof(SessionOpts::NameTransferType); j++) {
            SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
            int nm = nameTransferTypes[j];
#if (ALLJOYN_PROTOCOL_VERSION < 12)
            if (nm != -1) {
                /* Only run test once for lower protocol versions */
                break;
            }
#else
            switch (nm) {
            case EXCHANGE_ALL_NAMES:
                opts.SetAllNames();
                break;

            case EXCHANGE_SESSION_NAMES:
                opts.SetSessionNames();
                break;

            default:
                break;
            }
#endif
            /* Set up bus listeners */
            NamePropTestFindNameListener listenerA("busAttachmentA");
            listenerA.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrA->RegisterBusListener(listenerA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerB("busAttachmentB");
            listenerB.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrB->RegisterBusListener(listenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerC("busAttachmentC");
            listenerC.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrC->RegisterBusListener(listenerC);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Request name, advertise, bind session */
            status = BusPtrA->RequestName(listenerA.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrA->AdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestSessionListener sessionPortListenerA(BusPtrA);
            status = BusPtrA->BindSessionPort(sessionPortListenerA.port, opts, sessionPortListenerA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Find name */
            status = BusPtrB->FindAdvertisedNameByTransport(listenerB.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerB.nameFound) && (listenerB.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerB.nameFound) << "failed to find advertised name: " << listenerA.NameToMatch.c_str();
            ASSERT_TRUE(listenerB.nameMatched) << "failed to find advertised name via UDP transport: " << listenerA.NameToMatch.c_str();

            /* BusAttachment B: JoinSession */
            SessionId sessionIdB = 0;
            status = BusPtrB->JoinSession(listenerA.NameToMatch.c_str(), sessionPortListenerA.port, NULL, sessionIdB, opts);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerA.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session IDs */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdB) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerA.busSessionId, sessionIdB) << "  session ID's do not match";

            String bundledRouter = BusPtrA->GetUniqueName().substr(0, BusPtrA->GetUniqueName().find('.')) + ".1";
            String standAloneRouter = BusPtrB->GetUniqueName().substr(0, BusPtrB->GetUniqueName().find('.')) + ".1";

            /* BusAttachment A: Gets Presence NOC for B, SR.
             * Gets Presence NOC for C if protocol version <12 or EXCHANGE_ALL_NAMES nameTransfer was used.
             * BusAttachment B: Gets Presence NOC for A, BR.
             * BusAttachment C: Gets Presence NOC for A, BR.
             * No Absence NOCs must be received at this point.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerA.GotPresenceNOCFor(standAloneRouter) &&
                    ((ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) ||
                     listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName())) &&
                    listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerB.GotPresenceNOCFor(bundledRouter) &&
                    listenerC.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerC.GotPresenceNOCFor(bundledRouter)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotPresenceNOCFor(standAloneRouter));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));
            } else {
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));

            }
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(standAloneRouter));
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));

            EXPECT_TRUE(listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(bundledRouter));
            EXPECT_FALSE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_FALSE(listenerB.GotAbsenceNOCFor(bundledRouter));

            EXPECT_TRUE(listenerC.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerC.GotPresenceNOCFor(bundledRouter));
            EXPECT_FALSE(listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_FALSE(listenerC.GotAbsenceNOCFor(bundledRouter));

            /* BusAttachment B: CancelFindAdvertisedName */
            status = BusPtrB->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* Verify no Absence NOCs are received */
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(standAloneRouter));
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));

            /* BusAttachment A: Leave session */
            status = BusPtrA->LeaveSession(sessionIdB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Gets Absence NOC for B, SR.
             * Gets Absence NOC for C if protocol version <12 or EXCHANGE_ALL_NAMES nameTransfer was used.
             * BusAttachment B: Gets Absence NOC for A, BR.
             * BusAttachment C: Gets Absence NOC for A, BR.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerA.GotAbsenceNOCFor(standAloneRouter) &&
                    ((ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) ||
                     listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName())) &&
                    listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerB.GotAbsenceNOCFor(bundledRouter) &&
                    listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerC.GotAbsenceNOCFor(bundledRouter)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));
            } else {
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));
            }
            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(standAloneRouter));

            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(bundledRouter));

            EXPECT_TRUE(listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerC.GotAbsenceNOCFor(bundledRouter));

            /* Unregister Bus Listeners */
            BusPtrA->UnregisterBusListener(listenerA);
            BusPtrB->UnregisterBusListener(listenerB);
            BusPtrC->UnregisterBusListener(listenerC);

            /* BusAttachment A: CancelAdvertiseName, ReleaseName */
            status = BusPtrA->CancelAdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrA->ReleaseName(listenerA.NameToMatch.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
        }
    }
}

/*
 * P2P_ValidateResultantNameTransferType:
 * Validate the resultant Name transfer type for various combination of inputs.
 * Perform test for UDP and TCP for nameTransfer type values: default, EXCHANGE_SESSION_NAMES, EXCHANGE_ALL_NAMES.
 * (B)-(SR)         (BR)-(A)
 *      |
 *     (C)
 * SR = standalone RN
 * BR = bundled RN
 * B requests, advertises a name and binds a P2P session.
 * A finds and joins the session.
 * Check session IDs match.
 * Validate resultant nameTransfer Type:
 * If both are default or both are EXCHANGE_SESSION_NAMES, resultant is EXCHANGE_SESSION_NAMES.
 * otherwise if any is EXCHANGE_ALL_NAMES, result is EXCHANGE_ALL_NAMES.
 * Expected: A gets Presence NOC for B and the SR.
 *           A gets Presence NOC for C only if this is an EXCHANGE_ALL_NAMES session.
 *               B gets Presence NOC for A and BR.
 *               C gets Presence NOC for A and BR.
 * A leaves session
 * Expected: A gets Absence NOC for B and the SR. A gets Absence NOC for C only if this is an EXCHANGE_ALL_NAMES session.
 *               B gets Absence NOC for A and BR.
 *               C gets Absence NOC for A and BR.
 *               C does not get Absence NOC for B.
 */
TEST_F(NamePropagationTest, P2P_ValidateResultantNameTransferType) {
#if (ALLJOYN_PROTOCOL_VERSION < 12)
    /* Skip this test for lower protocol versions. */
    return;
#else
    QStatus status = ER_OK;
    for (size_t i = 0; i < sizeof(transportMasks) / sizeof(TransportMask); i++) {

        TransportMask tm = transportMasks[i];
        for (size_t j = 0; j < sizeof(nameTransferTypes) / sizeof(SessionOpts::NameTransferType); j++) {
            for (size_t k = 0; k < sizeof(nameTransferTypes) / sizeof(SessionOpts::NameTransferType); k++) {
                SessionOpts optsHost(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
                SessionOpts optsJoiner(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);

                switch (nameTransferTypes[j]) {
                case EXCHANGE_ALL_NAMES:
                    optsHost.SetAllNames();
                    break;

                case EXCHANGE_SESSION_NAMES:
                    optsHost.SetSessionNames();
                    break;

                default:
                    break;
                }
                switch (nameTransferTypes[k]) {
                case EXCHANGE_ALL_NAMES:
                    optsJoiner.SetAllNames();
                    break;

                case EXCHANGE_SESSION_NAMES:
                    optsJoiner.SetSessionNames();
                    break;

                default:
                    break;
                }
                /* Set up bus listeners */
                NamePropTestFindNameListener listenerA("busAttachmentA");
                listenerA.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
                BusPtrA->RegisterBusListener(listenerA);
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                NamePropTestFindNameListener listenerB("busAttachmentB");
                listenerB.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
                BusPtrB->RegisterBusListener(listenerB);
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                NamePropTestFindNameListener listenerC("busAttachmentC");
                listenerC.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
                BusPtrC->RegisterBusListener(listenerC);
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                /* BusAttachment B: Request name, advertise, bind session */
                status = BusPtrB->RequestName(listenerA.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                status = BusPtrB->AdvertiseName(listenerA.NameToMatch.c_str(), tm);
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                NamePropTestSessionListener sessionPortListenerB(BusPtrB);
                status = BusPtrB->BindSessionPort(sessionPortListenerB.port, optsHost, sessionPortListenerB);
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                /* BusAttachment A: find advertised name */
                status = BusPtrA->FindAdvertisedNameByTransport(listenerB.NameToMatch.c_str(), TRANSPORT_ANY);
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                /* BusAttachment A: wait for FoundAdvertisedName */
                for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                    if ((listenerA.nameFound) && (listenerA.nameMatched)) {
                        break;
                    }
                    qcc::Sleep(WAIT_TIME);
                }
                ASSERT_TRUE(listenerA.nameFound) << "failed to find advertised name: " << listenerA.NameToMatch.c_str();
                ASSERT_TRUE(listenerA.nameMatched) << "failed to find advertised name via UDP transport: " << listenerA.NameToMatch.c_str();

                /* BusAttachment A: JoinSession */
                SessionId sessionIdA = 0;
                status = BusPtrA->JoinSession(listenerA.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdA, optsJoiner);
                ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                /* BusAttachment B: wait for SessionJoined */
                for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                    if (sessionPortListenerB.sessionJoined) {
                        break;
                    }
                    qcc::Sleep(WAIT_TIME);
                }

                EXPECT_NE(static_cast<SessionId>(0), sessionIdA) << "  SessionID should not be '0'";
                EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdA) << "  session ID's do not match";

                /* Validate resultant nameTransfer Type:
                 * If both are default or both are EXCHANGE_SESSION_NAMES, resultant is EXCHANGE_SESSION_NAMES.
                 * otherwise if any is EXCHANGE_ALL_NAMES, result is EXCHANGE_ALL_NAMES.
                 */
                if ((nameTransferTypes[j] == EXCHANGE_ALL_NAMES) ||
                    (nameTransferTypes[k] == EXCHANGE_ALL_NAMES)) {
                    EXPECT_TRUE(optsJoiner.IsAllNames());
                    EXPECT_FALSE(optsJoiner.IsSessionNames());
                } else {
                    EXPECT_TRUE(optsJoiner.IsSessionNames());
                    EXPECT_FALSE(optsJoiner.IsAllNames());
                }

                String bundledRouter = BusPtrA->GetUniqueName().substr(0, BusPtrA->GetUniqueName().find('.')) + ".1";
                String standaloneRouter = BusPtrB->GetUniqueName().substr(0, BusPtrB->GetUniqueName().find('.')) + ".1";

                /* BusAttachment A: Gets Presence NOC for B, SR.
                 * Gets Presence NOC for C if protocol version <12 or EXCHANGE_ALL_NAMES nameTransfer was used.
                 * BusAttachment B: Gets Presence NOC for A, BR.
                 * BusAttachment C: Gets Presence NOC for A, BR.
                 * No Absence NOCs must be received at this point.
                 */
                for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                    if (listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()) &&
                        listenerA.GotPresenceNOCFor(standaloneRouter) &&
                        ((ALLJOYN_PROTOCOL_VERSION >= 12 && (optsJoiner.IsSessionNames())) ||
                         listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName())) &&
                        listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                        listenerB.GotPresenceNOCFor(bundledRouter) &&
                        listenerC.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                        listenerC.GotPresenceNOCFor(bundledRouter)) {
                        break;
                    }
                    qcc::Sleep(WAIT_TIME);
                }
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()));
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(standaloneRouter));
                if (optsJoiner.IsSessionNames()) {
                    EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));
                } else {
                    EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));

                }
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(standaloneRouter));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));

                EXPECT_TRUE(listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_TRUE(listenerB.GotPresenceNOCFor(bundledRouter));
                EXPECT_FALSE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_FALSE(listenerB.GotAbsenceNOCFor(bundledRouter));

                EXPECT_TRUE(listenerC.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_TRUE(listenerC.GotPresenceNOCFor(bundledRouter));
                EXPECT_FALSE(listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_FALSE(listenerC.GotAbsenceNOCFor(bundledRouter));

                /* BusAttachment A: cancel find */
                status = BusPtrA->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                /* Verify no Absence NOCs are received */
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(standaloneRouter));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));

                /* BusAttachment A: Leave session */
                status = BusPtrA->LeaveSession(sessionIdA);
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                /* BusAttachment A: Gets Absence NOC for B, SR.
                 * Gets Absence NOC for C if protocol version <12 or EXCHANGE_ALL_NAMES nameTransfer was used.
                 * BusAttachment B: Gets Absence NOC for A, BR.
                 * BusAttachment C: Gets Absence NOC for A, BR.
                 */
                for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                    if (listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()) &&
                        listenerA.GotAbsenceNOCFor(standaloneRouter) &&
                        ((ALLJOYN_PROTOCOL_VERSION >= 12 && (optsJoiner.IsSessionNames())) ||
                         listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName())) &&
                        listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                        listenerB.GotAbsenceNOCFor(bundledRouter) &&
                        listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                        listenerC.GotAbsenceNOCFor(bundledRouter)) {
                        break;
                    }
                    qcc::Sleep(WAIT_TIME);
                }

                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
                if (ALLJOYN_PROTOCOL_VERSION >= 12 && (optsJoiner.IsSessionNames())) {
                    EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));
                    EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));
                } else {
                    EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));
                }
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(standaloneRouter));

                EXPECT_TRUE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_TRUE(listenerB.GotAbsenceNOCFor(bundledRouter));

                EXPECT_TRUE(listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_TRUE(listenerC.GotAbsenceNOCFor(bundledRouter));

                /* Unregister Bus Listeners */
                BusPtrA->UnregisterBusListener(listenerA);
                BusPtrB->UnregisterBusListener(listenerB);
                BusPtrC->UnregisterBusListener(listenerC);

                /* BusAttachment B: CancelAdvertiseName, ReleaseName */
                status = BusPtrB->CancelAdvertiseName(listenerA.NameToMatch.c_str(), tm);
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                status = BusPtrB->ReleaseName(listenerA.NameToMatch.c_str());
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            }
        }
    }
#endif
}
/*
 * TwoRoutingNodeP2PWellKnownNames:
 * Verify that NOCs for well known names are received only when there is a session.
 * Perform test for UDP and TCP for nameTransfer type values: default, EXCHANGE_SESSION_NAMES, EXCHANGE_ALL_NAMES.
 * (B)-(SR)         (BR)-(A)
 *      |
 *     (C)
 * SR = standalone RN
 * BR = bundled RN
 * A and C request a wellknown name each.
 * B requests, advertises a name and binds a P2P session.
 * A finds and joins the session.
 * Check session IDs match.
 *
 * Expected: A gets Presence NOC for BusAttachment B's wellknown name. i.e. listenerA.NameToMatch
 * A does not get Presence NOC for BusAttachment C's wellknown name. i.e. wknC unless EXCHANGE_ALL_NAMES
 * B gets Presence NOC for BusAttachment A's wellknown name. i.e. wknA
 * C gets Presence NOC for BusAttachment A's wellknown name. i.e. wknA
 *
 * A, B and C release the wellknown names.
 *
 * Expected: A gets Absence NOC for BusAttachment B's wellknown name. i.e. listenerA.NameToMatch
 * A does not get Presence or Absence NOC for BusAttachment C's wellknown name. i.e. wknC unless EXCHANGE_ALL_NAMES
 * B gets Absence NOC for BusAttachment A's wellknown name. i.e. wknA
 * C gets Absence NOC for BusAttachment A's wellknown name. i.e. wknA
 *
 * A, B and C re-request new wellknown names.
 *
 * Expected: A gets Presence NOC for BusAttachment B's wellknown name. i.e. wknB
 * A does not get Presence NOC for BusAttachment C's wellknown name. i.e. wknC unless EXCHANGE_ALL_NAMES
 * B gets Presence NOC for BusAttachment A's wellknown name. i.e. wknA
 * C gets Presence NOC for BusAttachment A's wellknown name. i.e. wknA
 *
 */
TEST_F(NamePropagationTest, TwoRoutingNodeP2PWellKnownNames) {
    QStatus status = ER_OK;

    for (size_t i = 0; i < sizeof(transportMasks) / sizeof(TransportMask); i++) {

        TransportMask tm = transportMasks[i];
        for (size_t j = 0; j < sizeof(nameTransferTypes) / sizeof(SessionOpts::NameTransferType); j++) {
            SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
            int nm = nameTransferTypes[j];
#if (ALLJOYN_PROTOCOL_VERSION < 12)
            if (nm != -1) {
                /* Only run test once for lower protocol versions */
                break;
            }
#else
            switch (nm) {
            case EXCHANGE_ALL_NAMES:
                opts.SetAllNames();
                break;

            case EXCHANGE_SESSION_NAMES:
                opts.SetSessionNames();
                break;

            default:
                break;
            }
#endif            /* Set up bus listeners */
            String wknB = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            NamePropTestFindNameListener listenerA("busAttachmentA");
            listenerA.NameToMatch = wknB;
            BusPtrA->RegisterBusListener(listenerA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerB("busAttachmentB");
            listenerB.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrB->RegisterBusListener(listenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerC("busAttachmentC");
            listenerC.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrC->RegisterBusListener(listenerC);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: request a wellknown name */
            String wknA = "org.test.A" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrA->RequestName(wknA.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment C: request a wellknown name */
            String wknC = "org.test.C" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrC->RequestName(wknC.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Request name, advertise, bind session */
            status = BusPtrB->RequestName(listenerA.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->AdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestSessionListener sessionPortListenerB(BusPtrB);
            status = BusPtrB->BindSessionPort(sessionPortListenerB.port, opts, sessionPortListenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: find advertised name */
            status = BusPtrA->FindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerA.nameFound) && (listenerA.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerA.nameFound) << "failed to find advertised name: " << listenerA.NameToMatch.c_str();
            ASSERT_TRUE(listenerA.nameMatched) << "failed to find advertised name" << listenerA.NameToMatch.c_str();

            /* BusAttachment A: JoinSession */
            SessionId sessionIdA = 0;
            status = BusPtrA->JoinSession(listenerA.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdA, opts);
            ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerB.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session ID */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdA) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdA) << "  session ID's do not match";

            /* BusAttachment A: Gets Presence NOC for BusAttachment B's wellknown name. i.e. listenerA.NameToMatch
             * BusAttachment A does not get Presence NOC for BusAttachment C's wellknown name. i.e. wknC
             * BusAttachment B: Gets Presence NOC for BusAttachment A's wellknown name. i.e. wknA
             * BusAttachment C: Gets Presence NOC for BusAttachment A's wellknown name. i.e. wknA
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotPresenceNOCFor(listenerA.NameToMatch) && listenerB.GotPresenceNOCFor(wknA) &&
                    listenerC.GotPresenceNOCFor(wknA) &&
                    ((ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) ||
                     listenerA.GotPresenceNOCFor(wknC))) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotPresenceNOCFor(listenerA.NameToMatch));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(wknC));
            } else {
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(wknC));
            }
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(wknA));
            EXPECT_TRUE(listenerC.GotPresenceNOCFor(wknA));

            /* BusAttachment A: cancel find */
            status = BusPtrA->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* Release all names */
            status = BusPtrA->ReleaseName(wknA.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->ReleaseName(wknB.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrC->ReleaseName(wknC.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Gets Absence NOC for BusAttachment B's wellknown name. i.e. wknB
             * BusAttachment A does not get Presence or Absence NOC for BusAttachment C's wellknown name. i.e. wknC
             * BusAttachment B: Gets Absence NOC for BusAttachment A's wellknown name. i.e. wknA
             * BusAttachment C: Gets Absence NOC for BusAttachment A's wellknown name. i.e. wknA
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotAbsenceNOCFor(wknB) && listenerB.GotAbsenceNOCFor(wknA) &&
                    listenerC.GotAbsenceNOCFor(wknA) &&
                    ((ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) ||
                     listenerA.GotAbsenceNOCFor(wknC))) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(wknB));
            if ((ALLJOYN_PROTOCOL_VERSION >= 12) && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(wknC));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(wknC));
            } else {
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(wknC));
            }
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(wknA));
            EXPECT_TRUE(listenerC.GotAbsenceNOCFor(wknA));

            /* Request new wellknown names */
            wknA = "org.test1.A" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrA->RequestName(wknA.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            wknB = "org.test1.B" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrB->RequestName(wknB.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            wknC = "org.test1.C" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrC->RequestName(wknC.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Gets Presence NOC for wknB
             * BusAttachment A does not get Presence NOC for wknC unless this is an EXCHANGE_ALL_NAMES session.
             * BusAttachment B: Gets Presence NOC for wknA
             * BusAttachment C: Gets Presence NOC for wknA
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotPresenceNOCFor(wknB) && listenerB.GotPresenceNOCFor(wknA) &&
                    listenerC.GotPresenceNOCFor(wknA) &&
                    ((ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) ||
                     listenerA.GotPresenceNOCFor(wknC))) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotPresenceNOCFor(wknB));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(wknC));
            } else {
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(wknC));
            }
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(wknA));
            EXPECT_TRUE(listenerC.GotPresenceNOCFor(wknA));

            /* Leave session */
            status = BusPtrA->LeaveSession(sessionIdA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* Wait for session to be torn down completely
             * BusAttachment A: Gets Absence NOC for B, SR.
             * Gets Absence NOC for C if protocol version <12 or EXCHANGE_ALL_NAMES nameTransfer was used.
             * BusAttachment B: Gets Absence NOC for A, BR.
             * BusAttachment C: Gets Absence NOC for A, BR.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()) &&
                    ((ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) ||
                     listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName())) &&
                    listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName())) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));
            } else {
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));
            }

            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));

            /* Unregister Bus Listeners */
            BusPtrA->UnregisterBusListener(listenerA);
            BusPtrB->UnregisterBusListener(listenerB);
            BusPtrC->UnregisterBusListener(listenerC);

            /* Release names */
            status = BusPtrA->ReleaseName(wknA.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->ReleaseName(wknB.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrC->ReleaseName(wknC.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment B: CancelAdvertiseName */
            status = BusPtrB->CancelAdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

        }
    }

}

/* TwoRoutingNodeMPSessionTest1:
 * Perform test for UDP and TCP and for nameTransferType EXCHANGE_SESSION_NAMES and EXCHANGE_ALL_NAMES
 * P2P session
 * (B)-(SR)         (BR)-(A)
 *      |
 *     (C)
 * SR = standalone RN
 * BR = bundled RN
 * B requests, advertises a name and binds a P2P session.
 * A finds and joins the session.
 * Check session IDs match.
 * Expected: A gets Presence NOC for B and the SR.
 *           A gets Presence NOC for C only if this is an EXCHANGE_ALL_NAMES session.
 *               B gets Presence NOC for A and BR.
 *               C gets Presence NOC for A and BR.
 * C finds and joins the session.
 * Expected: A gets Presence NOC for C
 * C leaves session
 * A leaves session
 * Expected: A gets Absence NOC for B and the SR. A gets Absence NOC for C only if this is an EXCHANGE_ALL_NAMES session.
 *               C gets Absence NOC for A and BR.
 *               C does not get Absence NOC for B.
 */
TEST_F(NamePropagationTest, TwoRoutingNodeMPSessionTest1) {
    QStatus status = ER_OK;

    for (size_t i = 0; i < sizeof(transportMasks) / sizeof(TransportMask); i++) {

        TransportMask tm = transportMasks[i];

        for (size_t j = 0; j < sizeof(nameTransferTypes) / sizeof(SessionOpts::NameTransferType); j++) {
            SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, true, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
            int nm = nameTransferTypes[j];
#if (ALLJOYN_PROTOCOL_VERSION < 12)
            if (nm != -1) {
                /* Only run test once for lower protocol versions */
                break;
            }
#else
            switch (nm) {
            case EXCHANGE_ALL_NAMES:
                opts.SetAllNames();
                break;

            case EXCHANGE_SESSION_NAMES:
                opts.SetSessionNames();
                break;

            default:
                break;
            }
#endif
            /* Set up bus listeners */
            NamePropTestFindNameListener listenerA("busAttachmentA");
            listenerA.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrA->RegisterBusListener(listenerA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerB("busAttachmentB");
            listenerB.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrB->RegisterBusListener(listenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerC("busAttachmentC");
            listenerC.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrC->RegisterBusListener(listenerC);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Request name, advertise, bind session */
            status = BusPtrB->RequestName(listenerA.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->AdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestSessionListener sessionPortListenerB(BusPtrB);
            status = BusPtrB->BindSessionPort(sessionPortListenerB.port, opts, sessionPortListenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: find advertised name */
            status = BusPtrA->FindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerA.nameFound) && (listenerA.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerA.nameFound) << "failed to find advertised name: " << listenerA.NameToMatch.c_str();
            ASSERT_TRUE(listenerA.nameMatched) << "failed to find advertised name via UDP transport: " << listenerA.NameToMatch.c_str();

            /* BusAttachment A: JoinSession */
            SessionId sessionIdA = 0;
            status = BusPtrA->JoinSession(listenerA.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdA, opts);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerB.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session IDs */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdA) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdA) << "  session ID's do not match";

            String bundledRouter = BusPtrA->GetUniqueName().substr(0, BusPtrA->GetUniqueName().find('.')) + ".1";
            String standAloneRouter = BusPtrB->GetUniqueName().substr(0, BusPtrB->GetUniqueName().find('.')) + ".1";

            /* BusAttachment A: Gets Presence NOC for B, SR.
             * Gets Presence NOC for C if protocol version <12 or EXCHANGE_ALL_NAMES nameTransfer was used.
             * BusAttachment B: Gets Presence NOC for A, BR.
             * BusAttachment C: Gets Presence NOC for A, BR.
             * No Absence NOCs must be received at this point.
             */

            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerA.GotPresenceNOCFor(standAloneRouter) &&
                    ((ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) ||
                     listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName())) &&
                    listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerB.GotPresenceNOCFor(bundledRouter) &&
                    listenerC.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerC.GotPresenceNOCFor(bundledRouter)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotPresenceNOCFor(standAloneRouter));
            if ((ALLJOYN_PROTOCOL_VERSION >= 12) && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));
            } else {
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));

            }
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));

            EXPECT_TRUE(listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_FALSE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(bundledRouter));
            EXPECT_FALSE(listenerB.GotAbsenceNOCFor(bundledRouter));

            EXPECT_TRUE(listenerC.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_FALSE(listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerC.GotPresenceNOCFor(bundledRouter));
            EXPECT_FALSE(listenerC.GotAbsenceNOCFor(bundledRouter));

            /* BusAttachment C: find advertised name */
            status = BusPtrC->FindAdvertisedNameByTransport(listenerC.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment C: Wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerC.nameFound) && (listenerC.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerC.nameFound) << "failed to find advertised name: " << listenerC.NameToMatch.c_str();
            ASSERT_TRUE(listenerC.nameMatched) << "failed to find advertised name via UDP transport: " << listenerC.NameToMatch.c_str();

            /* BusAttachment C: Join session */
            sessionPortListenerB.sessionJoined = false;
            SessionId sessionIdC = 0;
            status = BusPtrC->JoinSession(listenerC.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdC, opts);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerB.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session IDs */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdC) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdC) << "  session ID's do not match";
            EXPECT_EQ(sessionIdA, sessionIdC) << "  session ID's do not match";

            /* BusAttachment A: Gets Presence NOC for C */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName())) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));

            /* BusAttachment A: CancelFindAdvertisedName */
            status = BusPtrA->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment C: CancelFindAdvertisedName */
            status = BusPtrC->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment C: Leave Session */
            status = BusPtrC->LeaveSession(sessionIdC);

            EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));

            sessionPortListenerB.sessionLost = false;
            // Leave session
            status = BusPtrA->LeaveSession(sessionIdA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment A: Gets Absence NOC for B, SR, C.
             * BusAttachment B: Gets Absence NOC for A, BR.
             * BusAttachment C: Gets Absence NOC for A, BR.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()) &&
                    listenerA.GotAbsenceNOCFor(standAloneRouter) &&
                    listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerB.GotAbsenceNOCFor(bundledRouter) &&
                    listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerC.GotAbsenceNOCFor(bundledRouter)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(standAloneRouter));

            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(bundledRouter));

            EXPECT_TRUE(listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerC.GotAbsenceNOCFor(bundledRouter));

            EXPECT_FALSE(listenerC.GotPresenceNOCFor(BusPtrB->GetUniqueName()));

            /* Unregister Bus Listeners */
            BusPtrA->UnregisterBusListener(listenerA);
            BusPtrB->UnregisterBusListener(listenerB);
            BusPtrC->UnregisterBusListener(listenerC);

            /* BusAttachment B: CancelAdvertise and release name */
            status = BusPtrB->CancelAdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->ReleaseName(listenerA.NameToMatch.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

        }
    }
}

/* TwoRoutingNodeMPSessionTest2:
 * The order of JoinSession is different.
 * Perform test for UDP and TCP and for nameTransferType EXCHANGE_SESSION_NAMES and EXCHANGE_ALL_NAMES
 * P2P session
 * (B)-(SR)         (BR)-(A)
 *      |
 *     (C)
 * SR = standalone RN
 * BR = bundled RN
 * B requests, advertises a name and binds a P2P session.
 * C finds and joins the session.
 * A finds and joins the session.
 * Check session IDs match.
 * Expected: A gets Presence NOC for B,C and the SR.
 *               B gets Presence NOC for A and BR.
 *               C gets Presence NOC for A and BR.
 * C leaves session
 * A leaves session
 * Expected: A gets Absence NOC for B and the SR. A gets Absence NOC for C.
 *               C gets Absence NOC for A and BR.
 *               C does not get Absence NOC for B.
 */
TEST_F(NamePropagationTest, TwoRoutingNodeMPSessionTest2) {
    QStatus status = ER_OK;

    for (size_t i = 0; i < sizeof(transportMasks) / sizeof(TransportMask); i++) {

        TransportMask tm = transportMasks[i];

        for (size_t j = 0; j < sizeof(nameTransferTypes) / sizeof(SessionOpts::NameTransferType); j++) {
            SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, true, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
            int nm = nameTransferTypes[j];
#if (ALLJOYN_PROTOCOL_VERSION < 12)
            if (nm != -1) {
                /* Only run test once for lower protocol versions */
                break;
            }
#else
            switch (nm) {
            case EXCHANGE_ALL_NAMES:
                opts.SetAllNames();
                break;

            case EXCHANGE_SESSION_NAMES:
                opts.SetSessionNames();
                break;

            default:
                break;
            }
#endif
            /* Set up bus listeners */
            NamePropTestFindNameListener listenerA("busAttachmentA");
            listenerA.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrA->RegisterBusListener(listenerA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerB("busAttachmentB");
            listenerB.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrB->RegisterBusListener(listenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerC("busAttachmentC");
            listenerC.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrC->RegisterBusListener(listenerC);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Request name, advertise, bind session */
            status = BusPtrB->RequestName(listenerA.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->AdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestSessionListener sessionPortListenerB(BusPtrB);
            status = BusPtrB->BindSessionPort(sessionPortListenerB.port, opts, sessionPortListenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);


            /* BusAttachment C: find advertised name */
            status = BusPtrC->FindAdvertisedNameByTransport(listenerC.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment C: Wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerC.nameFound) && (listenerC.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerC.nameFound) << "failed to find advertised name: " << listenerC.NameToMatch.c_str();
            ASSERT_TRUE(listenerC.nameMatched) << "failed to find advertised name via UDP transport: " << listenerC.NameToMatch.c_str();

            /* BusAttachment C: Join session */
            SessionId sessionIdC = 0;
            status = BusPtrC->JoinSession(listenerC.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdC, opts);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerB.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session IDs */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdC) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdC) << "  session ID's do not match";

            /* BusAttachment A: find advertised name */
            status = BusPtrA->FindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerA.nameFound) && (listenerA.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerA.nameFound) << "failed to find advertised name: " << listenerA.NameToMatch.c_str();
            ASSERT_TRUE(listenerA.nameMatched) << "failed to find advertised name via UDP transport: " << listenerA.NameToMatch.c_str();

            /* BusAttachment A: JoinSession */
            sessionPortListenerB.sessionJoined = false;
            SessionId sessionIdA = 0;
            status = BusPtrA->JoinSession(listenerA.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdA, opts);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerB.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session IDs */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdA) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdA) << "  session ID's do not match";
            EXPECT_EQ(sessionIdA, sessionIdC) << "  session ID's do not match";

            String bundledRouter = BusPtrA->GetUniqueName().substr(0, BusPtrA->GetUniqueName().find('.')) + ".1";
            String standAloneRouter = BusPtrB->GetUniqueName().substr(0, BusPtrB->GetUniqueName().find('.')) + ".1";

            /* BusAttachment A: Gets Presence NOC for B, SR.
             * Gets Presence NOC for C if protocol version <12 or EXCHANGE_ALL_NAMES nameTransfer was used.
             * BusAttachment B: Gets Presence NOC for A, BR.
             * BusAttachment C: Gets Presence NOC for A, BR.
             * No Absence NOCs must be received at this point.
             */

            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerA.GotPresenceNOCFor(standAloneRouter) &&
                    listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()) &&
                    listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerB.GotPresenceNOCFor(bundledRouter) &&
                    listenerC.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerC.GotPresenceNOCFor(bundledRouter)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotPresenceNOCFor(standAloneRouter));
            EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));

            EXPECT_TRUE(listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_FALSE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(bundledRouter));
            EXPECT_FALSE(listenerB.GotAbsenceNOCFor(bundledRouter));

            EXPECT_TRUE(listenerC.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_FALSE(listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerC.GotPresenceNOCFor(bundledRouter));
            EXPECT_FALSE(listenerC.GotAbsenceNOCFor(bundledRouter));


            /* BusAttachment A: CancelFindAdvertisedName */
            status = BusPtrA->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment C: CancelFindAdvertisedName */
            status = BusPtrC->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment C: Leave Session */
            status = BusPtrC->LeaveSession(sessionIdC);

            EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));

            sessionPortListenerB.sessionLost = false;
            // Leave session
            status = BusPtrA->LeaveSession(sessionIdA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment A: Gets Absence NOC for B, SR, C.
             * BusAttachment B: Gets Absence NOC for A, BR.
             * BusAttachment C: Gets Absence NOC for A, BR.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()) &&
                    listenerA.GotAbsenceNOCFor(standAloneRouter) &&
                    listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerB.GotAbsenceNOCFor(bundledRouter) &&
                    listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerC.GotAbsenceNOCFor(bundledRouter)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(standAloneRouter));

            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(bundledRouter));

            EXPECT_TRUE(listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerC.GotAbsenceNOCFor(bundledRouter));

            EXPECT_FALSE(listenerC.GotPresenceNOCFor(BusPtrB->GetUniqueName()));

            /* Unregister Bus Listeners */
            BusPtrA->UnregisterBusListener(listenerA);
            BusPtrB->UnregisterBusListener(listenerB);
            BusPtrC->UnregisterBusListener(listenerC);

            /* BusAttachment B: CancelAdvertise and release name */
            status = BusPtrB->CancelAdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->ReleaseName(listenerA.NameToMatch.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

        }
    }
}

/* TwoRoutingNodeMPSessionTest3:
 * The direction of JoinSession is different.
 * Perform test for UDP and TCP and for nameTransferType EXCHANGE_SESSION_NAMES and EXCHANGE_ALL_NAMES
 * P2P session
 * (B)-(SR)         (BR)-(A)
 *      |
 *     (C)
 * SR = standalone RN
 * BR = bundled RN
 * A requests, advertises a name and binds a P2P session.
 * B finds and joins the session.
 * Check session IDs match.
 * Expected: A gets Presence NOC for B and the SR.
 *           A gets Presence NOC for C if EXCHANGE_ALL_NAMES session.
 *               B gets Presence NOC for A and BR.
 *               C gets Presence NOC for A and BR.
 * C finds and joins the session
 * Expected: A gets Presence NOC for C
 * C leaves session
 * A leaves session
 * Expected: A gets Absence NOC for B and the SR. A gets Absence NOC for C.
 *               C gets Absence NOC for A and BR.
 *               C does not get Absence NOC for B.
 */
TEST_F(NamePropagationTest, TwoRoutingNodeMPSessionTest3) {
    QStatus status = ER_OK;

    for (size_t i = 0; i < sizeof(transportMasks) / sizeof(TransportMask); i++) {

        TransportMask tm = transportMasks[i];

        for (size_t j = 0; j < sizeof(nameTransferTypes) / sizeof(SessionOpts::NameTransferType); j++) {
            SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, true, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
            int nm = nameTransferTypes[j];
#if (ALLJOYN_PROTOCOL_VERSION < 12)
            if (nm != -1) {
                /* Only run test once for lower protocol versions */
                break;
            }
#else
            switch (nm) {
            case EXCHANGE_ALL_NAMES:
                opts.SetAllNames();
                break;

            case EXCHANGE_SESSION_NAMES:
                opts.SetSessionNames();
                break;

            default:
                break;
            }
#endif
            /* Set up bus listeners */
            NamePropTestFindNameListener listenerA("busAttachmentA");
            listenerA.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrA->RegisterBusListener(listenerA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerB("busAttachmentB");
            listenerB.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrB->RegisterBusListener(listenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerC("busAttachmentC");
            listenerC.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrC->RegisterBusListener(listenerC);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Request name, advertise, bind session */
            status = BusPtrA->RequestName(listenerA.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrA->AdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestSessionListener sessionPortListenerA(BusPtrA);
            status = BusPtrA->BindSessionPort(sessionPortListenerA.port, opts, sessionPortListenerA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: find advertised name */
            status = BusPtrB->FindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerB.nameFound) && (listenerB.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerB.nameFound) << "failed to find advertised name: " << listenerA.NameToMatch.c_str();
            ASSERT_TRUE(listenerB.nameMatched) << "failed to find advertised name via UDP transport: " << listenerA.NameToMatch.c_str();

            /* BusAttachment B: JoinSession */
            SessionId sessionIdB = 0;
            status = BusPtrB->JoinSession(listenerB.NameToMatch.c_str(), sessionPortListenerA.port, NULL, sessionIdB, opts);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerA.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session IDs */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdB) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerA.busSessionId, sessionIdB) << "  session ID's do not match";

            String bundledRouter = BusPtrA->GetUniqueName().substr(0, BusPtrA->GetUniqueName().find('.')) + ".1";
            String standAloneRouter = BusPtrB->GetUniqueName().substr(0, BusPtrB->GetUniqueName().find('.')) + ".1";

            /* BusAttachment A: Gets Presence NOC for B, SR.
             * Gets Presence NOC for C if protocol version <12 or EXCHANGE_ALL_NAMES nameTransfer was used.
             * BusAttachment B: Gets Presence NOC for A, BR.
             * BusAttachment C: Gets Presence NOC for A, BR.
             * No Absence NOCs must be received at this point.
             */

            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerA.GotPresenceNOCFor(standAloneRouter) &&
                    ((ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) ||
                     listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName())) &&
                    listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerB.GotPresenceNOCFor(bundledRouter) &&
                    listenerC.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerC.GotPresenceNOCFor(bundledRouter)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotPresenceNOCFor(standAloneRouter));
            if ((ALLJOYN_PROTOCOL_VERSION >= 12) && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));
            } else {
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));

            }
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));

            EXPECT_TRUE(listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_FALSE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(bundledRouter));
            EXPECT_FALSE(listenerB.GotAbsenceNOCFor(bundledRouter));

            EXPECT_TRUE(listenerC.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_FALSE(listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerC.GotPresenceNOCFor(bundledRouter));
            EXPECT_FALSE(listenerC.GotAbsenceNOCFor(bundledRouter));

            /* BusAttachment C: find advertised name */
            status = BusPtrC->FindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment C: Wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerC.nameFound) && (listenerC.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerC.nameFound) << "failed to find advertised name: " << listenerC.NameToMatch.c_str();
            ASSERT_TRUE(listenerC.nameMatched) << "failed to find advertised name via UDP transport: " << listenerC.NameToMatch.c_str();

            /* BusAttachment C: Join session */
            sessionPortListenerA.sessionJoined = false;
            SessionId sessionIdC = 0;
            status = BusPtrC->JoinSession(listenerA.NameToMatch.c_str(), sessionPortListenerA.port, NULL, sessionIdC, opts);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerA.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session IDs */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdC) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerA.busSessionId, sessionIdC) << "  session ID's do not match";
            EXPECT_EQ(sessionIdB, sessionIdC) << "  session ID's do not match";

            /* BusAttachment A: Gets Presence NOC for C */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName())) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            ASSERT_TRUE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));
            ASSERT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));

            /* BusAttachment B: CancelFindAdvertisedName */
            status = BusPtrB->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment C: CancelFindAdvertisedName */
            status = BusPtrC->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment C: Leave Session */
            status = BusPtrC->LeaveSession(sessionIdC);

            EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));

            /* Leave session */
            status = BusPtrA->LeaveSession(sessionIdB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment A: Gets Absence NOC for B, SR, C.
             * BusAttachment B: Gets Absence NOC for A, BR.
             * BusAttachment C: Gets Absence NOC for A, BR.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()) &&
                    listenerA.GotAbsenceNOCFor(standAloneRouter) &&
                    listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerB.GotAbsenceNOCFor(bundledRouter) &&
                    listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerC.GotAbsenceNOCFor(bundledRouter)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(standAloneRouter));

            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(bundledRouter));

            EXPECT_TRUE(listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerC.GotAbsenceNOCFor(bundledRouter));

            EXPECT_FALSE(listenerC.GotPresenceNOCFor(BusPtrB->GetUniqueName()));

            /* Unregister Bus Listeners */
            BusPtrA->UnregisterBusListener(listenerA);
            BusPtrB->UnregisterBusListener(listenerB);
            BusPtrC->UnregisterBusListener(listenerC);

            /* BusAttachment A: CancelAdvertise and release name */
            status = BusPtrA->CancelAdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrA->ReleaseName(listenerA.NameToMatch.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

        }
    }
}

/*
 * MP_ValidateResultantNameTransferType:
 * Validate the resultant Name transfer type for various combination of inputs.
 * Perform test for UDP and TCP for nameTransfer type values: default, EXCHANGE_SESSION_NAMES, EXCHANGE_ALL_NAMES.
 * (B)-(SR)         (BR)-(A)
 *      |
 *     (C)
 * SR = standalone RN
 * BR = bundled RN
 * B requests, advertises a name and binds a P2P session.
 * A finds and joins the session.
 * Check session IDs match.
 * Validate resultant nameTransfer Type:
 * If both are default or both are EXCHANGE_SESSION_NAMES, resultant is EXCHANGE_SESSION_NAMES.
 * otherwise if any is EXCHANGE_ALL_NAMES, result is EXCHANGE_ALL_NAMES.
 * Expected: A gets Presence NOC for B and the SR.
 *           A gets Presence NOC for C only if this is an EXCHANGE_ALL_NAMES session.
 *               B gets Presence NOC for A and BR.
 *               C gets Presence NOC for A and BR.
 * A leaves session
 * Expected: A gets Absence NOC for B and the SR. A gets Absence NOC for C only if this is an EXCHANGE_ALL_NAMES session.
 *               B gets Absence NOC for A and BR.
 *               C gets Absence NOC for A and BR.
 *               C does not get Absence NOC for B.
 */
TEST_F(NamePropagationTest, MP_ValidateResultantNameTransferType) {

#if (ALLJOYN_PROTOCOL_VERSION < 12)
    /* Skip this test for lower protocol versions. */
    return;
#else
    QStatus status = ER_OK;
    for (size_t i = 0; i < sizeof(transportMasks) / sizeof(TransportMask); i++) {

        TransportMask tm = transportMasks[i];
        for (size_t j = 0; j < sizeof(nameTransferTypes) / sizeof(SessionOpts::NameTransferType); j++) {
            for (size_t k = 0; k < sizeof(nameTransferTypes) / sizeof(SessionOpts::NameTransferType); k++) {
                SessionOpts optsHost(SessionOpts::TRAFFIC_MESSAGES, true, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
                /* Note: optsJoiner.isMultipoint is set to false to test this combination, this is not an error. */
                SessionOpts optsJoiner(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);

                switch (nameTransferTypes[j]) {
                case EXCHANGE_ALL_NAMES:
                    optsHost.SetAllNames();
                    break;

                case EXCHANGE_SESSION_NAMES:
                    optsHost.SetSessionNames();
                    break;

                default:
                    break;
                }
                switch (nameTransferTypes[k]) {
                case EXCHANGE_ALL_NAMES:
                    optsJoiner.SetAllNames();
                    break;

                case EXCHANGE_SESSION_NAMES:
                    optsJoiner.SetSessionNames();
                    break;

                default:
                    break;
                }
                /* Set up bus listeners */
                NamePropTestFindNameListener listenerA("busAttachmentA");
                listenerA.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
                BusPtrA->RegisterBusListener(listenerA);
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                NamePropTestFindNameListener listenerB("busAttachmentB");
                listenerB.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
                BusPtrB->RegisterBusListener(listenerB);
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                NamePropTestFindNameListener listenerC("busAttachmentC");
                listenerC.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
                BusPtrC->RegisterBusListener(listenerC);
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                /* BusAttachment B: Request name, advertise, bind session */
                status = BusPtrB->RequestName(listenerA.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                status = BusPtrB->AdvertiseName(listenerA.NameToMatch.c_str(), tm);
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                NamePropTestSessionListener sessionPortListenerB(BusPtrB);
                status = BusPtrB->BindSessionPort(sessionPortListenerB.port, optsHost, sessionPortListenerB);
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                /* BusAttachment A: find advertised name */
                status = BusPtrA->FindAdvertisedNameByTransport(listenerB.NameToMatch.c_str(), TRANSPORT_ANY);
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                /* BusAttachment A: wait for FoundAdvertisedName */
                for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                    if ((listenerA.nameFound) && (listenerA.nameMatched)) {
                        break;
                    }
                    qcc::Sleep(WAIT_TIME);
                }
                ASSERT_TRUE(listenerA.nameFound) << "failed to find advertised name: " << listenerA.NameToMatch.c_str();
                ASSERT_TRUE(listenerA.nameMatched) << "failed to find advertised name via UDP transport: " << listenerA.NameToMatch.c_str();

                /* BusAttachment A: JoinSession */
                SessionId sessionIdA = 0;
                status = BusPtrA->JoinSession(listenerA.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdA, optsJoiner);
                ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                /* BusAttachment B: wait for SessionJoined */
                for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                    if (sessionPortListenerB.sessionJoined) {
                        break;
                    }
                    qcc::Sleep(WAIT_TIME);
                }

                EXPECT_NE(static_cast<SessionId>(0), sessionIdA) << "  SessionID should not be '0'";
                EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdA) << "  session ID's do not match";

                /* Validate resultant nameTransfer Type:
                 * If both are default or both are MP, resultant is MP. otherwise if any is EXCHANGE_ALL_NAMES, result is EXCHANGE_ALL_NAMES.
                 */
                if ((nameTransferTypes[j] == EXCHANGE_ALL_NAMES) || (nameTransferTypes[k] == EXCHANGE_ALL_NAMES)) {
                    EXPECT_TRUE(optsJoiner.IsAllNames());
                    EXPECT_FALSE(optsJoiner.IsSessionNames());
                } else {
                    EXPECT_FALSE(optsJoiner.IsAllNames());
                    EXPECT_TRUE(optsJoiner.IsSessionNames());
                }

                String bundledRouter = BusPtrA->GetUniqueName().substr(0, BusPtrA->GetUniqueName().find('.')) + ".1";
                String standaloneRouter = BusPtrB->GetUniqueName().substr(0, BusPtrB->GetUniqueName().find('.')) + ".1";

                /* BusAttachment A: Gets Presence NOC for B, SR.
                 * Gets Presence NOC for C if protocol version <12 or EXCHANGE_ALL_NAMES nameTransfer was used.
                 * BusAttachment B: Gets Presence NOC for A, BR.
                 * BusAttachment C: Gets Presence NOC for A, BR.
                 * No Absence NOCs must be received at this point.
                 */
                for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                    if (listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()) &&
                        listenerA.GotPresenceNOCFor(standaloneRouter) &&
                        ((optsJoiner.IsSessionNames()) ||
                         listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName())) &&
                        listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                        listenerB.GotPresenceNOCFor(bundledRouter) &&
                        listenerC.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                        listenerC.GotPresenceNOCFor(bundledRouter)) {
                        break;
                    }
                    qcc::Sleep(WAIT_TIME);
                }
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()));
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(standaloneRouter));
                if (optsJoiner.IsSessionNames()) {
                    EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));
                } else {
                    EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));

                }
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(standaloneRouter));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));

                EXPECT_TRUE(listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_TRUE(listenerB.GotPresenceNOCFor(bundledRouter));
                EXPECT_FALSE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_FALSE(listenerB.GotAbsenceNOCFor(bundledRouter));

                EXPECT_TRUE(listenerC.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_TRUE(listenerC.GotPresenceNOCFor(bundledRouter));
                EXPECT_FALSE(listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_FALSE(listenerC.GotAbsenceNOCFor(bundledRouter));

                /* BusAttachment A: cancel find */
                status = BusPtrA->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                /* Verify no Absence NOCs are received */
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(standaloneRouter));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));

                /* BusAttachment A: Leave session */
                status = BusPtrA->LeaveSession(sessionIdA);
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                /* BusAttachment A: Gets Absence NOC for B, SR.
                 * Gets Absence NOC for C if protocol version <12 or EXCHANGE_ALL_NAMES nameTransfer was used.
                 * BusAttachment B: Gets Absence NOC for A, BR.
                 * BusAttachment C: Gets Absence NOC for A, BR.
                 */
                for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                    if (listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()) &&
                        listenerA.GotAbsenceNOCFor(standaloneRouter) &&
                        (((optsJoiner.IsSessionNames())) ||
                         listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName())) &&
                        listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                        listenerB.GotAbsenceNOCFor(bundledRouter) &&
                        listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                        listenerC.GotAbsenceNOCFor(bundledRouter)) {
                        break;
                    }
                    qcc::Sleep(WAIT_TIME);
                }

                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
                if (optsJoiner.IsSessionNames()) {
                    EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrC->GetUniqueName()));
                    EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));
                } else {
                    EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));
                }
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(standaloneRouter));

                EXPECT_TRUE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_TRUE(listenerB.GotAbsenceNOCFor(bundledRouter));

                EXPECT_TRUE(listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_TRUE(listenerC.GotAbsenceNOCFor(bundledRouter));

                /* Unregister Bus Listeners */
                BusPtrA->UnregisterBusListener(listenerA);
                BusPtrB->UnregisterBusListener(listenerB);
                BusPtrC->UnregisterBusListener(listenerC);

                /* BusAttachment B: CancelAdvertiseName, ReleaseName */
                status = BusPtrB->CancelAdvertiseName(listenerA.NameToMatch.c_str(), tm);
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

                status = BusPtrB->ReleaseName(listenerA.NameToMatch.c_str());
                EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            }
        }
    }
#endif
}
/*
 * TwoRoutingNodeMPWellKnownNames:
 * Verify that NOCs for well known names are received only when there is a session.
 * Perform test for UDP and TCP for nameTransfer type values: default, EXCHANGE_SESSION_NAMES, EXCHANGE_ALL_NAMES.
 * (B)-(SR)         (BR)-(A)
 *      |
 *     (C)
 * SR = standalone RN
 * BR = bundled RN
 * A and C request a wellknown name each.
 * B requests, advertises a name and binds a MP session.
 * A finds and joins the session.
 * C finds and joins the session
 * Check session IDs match.
 *
 * Expected: A gets Presence NOC for BusAttachment B's wellknown name. i.e. listenerA.NameToMatch
 * A gets Presence NOC for BusAttachment C's wellknown name.
 * B gets Presence NOC for BusAttachment A's wellknown name. i.e. wknA
 * C gets Presence NOC for BusAttachment A's wellknown name. i.e. wknA
 *
 * A, B and C release the wellknown names.
 *
 * Expected: A gets Absence NOC for BusAttachment B's wellknown name. i.e. listenerA.NameToMatch
 * A gets Presence or Absence NOC for BusAttachment C's wellknown name.
 * B gets Absence NOC for BusAttachment A's wellknown name. i.e. wknA
 * C gets Absence NOC for BusAttachment A's wellknown name. i.e. wknA
 *
 * A, B and C re-request new wellknown names.
 *
 * Expected: A gets Presence NOC for BusAttachment B's wellknown name. i.e. wknB
 * A gets Presence NOC for BusAttachment C's wellknown name.
 * B gets Presence NOC for BusAttachment A's wellknown name. i.e. wknA
 * C gets Presence NOC for BusAttachment A's wellknown name. i.e. wknA
 *
 */
TEST_F(NamePropagationTest, TwoRoutingNodeMPWellKnownNames) {
    QStatus status = ER_OK;

    for (size_t i = 0; i < sizeof(transportMasks) / sizeof(TransportMask); i++) {

        TransportMask tm = transportMasks[i];
        for (size_t j = 0; j < sizeof(nameTransferTypes) / sizeof(SessionOpts::NameTransferType); j++) {
            SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, true, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
            int nm = nameTransferTypes[j];
#if (ALLJOYN_PROTOCOL_VERSION < 12)
            if (nm != -1) {
                /* Only run test once for lower protocol versions */
                break;
            }
#else
            switch (nm) {
            case EXCHANGE_ALL_NAMES:
                opts.SetAllNames();
                break;

            case EXCHANGE_SESSION_NAMES:
                opts.SetSessionNames();
                break;

            default:
                break;
            }
#endif
            /* Set up bus listeners */
            String wknB = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            NamePropTestFindNameListener listenerA("busAttachmentA");
            listenerA.NameToMatch = wknB;
            BusPtrA->RegisterBusListener(listenerA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerB("busAttachmentB");
            listenerB.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrB->RegisterBusListener(listenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerC("busAttachmentC");
            listenerC.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrC->RegisterBusListener(listenerC);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: request a wellknown name */
            String wknA = "org.test.A" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrA->RequestName(wknA.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment C: request a wellknown name */
            String wknC = "org.test.C" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrC->RequestName(wknC.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Request name, advertise, bind session */
            status = BusPtrB->RequestName(listenerA.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->AdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestSessionListener sessionPortListenerB(BusPtrB);
            status = BusPtrB->BindSessionPort(sessionPortListenerB.port, opts, sessionPortListenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: find advertised name */
            status = BusPtrA->FindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerA.nameFound) && (listenerA.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerA.nameFound) << "failed to find advertised name: " << listenerA.NameToMatch.c_str();
            ASSERT_TRUE(listenerA.nameMatched) << "failed to find advertised name" << listenerA.NameToMatch.c_str();

            /* BusAttachment A: JoinSession */
            SessionId sessionIdA = 0;
            status = BusPtrA->JoinSession(listenerA.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdA, opts);
            ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerB.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session ID */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdA) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdA) << "  session ID's do not match";

            /* BusAttachment C: JoinSession */
            SessionId sessionIdC = 0;
            sessionPortListenerB.sessionJoined = 0;
            status = BusPtrC->JoinSession(listenerA.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdC, opts);
            ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerB.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session ID */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdC) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdC) << "  session ID's do not match";
            EXPECT_EQ(sessionIdA, sessionIdC) << "  session ID's do not match";

            /* BusAttachment A: Gets Presence NOC for BusAttachment B's wellknown name. i.e. listenerA.NameToMatch
             * BusAttachment A gets Presence NOC for BusAttachment C's wellknown name. i.e. wknC
             * BusAttachment B: Gets Presence NOC for BusAttachment A's wellknown name. i.e. wknA
             * BusAttachment C: Gets Presence NOC for BusAttachment A's wellknown name. i.e. wknA
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotPresenceNOCFor(listenerA.NameToMatch) && listenerB.GotPresenceNOCFor(wknA) &&
                    listenerC.GotPresenceNOCFor(wknA) &&
                    listenerA.GotPresenceNOCFor(wknC)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotPresenceNOCFor(listenerA.NameToMatch));

            EXPECT_TRUE(listenerA.GotPresenceNOCFor(wknC));
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(wknA));
            EXPECT_TRUE(listenerC.GotPresenceNOCFor(wknA));

            /* BusAttachment A: cancel find */
            status = BusPtrA->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* Release all names */
            status = BusPtrA->ReleaseName(wknA.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->ReleaseName(wknB.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrC->ReleaseName(wknC.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Gets Absence NOC for BusAttachment B's wellknown name. i.e. wknB
             * BusAttachment A gets Absence NOC for BusAttachment C's wellknown name. i.e. wknC
             * BusAttachment B: Gets Absence NOC for BusAttachment A's wellknown name. i.e. wknA
             * BusAttachment C: Gets Absence NOC for BusAttachment A's wellknown name. i.e. wknA
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotAbsenceNOCFor(wknB) && listenerB.GotAbsenceNOCFor(wknA) &&
                    listenerC.GotAbsenceNOCFor(wknA) &&
                    listenerA.GotAbsenceNOCFor(wknC)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(wknB));
            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(wknC));
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(wknA));
            EXPECT_TRUE(listenerC.GotAbsenceNOCFor(wknA));

            /* Request new wellknown names */
            wknA = "org.test1.A" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrA->RequestName(wknA.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            wknB = "org.test1.B" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrB->RequestName(wknB.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            wknC = "org.test1.C" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrC->RequestName(wknC.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Gets Presence NOC for wknB
             * BusAttachment A gets Presence NOC for wknC.
             * BusAttachment B: Gets Presence NOC for wknA
             * BusAttachment C: Gets Presence NOC for wknA
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotPresenceNOCFor(wknB) && listenerB.GotPresenceNOCFor(wknA) &&
                    listenerC.GotPresenceNOCFor(wknA) &&
                    listenerA.GotPresenceNOCFor(wknC)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotPresenceNOCFor(wknB));
            EXPECT_TRUE(listenerA.GotPresenceNOCFor(wknC));
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(wknA));
            EXPECT_TRUE(listenerC.GotPresenceNOCFor(wknA));

            /* Leave session */
            status = BusPtrA->LeaveSession(sessionIdA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* Wait for session to be torn down completely
             * BusAttachment A: Gets Absence NOC for B, SR.
             * Gets Absence NOC for C.
             * BusAttachment B: Gets Absence NOC for A, BR.
             * BusAttachment C: Gets Absence NOC for A, BR.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()) &&
                    listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName())) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrC->GetUniqueName()));

            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerC.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));

            /* Unregister Bus Listeners */
            BusPtrA->UnregisterBusListener(listenerA);
            BusPtrB->UnregisterBusListener(listenerB);
            BusPtrC->UnregisterBusListener(listenerC);

            /* Release names */
            status = BusPtrA->ReleaseName(wknA.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->ReleaseName(wknB.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrC->ReleaseName(wknC.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment B: CancelAdvertiseName */
            status = BusPtrB->CancelAdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

        }
    }

}

/* ThreeRoutingNodeP2PSessionTest1:
 * Perform test for UDP and TCP and for nameTransferType EXCHANGE_SESSION_NAMES and EXCHANGE_ALL_NAMES
 * P2P session
 * (B)-(SR)         (BR)-(A)
 *
 *     (SR2)
 *      |  \
 *     (D) (E)
 * SR = standalone RN
 * SR2 = second standalone RN
 * BR = bundled RN
 * B requests, advertises a name and binds a P2P session.
 * A finds and joins the session.
 * Check session IDs match.
 * Expected: A gets Presence NOC for B and the SR.
 *           B gets Presence NOC for A and BR.
 * D finds and joins the session.
 * Expected:
 *           A gets presence NOC for SR2, D and E only if this is an EXCHANGE_ALL_NAMES session.
 *           B gets Presence NOC for D and SR2.
 *           D gets presence NOC for B and SR.
 *           D gets Presence NOC for A and BR only if this is an EXCHANGE_ALL_NAMES session.
 * D leaves session
 * Expected:
 *           A gets Absence NOC for SR2, D and E only if this is an EXCHANGE_ALL_NAMES session.
 *           B gets Absence NOC for D and SR2.
 *           D gets Absence NOC for B and SR.
 *           D gets Absence NOC for A and BR only if this is an EXCHANGE_ALL_NAMES session.
 * A leaves session
 * Expected: A gets Absence NOC for B and the SR.
 *           B gets Absence NOC for A and BR.
 */
TEST_F(NamePropagationTest, ThreeRoutingNodeP2PSessionTest1) {
    QStatus status = ER_OK;

    for (size_t i = 0; i < sizeof(transportMasks) / sizeof(TransportMask); i++) {

        TransportMask tm = transportMasks[i];


        for (size_t j = 0; j < sizeof(nameTransferTypes) / sizeof(SessionOpts::NameTransferType); j++) {
            SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
            int nm = nameTransferTypes[j];
#if (ALLJOYN_PROTOCOL_VERSION < 12)
            if (nm != -1) {
                /* Only run test once for lower protocol versions */
                break;
            }
#else
            switch (nm) {
            case EXCHANGE_ALL_NAMES:
                opts.SetAllNames();
                break;

            case EXCHANGE_SESSION_NAMES:
                opts.SetSessionNames();
                break;

            default:
                break;
            }
#endif
            /* Set up bus listeners */
            NamePropTestFindNameListener listenerA("busAttachmentA");
            listenerA.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();

            BusPtrA->RegisterBusListener(listenerA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerB("busAttachmentB");
            listenerB.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();

            BusPtrB->RegisterBusListener(listenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerD("busAttachmentD");
            listenerD.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();

            BusPtrD->RegisterBusListener(listenerD);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Request name, advertise, bind session */
            status = BusPtrB->RequestName(listenerA.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->AdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestSessionListener sessionPortListenerB(BusPtrB);
            status = BusPtrB->BindSessionPort(sessionPortListenerB.port, opts, sessionPortListenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Find Name */
            status = BusPtrA->FindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment A: Wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerA.nameFound) && (listenerA.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerA.nameFound) << "failed to find advertised name: " << listenerA.NameToMatch.c_str();
            ASSERT_TRUE(listenerA.nameMatched) << "failed to find advertised name via UDP transport: " << listenerA.NameToMatch.c_str();

            /* BusAttachment A: JoinSession */
            SessionId sessionIdA = 0;
            status = BusPtrA->JoinSession(listenerA.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdA, opts);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment B: Wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerB.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session IDs are matching */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdA) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdA) << "  session ID's do not match";

            String bundledRouter = BusPtrA->GetUniqueName().substr(0, BusPtrA->GetUniqueName().find('.')) + ".1";
            String standAloneRouter = BusPtrB->GetUniqueName().substr(0, BusPtrB->GetUniqueName().find('.')) + ".1";
            String standAloneRouter2 = BusPtrD->GetUniqueName().substr(0, BusPtrD->GetUniqueName().find('.')) + ".1";
            /* BusAttachment A: Gets Presence NOC for B, SR.
             * BusAttachment B: Gets Presence NOC for A, BR.
             * No Absence NOCs must be received at this point.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerB.GotPresenceNOCFor(bundledRouter) &&
                    listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerA.GotPresenceNOCFor(standAloneRouter)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }


            EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotPresenceNOCFor(standAloneRouter));
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));

            EXPECT_TRUE(listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(bundledRouter));
            EXPECT_FALSE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_FALSE(listenerB.GotAbsenceNOCFor(bundledRouter));

            /* BusAttachment D: find advertised name */
            status = BusPtrD->FindAdvertisedNameByTransport(listenerD.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment D: Wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerD.nameFound) && (listenerD.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerD.nameFound) << "failed to find advertised name: " << listenerD.NameToMatch.c_str();
            ASSERT_TRUE(listenerD.nameMatched) << "failed to find advertised name via UDP transport: " << listenerD.NameToMatch.c_str();

            /* BusAttachment D: JoinSession */
            sessionPortListenerB.sessionJoined = false;
            SessionId sessionIdD = 0;
            status = BusPtrD->JoinSession(listenerA.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdD, opts);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment B: wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerB.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session IDs are matching */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdD) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdD) << "  session ID's do not match";


            /* BusAttachment A gets presence NOC for SR2, D and E only if this is an ALL_NAMES session.
             * BusAttachment B gets Presence NOC for D and SR2.
             * BusAttachment D gets presence NOC for B and SR.
             * BusAttachment D gets Presence NOC for A and BR only if this is an ALL_NAMES session.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerB.GotPresenceNOCFor(BusPtrD->GetUniqueName()) &&
                    listenerB.GotPresenceNOCFor(standAloneRouter2) &&
                    listenerD.GotPresenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerD.GotPresenceNOCFor(standAloneRouter) &&
                    ((ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) ||
                     (listenerA.GotPresenceNOCFor(standAloneRouter2) &&
                      listenerA.GotPresenceNOCFor(BusPtrD->GetUniqueName()) &&
                      listenerA.GotPresenceNOCFor(BusPtrE->GetUniqueName()) &&
                      listenerD.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                      listenerD.GotPresenceNOCFor(bundledRouter)))) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerB.GotPresenceNOCFor(BusPtrD->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(standAloneRouter2));
            EXPECT_TRUE(listenerD.GotPresenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerD.GotPresenceNOCFor(standAloneRouter));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(standAloneRouter2));
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrD->GetUniqueName()));
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrE->GetUniqueName()));
                EXPECT_FALSE(listenerD.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_FALSE(listenerD.GotPresenceNOCFor(bundledRouter));
            } else {
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(standAloneRouter2));
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrD->GetUniqueName()));
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrE->GetUniqueName()));
                EXPECT_TRUE(listenerD.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_TRUE(listenerD.GotPresenceNOCFor(bundledRouter));
            }

            /* CancelFindAdvertisedName */
            status = BusPtrA->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrD->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment D: Leave session */
            status = BusPtrD->LeaveSession(sessionIdD);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment A gets Absence NOC for SR2, D and E only if this is an ALL_NAMES session.
             * BusAttachment B gets Absence NOC for D and SR2.
             * BusAttachment D gets Absence NOC for B and SR.
             * BusAttachment D gets Absence NOC for A and BR only if this is an ALL_NAMES session.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerD.GotAbsenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerD.GotAbsenceNOCFor(standAloneRouter) &&
                    (((ALLJOYN_PROTOCOL_VERSION >= 12) && (nm != EXCHANGE_ALL_NAMES)) ||
                     (listenerA.GotAbsenceNOCFor(BusPtrD->GetUniqueName()) && listenerA.GotAbsenceNOCFor(standAloneRouter2) &&
                      listenerA.GotAbsenceNOCFor(BusPtrE->GetUniqueName()) &&
                      listenerD.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) && listenerD.GotAbsenceNOCFor(bundledRouter))) &&
                    listenerB.GotAbsenceNOCFor(BusPtrD->GetUniqueName()) &&
                    listenerB.GotAbsenceNOCFor(standAloneRouter2)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            EXPECT_TRUE(listenerD.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerD.GotAbsenceNOCFor(standAloneRouter));
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(BusPtrD->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(standAloneRouter2));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrD->GetUniqueName()));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrE->GetUniqueName()));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(standAloneRouter2));
                EXPECT_FALSE(listenerD.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_FALSE(listenerD.GotAbsenceNOCFor(bundledRouter));

            } else {
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrD->GetUniqueName()));
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrE->GetUniqueName()));
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(standAloneRouter2));
                EXPECT_TRUE(listenerD.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_TRUE(listenerD.GotAbsenceNOCFor(bundledRouter));

            }
            /* BusAttachment A: Leave session */
            status = BusPtrA->LeaveSession(sessionIdA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment A gets Absence NOC for B and the SR.
             * BusAttachment B gets Absence NOC for A and BR.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerA.GotAbsenceNOCFor(standAloneRouter) &&
                    listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerB.GotAbsenceNOCFor(bundledRouter)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(standAloneRouter));

            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(bundledRouter));

            /* Unregister Bus Listeners */
            BusPtrA->UnregisterBusListener(listenerA);
            BusPtrB->UnregisterBusListener(listenerB);
            BusPtrD->UnregisterBusListener(listenerD);

            /* BusAttachment B: CancelAdvertiseName and ReleaseName */
            status = BusPtrB->CancelAdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->ReleaseName(listenerA.NameToMatch.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
        }
    }
}

/* ThreeRoutingNodeP2PSessionTest2:
 * Perform test for UDP and TCP and for nameTransferType EXCHANGE_SESSION_NAMES and EXCHANGE_ALL_NAMES.
 * The difference is the direction of JoinSessions.
 * P2P session
 * (B)-(SR)         (BR)-(A)
 *
 *     (SR2)
 *      |  \
 *     (D) (E)
 * SR = standalone RN
 * SR2 = second standalone RN
 * BR = bundled RN
 * A requests, advertises a name and binds a P2P session.
 * B finds and joins the session.
 * Check session IDs match.
 * Expected: A gets Presence NOC for B and the SR.
 *           B gets Presence NOC for A and BR.
 * D requests, advertises a name and binds a P2P session.
 * B finds and joins the session.
 * Expected:
 *           A gets presence NOC for SR2, D and E only if this is an EXCHANGE_ALL_NAMES session.
 *           B gets Presence NOC for D and SR2.
 *           D gets presence NOC for B and SR.
 *           D gets Presence NOC for A and BR only if this is an EXCHANGE_ALL_NAMES session.
 * D leaves session
 * Expected:
 *           A gets Absence NOC for SR2 and D only if this is an EXCHANGE_ALL_NAMES session.
 *           B gets Absence NOC for D and SR2.
 *           D gets Absence NOC for B and SR.
 *           D gets Absence NOC for A and BR only if this is an ALL_NAMES session.
 * A leaves session
 * Expected: A gets Absence NOC for B and the SR.
 *           B gets Absence NOC for A and BR.
 */
TEST_F(NamePropagationTest, ThreeRoutingNodeP2PSessionTest2) {
    QStatus status = ER_OK;

    for (size_t i = 0; i < sizeof(transportMasks) / sizeof(TransportMask); i++) {

        TransportMask tm = transportMasks[i];


        for (size_t j = 0; j < sizeof(nameTransferTypes) / sizeof(SessionOpts::NameTransferType); j++) {
            SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
            int nm = nameTransferTypes[j];
#if (ALLJOYN_PROTOCOL_VERSION < 12)
            if (nm != -1) {
                /* Only run test once for lower protocol versions */
                break;
            }
#else
            switch (nm) {
            case EXCHANGE_ALL_NAMES:
                opts.SetAllNames();
                break;

            case EXCHANGE_SESSION_NAMES:
                opts.SetSessionNames();
                break;

            default:
                break;
            }
#endif

            /* Set up bus listeners */
            NamePropTestFindNameListener listenerA("busAttachmentA");
            String wknA = "org.test.A" + BusPtrA->GetGlobalGUIDShortString();;
            listenerA.NameToMatch = wknA;

            BusPtrA->RegisterBusListener(listenerA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerB("busAttachmentB");
            listenerB.NameToMatch = wknA;

            BusPtrB->RegisterBusListener(listenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerD("busAttachmentD");
            listenerD.NameToMatch = wknA;

            BusPtrD->RegisterBusListener(listenerD);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Request name, advertise, bind session */
            status = BusPtrA->RequestName(wknA.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrA->AdvertiseName(wknA.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestSessionListener sessionPortListenerA(BusPtrA);
            status = BusPtrA->BindSessionPort(sessionPortListenerA.port, opts, sessionPortListenerA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Find Name */
            status = BusPtrB->FindAdvertisedNameByTransport(wknA.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerB.nameFound) && (listenerB.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerB.nameFound) << "failed to find advertised name: " << wknA.c_str();
            ASSERT_TRUE(listenerB.nameMatched) << "failed to find advertised name via UDP transport: " << wknA.c_str();

            /* BusAttachment B: JoinSession */
            SessionId sessionIdB = 0;
            status = BusPtrB->JoinSession(wknA.c_str(), sessionPortListenerA.port, NULL, sessionIdB, opts);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment A: Wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerA.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session IDs are matching */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdB) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerA.busSessionId, sessionIdB) << "  session ID's do not match";

            String bundledRouter = BusPtrA->GetUniqueName().substr(0, BusPtrA->GetUniqueName().find('.')) + ".1";
            String standAloneRouter = BusPtrB->GetUniqueName().substr(0, BusPtrB->GetUniqueName().find('.')) + ".1";
            String standAloneRouter2 = BusPtrD->GetUniqueName().substr(0, BusPtrD->GetUniqueName().find('.')) + ".1";
            /* BusAttachment A: Gets Presence NOC for B, SR.
             * BusAttachment B: Gets Presence NOC for A, BR.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerB.GotPresenceNOCFor(bundledRouter) &&
                    listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerA.GotPresenceNOCFor(standAloneRouter)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }


            EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotPresenceNOCFor(standAloneRouter));
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));

            EXPECT_TRUE(listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(bundledRouter));
            EXPECT_FALSE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_FALSE(listenerB.GotAbsenceNOCFor(bundledRouter));

            /* BusAttachment D: request, advertise name and bind session port */
            String wknD = "org.test.D" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrD->RequestName(wknD.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrD->AdvertiseName(wknD.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestSessionListener sessionPortListenerD(BusPtrD);
            status = BusPtrD->BindSessionPort(sessionPortListenerD.port, opts, sessionPortListenerD);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Find advertisedname */
            listenerB.nameFound = 0;
            listenerB.nameMatched = 0;
            listenerB.NameToMatch = wknD;
            status = BusPtrB->FindAdvertisedNameByTransport(wknD.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerB.nameFound) && (listenerB.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerB.nameFound) << "failed to find advertised name: " << wknD.c_str();
            ASSERT_TRUE(listenerB.nameMatched) << "failed to find advertised name " << wknD.c_str();

            /* BusAttachment B: JoinSession */
            sessionIdB = 0;
            status = BusPtrB->JoinSession(wknD.c_str(), sessionPortListenerD.port, NULL, sessionIdB, opts);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment D: wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerD.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session IDs are matching */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdB) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerD.busSessionId, sessionIdB) << "  session ID's do not match";

            /* BusAttachment A gets presence NOC for SR2, D and E only if this is an EXCHANGE_ALL_NAMES session.
             * BusAttachment B gets Presence NOC for D and SR2.
             * BusAttachment D gets presence NOC for B and SR.
             * BusAttachment D gets Presence NOC for A and BR only if this is an EXCHANGE_ALL_NAMES session.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerB.GotPresenceNOCFor(BusPtrD->GetUniqueName()) &&
                    listenerB.GotPresenceNOCFor(standAloneRouter2) &&
                    listenerD.GotPresenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerD.GotPresenceNOCFor(standAloneRouter) &&
                    ((ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) ||
                     (listenerA.GotPresenceNOCFor(standAloneRouter2) &&
                      listenerA.GotPresenceNOCFor(BusPtrD->GetUniqueName()) &&
                      listenerA.GotPresenceNOCFor(BusPtrE->GetUniqueName()) &&
                      listenerD.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                      listenerD.GotPresenceNOCFor(bundledRouter)))) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }


            EXPECT_TRUE(listenerB.GotPresenceNOCFor(BusPtrD->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(standAloneRouter2));
            EXPECT_TRUE(listenerD.GotPresenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerD.GotPresenceNOCFor(standAloneRouter));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(standAloneRouter2));
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrD->GetUniqueName()));
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrE->GetUniqueName()));
                EXPECT_FALSE(listenerD.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_FALSE(listenerD.GotPresenceNOCFor(bundledRouter));
            } else {
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(standAloneRouter2));
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrD->GetUniqueName()));
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrE->GetUniqueName()));
                EXPECT_TRUE(listenerD.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_TRUE(listenerD.GotPresenceNOCFor(bundledRouter));
            }

            /* CancelFindAdvertisedName */
            status = BusPtrB->CancelFindAdvertisedNameByTransport(wknA.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->CancelFindAdvertisedNameByTransport(wknD.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment D: Leave session */
            status = BusPtrD->LeaveSession(sessionPortListenerD.busSessionId);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A gets Absence NOC for SR2, D and E only if this is an EXCHANGE_ALL_NAMES session.
             * BusAttachment B gets Absence NOC for D and SR2.
             * BusAttachment D gets Absence NOC for B and SR.
             * BusAttachment D gets Absence NOC for A and BR only if this is an EXCHANGE_ALL_NAMES session.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerD.GotAbsenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerD.GotAbsenceNOCFor(standAloneRouter) &&
                    (((ALLJOYN_PROTOCOL_VERSION >= 12) && (nm != EXCHANGE_ALL_NAMES)) ||
                     (listenerA.GotAbsenceNOCFor(BusPtrD->GetUniqueName()) && listenerA.GotAbsenceNOCFor(standAloneRouter2) &&
                      listenerA.GotAbsenceNOCFor(BusPtrE->GetUniqueName()) &&
                      listenerD.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) && listenerD.GotAbsenceNOCFor(bundledRouter))) &&
                    listenerB.GotAbsenceNOCFor(BusPtrD->GetUniqueName()) &&
                    listenerB.GotAbsenceNOCFor(standAloneRouter2)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            EXPECT_TRUE(listenerD.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerD.GotAbsenceNOCFor(standAloneRouter));
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(BusPtrD->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(standAloneRouter2));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrD->GetUniqueName()));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrE->GetUniqueName()));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(standAloneRouter2));
                EXPECT_FALSE(listenerD.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_FALSE(listenerD.GotAbsenceNOCFor(bundledRouter));

            } else {
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrD->GetUniqueName()));
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrE->GetUniqueName()));
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(standAloneRouter2));
                EXPECT_TRUE(listenerD.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_TRUE(listenerD.GotAbsenceNOCFor(bundledRouter));

            }
            /* BusAttachment A: Leave session */
            status = BusPtrA->LeaveSession(sessionPortListenerA.busSessionId);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment A gets Absence NOC for B and the SR.
             * BusAttachment B gets Absence NOC for A and BR.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerA.GotAbsenceNOCFor(standAloneRouter) &&
                    listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerB.GotAbsenceNOCFor(bundledRouter)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(standAloneRouter));

            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(bundledRouter));

            /* Unregister Bus Listeners */
            BusPtrA->UnregisterBusListener(listenerA);
            BusPtrB->UnregisterBusListener(listenerB);
            BusPtrD->UnregisterBusListener(listenerD);

            /* BusAttachment A: CancelAdvertiseName and ReleaseName */
            status = BusPtrA->CancelAdvertiseName(wknA.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrA->ReleaseName(wknA.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment D: CancelAdvertiseName and ReleaseName */
            status = BusPtrD->CancelAdvertiseName(wknD.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrD->ReleaseName(wknD.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

        }
    }
}

/* ThreeRoutingNodeSingleMPSessionTest:
 * Perform test for UDP and TCP and for nameTransferType MP_NAMES and ALL_NAMES
 * P2P session
 * (B)-(SR)         (BR)-(A)
 *
 *     (SR2)
 *      |  \
 *     (D) (E)
 * SR = standalone RN
 * SR2 = second standalone RN
 * BR = bundled RN
 * B requests, advertises a name and binds a MP session.
 * A finds and joins the session.
 * Check session IDs match.
 * Expected: A gets Presence NOC for B and the SR.
 *           B gets Presence NOC for A and BR.
 * D finds and joins the session.
 * Expected:
 *           A gets presence NOC for SR2 and D.
 *           A gets presence NOC for E only if ALL_NAMES
 *           B gets Presence NOC for D and SR2.
 *           D gets presence NOC for B and SR, A and BR.
 * D leaves session
 * Expected:
 *           A gets Absence NOC for SR2 and D.
 *           A gets Absence NOC for E only if ALL_NAMES
 *           B gets Absence NOC for D and SR2.
 *           D gets Absence NOC for B and SR, A and BR.
 * A leaves session
 * Expected: A gets Absence NOC for B and the SR.
 *           B gets Absence NOC for A and BR.
 */
TEST_F(NamePropagationTest, ThreeRoutingNodeSingleMPSessionTest) {
    QStatus status = ER_OK;

    for (size_t i = 0; i < sizeof(transportMasks) / sizeof(TransportMask); i++) {

        TransportMask tm = transportMasks[i];


        for (size_t j = 0; j < sizeof(nameTransferTypes) / sizeof(SessionOpts::NameTransferType); j++) {
            SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, true, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
            int nm = nameTransferTypes[j];
#if (ALLJOYN_PROTOCOL_VERSION < 12)
            if (nm != -1) {
                /* Only run test once for lower protocol versions */
                break;
            }
#else
            switch (nm) {
            case EXCHANGE_ALL_NAMES:
                opts.SetAllNames();
                break;

            case EXCHANGE_SESSION_NAMES:
                opts.SetSessionNames();
                break;

            default:
                break;
            }
#endif
            /* Set up bus listeners */
            NamePropTestFindNameListener listenerA("busAttachmentA");
            listenerA.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();

            BusPtrA->RegisterBusListener(listenerA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerB("busAttachmentB");
            listenerB.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();

            BusPtrB->RegisterBusListener(listenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerD("busAttachmentD");
            listenerD.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();

            BusPtrD->RegisterBusListener(listenerD);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Request name, advertise, bind session */
            status = BusPtrB->RequestName(listenerA.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->AdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestSessionListener sessionPortListenerB(BusPtrB);
            status = BusPtrB->BindSessionPort(sessionPortListenerB.port, opts, sessionPortListenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Find Name */
            status = BusPtrA->FindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment A: Wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerA.nameFound) && (listenerA.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerA.nameFound) << "failed to find advertised name: " << listenerA.NameToMatch.c_str();
            ASSERT_TRUE(listenerA.nameMatched) << "failed to find advertised name via UDP transport: " << listenerA.NameToMatch.c_str();

            /* BusAttachment A: JoinSession */
            SessionId sessionIdA = 0;
            status = BusPtrA->JoinSession(listenerA.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdA, opts);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment B: Wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerB.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session IDs are matching */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdA) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdA) << "  session ID's do not match";

            String bundledRouter = BusPtrA->GetUniqueName().substr(0, BusPtrA->GetUniqueName().find('.')) + ".1";
            String standAloneRouter = BusPtrB->GetUniqueName().substr(0, BusPtrB->GetUniqueName().find('.')) + ".1";
            String standAloneRouter2 = BusPtrD->GetUniqueName().substr(0, BusPtrD->GetUniqueName().find('.')) + ".1";
            /* BusAttachment A: Gets Presence NOC for B, SR.
             * BusAttachment B: Gets Presence NOC for A, BR.
             * No Absence NOCs must be received at this point.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerB.GotPresenceNOCFor(bundledRouter) &&
                    listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerA.GotPresenceNOCFor(standAloneRouter)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotPresenceNOCFor(standAloneRouter));
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));

            EXPECT_TRUE(listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(bundledRouter));
            EXPECT_FALSE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_FALSE(listenerB.GotAbsenceNOCFor(bundledRouter));

            /* BusAttachment D: find advertised name */
            status = BusPtrD->FindAdvertisedNameByTransport(listenerD.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment D: Wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerD.nameFound) && (listenerD.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerD.nameFound) << "failed to find advertised name: " << listenerD.NameToMatch.c_str();
            ASSERT_TRUE(listenerD.nameMatched) << "failed to find advertised name via UDP transport: " << listenerD.NameToMatch.c_str();

            /* BusAttachment D: JoinSession */
            sessionPortListenerB.sessionJoined = false;
            SessionId sessionIdD = 0;
            status = BusPtrD->JoinSession(listenerA.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdD, opts);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment B: wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerB.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session IDs are matching */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdD) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdD) << "  session ID's do not match";

            /* BusAttachment A gets presence NOC for SR2 and D.
             *                 gets presence NOC for E only if EXCHANGE_ALL_NAMES
             * BusAttachment B gets Presence NOC for D and SR2.
             * BusAttachment D gets presence NOC for B and SR, A and BR.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerB.GotPresenceNOCFor(BusPtrD->GetUniqueName()) &&
                    listenerB.GotPresenceNOCFor(standAloneRouter2) &&
                    listenerD.GotPresenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerD.GotPresenceNOCFor(standAloneRouter) &&
                    listenerA.GotPresenceNOCFor(standAloneRouter2) &&
                    listenerA.GotPresenceNOCFor(BusPtrD->GetUniqueName()) &&
                    (((ALLJOYN_PROTOCOL_VERSION >= 12) && (nm != EXCHANGE_ALL_NAMES)) ||
                     (listenerA.GotPresenceNOCFor(BusPtrE->GetUniqueName()) &&
                      listenerD.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                      listenerD.GotPresenceNOCFor(bundledRouter)))) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }


            EXPECT_TRUE(listenerB.GotPresenceNOCFor(BusPtrD->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(standAloneRouter2));
            EXPECT_TRUE(listenerD.GotPresenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerD.GotPresenceNOCFor(standAloneRouter));
            EXPECT_TRUE(listenerA.GotPresenceNOCFor(standAloneRouter2));
            EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrD->GetUniqueName()));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrE->GetUniqueName()));
            } else {
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrE->GetUniqueName()));
            }
            EXPECT_TRUE(listenerD.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerD.GotPresenceNOCFor(bundledRouter));

            /* CancelFindAdvertisedName */
            status = BusPtrA->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrD->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment D: Leave session */
            status = BusPtrD->LeaveSession(sessionIdD);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment A gets Absence NOC for SR2 and D.
             *                 gets absence NOC for E only if EXCHANGE_ALL_NAMES
             * BusAttachment B gets Absence NOC for D and SR2.
             * BusAttachment D gets Absence NOC for B and SR, A and BR.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerD.GotAbsenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerD.GotAbsenceNOCFor(standAloneRouter) &&
                    listenerA.GotAbsenceNOCFor(BusPtrD->GetUniqueName()) &&
                    listenerA.GotAbsenceNOCFor(standAloneRouter2) &&
                    (((ALLJOYN_PROTOCOL_VERSION >= 12) && (nm != EXCHANGE_ALL_NAMES)) ||
                     (listenerA.GotAbsenceNOCFor(BusPtrE->GetUniqueName()) &&
                      listenerD.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                      listenerD.GotAbsenceNOCFor(bundledRouter) &&
                      listenerB.GotAbsenceNOCFor(BusPtrD->GetUniqueName()) &&
                      listenerB.GotAbsenceNOCFor(standAloneRouter2)))) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerD.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerD.GotAbsenceNOCFor(standAloneRouter));
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(BusPtrD->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(standAloneRouter2));
            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrD->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(standAloneRouter2));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrE->GetUniqueName()));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrE->GetUniqueName()));
            } else {
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrE->GetUniqueName()));
            }
            EXPECT_TRUE(listenerD.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerD.GotAbsenceNOCFor(bundledRouter));

            /* BusAttachment A: Leave session */
            status = BusPtrA->LeaveSession(sessionIdA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment A gets Absence NOC for B and the SR.
             * BusAttachment B gets Absence NOC for A and BR.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerA.GotAbsenceNOCFor(standAloneRouter) &&
                    listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerB.GotAbsenceNOCFor(bundledRouter)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(standAloneRouter));

            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(bundledRouter));

            /* Unregister Bus Listeners */
            BusPtrA->UnregisterBusListener(listenerA);
            BusPtrB->UnregisterBusListener(listenerB);
            BusPtrD->UnregisterBusListener(listenerD);

            /* BusAttachment B: CancelAdvertiseName and ReleaseName */
            status = BusPtrB->CancelAdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->ReleaseName(listenerA.NameToMatch.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
        }
    }
}

/* ThreeRoutingNodeSeparateMPSessionTest:
 * Perform test for UDP and TCP and for nameTransferType MP_NAMES and ALL_NAMES
 * P2P session
 * (B)-(SR)         (BR)-(A)
 *
 *     (SR2)
 *      |  \
 *     (D) (E)
 * SR = standalone RN
 * SR2 = second standalone RN
 * BR = bundled RN
 * B requests, advertises two names and binds a MP session.
 * A finds and joins the session.
 * Check session IDs match.
 * Expected: A gets Presence NOC for B and the SR.
 *           B gets Presence NOC for A and BR.
 * D finds and joins the session.
 * Expected:
 *           A gets presence NOC for SR2, D and E only if this is an ALL_NAMES session.
 *           B gets Presence NOC for D and SR2.
 *           D gets presence NOC for B and SR.
 *           D gets Presence NOC for A and BR only if this is an ALL_NAMES session.
 * D leaves session
 * Expected:
 *           A gets Absence NOC for SR2, D and E only if this is an ALL_NAMES session.
 *           B gets Absence NOC for D and SR2.
 *           D gets Absence NOC for B and SR.
 *           D gets Absence NOC for A and BR only if this is an ALL_NAMES session.
 */
TEST_F(NamePropagationTest, ThreeRoutingNodeSeparateMPSessionTest) {
    QStatus status = ER_OK;

    for (size_t i = 0; i < sizeof(transportMasks) / sizeof(TransportMask); i++) {

        TransportMask tm = transportMasks[i];


        for (size_t j = 0; j < sizeof(nameTransferTypes) / sizeof(SessionOpts::NameTransferType); j++) {
            SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, true, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
            int nm = nameTransferTypes[j];

#if (ALLJOYN_PROTOCOL_VERSION < 12)
            if (nm != -1) {
                /* Only run test once for lower protocol versions */
                break;
            }
#else
            switch (nm) {
            case EXCHANGE_ALL_NAMES:
                opts.SetAllNames();
                break;

            case EXCHANGE_SESSION_NAMES:
                opts.SetSessionNames();
                break;

            default:
                break;
            }
#endif
            /* Set up bus listeners */
            NamePropTestFindNameListener listenerA("busAttachmentA");
            listenerA.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();

            BusPtrA->RegisterBusListener(listenerA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerB("busAttachmentB");
            listenerB.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();

            BusPtrB->RegisterBusListener(listenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerD("busAttachmentD");
            listenerD.NameToMatch = "org.test.D" + BusPtrA->GetGlobalGUIDShortString();

            BusPtrD->RegisterBusListener(listenerD);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Request names, advertise, bind session */
            status = BusPtrB->RequestName(listenerA.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->AdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->RequestName(listenerD.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->AdvertiseName(listenerD.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestSessionListener sessionPortListenerB(BusPtrB);
            status = BusPtrB->BindSessionPort(sessionPortListenerB.port, opts, sessionPortListenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestSessionListener sessionPortListenerB2(BusPtrB);
            status = BusPtrB->BindSessionPort(sessionPortListenerB2.port, opts, sessionPortListenerB2);

            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Find Name */
            status = BusPtrA->FindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment A: Wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerA.nameFound) && (listenerA.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerA.nameFound) << "failed to find advertised name: " << listenerA.NameToMatch.c_str();
            ASSERT_TRUE(listenerA.nameMatched) << "failed to find advertised name via UDP transport: " << listenerA.NameToMatch.c_str();

            /* BusAttachment A: JoinSession */
            SessionId sessionIdA = 0;
            status = BusPtrA->JoinSession(listenerA.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdA, opts);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment B: Wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerB.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session IDs are matching */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdA) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdA) << "  session ID's do not match";

            String bundledRouter = BusPtrA->GetUniqueName().substr(0, BusPtrA->GetUniqueName().find('.')) + ".1";
            String standAloneRouter = BusPtrB->GetUniqueName().substr(0, BusPtrB->GetUniqueName().find('.')) + ".1";
            String standAloneRouter2 = BusPtrD->GetUniqueName().substr(0, BusPtrD->GetUniqueName().find('.')) + ".1";
            /* BusAttachment A: Gets Presence NOC for B, SR.
             * BusAttachment B: Gets Presence NOC for A, BR.
             * No Absence NOCs must be received at this point.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerB.GotPresenceNOCFor(bundledRouter) &&
                    listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerA.GotPresenceNOCFor(standAloneRouter)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }


            EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotPresenceNOCFor(standAloneRouter));
            EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));

            EXPECT_TRUE(listenerB.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(bundledRouter));
            EXPECT_FALSE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_FALSE(listenerB.GotAbsenceNOCFor(bundledRouter));

            /* BusAttachment D: find advertised name */
            status = BusPtrD->FindAdvertisedNameByTransport(listenerD.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment D: Wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerD.nameFound) && (listenerD.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerD.nameFound) << "failed to find advertised name: " << listenerD.NameToMatch.c_str();
            ASSERT_TRUE(listenerD.nameMatched) << "failed to find advertised name via UDP transport: " << listenerD.NameToMatch.c_str();

            /* BusAttachment D: JoinSession */
            SessionId sessionIdD = 0;
            status = BusPtrD->JoinSession(listenerD.NameToMatch.c_str(), sessionPortListenerB2.port, NULL, sessionIdD, opts);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment B: wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerB2.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session IDs are matching */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdD) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerB2.busSessionId, sessionIdD) << "  session ID's do not match";

            /* BusAttachment A gets presence NOC for SR2, D and E only if this is an ALL_NAMES session.
             * BusAttachment B gets Presence NOC for D and SR2.
             * BusAttachment D gets presence NOC for B and SR.
             * BusAttachment D gets Presence NOC for A and BR only if this is an ALL_NAMES session.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerB.GotPresenceNOCFor(BusPtrD->GetUniqueName()) &&
                    listenerB.GotPresenceNOCFor(standAloneRouter2) &&
                    listenerD.GotPresenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerD.GotPresenceNOCFor(standAloneRouter) &&
                    ((ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) ||
                     (listenerA.GotPresenceNOCFor(standAloneRouter2) &&
                      listenerA.GotPresenceNOCFor(BusPtrD->GetUniqueName()) &&
                      listenerA.GotPresenceNOCFor(BusPtrE->GetUniqueName()) &&
                      listenerD.GotPresenceNOCFor(BusPtrA->GetUniqueName()) &&
                      listenerD.GotPresenceNOCFor(bundledRouter)))) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerB.GotPresenceNOCFor(BusPtrD->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(standAloneRouter2));
            EXPECT_TRUE(listenerD.GotPresenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerD.GotPresenceNOCFor(standAloneRouter));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(standAloneRouter2));
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrD->GetUniqueName()));
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrE->GetUniqueName()));
                EXPECT_FALSE(listenerD.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_FALSE(listenerD.GotPresenceNOCFor(bundledRouter));
            } else {
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(standAloneRouter2));
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrD->GetUniqueName()));
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(BusPtrE->GetUniqueName()));
                EXPECT_TRUE(listenerD.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_TRUE(listenerD.GotPresenceNOCFor(bundledRouter));
            }

            /* CancelFindAdvertisedName */
            status = BusPtrA->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrD->CancelFindAdvertisedNameByTransport(listenerD.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment D: Leave session */
            status = BusPtrD->LeaveSession(sessionIdD);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
            /* BusAttachment A gets Absence NOC for SR2, D and E only if this is an ALL_NAMES session.
             * BusAttachment B gets Absence NOC for D and SR2.
             * BusAttachment D gets Absence NOC for B and SR.
             * BusAttachment D gets Absence NOC for A and BR only if this is an ALL_NAMES session.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerD.GotAbsenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerD.GotAbsenceNOCFor(standAloneRouter) &&
                    (((ALLJOYN_PROTOCOL_VERSION >= 12) && (nm != EXCHANGE_ALL_NAMES)) ||
                     (listenerA.GotAbsenceNOCFor(BusPtrD->GetUniqueName()) && listenerA.GotAbsenceNOCFor(standAloneRouter2) &&
                      listenerA.GotAbsenceNOCFor(BusPtrE->GetUniqueName()) &&
                      listenerD.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) && listenerD.GotAbsenceNOCFor(bundledRouter))) &&
                    listenerB.GotAbsenceNOCFor(BusPtrD->GetUniqueName()) &&
                    listenerB.GotAbsenceNOCFor(standAloneRouter2)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            EXPECT_TRUE(listenerD.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerD.GotAbsenceNOCFor(standAloneRouter));
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(BusPtrD->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(standAloneRouter2));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrD->GetUniqueName()));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrE->GetUniqueName()));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(standAloneRouter2));
                EXPECT_FALSE(listenerD.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_FALSE(listenerD.GotAbsenceNOCFor(bundledRouter));

            } else {
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrD->GetUniqueName()));
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrE->GetUniqueName()));
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(standAloneRouter2));
                EXPECT_TRUE(listenerD.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_TRUE(listenerD.GotAbsenceNOCFor(bundledRouter));

            }

            /* BusAttachment A: Leave session */
            status = BusPtrA->LeaveSession(sessionIdA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A gets Absence NOC for B and the SR.
             * BusAttachment B gets Absence NOC for A and BR.
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerA.GotAbsenceNOCFor(standAloneRouter) &&
                    listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerB.GotAbsenceNOCFor(bundledRouter)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(standAloneRouter));

            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(bundledRouter));


            /* Unregister Bus Listeners */
            BusPtrA->UnregisterBusListener(listenerA);
            BusPtrB->UnregisterBusListener(listenerB);
            BusPtrD->UnregisterBusListener(listenerD);

            /* BusAttachment B: CancelAdvertiseName and ReleaseName */
            status = BusPtrB->CancelAdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->CancelAdvertiseName(listenerD.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->ReleaseName(listenerA.NameToMatch.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->ReleaseName(listenerD.NameToMatch.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

        }
    }
}

/*
 * ThreeRoutingNodeP2PWellKnownNames:
 * Verify that NOCs for well known names are received only when there is a session.
 * Perform test for UDP and TCP for nameTransfer type values: default, EXCHANGE_SESSION_NAMES, EXCHANGE_ALL_NAMES.
 * (B)-(SR)         (BR)-(A)
 *
 *     (SR2)
 *      |  \
 *     (D) (E)
 * SR = standalone RN
 * SR2 = second standalone RN
 * BR = bundled RN
 * A, D and E request a wellknown name each.
 * B requests, advertises a name and binds a P2P session.
 * A finds and joins the session.
 * D finds and joins the session.
 * Check session IDs match.
 *
 * Expected: A gets Presence NOC for BusAttachment B's wellknown name. i.e. listenerA.NameToMatch
 * A does not get Presence NOC for BusAttachment D's and E's wellknown name. unless EXCHANGE_ALL_NAMES
 * B gets Presence NOC for BusAttachment A's wellknown name. i.e. wknA
 * D does not get Presence NOC for BusAttachment A's wellknown name. i.e. wknA unless EXCHANGE_ALL_NAMES
 *
 * A, B and D release the wellknown names.
 *
 * Expected: A gets Absence NOC for BusAttachment B's wellknown name. i.e. listenerA.NameToMatch
 * A does not get Presence or Absence NOC for BusAttachment D's and E's wellknown name. unless EXCHANGE_ALL_NAMES
 * B gets Absence NOC for BusAttachment A's wellknown name. i.e. wknA
 * D does not get Absence NOC for BusAttachment A's wellknown name. i.e. wknA unless EXCHANGE_ALL_NAMES
 *
 * A, B and D re-request new wellknown names.
 *
 * Expected: A gets Presence NOC for BusAttachment B's wellknown name. i.e. wknB
 * A does not get Presence NOC for BusAttachment D's and E's wellknown name. unless EXCHANGE_ALL_NAMES
 * B gets Presence NOC for BusAttachment A's wellknown name. i.e. wknA
 * D does not get Presence NOC for BusAttachment A's wellknown name. i.e. wknA unless EXCHANGE_ALL_NAMES
 *
 */
TEST_F(NamePropagationTest, ThreeRoutingNodeP2PWellKnownNames) {
    QStatus status = ER_OK;
    for (size_t i = 0; i < sizeof(transportMasks) / sizeof(TransportMask); i++) {

        TransportMask tm = transportMasks[i];


        for (size_t j = 0; j < sizeof(nameTransferTypes) / sizeof(SessionOpts::NameTransferType); j++) {
            SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, false, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
            int nm = nameTransferTypes[j];
#if (ALLJOYN_PROTOCOL_VERSION < 12)
            if (nm != -1) {
                /* Only run test once for lower protocol versions */
                break;
            }
#else
            switch (nm) {
            case EXCHANGE_ALL_NAMES:
                opts.SetAllNames();
                break;

            case EXCHANGE_SESSION_NAMES:
                opts.SetSessionNames();
                break;

            default:
                break;
            }
#endif
            /* Set up bus listeners */
            String wknB = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            NamePropTestFindNameListener listenerA("busAttachmentA");
            listenerA.NameToMatch = wknB;
            BusPtrA->RegisterBusListener(listenerA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerB("busAttachmentB");
            listenerB.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrB->RegisterBusListener(listenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerD("busAttachmentD");
            listenerD.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrD->RegisterBusListener(listenerD);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: request a wellknown name */
            String wknA = "org.test.A" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrA->RequestName(wknA.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment D: request a wellknown name */
            String wknD = "org.test.D" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrD->RequestName(wknD.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment E: request a wellknown name */
            String wknE = "org.test.E" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrE->RequestName(wknE.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Request name, advertise, bind session */
            status = BusPtrB->RequestName(listenerA.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->AdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestSessionListener sessionPortListenerB(BusPtrB);
            status = BusPtrB->BindSessionPort(sessionPortListenerB.port, opts, sessionPortListenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: find advertised name */
            status = BusPtrA->FindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerA.nameFound) && (listenerA.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerA.nameFound) << "failed to find advertised name: " << listenerA.NameToMatch.c_str();
            ASSERT_TRUE(listenerA.nameMatched) << "failed to find advertised name" << listenerA.NameToMatch.c_str();

            /* BusAttachment A: JoinSession */
            SessionId sessionIdA = 0;
            status = BusPtrA->JoinSession(listenerA.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdA, opts);
            ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerB.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session ID */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdA) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdA) << "  session ID's do not match";

            /* BusAttachment D: find advertised name */
            status = BusPtrD->FindAdvertisedNameByTransport(listenerD.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);


            /* BusAttachment D: wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerD.nameFound) && (listenerD.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerD.nameFound) << "failed to find advertised name: " << listenerD.NameToMatch.c_str();
            ASSERT_TRUE(listenerD.nameMatched) << "failed to find advertised name" << listenerD.NameToMatch.c_str();

            /* BusAttachment D: JoinSession */
            SessionId sessionIdD = 0;
            sessionPortListenerB.sessionJoined = false;
            status = BusPtrD->JoinSession(listenerD.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdD, opts);
            ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerB.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session ID */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdD) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdD) << "  session ID's do not match";
            EXPECT_NE(sessionIdA, sessionIdD) << "  session ID's match";

            /* BusAttachment A: Gets Presence NOC for BusAttachment B's wellknown name. i.e. listenerA.NameToMatch
             * BusAttachment A does not get Presence NOC for BusAttachment D's and E's wellknown name. unless ALL_NAMES
             * BusAttachment B: Gets Presence NOC for BusAttachment A's wellknown name. i.e. wknA
             * BusAttachment D does not get Presence NOC for BusAttachment A's wellknown name. i.e. wknA unless ALL_NAMES
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotPresenceNOCFor(listenerA.NameToMatch) && listenerB.GotPresenceNOCFor(wknA) &&
                    ((ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) ||
                     (listenerA.GotPresenceNOCFor(wknD) && listenerA.GotPresenceNOCFor(wknE) &&
                      listenerD.GotPresenceNOCFor(wknA)))) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotPresenceNOCFor(listenerA.NameToMatch));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(wknD));
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(wknE));
                EXPECT_FALSE(listenerD.GotPresenceNOCFor(wknA));
            } else {
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(wknD));
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(wknE));
                EXPECT_TRUE(listenerD.GotPresenceNOCFor(wknA));
            }
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(wknA));

            /* BusAttachment A: cancel find */
            status = BusPtrA->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment D: cancel find */
            status = BusPtrD->CancelFindAdvertisedNameByTransport(listenerD.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* Release all names */
            status = BusPtrA->ReleaseName(wknA.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->ReleaseName(wknB.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrD->ReleaseName(wknD.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrE->ReleaseName(wknE.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Gets Absence NOC for BusAttachment B's wellknown name. i.e. wknB
             * BusAttachment A does not get Absence NOC for BusAttachment D's and E's wellknown name. unless ALL_NAMES
             * BusAttachment B: Gets Absence NOC for BusAttachment A's wellknown name. i.e. wknA
             * BusAttachment D does not get Absence NOC for BusAttachment A's wellknown name. i.e. wknA unless ALL_NAMES
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotAbsenceNOCFor(wknB) && listenerB.GotAbsenceNOCFor(wknA) &&
                    ((ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) ||
                     (listenerA.GotAbsenceNOCFor(wknD) && listenerA.GotAbsenceNOCFor(wknE) &&
                      listenerD.GotAbsenceNOCFor(wknA)))) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(wknB));
            if ((ALLJOYN_PROTOCOL_VERSION >= 12) && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(wknD));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(wknD));
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(wknE));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(wknE));
                EXPECT_FALSE(listenerD.GotPresenceNOCFor(wknA));
                EXPECT_FALSE(listenerD.GotAbsenceNOCFor(wknA));

            } else {
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(wknD));
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(wknE));
                EXPECT_TRUE(listenerD.GotAbsenceNOCFor(wknA));
            }
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(wknA));

            /* Request new wellknown names */
            wknA = "org.test1.A" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrA->RequestName(wknA.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            wknB = "org.test1.B" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrB->RequestName(wknB.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            wknD = "org.test1.D" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrD->RequestName(wknD.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            wknE = "org.test1.E" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrE->RequestName(wknE.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Gets Presence NOC for wknB
             * BusAttachment A does not get Presence NOC for BusAttachment D's and E's wellknown name. unless ALL_NAMES
             * BusAttachment B: Gets Presence NOC for wknA
             * BusAttachment D does not get Presence NOC for BusAttachment A's wellknown name. i.e. wknA unless ALL_NAMES
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotPresenceNOCFor(wknB) && listenerB.GotPresenceNOCFor(wknA) &&
                    ((ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) ||
                     (listenerA.GotPresenceNOCFor(wknD) && listenerA.GotPresenceNOCFor(wknE) &&
                      listenerD.GotPresenceNOCFor(wknA)))) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotPresenceNOCFor(wknB));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(wknD));
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(wknE));
                EXPECT_FALSE(listenerD.GotPresenceNOCFor(wknA));
            } else {
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(wknD));
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(wknE));
                EXPECT_TRUE(listenerD.GotPresenceNOCFor(wknA));
            }
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(wknA));

            /* Leave session */
            status = BusPtrA->LeaveSession(sessionIdA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* Leave session */
            status = BusPtrD->LeaveSession(sessionIdD);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* Wait for session to be torn down completely
             * BusAttachment A: Gets Absence NOC for B, SR.
             * Gets Absence NOC for D and E if  ALL_NAMES.
             * BusAttachment B: Gets Absence NOC for A, BR.
             * BusAttachment D gets NOC for A if ALL_NAMES
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()) &&
                    ((ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) ||
                     (listenerA.GotAbsenceNOCFor(BusPtrD->GetUniqueName()) &&
                      listenerA.GotAbsenceNOCFor(BusPtrE->GetUniqueName()) &&
                      listenerD.GotAbsenceNOCFor(BusPtrA->GetUniqueName()))) &&
                    listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName())) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrD->GetUniqueName()));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrD->GetUniqueName()));
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(BusPtrE->GetUniqueName()));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(BusPtrE->GetUniqueName()));
                EXPECT_FALSE(listenerD.GotPresenceNOCFor(BusPtrA->GetUniqueName()));
                EXPECT_FALSE(listenerD.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));

            } else {
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrD->GetUniqueName()));
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrE->GetUniqueName()));
                EXPECT_TRUE(listenerD.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));
            }

            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));

            /* Unregister Bus Listeners */
            BusPtrA->UnregisterBusListener(listenerA);
            BusPtrB->UnregisterBusListener(listenerB);
            BusPtrD->UnregisterBusListener(listenerD);

            /* Release names */
            status = BusPtrA->ReleaseName(wknA.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->ReleaseName(wknB.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrD->ReleaseName(wknD.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrE->ReleaseName(wknE.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: CancelAdvertiseName */
            status = BusPtrB->CancelAdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

        }
    }

}

/*
 * ThreeRoutingNodeMPWellKnownNames:
 * Verify that NOCs for well known names are received only when there is a session.
 * Perform test for UDP and TCP for nameTransfer type values: default, EXCHANGE_SESSION_NAMES, EXCHANGE_ALL_NAMES.
 * (B)-(SR)         (BR)-(A)
 *
 *     (SR2)
 *      |  \
 *     (D) (E)
 * SR = standalone RN
 * SR2 = second standalone RN
 * BR = bundled RN
 * A, D and E request a wellknown name each.
 * B requests, advertises a name and binds a P2P session.
 * A finds and joins the session.
 * D finds and joins the session.
 * Check session IDs match.
 *
 * Expected: A gets Presence NOC for BusAttachment B's wellknown name. i.e. listenerA.NameToMatch
 * A gets Presence NOC for BusAttachment D's wellknown name.
 * A gets Presence NOC for BusAttachment E's wellknown name if EXCHANGE_ALL_NAMES.
 * B gets Presence NOC for BusAttachment A's wellknown name. i.e. wknA
 * D gets Presence NOC for BusAttachment A's wellknown name. i.e. wknA
 *
 * A, B, D and E release the wellknown names.
 *
 * Expected: A gets Absence NOC for BusAttachment B's wellknown name. i.e. listenerA.NameToMatch
 * A gets Absence NOC for BusAttachment D's wellknown name.
 * A does not get Absence NOC for BusAttachment E's wellknown name unless EXCHANGE_ALL_NAMES.
 * B gets Absence NOC for BusAttachment A's wellknown name. i.e. wknA
 * D gets Absence NOC for BusAttachment A's wellknown name. i.e. wknA
 *
 * A, B, D and E re-request new wellknown names.
 *
 * Expected: A gets Presence NOC for BusAttachment B's wellknown name. i.e. wknB
 * A gets Presence NOC for BusAttachment D's wellknown name.
 * A gets Presence NOC for BusAttachment E's wellknown name if EXCHANGE_ALL_NAMES.
 * B gets Presence NOC for BusAttachment A's wellknown name. i.e. wknA
 * D gets Presence NOC for BusAttachment A's wellknown name. i.e. wknA
 *
 */
TEST_F(NamePropagationTest, ThreeRoutingNodeMPWellKnownNames) {
    QStatus status = ER_OK;

    for (size_t j = 0; j < sizeof(nameTransferTypes) / sizeof(SessionOpts::NameTransferType); j++) {
        SessionOpts opts(SessionOpts::TRAFFIC_MESSAGES, true, SessionOpts::PROXIMITY_ANY, TRANSPORT_ANY);
        int nm = nameTransferTypes[j];
#if (ALLJOYN_PROTOCOL_VERSION < 12)
        if (nm != -1) {
            /* Only run test once for lower protocol versions */
            break;
        }
#else
        switch (nm) {
        case EXCHANGE_ALL_NAMES:
            opts.SetAllNames();
            break;

        case EXCHANGE_SESSION_NAMES:
            opts.SetSessionNames();
            break;

        default:
            break;
        }
#endif
        for (size_t i = 0; i < sizeof(transportMasks) / sizeof(TransportMask); i++) {

            TransportMask tm = transportMasks[i];

            /* Set up bus listeners */
            String wknB = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            NamePropTestFindNameListener listenerA("busAttachmentA");
            listenerA.NameToMatch = wknB;
            BusPtrA->RegisterBusListener(listenerA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerB("busAttachmentB");
            listenerB.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrB->RegisterBusListener(listenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestFindNameListener listenerD("busAttachmentD");
            listenerD.NameToMatch = "org.test.F" + BusPtrA->GetGlobalGUIDShortString();
            BusPtrD->RegisterBusListener(listenerD);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: request a wellknown name */
            String wknA = "org.test.A" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrA->RequestName(wknA.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment D: request a wellknown name */
            String wknD = "org.test.D" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrD->RequestName(wknD.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment E: request a wellknown name */
            String wknE = "org.test.E" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrE->RequestName(wknE.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Request name, advertise, bind session */
            status = BusPtrB->RequestName(listenerA.NameToMatch.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->AdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            NamePropTestSessionListener sessionPortListenerB(BusPtrB);
            status = BusPtrB->BindSessionPort(sessionPortListenerB.port, opts, sessionPortListenerB);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: find advertised name */
            status = BusPtrA->FindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerA.nameFound) && (listenerA.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerA.nameFound) << "failed to find advertised name: " << listenerA.NameToMatch.c_str();
            ASSERT_TRUE(listenerA.nameMatched) << "failed to find advertised name" << listenerA.NameToMatch.c_str();

            /* BusAttachment A: JoinSession */
            SessionId sessionIdA = 0;
            status = BusPtrA->JoinSession(listenerA.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdA, opts);
            ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerB.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session ID */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdA) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdA) << "  session ID's do not match";

            /* BusAttachment D: find advertised name */
            status = BusPtrD->FindAdvertisedNameByTransport(listenerD.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment D: wait for FoundAdvertisedName */
            for (unsigned int msec = 0; msec < FIND_NAME_TIME; msec += WAIT_TIME) {
                if ((listenerD.nameFound) && (listenerD.nameMatched)) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            ASSERT_TRUE(listenerD.nameFound) << "failed to find advertised name: " << listenerD.NameToMatch.c_str();
            ASSERT_TRUE(listenerD.nameMatched) << "failed to find advertised name" << listenerD.NameToMatch.c_str();

            /* BusAttachment D: JoinSession */
            SessionId sessionIdD = 0;
            sessionPortListenerB.sessionJoined = false;
            status = BusPtrD->JoinSession(listenerD.NameToMatch.c_str(), sessionPortListenerB.port, NULL, sessionIdD, opts);
            ASSERT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: Wait for SessionJoined */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (sessionPortListenerB.sessionJoined) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            /* Check session ID */
            EXPECT_NE(static_cast<SessionId>(0), sessionIdD) << "  SessionID should not be '0'";
            EXPECT_EQ(sessionPortListenerB.busSessionId, sessionIdD) << "  session ID's do not match";
            EXPECT_EQ(sessionIdA, sessionIdD) << "  session ID's do not match";

            /* BusAttachment A: Gets Presence NOC for BusAttachment B's wellknown name. i.e. listenerA.NameToMatch
             * BusAttachment A gets Presence NOC for BusAttachment D's wellknown name.
             * BusAttachment A does not get Presence NOC for BusAttachment E's wellknown name. i.e. wknE unless ALL_NAMES
             * BusAttachment B: Gets Presence NOC for BusAttachment A's wellknown name. i.e. wknA
             * BusAttachment D does not get Presence NOC for BusAttachment A's wellknown name. i.e. wknA unless ALL_NAMES
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotPresenceNOCFor(listenerA.NameToMatch) && listenerB.GotPresenceNOCFor(wknA) &&
                    listenerA.GotPresenceNOCFor(wknD) && listenerD.GotPresenceNOCFor(wknA) &&
                    ((ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) || listenerA.GotPresenceNOCFor(wknE))) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotPresenceNOCFor(listenerA.NameToMatch));
            EXPECT_TRUE(listenerA.GotPresenceNOCFor(wknD));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(wknE));
            } else {
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(wknE));
            }
            EXPECT_TRUE(listenerD.GotPresenceNOCFor(wknA));
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(wknA));

            /* BusAttachment A: cancel find */
            status = BusPtrA->CancelFindAdvertisedNameByTransport(listenerA.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment D: cancel find */
            status = BusPtrD->CancelFindAdvertisedNameByTransport(listenerD.NameToMatch.c_str(), TRANSPORT_ANY);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* Release all names */
            status = BusPtrA->ReleaseName(wknA.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->ReleaseName(wknB.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrD->ReleaseName(wknD.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrE->ReleaseName(wknE.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Gets Absence NOC for BusAttachment B's wellknown name. i.e. wknB
             * BusAttachment A gets Absence NOC for BusAttachment D's wellknown name.
             * BusAttachment A does not get Absence NOC for BusAttachment E's wellknown name. i.e. wknE unless ALL_NAMES
             * BusAttachment B: Gets Absence NOC for BusAttachment A's wellknown name. i.e. wknA
             * BusAttachment D does not get Absence NOC for BusAttachment A's wellknown name. i.e. wknA unless ALL_NAMES
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotAbsenceNOCFor(wknB) && listenerB.GotAbsenceNOCFor(wknA) &&
                    listenerA.GotAbsenceNOCFor(wknD) && listenerD.GotAbsenceNOCFor(wknA) &&
                    (((ALLJOYN_PROTOCOL_VERSION >= 12) && (nm != EXCHANGE_ALL_NAMES)) || listenerA.GotAbsenceNOCFor(wknE))) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }
            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(wknB));
            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(wknD));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(wknE));
                EXPECT_FALSE(listenerA.GotAbsenceNOCFor(wknE));
            } else {
                EXPECT_TRUE(listenerA.GotAbsenceNOCFor(wknE));
            }

            EXPECT_TRUE(listenerD.GotAbsenceNOCFor(wknA));
            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(wknA));

            /* Request new wellknown names */
            wknA = "org.test1.A" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrA->RequestName(wknA.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            wknB = "org.test1.B" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrB->RequestName(wknB.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            wknD = "org.test1.D" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrD->RequestName(wknD.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            wknE = "org.test1.E" + BusPtrA->GetGlobalGUIDShortString();
            status = BusPtrE->RequestName(wknE.c_str(), DBUS_NAME_FLAG_DO_NOT_QUEUE);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment A: Gets Presence NOC for wknB
             * BusAttachment A does not get Presence NOC for BusAttachment D's wellknown name. i.e. wknD unless ALL_NAMES
             * BusAttachment B: Gets Presence NOC for wknA
             * BusAttachment D does not get Presence NOC for BusAttachment A's wellknown name. i.e. wknA unless ALL_NAMES
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotPresenceNOCFor(wknB) && listenerB.GotPresenceNOCFor(wknA) &&
                    listenerA.GotPresenceNOCFor(wknD) && listenerD.GotPresenceNOCFor(wknA) &&
                    (((ALLJOYN_PROTOCOL_VERSION >= 12) && (nm != EXCHANGE_ALL_NAMES)) || listenerA.GotPresenceNOCFor(wknE))) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotPresenceNOCFor(wknB));
            EXPECT_TRUE(listenerA.GotPresenceNOCFor(wknD));
            if (ALLJOYN_PROTOCOL_VERSION >= 12 && (nm != EXCHANGE_ALL_NAMES)) {
                EXPECT_FALSE(listenerA.GotPresenceNOCFor(wknE));
            } else {
                EXPECT_TRUE(listenerA.GotPresenceNOCFor(wknE));
            }

            EXPECT_TRUE(listenerD.GotPresenceNOCFor(wknA));
            EXPECT_TRUE(listenerB.GotPresenceNOCFor(wknA));

            /* Leave session */
            status = BusPtrA->LeaveSession(sessionIdA);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* Leave session */
            status = BusPtrD->LeaveSession(sessionIdD);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* Wait for session to be torn down completely
             * BusAttachment A: Gets Absence NOC for B, SR.
             * Gets Absence NOC for D if  ALL_NAMES.
             * BusAttachment B: Gets Absence NOC for A, BR.
             * BusAttachment D gets NOC for A if ALL_NAMES
             */
            for (unsigned int msec = 0; msec < 5000; msec += WAIT_TIME) {
                if (listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()) &&
                    listenerA.GotAbsenceNOCFor(BusPtrD->GetUniqueName()) &&
                    listenerD.GotAbsenceNOCFor(BusPtrA->GetUniqueName()) &&
                    listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName())) {
                    break;
                }
                qcc::Sleep(WAIT_TIME);
            }

            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrB->GetUniqueName()));
            EXPECT_TRUE(listenerA.GotAbsenceNOCFor(BusPtrD->GetUniqueName()));
            EXPECT_TRUE(listenerD.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));

            EXPECT_TRUE(listenerB.GotAbsenceNOCFor(BusPtrA->GetUniqueName()));

            /* Unregister Bus Listeners */
            BusPtrA->UnregisterBusListener(listenerA);
            BusPtrB->UnregisterBusListener(listenerB);
            BusPtrD->UnregisterBusListener(listenerD);

            /* Release names */
            status = BusPtrA->ReleaseName(wknA.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrB->ReleaseName(wknB.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrD->ReleaseName(wknD.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            status = BusPtrE->ReleaseName(wknE.c_str());
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);

            /* BusAttachment B: CancelAdvertiseName */
            status = BusPtrB->CancelAdvertiseName(listenerA.NameToMatch.c_str(), tm);
            EXPECT_EQ(ER_OK, status) << "  Actual Status: " << QCC_StatusText(status);
        }
    }

}

