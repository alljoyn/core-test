/******************************************************************************
 *    Copyright (c) Open Connectivity Foundation (OCF), AllJoyn Open Source
 *    Project (AJOSP) Contributors and others.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Copyright (c) Open Connectivity Foundation and Contributors to AllSeen
 *    Alliance. All rights reserved.
 *
 *    Permission to use, copy, modify, and/or distribute this software for
 *    any purpose with or without fee is hereby granted, provided that the
 *    above copyright notice and this permission notice appear in all
 *    copies.
 *
 *    THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 *    WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 *    WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 *    AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 *    DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 *    PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 *    TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *    PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/

#ifndef __STDC_LIMIT_MACROS
#define __STDC_LIMIT_MACROS // Android needs this #define to get UINT*_MAX
#include <stdint.h>
#undef __STDC_LIMIT_MACROS
#endif

#include <iostream>

#include <cassert>
#include <csignal>
#include <ctime>

#include <qcc/Debug.h>
#include <qcc/String.h>
#include <qcc/StringUtil.h>
#include <qcc/Thread.h>
#include <qcc/Util.h>
#include <qcc/time.h>

#include <alljoyn/AllJoynStd.h>
#include <alljoyn/BusAttachment.h>
#include <alljoyn/Init.h>
#include <alljoyn/Status.h>
#include <alljoyn/version.h>

#define QCC_MODULE "ADVTDISCOV TEST PROGRAM"

// Based on guidelines at http://www.freebsd.org/cgi/man.cgi?query=sysexits
enum retval_t {
    EXIT_OK = 0,
    EXIT_USAGE = 64,
    EXIT_SOFTWARE = 70
};

enum runmode_t {
    RM_ADVERTISE,
    RM_DISCOVER
};

// Timestamps collected at consumer's end (the end that is discovering)
typedef struct nameTimestamp_t_ {
    char name[UINT8_MAX +  1]; // 255 character name + '\0'

    uint64_t foundAdvertisementTimestamp;
    uint64_t lostAdvertisementTimestamp;

    uint64_t findApiStartTimestamp;
    uint64_t findApiEndTimestamp;

    uint64_t pingApiStartTimestamp;
    uint64_t pingApiEndTimestamp;
} nameTimestamp_t;

// Forward declarations
static void displayUsage(void);
static void CDECL_CALL ctrlCHandler(int sig);
static void parseCmdLineArgs(const int argc, const char* argv[]);
static qcc::String generateName(const qcc::String& wknPrefix, const qcc::String& shortGUID, const uint64_t timestamp, const uint32_t ttl, bool return_as_is);
static bool isPingApiAvailable(ajn::BusAttachment* bus);
static uint64_t MyGetTimestamp64();
void DisplayStats(void);

// Names advertised/discovered are in the following format:
// wkn-prefix.guidSHRTGUID.tsMMMMMMMMMMMMMMMMMM.ttlNNNNN
// .guidSHRTGUID - SHRTGUID is the 8-character guid of the BusAttachment
//                 (accounts for 13 characters)
// .tsMMMMMMMMMMMMMMMMMM - MMMMMMMMMMMMMMMMMM is the time stamp at which name
//                         has been requested and advertised
//                         (accounts for 23 characters)
// .ttlNNNNNNNNNN - NNNNNNNNNN is the time after which the name would expire
//             (accounts for 14 characters)
static const uint8_t c_maxWKNPrefixLength = 205;

// Which transport to use when advertising a name?
// Ideally, it should be TRANSPORT_ANY. This would imply that the test
// program could get multiple FoundAdvertisedName and LostAdvertisedName
// callbacks based on the number of transports available (viz. TCP / UDP).
// However, as far as network activity is concerned, all it takes is one
// NS (Legacy/NGNS) packet to trigger callbacks. Multiple NS packets
// are NOT going out for multiple transports. Hence:
// i.  to make life simpler and
// ii. allow the test program to be compiled against older AllJoyn versions
// TRANSPORT_TCP is used as the default.
// But it can be changed to UDP by using command line option "-u".

static ajn::TransportMask g_transportToUse = ajn::TRANSPORT_TCP;

// Options that can be configured via command-line
static runmode_t g_runMode = RM_ADVERTISE;
static qcc::String g_wellKnownNamePrefix = "org.dreamworks.kungfupanda";

static uint8_t g_numNames = 1; // default number of names to discover
static bool g_dontPingRemoteName = false;
static uint16_t g_pingTimeout = 20000;
static bool g_dontWaitForLost = false;

// default duration of advertising / discovering, in ms
static uint32_t g_advtdiscovTTL = 10000;
static bool g_advertiseSequentially = false;
static bool g_fixedNameAdvertisement = false; // append timestamp by default
static bool g_hangAround = false; // Wait for 45s before exiting the advertiser
static bool g_advertiseQuietly = false;
static bool g_advertiseBeforeRWKN = true;

// Number of threads to use while creating discoverer BusAttachment
//
// The Advertiser doesn't have any call backs. It doesn't need multiple threads.
// In fact, they are unused even if available.
static uint8_t g_numDiscoverThreads = 4;

// The offset to apply to generated timestamp (milliseconds since epoch),
// to make it match a standard time (GMT or any standard clock).
// The max offset is intentionally limited to INT16_MAX = 32767ms.
// It is possible to manually correct clocks on devices to be accurate within
// 30s.
static int16_t g_timeCorrectionOffset = 0;

static qcc::String g_connectSpec = "";

// Globals
static volatile sig_atomic_t g_interrupted = false; // For Ctrl-C handling

static ajn::BusAttachment* g_ajBus = NULL;

static ajn::InterfaceDescription* g_allJoynObjIntf = NULL;

static nameTimestamp_t* g_NameTimestamps = NULL; // Storage for stats of each discovered name

// The following are counters to keep track of the progress of the test program
// Every name found is pinged. Hence the difference,
//(g_numFoundNames - g_numSuccessfullyPingedNames) gives the number of
// failed Pings.
static uint8_t g_numFoundNames = 0;
static uint8_t g_numSuccessfullyPingedNames = 0;
static uint8_t g_numLostNames = 0;

// The following three counters are used to keep track of
// performance requirements laid out in Ashutosh's HLD
static uint8_t hld_countFoundWithin1250ms = 0;
static uint8_t hld_countFoundWithin10250ms = 0;
static uint8_t hld_countFoundAfter10250ms = 0;

static uint64_t g_findStartTimestamp = 0;

// To be used to get passed contexts from callbacks
static uint8_t for_callback_ctxts = 42;

// Handle the asynchronous ping responses
class AsyncPresenceResponseReceiver : public ajn::MessageReceiver {
  public:
    void PresenceResponseHandler(ajn::Message& msg, void* ctx)
    {
        uint64_t pingEndTimestamp = qcc::GetTimestamp64();

        QStatus status = ER_FAIL;

        uint8_t msgType = msg->GetType();

        uint8_t index = ((static_cast<uint8_t*> (ctx)) - &for_callback_ctxts);

        if (ajn::MESSAGE_METHOD_RET == msgType) {
            uint32_t disposition = 0;
            status = msg->GetArgs("u", &disposition);
            if (ER_OK != status) {
                QCC_LogError(status, ("Message::GetArgs failed"));
            } else {
                // disposition value 1 indicates ALLJOYN_PING_REPLY_SUCCESS
                // The reason for using the literal 1, instead of #define
                // is to let the code compile against older AllJoyn SDKs.
                if (1 == disposition) {
                    g_NameTimestamps[index].pingApiEndTimestamp = pingEndTimestamp;

                    // An increment-only global variable doesn't need to be
                    // locked
                    g_numSuccessfullyPingedNames++;
                } else {
                    QCC_LogError(status, ("Ping returned dispostion %u for name: %s", disposition, g_NameTimestamps[index].name));
                }
            }
        } else if (ajn::MESSAGE_ERROR == msgType) {
            QCC_LogError(status, ("Presence response returned: %s for name: %s", msg->GetErrorDescription().c_str(), g_NameTimestamps[index].name));
        } else {
            QCC_LogError(status, ("Received invalid message type(%u) as ping response for name: %s", msgType, g_NameTimestamps[index].name));
        }
    }
};

AsyncPresenceResponseReceiver g_presenceRspRcv;

static qcc::Mutex g_foundAdvLock;
static qcc::Mutex g_lostAdvLock;

// Listen to events informing that names have been discovered
class DiscoverBL : public ajn::BusListener {
    void FoundAdvertisedName(const char* name, ajn::TransportMask transport, const char* namePrefix) {
        QCC_UNUSED(namePrefix);
        if (ajn::TRANSPORT_ANY != g_transportToUse && g_transportToUse != transport) {
            // Got a FoundAdvertisedName for a transport that this test program
            // is not interested in. Ignore.
            return;
        }

        uint64_t foundNameTimestamp = MyGetTimestamp64();

        uint64_t findEndTimestamp = qcc::GetTimestamp64();

        uint8_t numNamesFoundSoFar; // local copy for number of found names
        g_foundAdvLock.Lock(MUTEX_CONTEXT);
        g_numFoundNames++;
        numNamesFoundSoFar = g_numFoundNames;
        g_foundAdvLock.Unlock(MUTEX_CONTEXT);

        // Nothing to do, if all the names have been found
        if (g_numNames < numNamesFoundSoFar) {
            return;
        }

        // If n names have been found so far, then the array index is n - 1
        uint8_t index = numNamesFoundSoFar - 1;

        strncpy(g_NameTimestamps[index].name, name, ArraySize(g_NameTimestamps[index].name));
        g_NameTimestamps[index].name[ArraySize(g_NameTimestamps[index].name) - 1] = '\0';
        g_NameTimestamps[index].foundAdvertisementTimestamp = foundNameTimestamp;
        g_NameTimestamps[index].findApiStartTimestamp = g_findStartTimestamp;
        g_NameTimestamps[index].findApiEndTimestamp = findEndTimestamp;

        if (!g_dontPingRemoteName) {
            // Ping signature is "su" and one needs to set name and timeout
            ajn::MsgArg args[2];
            size_t numArgs = ArraySize(args);
            ajn::MsgArg::Set(args, numArgs, "su", name, g_pingTimeout);
            ajn::Message reply(*g_ajBus);

            uint64_t pingStartTimestamp = qcc::GetTimestamp64();

            QStatus status = g_ajBus->GetAllJoynProxyObj().MethodCallAsync(*(g_allJoynObjIntf->GetMember("Ping")),
                                                                           &g_presenceRspRcv,
                                                                           static_cast<ajn::MessageReceiver::ReplyHandler> (&AsyncPresenceResponseReceiver::PresenceResponseHandler),
                                                                           args,
                                                                           numArgs,
                                                                           static_cast<void*> (&for_callback_ctxts + index),
                                                                           (g_pingTimeout + 5000)
                                                                           );

            if (ER_OK != status) {
                QCC_LogError(status, ("ProxyBusObject::MethodCallAsync failed for method: Ping, name: %s", name));
            } else {
                g_NameTimestamps[index].pingApiStartTimestamp = pingStartTimestamp;
            }
        }
    }

    void LostAdvertisedName(const char* name, ajn::TransportMask transport, const char* prefix) {
        QCC_UNUSED(prefix);
        if (ajn::TRANSPORT_ANY != g_transportToUse && g_transportToUse != transport) {
            // Got a LostAdvertisedName for a transport that this test program
            // is not interested in. Ignore.
            return;
        }
        uint64_t lostNameTimestamp = MyGetTimestamp64();

        uint8_t numNamesLostSoFar; // local copy for number lost names

        g_lostAdvLock.Lock(MUTEX_CONTEXT);
        g_numLostNames++;
        numNamesLostSoFar = g_numLostNames;
        g_lostAdvLock.Unlock(MUTEX_CONTEXT);

        // Nothing to do, if all the names have been lost
        if (g_numNames < numNamesLostSoFar) {
            return;
        }

        for (uint8_t i = 0; i < g_numNames; i++) {
            if (0 == strncmp(g_NameTimestamps[i].name, name, ArraySize(g_NameTimestamps[i].name))) {
                g_NameTimestamps[i].lostAdvertisementTimestamp = lostNameTimestamp;
                break;
            }
        }
    }
};

int TestAppMain(const int argc, const char* argv[])
{
    QStatus status = ER_FAIL;

    std::cout << "AllJoyn Library version: " << ajn::GetVersion() <<
        std::endl << "AllJoyn Library build info: " << ajn::GetBuildInfo() <<
        std::endl;

    // Install Ctrl-C (SIGINT) handler
    signal(SIGINT, ctrlCHandler);

    parseCmdLineArgs(argc, argv);

    std::cout << "INFO: Running in " << ((RM_ADVERTISE == g_runMode) ? "advertising" : "discovering") << " mode" <<
        std::endl << "INFO: Prefix for well-known name is " << g_wellKnownNamePrefix.c_str() <<
        std::endl << "INFO: Number of names to " << ((RM_ADVERTISE == g_runMode) ? "advertise" : "discover") << " is " << (uint16_t) g_numNames <<
        std::endl << "INFO: Time-Offset is " << g_timeCorrectionOffset <<
        std::endl << "INFO: The duration for which names are advertised / discovered is " <<
        g_advtdiscovTTL << "ms" << std::endl;

    if (!g_connectSpec.empty()) {
        std::cout << "INFO: The connect spec is " << g_connectSpec.c_str() << std::endl;
    }

    uint8_t numThreads = 4;
    if (RM_DISCOVER == g_runMode) {
        numThreads = g_numDiscoverThreads;
    }

    ajn::BusAttachment bus(((RM_ADVERTISE == g_runMode) ? "advertise" : "discover"), true, numThreads);
    g_ajBus = &bus;

    status = g_ajBus->Start();
    if (ER_OK != status) {
        QCC_LogError(status, ("BusAttachment::Start failed"));
        return EXIT_SOFTWARE;
    }

    status = g_connectSpec.empty() ? g_ajBus->Connect() : g_ajBus->Connect(g_connectSpec.c_str());
    if (ER_OK != status) {
        QCC_LogError(status, ("BusAttachment::Connect failed"));
        return EXIT_SOFTWARE;
    }

    g_allJoynObjIntf = new ajn::InterfaceDescription(*(g_ajBus->GetAllJoynProxyObj().GetInterface("org.alljoyn.Bus")));

    if (RM_ADVERTISE == g_runMode) {
        std::cout << "INFO: Flag to advertise sequentially is " <<
        (g_advertiseSequentially ? "enabled" : "disabled") << std::endl <<
            "INFO: Flag to advertise prefix as-is is " <<
        (g_fixedNameAdvertisement ? "enabled" : "disabled") << std::endl <<
            "INFO: Flag to linger for 45s before exiting is " <<
        (g_hangAround ? "enabled" : "disabled") << std::endl <<
            "INFO: Flag to advertise quietly is " <<
        (g_advertiseQuietly ? "enabled" : "disabled") << std::endl <<
            "INFO: Flag to advertise WKN before requesting WKN is " <<
        (g_advertiseBeforeRWKN ? "enabled" : "disabled") << std::endl <<
            std::endl;

        // Store the timestamps at which each name is advertised
        // to be able to correctly determine when the names should be cancelled.
        uint64_t* advtTimestamps = new uint64_t[g_numNames];
        memset(advtTimestamps, 0, sizeof(uint64_t) * g_numNames);

        for (uint8_t i = 0; i < g_numNames; i++) {
            // Generate a name to advertise in the following format:
            // wkn-prefix.guidSHRTGUID.tsMMMMMMMMMMMMMMMMMM.ttlNNNNN
            advtTimestamps[i] = MyGetTimestamp64();
            qcc::String nameToAdvertise = generateName(g_wellKnownNamePrefix,
                                                       g_ajBus->GetGlobalGUIDShortString(),
                                                       advtTimestamps[i],
                                                       g_advtdiscovTTL,
                                                       g_fixedNameAdvertisement);

            if (g_advertiseBeforeRWKN) {
                // Even though the usual sequence of events is to request a name,
                // and then advertise it, this program intentionally does the reverse
                status = g_ajBus->AdvertiseName(g_advertiseQuietly ? ("quiet@" + nameToAdvertise).c_str() : nameToAdvertise.c_str(),
                                                g_transportToUse);

                if (ER_OK != status) {
                    // No point in proceeding further, when name wasn't successfully
                    // advertised
                    QCC_LogError(status, ("BusAttachment::AdvertiseName failed for name: %s transport: 0x%x", nameToAdvertise.c_str(), g_transportToUse));
                    return EXIT_SOFTWARE;
                }
                status = g_ajBus->RequestName(nameToAdvertise.c_str(),
                                              DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE);
                if (ER_OK != status) {
                    // No point in proceeding further, when one didn't get the name
                    QCC_LogError(status, ("BusAttachment::RequestName failed for name: %s", nameToAdvertise.c_str()));
                    return EXIT_SOFTWARE;
                }
            } else {
                status = g_ajBus->RequestName(nameToAdvertise.c_str(),
                                              DBUS_NAME_FLAG_REPLACE_EXISTING | DBUS_NAME_FLAG_DO_NOT_QUEUE);
                if (ER_OK != status) {
                    // No point in proceeding further, when one didn't get the name
                    QCC_LogError(status, ("BusAttachment::RequestName failed for name: %s", nameToAdvertise.c_str()));
                    return EXIT_SOFTWARE;
                }
                status = g_ajBus->AdvertiseName(g_advertiseQuietly ? ("quiet@" + nameToAdvertise).c_str() : nameToAdvertise.c_str(),
                                                g_transportToUse);
                if (ER_OK != status) {
                    // No point in proceeding further, when name wasn't successfully
                    // advertised
                    QCC_LogError(status, ("BusAttachment::AdvertiseName failed for name: %s transport: 0x%x", nameToAdvertise.c_str(), g_transportToUse));
                    return EXIT_SOFTWARE;
                }
            }

            std::cout << "Advertising the name (index = " << (uint16_t) i << "): " << nameToAdvertise.c_str() <<
                std::endl;

            if (g_advertiseSequentially) {
                // Wait time-to-live milliseconds for the name to expire, or
                // until interrupted by Ctrl-C
                uint64_t numMsToWait = g_advtdiscovTTL - (MyGetTimestamp64() - advtTimestamps[i]);
                while (!g_interrupted && 0 < numMsToWait) {
                    uint8_t sleepTime = (100 <= numMsToWait) ? 100 : numMsToWait;
                    qcc::Sleep(sleepTime);
                    numMsToWait -= sleepTime;
                }
                if (g_interrupted) {
                    std::cout << "Interrupted by Ctrl-C..." << std::endl;
                    break;
                } else {
                    // Done waiting the necessary amount of time
                    status = g_ajBus->CancelAdvertiseName(nameToAdvertise.c_str(),
                                                          g_transportToUse);

                    if (ER_OK != status) {
                        QCC_LogError(status, ("BusAttachment::CancelAdvertiseName failed for name: %s, transport: 0x%x", nameToAdvertise.c_str(), g_transportToUse));
                    }

                    status = g_ajBus->ReleaseName(nameToAdvertise.c_str());

                    if (ER_OK != status) {
                        QCC_LogError(status, ("BusAttachment::ReleaseName failed for %s", nameToAdvertise.c_str()));
                    }
                }
            }

            // On fast machines, the millisecond timer might not have moved
            // from one iteration to the next causing the timestamp to be
            // unchanged which leads to the advertising a name that is already
            // been advertised. To avoid that have a tiny delay between loop
            // iterations.
            qcc::Sleep(5);
        }

        // If the names were NOT advertised sequentially, then they need
        // to be cancelled at appropriate times based on when they were
        // advertised.
        if (!g_advertiseSequentially) {
            for (uint8_t i = 0; i < g_numNames; i++) {
                // Wait time-to-live milliseconds for the name to expire, or
                // until interrupted by Ctrl-C
                uint64_t timeElapsed = (MyGetTimestamp64() - advtTimestamps[i]);
                uint64_t numMsToWait = (g_advtdiscovTTL > timeElapsed) ? (g_advtdiscovTTL - timeElapsed) : 0;
                while (!g_interrupted && 0 < numMsToWait) {
                    uint8_t sleepTime = (100 <= numMsToWait) ? 100 : numMsToWait;
                    qcc::Sleep(sleepTime);
                    numMsToWait -= sleepTime;
                }
                if (g_interrupted) {
                    std::cout << "Interrupted by Ctrl-C..." << std::endl;
                    break;
                } else {
                    // Done waiting the necessary amount of time
                    qcc::String nameAdvertised = generateName(g_wellKnownNamePrefix,
                                                              g_ajBus->GetGlobalGUIDShortString(),
                                                              advtTimestamps[i],
                                                              g_advtdiscovTTL,
                                                              g_fixedNameAdvertisement);

                    status = g_ajBus->CancelAdvertiseName(nameAdvertised.c_str(),
                                                          g_transportToUse);

                    if (ER_OK != status) {
                        QCC_LogError(status, ("BusAttachment::CancelAdvertiseName failed for name: %s transport: 0x%x", nameAdvertised.c_str(), g_transportToUse));
                    }

                    status = g_ajBus->ReleaseName(nameAdvertised.c_str());

                    if (ER_OK != status) {
                        QCC_LogError(status, ("BusAttachment::ReleaseName failed for %s", nameAdvertised.c_str()));
                    }
                }
            }
        }

        // Linger, if asked
        if (g_hangAround) {
            std::cout << "Option '-linger' was specified. Waiting for 45s before exiting..." <<
                " (will not respond to Ctrl-C during these 45s)" << std::endl;
            qcc::Sleep(45000);
            std::cout << "Done." << std::endl;
        }

        delete [] advtTimestamps;
        advtTimestamps = NULL;
    } else {
        // Discovering side of things

        // To ping or not to ping is the question
        g_dontPingRemoteName = (isPingApiAvailable(g_ajBus) && !g_dontPingRemoteName) ? false : true;
        std::cout << "INFO: Ping remote name is " << (!g_dontPingRemoteName ? "enabled" : "disabled") << std::endl;
        if (!g_dontPingRemoteName) {
            std::cout << "INFO: Ping timeout is set as " << g_pingTimeout << std::endl;
        }
        std::cout << "INFO: Flag to exit after finding desired number of names (and not wait for LostAdvertisedName) is " << (g_dontWaitForLost ? "true" : "false") << std::endl <<
            "INFO: Number of BusAttachment threads is " << (uint16_t) numThreads <<
            std::endl;

        g_NameTimestamps = new nameTimestamp_t[g_numNames];
        memset(g_NameTimestamps, 0, sizeof(nameTimestamp_t) * g_numNames);

        DiscoverBL dbl;
        g_ajBus->RegisterBusListener(dbl);

        // Api duration computation doesn't need the fancy MyGetTimestamp64()
        g_findStartTimestamp = qcc::GetTimestamp64();

        status = g_ajBus->FindAdvertisedNameByTransport(g_wellKnownNamePrefix.c_str(), g_transportToUse);
        if (ER_OK != status) {
            // No point in proceeding further, when FindAdvertiseName wasn't ok
            QCC_LogError(status, ("BusAttachment::FindAdvertisedNameByTransport failed for prefix: %s, transport: 0x%x", g_wellKnownNamePrefix.c_str(), g_transportToUse));
            return EXIT_SOFTWARE;
        }

        // Need to wait until one of :
        // a. the desired number of names have been discovered & pinged & lost
        //    (don't wait for LostAdvertisement, if configured)
        // b. interrupted by Ctrl-C
        // c. Time to discover has elapsed

        // Every name found is pinged and a name can only be lost if it
        // was found earlier. Hence, numLostNames is an indicator of
        // progress / completion.
        uint64_t numMsToWait = g_advtdiscovTTL - (qcc::GetTimestamp64() - g_findStartTimestamp);
        while (!g_interrupted && ((g_dontWaitForLost && g_numNames > g_numFoundNames) || (!g_dontWaitForLost && g_numNames > g_numLostNames)) && (0 < numMsToWait)) {
            uint16_t sleepTime = (1000 <= numMsToWait) ? 1000 : numMsToWait;
            qcc::Sleep(sleepTime);
            numMsToWait -= sleepTime;
            std::cout << "Found " << (uint16_t)g_numFoundNames << " names" <<
                " and Lost " << (uint16_t) g_numLostNames << " names so far..." <<
                std::endl;
        }
        if (g_interrupted) {
            std::cout << "Interrupted by Ctrl-C..." << std::endl;
        } else if (0 == numMsToWait) {
            // Time to discover has elapsed
            std::cout << g_advtdiscovTTL << "ms have elapsed while discovering. Exiting..." << std::endl;
        } else {
            // All names have been discovered
            status = g_ajBus->CancelFindAdvertisedNameByTransport(g_wellKnownNamePrefix.c_str(), g_transportToUse);
            if (ER_OK != status) {
                QCC_LogError(status, ("BusAttachment::CancelFindAdvertisedNameByTransport failed for name: %s, transport: 0x%x", g_wellKnownNamePrefix.c_str(), g_transportToUse));
            }
        }
    }

    std::cout << std::flush;

    delete g_allJoynObjIntf;

    status = g_ajBus->Disconnect();
    if (ER_OK != status) {
        QCC_LogError(status, ("BusAttachment::Disconnect failed"));
        return EXIT_SOFTWARE;
    }

    status = g_ajBus->Stop();
    if (ER_OK != status) {
        QCC_LogError(status, ("BusAttachment::Stop failed"));
        return EXIT_SOFTWARE;
    }

    status = g_ajBus->Join();
    if (ER_OK != status) {
        QCC_LogError(status, ("BusAttachment::Join failed"));
        return EXIT_SOFTWARE;
    }

    // Stats are only collected on the end that is discovering
    if (RM_DISCOVER == g_runMode) {
        DisplayStats();
        // Given that display of stats is complete, free the memory
        delete [] g_NameTimestamps;
    }

    return EXIT_OK;
}

int CDECL_CALL main(const int argc, const char* argv[])
{
    QStatus status = AllJoynInit();
    if (ER_OK != status) {
        return EXIT_SOFTWARE;
    }
#ifdef ROUTER
    status = AllJoynRouterInit();
    if (ER_OK != status) {
        AllJoynShutdown();
        return EXIT_SOFTWARE;
    }
#endif

    int ret = TestAppMain(argc, argv);

#ifdef ROUTER
    AllJoynRouterShutdown();
#endif
    AllJoynShutdown();

    return ret;
}

static void displayUsage(void)
{
    std::cout << "USAGE: advtdiscov [OPTIONS]" <<
        std::endl << std::endl << "OPTIONS:" << std::endl <<
        std::endl << "  -m <advertise | discover>  \tMode of the run (advertise or discover)" << std::endl <<
        std::endl << "  -n <well-known-name-prefix>\tWell-known-name prefix advertised/discovered" <<
        std::endl << "                             \t(max length: " << (uint16_t) c_maxWKNPrefixLength << " characters)" <<
        std::endl << "  -cn <number-of-names>      \tNumber of names to advertise / discover (max: 255)" <<
        std::endl << "  -nopresence                \tDon't 'ping' the remote name" <<
        std::endl << "                             \t(valid only in discovering mode.)" <<
        std::endl << "  -presence-timeout <ms>     \tTimeout to pass to presence query" <<
        std::endl << "                             \t(valid only in discovering mode. min: 0 & max: 65535)" <<
        std::endl << "  -cbath <number-of-threads> \tNumber of BusAttachment threads to use" <<
        std::endl << "                             \t(valid only in discovering mode. min: 1 & max: 255)" <<
        std::endl << "  -ttl                       \tDuration for which the name is advertised / discovered" <<
        std::endl << "                             \t(min: 500ms max: 4294967295ms)" <<
        std::endl << "  -advtseq                   \tAdvertise the names one after another (instead of the default all-at-once)" <<
        std::endl << "                             \t(valid only in advertising mode)" <<
        std::endl << "  -fixed-name                \tDon't append timestamp to prefix before advertising" <<
        std::endl << "                             \t(valid only in advertising mode)" <<
        std::endl << "  -linger                    \tWait for 45s before exiting" <<
        std::endl << "                             \t(valid only in advertising mode)" <<
        std::endl << "  -quiet-advt                \tAdvertise the name quietly" <<
        std::endl << "                             \t(valid only in advertising mode)" <<
        std::endl << "  -dont-wait-for-lost        \tExit when all the names are found (don't wait for lost)" <<
        std::endl << "                             \t(valid only in discovering mode)" <<
        std::endl << "  -time-offset <miliseconds> \tOffset generated timestamps (min: - 32768ms & max: 32767ms)" <<
        std::endl << "  -connect-spec <spec>       \tExplicitly connect to the spec provided" <<
        std::endl << "  -rkwn-before-advertise     \tRequest WKN before advertising WKN" <<
        std::endl << "                             \t(valid only in advertising mode)" <<
        std::endl << "  -u                         \tUse UDP transport (default transport is TCP)" <<
        std::endl << "  -h                         \tDisplay usage" <<
        std::endl;
}

static void CDECL_CALL ctrlCHandler(int sig)
{
    QCC_UNUSED(sig);
    g_interrupted = true;
}

static void parseCmdLineArgs(const int argc, const char* argv[])
{
    if (1 == argc) {
        displayUsage();
        exit(EXIT_USAGE);
    } else if (UINT8_MAX == argc) {
        std::cout << "Too many options" << std::endl;
        displayUsage();
        exit(EXIT_USAGE);
    }
    // Start the loop from index 1, as options start from argv[1]
    for (uint8_t i = 1; i < argc; ++i) {
        if (0 == strcmp("-h", argv[i])) {
            displayUsage();
            exit(EXIT_USAGE);
        } else if (0 == strcmp("-m", argv[i])) {
            i++; // Looking for mode of run
            if (argc != i) {
                g_runMode = (0 != strcmp("advertise", argv[i])) ? RM_DISCOVER : RM_ADVERTISE;
            } else {
                std::cout << "Option " << argv[i - 1] << " requires a " <<
                    "parameter (advertise or discover)" << std::endl << std::endl;
                displayUsage();
                exit(EXIT_USAGE);
            }
        } else if (0 == strcmp("-connect-spec", argv[i])) {
            i++; // Looking for the connect spec
            if (argc != i) {
                g_connectSpec = argv[i];
            } else {
                std::cout << "Option " << argv[i - 1] << " requires a " <<
                    "parameter" << std::endl << std::endl;
                displayUsage();
                exit(EXIT_USAGE);
            }
        } else if (0 == strcmp("-n", argv[i])) {
            i++; // Looking for a name prefix
            if (argc != i) {
                g_wellKnownNamePrefix = argv[i];
                if (c_maxWKNPrefixLength < g_wellKnownNamePrefix.length()) {
                    std::cout << "\tWARN: Length of well known name prefix: " <<
                        g_wellKnownNamePrefix.length() << ", is more " <<
                        "than max allowed (" << (uint16_t)c_maxWKNPrefixLength << ")" <<
                        std::endl << std::endl;

                    g_wellKnownNamePrefix = ('.' == g_wellKnownNamePrefix[c_maxWKNPrefixLength - 1]) ?
                                            g_wellKnownNamePrefix.substr(0, c_maxWKNPrefixLength - 1) :
                                            g_wellKnownNamePrefix.substr(0, c_maxWKNPrefixLength);

                    std::cout << "\tWARN: Truncating and using the name..." <<
                        std::endl;
                }
            } else {
                std::cout << "Option " << argv[i - 1] << " requires a parameter" <<
                    std::endl << std::endl;
                displayUsage();
                exit(EXIT_USAGE);
            }
        } else if (0 == strcmp("-cn", argv[i])) {
            i++; // Looking for number of names
            if (argc != i) {
                g_numNames = (uint16_t) ((UINT16_MAX >= strtoul(argv[i], NULL, 10)) ? strtoul(argv[i], NULL, 10) : UINT16_MAX);
            } else {
                std::cout << "Option " << argv[i - 1] << " requires a parameter" <<
                    std::endl << std::endl;
                displayUsage();
                exit(EXIT_USAGE);
            }
        } else if (0 == strcmp("-nopresence",  argv[i])) {
            g_dontPingRemoteName = true;
        } else if (0 == strcmp("-dont-wait-for-lost",  argv[i])) {
            g_dontWaitForLost = true;
        } else if (0 == strcmp("-presence-timeout",  argv[i])) {
            i++; // Looking for the presence timeout value
            if (argc != i) {
                g_pingTimeout = (uint16_t) ((UINT16_MAX >= strtoul(argv[i], NULL, 10)) ? strtoul(argv[i], NULL, 10) : UINT16_MAX);
            } else {
                std::cout << "Option " << argv[i - 1] << " requires a parameter" <<
                    std::endl << std::endl;
                displayUsage();
                exit(EXIT_USAGE);
            }
        } else if (0 == strcmp("-cbath",  argv[i])) {
            i++; // Looking for number of threads
            if (argc != i) {
                g_numDiscoverThreads = (uint8_t) ((UINT8_MAX >= strtoul(argv[i], NULL, 10)) ? strtoul(argv[i], NULL, 10) : UINT8_MAX);
                g_numDiscoverThreads = (1 >= g_numDiscoverThreads) ? 1 : g_numDiscoverThreads;
            } else {
                std::cout << "Option " << argv[i - 1] << " requires a parameter" <<
                    std::endl << std::endl;
                displayUsage();
                exit(EXIT_USAGE);
            }
        } else if (0 == strcmp("-ttl", argv[i])) {
            i++; // Looking for number of names
            if (argc != i) {
                unsigned long int inputHolderVal = strtoul(argv[i], NULL, 10);
                g_advtdiscovTTL = (uint32_t) (UINT32_MAX >= inputHolderVal) ? inputHolderVal : UINT32_MAX;
                g_advtdiscovTTL = (500 <= g_advtdiscovTTL) ? g_advtdiscovTTL : 500; // 500ms is the min TTL
            } else {
                std::cout << "Option " << argv[i - 1] << " requires a parameter" <<
                    std::endl << std::endl;
                displayUsage();
                exit(EXIT_USAGE);
            }
        } else if (0 == strcmp("-time-offset", argv[i])) {
            i++; // Looking for number of names
            if (argc != i) {
                if (0 < strtol(argv[i], NULL, 10)) {
                    g_timeCorrectionOffset = (int16_t) (UINT16_MAX >= strtol(argv[i], NULL, 10)) ? strtol(argv[i], NULL, 10) : UINT16_MAX;
                } else if (0 > strtol(argv[i], NULL, 10)) {
                    g_timeCorrectionOffset = (int16_t) (INT16_MIN <= strtol(argv[i], NULL, 10)) ? strtol(argv[i], NULL, 10) : INT16_MIN;
                }
            } else {
                std::cout << "Option " << argv[i - 1] << " requires a parameter" <<
                    std::endl << std::endl;
                displayUsage();
                exit(EXIT_USAGE);
            }
        } else if (0 == strcmp("-advtseq",  argv[i])) {
            g_advertiseSequentially = true;
        } else if (0 == strcmp("-fixed-name",  argv[i])) {
            g_fixedNameAdvertisement = true;
        } else if (0 == strcmp("-linger",  argv[i])) {
            g_hangAround = true;
        } else if (0 == strcmp("-quiet-advt",  argv[i])) {
            g_advertiseQuietly = true;
        } else if (0 == strcmp("-u",  argv[i])) {
            g_transportToUse = ajn::TRANSPORT_UDP;
        } else if (0 == strcmp("-rkwn-before-advertise",  argv[i])) {
            g_advertiseBeforeRWKN = false;
        } else {
            std::cout << "Unknown option: " << argv[i] << std::endl << std::endl;
            displayUsage();
            exit(EXIT_USAGE);
        }
    }

    // Inform about any options that aren't relevant
    if (RM_ADVERTISE == g_runMode) {
        if (g_dontPingRemoteName || 4 != g_numDiscoverThreads) {
            std::cout << "\tWARN: Ignoring options:" <<
            (g_dontPingRemoteName ? " -nopresence" : "") <<
            (g_dontWaitForLost ? " -dont-wait-for-lost" : "") <<
            ((4 != g_numDiscoverThreads) ? " -cbath" : "") <<
                std::endl;
        }
    } else {
        if (g_advertiseSequentially || g_fixedNameAdvertisement || g_hangAround || g_advertiseQuietly) {
            std::cout << "\tWARN: Ignoring options:" <<
            ((g_advertiseSequentially) ? " -advtseq" : "") <<
            ((g_fixedNameAdvertisement) ? " -fixed-name" : "") <<
            ((g_hangAround) ? " -linger" : "") <<
            ((g_advertiseQuietly) ? " -quiet-advt" : "") <<
                std::endl;
        }
    }
}

#if defined(QCC_OS_GROUP_WINDOWS)
// inttypes.h that provides standard format specifiers for printf and scanf
// is not available on Visual Studio as it doesn't support C99.
// Unfortunately, even though Visual Studio has latest C++ support, it
// does not provide cinttypes either, for versions earlier than VS2013.
#ifndef PRIu32
#define PRIu32      "I32u"
#endif
#ifndef PRIu64
#define PRIu64       "I64u"
#endif
#elif defined(QCC_OS_ANDROID) || defined(QCC_OS_DARWIN)
#define __STDC_FORMAT_MACROS
#include <tr1/cinttypes>
#undef __STDC_FORMAT_MACROS
#else // if not on Windows / Android / OSX
#include <cinttypes>
#endif

static inline qcc::String generateName(const qcc::String& wknPrefix, const qcc::String& shortGUID, const uint64_t timestamp, const uint32_t ttl, bool return_as_is) {
    qcc::String name = wknPrefix + ".guid" + shortGUID;

    if (return_as_is) {
        return name;
    }


    // uint64_t max is 18446744073709551615 and thus needs a 21-byte buffer
    char tsBuf[21];
    snprintf(tsBuf, ArraySize(tsBuf), "%020" PRIu64, timestamp);

    name = name + ".ts" + tsBuf;

    // uint32_t max is 4294967295 and thus needs a 11-byte buffer
    char ttlBuf[11];
    snprintf(ttlBuf, ArraySize(ttlBuf), "%010" PRIu32, ttl);

    name = name + ".ttl" + ttlBuf;

    return name;
}

static bool isPingApiAvailable(ajn::BusAttachment* bus)
{
    QCC_UNUSED(bus);
    // ASACORE-202 - Cannot use the following due to 'const' restrictions
    //return (bus->GetAllJoynProxyObj().GetInterface("org.alljoyn.Bus"))->HasMember("Ping", "su", "u");

    return g_allJoynObjIntf->HasMember("Ping", "su", "u");
}

// Need a function that provide the time since epoch, to be able to measure
// latencies based on sent and received timestamps.
// Without opening the 'clock time in distributed systems' can-of-worms,
// lets go with:
// a. _ftime on Windows
// b. CALENDAR_CLOCK on OSX
// c. CLOCK_REALTIME on Linux/Android

#include <qcc/platform.h>

#if defined(QCC_OS_GROUP_WINDOWS)
#include <windows.h>
#include <sys/timeb.h>
#elif defined(QCC_OS_DARWIN)
#include <sys/time.h>
#include <mach/mach_time.h>
#include <mach/clock.h>
#include <mach/mach.h>
#endif

// The contents of the following function has been shamelessly copied from
// i.  alljoyn/common/os/windows/time.cc
// ii. alljoyn/common/os/posix/time.cc
static inline uint64_t MyGetTimestamp64() {
    uint64_t ret_val = 0;

#if defined(QCC_OS_GROUP_WINDOWS)
    struct _timeb timebuffer;

    _ftime(&timebuffer);

    ret_val = ((uint64_t)timebuffer.time) * 1000;
    ret_val += timebuffer.millitm;
#elif defined(QCC_OS_DARWIN)
    struct timespec tspec;
    struct timespec* ts = &tspec;
    clock_serv_t cclock;
    mach_timespec_t mts;
    host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
    clock_get_time(cclock, &mts);
    mach_port_deallocate(mach_task_self(), cclock);
    ts->tv_sec = mts.tv_sec;
    ts->tv_nsec = mts.tv_nsec;

    ret_val = (uint64_t)(ts->tv_sec * 1000);
    ret_val += (uint64_t)ts->tv_nsec / 1000000;
#elif defined(QCC_OS_GROUP_POSIX)
    // The remaining candidates are Linux and Android
    struct timespec tspec;
    struct timespec* ts = &tspec;
    clock_gettime(CLOCK_REALTIME, ts);

    ret_val = (uint64_t)(ts->tv_sec * 1000);
    ret_val += (uint64_t)ts->tv_nsec / 1000000;
#endif

    // Apply the offset, if any
    return ret_val + g_timeCorrectionOffset;
}

void DisplayStats(void)
{
    uint32_t minFindApiDuration = 0;
    uint32_t maxFindApiDuration = 0;

    uint16_t minPingApiDuration = 0;
    uint16_t maxPingApiDuration = 0;

    uint32_t sumFindApiDuration = 0;
    uint32_t sumPingApiDuration = 0;

    double avgFindApiDuration = 0.0;
    double avgPingApiDuration = 0.0;

    uint32_t minFoundAdvLatency = 0;
    uint32_t maxFoundAdvLatency = 0;

    uint16_t minLostAdvLatency = 0;
    uint16_t maxLostAdvLatency = 0;

    uint32_t sumFoundAdvLatency = 0;
    uint32_t sumLostAdvLatency = 0;

    double avgFoundAdvLatency = 0.0;
    double avgLostAdvLatency = 0.0;


    // AllJoyn guarantees that a name cannot be lost without it having been
    // found earlier. However, due to the limits imposed on the storage
    // of stats, its very much possible that this program stored 'found stats'
    // for one name and didn't get to store the 'lost stats' for it
    // or that Ctrl-C was pressed before LostAdvertisedName was even received.
    // To get averages which make sense, we need to keep track of names
    // for which all stats (Found, Pinged, Lost) are available.
    // This counter does NOT have anything to do with successful/failed pings.
    uint8_t numNamesForWhichWeHaveCompleteDiscoveryStats = 0;

    // It might possible that the program received a Ctrl-C before all the names
    // have been found. In that case, the for loop below should iterate only
    // over those names which have been found.

    for (uint8_t i = 0; i < (g_numNames > g_numFoundNames ? g_numFoundNames : g_numNames); i++) {
        std::cout << "Name (index: " << (uint16_t)i << "): " << g_NameTimestamps[i].name;
        // Given that this loop is going through the names that are found,
        // it is always possible to compute the FindApiDuration.
        uint32_t findApiDuration = g_NameTimestamps[i].findApiEndTimestamp - g_NameTimestamps[i].findApiStartTimestamp;
        hld_countFoundWithin1250ms = (1250 >= findApiDuration) ? (hld_countFoundWithin1250ms + 1) : hld_countFoundWithin1250ms;
        hld_countFoundWithin10250ms = (10250 >= findApiDuration) ? (hld_countFoundWithin10250ms + 1) : hld_countFoundWithin10250ms;
        hld_countFoundAfter10250ms = (10250 < findApiDuration) ? (hld_countFoundAfter10250ms + 1) : hld_countFoundAfter10250ms;
        std::cout << " FindApiDuration " << findApiDuration;

        // If enabled & valid, every name that is found is pinged.
        // Hence, it is possible to get Ping duration as well.
        uint16_t pingApiDuration = 0;
        if (!g_dontPingRemoteName) {
            // If the presence query timed out, then the pingApiEndTimestamp
            // wouldn't be set (i.e. it would remain at it uninitialized value
            // 0).
            pingApiDuration = (g_NameTimestamps[i].pingApiEndTimestamp <= g_NameTimestamps[i].pingApiStartTimestamp) ? 0 : (g_NameTimestamps[i].pingApiEndTimestamp - g_NameTimestamps[i].pingApiStartTimestamp);
            // No point in displaying ping duration if it is set to zero.
            if (0 != pingApiDuration) {
                std::cout << "  PingApiDuration " << pingApiDuration;
            }
        }

        // Latency values need to computed after extracting the timestamps
        // and ttl values present in the advertised/found name.
        uint32_t foundAdvLatency = 0;
        uint16_t lostAdvLatency = 0;

        qcc::String name = g_NameTimestamps[i].name;
        size_t startTimestampMarker = name.find(".ts");
        size_t startTTLMarker = name.find(".ttl", startTimestampMarker);
        if (qcc::String::npos != startTimestampMarker && qcc::String::npos != startTTLMarker) {
            uint64_t nameAdvertisedAtTimestamp = qcc::StringToU64(name.substr(startTimestampMarker + 3, 20), 10); // 20 characters in a uint64_t

            if (nameAdvertisedAtTimestamp > g_NameTimestamps[i].foundAdvertisementTimestamp) {
                // This indicates a clock sync problem
                std::cout << "\n\tWARN: Name " << g_NameTimestamps[i].name <<
                    " discovered timestamp (" << g_NameTimestamps[i].foundAdvertisementTimestamp <<
                    ") is earlier than name advertised timestamp (" << nameAdvertisedAtTimestamp <<
                    "). Ignoring..." << std::endl;

                continue;
            }

            foundAdvLatency = g_NameTimestamps[i].foundAdvertisementTimestamp - nameAdvertisedAtTimestamp;
            std::cout << "  FoundAdvLatency " << foundAdvLatency;

            // If the name found was not yet lost, then the LostAdvertisedName
            // time stamp wouldn't even be initialized. In that case,
            // nothing to do w.r.t LostAdvertisedName latency
            if (0 != g_NameTimestamps[i].lostAdvertisementTimestamp) {
                uint32_t nameTTL = qcc::StringToU32(name.substr(startTTLMarker + 4, 10), 10); // 10 characters in a uint32_t
                uint64_t cancelAdvertisedAtTimestamp = nameAdvertisedAtTimestamp + nameTTL;

                if (cancelAdvertisedAtTimestamp >= g_NameTimestamps[i].lostAdvertisementTimestamp) {
                    // This indicates a clock sync problem
                    std::cout << "\n\tWARN: Name " << g_NameTimestamps[i].name <<
                        " lost timestamp (" << g_NameTimestamps[i].lostAdvertisementTimestamp <<
                        ") is earlier than name cancelled timestamp (" << cancelAdvertisedAtTimestamp <<
                        "). Ignoring...\n" << std::endl;

                    continue;
                }

                lostAdvLatency = g_NameTimestamps[i].lostAdvertisementTimestamp - cancelAdvertisedAtTimestamp;
                std::cout << "  LostAdvLatency " << lostAdvLatency;
            }
        } else {
            std::cout << "\n\tWARN: Name " << g_NameTimestamps[i].name << " is "
                "not in an expected format. Skipping it" << std::endl;

            continue;
        }

        // All the stats for the name are now available
        //
        // Skip those entries where LostLatency is unset when one of
        // FoundDuration are set. Such entries typically mean that
        // Ctrl-C was pressed before LostAdvertisedName was received for all
        // the names that were discovered.
        if (0 != findApiDuration && 0 == lostAdvLatency) {
            std::cout << "\n\tWARN: Name " << g_NameTimestamps[i].name << " does "
                "not seem to have complete stats. Skipping it from computation of averages ..." << std::endl;

            continue;
        } else {
            numNamesForWhichWeHaveCompleteDiscoveryStats++;
        }

        minFindApiDuration = (0 == i) ? findApiDuration : minFindApiDuration;
        maxFindApiDuration = (0 == i) ? findApiDuration : maxFindApiDuration;

        sumFindApiDuration += findApiDuration;
        minFindApiDuration = (minFindApiDuration <= findApiDuration) ? minFindApiDuration : findApiDuration;
        maxFindApiDuration = (maxFindApiDuration >= findApiDuration) ? maxFindApiDuration : findApiDuration;

        if (!g_dontPingRemoteName) {
            minPingApiDuration = (0 == i) ? pingApiDuration : minPingApiDuration;
            maxPingApiDuration = (0 == i) ? pingApiDuration : maxPingApiDuration;

            sumPingApiDuration += pingApiDuration;
            // Don't record timed out pings (for which pingApiDuration is 0)
            if (0 != pingApiDuration) {
                minPingApiDuration = (minPingApiDuration <= pingApiDuration) ? minPingApiDuration : pingApiDuration;
            }
            maxPingApiDuration = (maxPingApiDuration >= pingApiDuration) ? maxPingApiDuration : pingApiDuration;
        }

        minFoundAdvLatency = (0 == i) ? foundAdvLatency : minFoundAdvLatency;
        maxFoundAdvLatency = (0 == i) ? foundAdvLatency : maxFoundAdvLatency;
        sumFoundAdvLatency += foundAdvLatency;
        minFoundAdvLatency = (minFoundAdvLatency <= foundAdvLatency) ? minFoundAdvLatency : foundAdvLatency;
        maxFoundAdvLatency = (maxFoundAdvLatency >= foundAdvLatency) ? maxFoundAdvLatency : foundAdvLatency;

        minLostAdvLatency = (0 == i) ? lostAdvLatency : minLostAdvLatency;
        maxLostAdvLatency = (0 == i) ? lostAdvLatency : maxLostAdvLatency;
        sumLostAdvLatency += lostAdvLatency;
        minLostAdvLatency = (minLostAdvLatency <= lostAdvLatency) ? minLostAdvLatency : lostAdvLatency;
        maxLostAdvLatency = (maxLostAdvLatency >= lostAdvLatency) ? maxLostAdvLatency : lostAdvLatency;
        std::cout << std::endl;
    }

    std::cout << "Summary" <<
        std::endl << "-------" << std::endl;

    avgFindApiDuration = sumFindApiDuration / (numNamesForWhichWeHaveCompleteDiscoveryStats * 1.0);
    std::cout << "FindApiDuration (min/avg/max): " << minFindApiDuration <<
        "/" << avgFindApiDuration << "/" << maxFindApiDuration << " ms" << std::endl;

    if (!g_dontPingRemoteName) {
        std::cout << "Number of names successfully queried: " << (uint16_t) g_numSuccessfullyPingedNames <<
            " out of " << (uint16_t) g_numFoundNames << std::endl;
        avgPingApiDuration = sumPingApiDuration / (g_numSuccessfullyPingedNames * 1.0);
        std::cout << "\tPingApiDuration (min/avg/max): " << minPingApiDuration <<
            "/" << avgPingApiDuration << "/" << maxPingApiDuration << " ms" << std::endl;
    }

    avgFoundAdvLatency = sumFoundAdvLatency / (numNamesForWhichWeHaveCompleteDiscoveryStats * 1.0);
    std::cout << "FoundAdvLatency (min/avg/max): " << minFoundAdvLatency << "/" <<
        avgFoundAdvLatency << "/" << maxFoundAdvLatency << " ms" << std::endl;

    avgLostAdvLatency = sumLostAdvLatency / (numNamesForWhichWeHaveCompleteDiscoveryStats * 1.0);
    std::cout << "LostAdvLatency (min/avg/max): " << minLostAdvLatency << "/" <<
        avgLostAdvLatency << "/" << maxLostAdvLatency << " ms" << std::endl;

    std::cout << "HLD - Number of names found within 1.25s  = " << (uint16_t) hld_countFoundWithin1250ms << std::endl;
    std::cout << "HLD - Number of names found within 10.25s = " << (uint16_t) hld_countFoundWithin10250ms << std::endl;
    std::cout << "HLD - Number of names found after  10.25s = " << (uint16_t) hld_countFoundAfter10250ms << std::endl;

    std::cout << std::flush;
}