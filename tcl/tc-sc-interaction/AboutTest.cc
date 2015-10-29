/******************************************************************************
 * Copyright (c) Open Connectivity Foundation (OCF) and AllJoyn Open
 *    Source Project (AJOSP) Contributors and others.
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
 *     THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
 *     WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
 *     WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
 *     AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL
 *     DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR
 *     PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER
 *     TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
 *     PERFORMANCE OF THIS SOFTWARE.
 ******************************************************************************/

#include "ajtcscTestCommon.h"

// Define necessary classes and functions for this test
namespace { // start-of-anonymous-namespace

const char* const tcPublicInterface[] = {
    "test.alljoyn.santa.PublicInterface",
    "?was_i_nice_last_year your_guesstimate<b santas_judgement>b",
    "!a_gift_for_you gift_value>x",
    "@quote_of_the_day>s",
    NULL
};

const AJ_InterfaceDescription tcPublicInterfaceList[] = {
    tcPublicInterface,
    NULL
};

const char* const tcPrivateInterface[] = {
    "test.alljoyn.santa.PrivateInterface",
    "@passcode_to_start_reindeer_sleigh=ay",
    NULL
};

const AJ_InterfaceDescription tcPrivateInterfaceList[] = {
    tcPublicInterface,
    NULL
};

const AJ_InterfaceDescription tcPrviateInterfaceList[] = {
    tcPrivateInterface,
    NULL
};

const AJ_Object tcTestObjs[] = {
    { "/test/alljoyn/santa/Public", tcPublicInterfaceList, AJ_OBJ_FLAG_ANNOUNCED },
    { "/test/alljoyn/santa/Private", tcPrivateInterfaceList, AJ_OBJ_FLAG_HIDDEN },
    { NULL }
};

uint16_t testSessionPort;

// About metadata fields
uint8_t testAppId[16];
const char* const testLocalizedDeviceName[] = { "Personal Computer",
                                            "personal De'wl'"};
const char* testDefaultDeviceName = testLocalizedDeviceName[0];
qcc::String testDeviceId;

const char* const testLocalizedAppName[] = { "North Pole Event Action",
                                         "north DuraS wanI' Action" };
const char* testDefaultAppName = testLocalizedAppName[0];

const char* const testLocalizedManufacturer[] = { "Santa's Little Helpers",
                                              "santa loQ Helpers" };
const char* testDefaultManufacturer = testLocalizedManufacturer[0];

const char* testModelNumber = "Polaris";

const char* const testSupportedLanguages[] = { "en", "tlh" };
const char* testDefaultLanguage = testSupportedLanguages[0];

const char* const testLocalizedDescription[] = { "Gift Delivery Vehicle",
                                               "cha'nob Delivery Vehicle" };
const char* testDefaultDescription = testLocalizedDescription[0];

qcc::String testDateOfManufacture;
qcc::String testSoftwareVersion;
qcc::String testHardwareVersion;
qcc::String testSupportUrl;

const char* testUserDefinedMetadataFieldName = "AnswerToTheUltimateQuestionOfLife,TheUniverse,AndEverything";
const uint8_t andTheAnswerIs = 42; // AllJoyn data type for uint8_t is 'y'

// AboutIcon
uint16_t testAboutIconSize;
uint8_t* testAboutIcon = NULL;

qcc::String testAboutIconMimeType;
qcc::String testAboutIconUrl;

// As can be learned from:
// https://allseenalliance.org/developers/learn/core/about-announcement
// there are two separate outlets through which the information is shared.
// One is the Announce signal and the other is GetAboutData method call.
// The following function gets registered with:
// AJ_AboutRegisterPropStoreGetter()
// This function gets called to fill in the AboutData for Announce signal and
// GetAboutData method call and there isn't really a way to infer for which
// purpose this function is invoked.
AJ_Status TCFillInAboutData(AJ_Message* reply, const char* language)
{
    // An AllJoyn method call parameter cannot be NULL (it can be empty "")
    EXPECT_STRNE(NULL, language);

    // If a language has been specified (i.e. it hasn't been left as empty "",
    // which indicates the default language), check if its indeed supported.
    uint8_t i = 0;
    if ('\0' != language[0]) {
        while (i < ARRAY_SIZE(testSupportedLanguages)) {
            if (0 == strcmp(language, testSupportedLanguages[i])) {
                break;
            }

            i++;
        }

        if (ARRAY_SIZE(testSupportedLanguages) == i) {
            return AJ_ERR_NO_MATCH;
        }
    }

    // Now that the language parameter has been checked to be supported,
    // fill in the metadata fields.
    //
    // * Of all the About metadata fields, some are mandatory and the remaining
    //   are optional.
    // * All the mandatory fields need to be filled in when sending out an
    //   Announcement signal or responding to GetAboutData method call.
    // * Of the mandatory fields, a subset are 'Announced' essentially meaning
    //   that they need to be filled in for an Announcement.
    AJ_Arg aboutMetaData;
    EXPECT_EQ(AJ_OK, AJ_MarshalContainer(reply, &aboutMetaData, AJ_ARG_ARRAY));

    // For the sake of clarity, fill in the non-localized fields
    // first (there is no mandated order in which items need to be filled in)
    EXPECT_EQ(AJ_OK, AJ_MarshalArgs(reply, "{sv}", "AppId", "ay", testAppId, ARRAY_SIZE(testAppId)));
    EXPECT_EQ(AJ_OK, AJ_MarshalArgs(reply, "{sv}", "DefaultLanguage", "s", testDefaultLanguage));
    EXPECT_EQ(AJ_OK, AJ_MarshalArgs(reply, "{sv}", "DeviceId", "s", testDeviceId.c_str()));
    EXPECT_EQ(AJ_OK, AJ_MarshalArgs(reply, "{sv}", "AppName", "s", testLocalizedAppName[i]));
    EXPECT_EQ(AJ_OK, AJ_MarshalArgs(reply, "{sv}", "Manufacturer", "s", testLocalizedManufacturer[i]));
    EXPECT_EQ(AJ_OK, AJ_MarshalArgs(reply, "{sv}", "ModelNumber", "s", testModelNumber));
    EXPECT_EQ(AJ_OK, AJ_MarshalArgs(reply, "{sv}", "Description", "s", testLocalizedDescription[i]));
    EXPECT_EQ(AJ_OK, AJ_MarshalArgs(reply, "{sv}", "SoftwareVersion", "s", testSoftwareVersion.c_str()));
    EXPECT_EQ(AJ_OK, AJ_MarshalArgs(reply, "{sv}", "AJSoftwareVersion", "s", AJ_GetVersion()));
    // Supported languages has a signature "as" (array of strings), which
    // needs to be marshaled by hand. Scalars and array of scalars can
    // be marshaled by AJ_MarshalArgs directly, but not array of strings
    // {sv} where 's' is "SupportedLanguaged" and 'v' is "as" (array of strings)
    AJ_Arg supportedLanguagesDictEntry;
    // {
    EXPECT_EQ(AJ_OK, AJ_MarshalContainer(reply, &supportedLanguagesDictEntry, AJ_ARG_DICT_ENTRY));
    // s
    EXPECT_EQ(AJ_OK, AJ_MarshalArgs(reply, "s", "SupportedLanguages"));
    // v whose signature is "as"
    EXPECT_EQ(AJ_OK, AJ_MarshalVariant(reply, "as"));
    AJ_Arg listOfSupportedLanguages;
    EXPECT_EQ(AJ_OK, AJ_MarshalContainer(reply, &listOfSupportedLanguages, AJ_ARG_ARRAY));
    for (uint8_t j = 0; j < ARRAY_SIZE(testSupportedLanguages); j++) {
        EXPECT_EQ(AJ_OK, AJ_MarshalArgs(reply, "s", testSupportedLanguages[j]));
    }
    EXPECT_EQ(AJ_OK, AJ_MarshalCloseContainer(reply, &listOfSupportedLanguages));
    // }
    EXPECT_EQ(AJ_OK, AJ_MarshalCloseContainer(reply, &supportedLanguagesDictEntry));

    // Non-mandatory fields of metadata
    EXPECT_EQ(AJ_OK, AJ_MarshalArgs(reply, "{sv}", "DeviceName", "s", testLocalizedDeviceName[i]));
    EXPECT_EQ(AJ_OK, AJ_MarshalArgs(reply, "{sv}", "DateOfManufacture", "s", testDateOfManufacture.c_str()));
    EXPECT_EQ(AJ_OK, AJ_MarshalArgs(reply, "{sv}", "HardwareVersion", "s", testHardwareVersion.c_str()));
    EXPECT_EQ(AJ_OK, AJ_MarshalArgs(reply, "{sv}", "SupportUrl", "s", testSupportUrl.c_str()));

    // User-defined field of metadata
    EXPECT_EQ(AJ_OK, AJ_MarshalArgs(reply, "{sv}", testUserDefinedMetadataFieldName, "y", andTheAnswerIs));

    EXPECT_EQ(AJ_OK, AJ_MarshalCloseContainer(reply, &aboutMetaData));

    return AJ_OK;
}

AJ_BusAttachment* leanBus = NULL;

class SCAboutListener : public ajn::AboutListener {
  public:
    SCAboutListener() : numAnnouncementsReceived(0), aboutVersionOfLastAnnouncement(0)
    {};
    void Announced(const char* peerUniqueName, uint16_t peerAboutVersion,
                   ajn::SessionPort peerSessionPort, const ajn::MsgArg& peerObjDescMsgArg,
                   const ajn::MsgArg& peerAboutDataMsgArg) {

        // Ignore any announcements received from 'unexpected peers'
        // Why is this needed?
        // About is a means by which Apps discover one another and thus
        // About announcements are public. There is nearly no way to keep
        // them private.
        // Thus it is possible that when tests are run simultaneously, there is
        // a scope of crosstalk. To play nicely in a scenario where tests might
        // be executed concurrently, Announcements from unexpected peers are
        // ignored.
        if (qcc::String(peerUniqueName) != AJ_GetUniqueName(leanBus)) {
            return;
        }

        // There isn't much one can do to 'verify' peerAboutVersion
        aboutVersionOfLastAnnouncement = peerAboutVersion;

        EXPECT_EQ(testSessionPort, peerSessionPort);

        ajn::AboutObjectDescription peerAboutObjectDescription(peerObjDescMsgArg);
        size_t numObjects = peerAboutObjectDescription.GetPaths(NULL, 0);
        const char** objectsInAnnouncement = new const char* [numObjects];
        peerAboutObjectDescription.GetPaths(objectsInAnnouncement, numObjects);

        for(size_t i = 0; i < numObjects; i++) {
            // Skip the standard About object paths
            if (qcc::String(objectsInAnnouncement[i]) == "/About" ||
                qcc::String(objectsInAnnouncement[i]) == "/About/DeviceIcon") {
                    continue;
            }

            // Only one object has been announced
            EXPECT_STREQ(tcTestObjs[0].path, objectsInAnnouncement[i]);

            size_t numInterfacesForObjInAnnouncement = peerAboutObjectDescription.GetInterfaces(objectsInAnnouncement[i], NULL, 0);
            // Only public interfaces were announced
            // the last element of Thin Core Library interface lists is
            // the marker NULL
            EXPECT_EQ((ARRAY_SIZE(tcPublicInterfaceList) - 1), numInterfacesForObjInAnnouncement);

            const char** interfacesForObjInAnnouncement = new const char* [numInterfacesForObjInAnnouncement];
            peerAboutObjectDescription.GetInterfaces(objectsInAnnouncement[i], interfacesForObjInAnnouncement, numInterfacesForObjInAnnouncement);
            for(size_t j = 0; j < numInterfacesForObjInAnnouncement; j++) {
                EXPECT_STREQ(tcPublicInterfaceList[j][0], interfacesForObjInAnnouncement[j]);
            }
            delete [] interfacesForObjInAnnouncement;
            interfacesForObjInAnnouncement = NULL;
        }

        delete [] objectsInAnnouncement;
        objectsInAnnouncement = NULL;

        ajn::AboutData peerAboutData(peerAboutDataMsgArg);

        // Verify that received metadata is consistent with sent metadata.

        uint8_t* appIdInAnnouncement = NULL;
        size_t lengthOfAppIdInAnnouncement = 0;
        EXPECT_EQ(ER_OK, peerAboutData.GetAppId(&appIdInAnnouncement, &lengthOfAppIdInAnnouncement));
        EXPECT_EQ(ARRAY_SIZE(testAppId), lengthOfAppIdInAnnouncement);
        for(size_t i = 0; i < lengthOfAppIdInAnnouncement; i++) {
            EXPECT_EQ(testAppId[i], appIdInAnnouncement[i]);
        }

        char* defaultLanguageInAnnouncement = NULL;
        EXPECT_EQ(ER_OK, peerAboutData.GetDefaultLanguage(&defaultLanguageInAnnouncement));
        EXPECT_STREQ(testDefaultLanguage, defaultLanguageInAnnouncement);

        char* deviceNameInAnnouncement = NULL;
        EXPECT_EQ(ER_OK, peerAboutData.GetDeviceName(&deviceNameInAnnouncement));
        EXPECT_STREQ(testDefaultDeviceName, deviceNameInAnnouncement);

        char* deviceIdInAnnouncement = NULL;
        EXPECT_EQ(ER_OK, peerAboutData.GetDeviceId(&deviceIdInAnnouncement));
        EXPECT_STREQ(testDeviceId.c_str(), deviceIdInAnnouncement);

        char* appNameInAnnouncement = NULL;
        EXPECT_EQ(ER_OK, peerAboutData.GetAppName(&appNameInAnnouncement));
        EXPECT_STREQ(testDefaultAppName, appNameInAnnouncement);

        char* manufacturerInAnnouncement = NULL;
        EXPECT_EQ(ER_OK, peerAboutData.GetManufacturer(&manufacturerInAnnouncement));
        EXPECT_STREQ(testDefaultManufacturer, manufacturerInAnnouncement);

        char* modelNumberInAnnouncement = NULL;
        EXPECT_EQ(ER_OK, peerAboutData.GetModelNumber(&modelNumberInAnnouncement));
        EXPECT_STREQ(testModelNumber, modelNumberInAnnouncement);

        size_t numSupportedLanguagesInAnnouncement = peerAboutData.GetSupportedLanguages(NULL, 0);
        EXPECT_EQ(ARRAY_SIZE(testSupportedLanguages), numSupportedLanguagesInAnnouncement);

        const char** supportedLanguageListInAnnouncement = new const char* [numSupportedLanguagesInAnnouncement];
        EXPECT_EQ(numSupportedLanguagesInAnnouncement, peerAboutData.GetSupportedLanguages(supportedLanguageListInAnnouncement, numSupportedLanguagesInAnnouncement));
        for(size_t i = 0; i < numSupportedLanguagesInAnnouncement; i++) {
            EXPECT_STREQ(testSupportedLanguages[i], supportedLanguageListInAnnouncement[i]);
        }
        delete [] supportedLanguageListInAnnouncement;
        supportedLanguageListInAnnouncement = NULL;

        char* descriptionInAnnouncement = NULL;
        EXPECT_EQ(ER_OK, peerAboutData.GetDescription(&descriptionInAnnouncement));
        EXPECT_STREQ(testDefaultDescription, descriptionInAnnouncement);

        char* dateOfManufactureInAnnouncement = NULL;
        EXPECT_EQ(ER_OK, peerAboutData.GetDateOfManufacture(&dateOfManufactureInAnnouncement));
        EXPECT_STREQ(testDateOfManufacture.c_str(), dateOfManufactureInAnnouncement);

        char* softwareVersionInAnnouncement = NULL;
        EXPECT_EQ(ER_OK, peerAboutData.GetSoftwareVersion(&softwareVersionInAnnouncement));
        EXPECT_STREQ(testSoftwareVersion.c_str(), softwareVersionInAnnouncement);

        char* hardwareVersionInAnnouncement = NULL;
        EXPECT_EQ(ER_OK, peerAboutData.GetHardwareVersion(&hardwareVersionInAnnouncement));
        EXPECT_STREQ(testHardwareVersion.c_str(), hardwareVersionInAnnouncement);

        char* supportUrlInAnnouncement = NULL;
        EXPECT_EQ(ER_OK, peerAboutData.GetSupportUrl(&supportUrlInAnnouncement));
        EXPECT_STREQ(testSupportUrl.c_str(), supportUrlInAnnouncement);

        ajn::MsgArg* userDefinedFieldInAnnouncement;
        EXPECT_EQ(ER_OK, peerAboutData.GetField(testUserDefinedMetadataFieldName, userDefinedFieldInAnnouncement));
        uint8_t userDefinedFieldValue = 0;
        EXPECT_EQ(ER_OK,userDefinedFieldInAnnouncement->Get("y", &userDefinedFieldValue));
        EXPECT_EQ(andTheAnswerIs, userDefinedFieldValue);

        // Announcement has been completely 'processed'
        numAnnouncementsReceived++;
    }

    uint16_t GetNumAnnouncementsReceived() {
        return numAnnouncementsReceived;
    }
  private:
    uint8_t numAnnouncementsReceived;
    uint16_t aboutVersionOfLastAnnouncement;
};

SCAboutListener* testAboutListener;
} // end-of-anonymous-namespace

class AboutTest : public testing::Test {
  public:
    AboutTest() :
        scBus("StandardCoreLibraryBus", true)
    {
        leanBus = &tcBus;
    };
    void SetUp() {
        ASSERT_EQ(ER_OK, scBus.Start());
        ASSERT_EQ(ER_OK, scBus.Connect());

        testAboutListener = new SCAboutListener();
        scBus.RegisterAboutListener(*testAboutListener);

        // To avoid cross-talk, i.e. thin leaf node connect to unintended
        // routing nodes, generate and advertise a random routing node prefix.
        qcc::String routingNodePrefix = "test.rnPrefix.randhex" +
                                        qcc::RandHexString(64);

        qcc::String advertisingPrefix = "quiet@" + routingNodePrefix;

        ASSERT_EQ(ER_OK, scBus.AdvertiseName(advertisingPrefix.c_str(), ajn::TRANSPORT_ANY));

        AJ_RandBytes(testAppId, ARRAY_SIZE(testAppId));
        testDeviceId = qcc::RandomString();
        testDateOfManufacture = qcc::RandomString();
        testSoftwareVersion = qcc::RandomString();
        testHardwareVersion = qcc::RandomString();
        testSupportUrl = qcc::RandomString();

        // PropStore (short for PropertyStore) is older terminology.
        // The more current term is AboutData
        AJ_AboutRegisterPropStoreGetter(TCFillInAboutData);

        testAboutIconSize = qcc::Rand16();
        testAboutIcon = new uint8_t [testAboutIconSize];
        AJ_RandBytes(testAboutIcon, testAboutIconSize);

        testAboutIconMimeType = qcc::RandomString();
        testAboutIconUrl = qcc::RandomString();
        AJ_AboutSetIcon(testAboutIcon, testAboutIconSize,
                        testAboutIconMimeType.c_str(), testAboutIconUrl.c_str());

        AJ_Initialize();
        AJ_RegisterObjects(tcTestObjs, NULL);

        // Ensure that a routing node is found as quickly as possible
        AJ_SetSelectionTimeout(0);

        ASSERT_EQ(AJ_OK, AJ_FindBusAndConnect(&tcBus, routingNodePrefix.c_str(), TC_LEAFNODE_CONNECT_TIMEOUT));

        ASSERT_EQ(AJ_OK, AJ_BusBindSessionPort(&tcBus, AJ_SESSION_PORT_ANY, NULL, AJ_NO_FLAGS));

        // Now that BindSessionPort has been 'kicked off', wait until it
        // a reply arrives that the operation is successfully complete
        AJ_Message tcMsg;
        AJ_Status tcMsgStatus = AJ_UnmarshalMsg(&tcBus, &tcMsg, TC_UNMARSHAL_TIMEOUT);
        while (AJ_ERR_TIMEOUT != tcMsgStatus) {
            if (AJ_OK == tcMsgStatus) {
                if (AJ_REPLY_ID(AJ_METHOD_BIND_SESSION_PORT) == tcMsg.msgId) {
                    ASSERT_EQ(AJ_MSG_METHOD_RET, tcMsg.hdr->msgType);
                    uint32_t disposition = 0;
                    ASSERT_EQ(AJ_OK, AJ_UnmarshalArgs(&tcMsg, "uq", &disposition, &testSessionPort));
                    ASSERT_EQ(static_cast<uint32_t>(ALLJOYN_BINDSESSIONPORT_REPLY_SUCCESS), disposition);
                    // If BindSessionPort was successful, then the
                    // program should have received a non-zero sessionPort.
                    ASSERT_NE(static_cast<uint16_t>(0), testSessionPort);
                } else {
                    AJ_BusHandleBusMessage(&tcMsg);
                }
                AJ_CloseMsg(&tcMsg);
            }
            tcMsgStatus = AJ_UnmarshalMsg(&tcBus, &tcMsg, TC_UNMARSHAL_TIMEOUT);
        }

        // The scBus should look for those apps that implement a specific
        // interface == same interface Announced by tcBus.
        const char* interestedInterfaceList[] = {tcPublicInterface[0]};
        ASSERT_EQ(ER_OK, scBus.WhoImplements(interestedInterfaceList, ARRAY_SIZE(interestedInterfaceList)));

    }

    void TearDown() {
        AJ_Disconnect(&tcBus);

        delete [] testAboutIcon;
        testAboutIcon = NULL;

        scBus.UnregisterAboutListener(*testAboutListener);
        delete testAboutListener;
        testAboutListener = NULL;

        ASSERT_EQ(ER_OK, scBus.Disconnect());
        ASSERT_EQ(ER_OK, scBus.Stop());
        ASSERT_EQ(ER_OK, scBus.Join());
    }

    ajn::BusAttachment scBus;
    AJ_BusAttachment tcBus;
};

TEST_F(AboutTest, TC_Sending_Annnouncement) {
    ASSERT_EQ(AJ_OK, AJ_AboutInit(&tcBus, testSessionPort));

    // Wait until the announcement has been received by scBus
    uint16_t remainingWaitTime = WAIT_TIME;
    while (0 >= testAboutListener->GetNumAnnouncementsReceived() &&
           0 < remainingWaitTime) {
        AJ_Sleep(100);
        remainingWaitTime -= 100;
    }

    // Exactly one announcement is expected
    EXPECT_EQ(static_cast<uint16_t>(1), testAboutListener->GetNumAnnouncementsReceived());
}

TEST_F(AboutTest, TC_Withdrawing_Annnouncement) {
    ASSERT_EQ(AJ_OK, AJ_AboutInit(&tcBus, testSessionPort));

    // Wait until the announcement has been received by scBus
    uint16_t remainingWaitTime = WAIT_TIME;
    while (0 >= testAboutListener->GetNumAnnouncementsReceived() &&
           0 < remainingWaitTime) {
        AJ_Sleep(100);
        remainingWaitTime -= 100;
    }

    // Exactly one announcement is expected, at this time
    EXPECT_EQ(static_cast<uint16_t>(1), testAboutListener->GetNumAnnouncementsReceived());

    // Cancel the Announcement
    EXPECT_EQ(AJ_OK, AJ_AboutUnannounce(&tcBus));

    ajn::BusAttachment throwAwaySCBus("ThrowAwaySCBus", true);
    ASSERT_EQ(ER_OK, throwAwaySCBus.Start());
    ASSERT_EQ(ER_OK, throwAwaySCBus.Connect());

    SCAboutListener throwAwayAboutListener;
    throwAwaySCBus.RegisterAboutListener(throwAwayAboutListener);

    const char* throwAwayInterestedInterfaceList[] = {tcPublicInterface[0]};
    ASSERT_EQ(ER_OK, throwAwaySCBus.WhoImplements(throwAwayInterestedInterfaceList, ARRAY_SIZE(throwAwayInterestedInterfaceList)));

    // Wait to see if the Announcement is received (it has been cancelled)
    remainingWaitTime = WAIT_TIME;
    while (0 >= throwAwayAboutListener.GetNumAnnouncementsReceived() &&
           0 < remainingWaitTime) {
        AJ_Sleep(100);
        remainingWaitTime -= 100;
    }

    // No announcements should be received
    EXPECT_EQ(static_cast<uint16_t>(0), throwAwayAboutListener.GetNumAnnouncementsReceived());

    // Announce again
    ASSERT_EQ(AJ_OK, AJ_AboutInit(&tcBus, testSessionPort));

    // Wait until both interested parties have received the announcement
    remainingWaitTime = WAIT_TIME;
    while (1 >= testAboutListener->GetNumAnnouncementsReceived() &&
           0 >= throwAwayAboutListener.GetNumAnnouncementsReceived() &&
           0 < remainingWaitTime) {
        AJ_Sleep(100);
        remainingWaitTime -= 100;
    }

    // This would be the second time scBus would receive the announcement
    EXPECT_EQ(static_cast<uint16_t>(2), testAboutListener->GetNumAnnouncementsReceived());

    // The first time throwAwaySCBus would receive the announcement
    EXPECT_EQ(static_cast<uint16_t>(1), throwAwayAboutListener.GetNumAnnouncementsReceived());

    throwAwaySCBus.UnregisterAllAboutListeners();
}