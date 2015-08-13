/**
 * @file
 * Sessionless signal sender app
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

#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_crypto.h>

static const char DaemonName[] = "org.alljoyn.BusNode";

static const char ServiceName[] = "sigtest.one";


static const char* const testInterface[] = {
        "org.alljoyn.bbsigtest",
        "!sls_signal >u >t >q >ay >u >u",
        NULL
};

static const AJ_InterfaceDescription testInterfaces[] = {
        testInterface,
        NULL
};

/**
 * Objects implemented by the application
 */
static const AJ_Object ProxyObjects[] = {
        { "/org/alljoyn/bbsigtest", testInterfaces },
        { NULL }
};

#define APP_SLS_SIGNAL       AJ_APP_MESSAGE_ID(0, 0, 0)
#define PRX_SLS_SIGNAL       AJ_PRX_MESSAGE_ID(0, 0, 0)


static AJ_BusAttachment g_bus;

static unsigned long g_timeToLive = 30;
//static uint8_t g_debug = FALSE;

static uint32_t g_sleepTime = 60000;  //default of 1 minute
static uint32_t g_payload = 50;
static uint8_t g_random = FALSE;
static uint8_t g_random_ttl = FALSE;


static AJ_SessionId g_SessionId = 0;

static AJ_Time StartTime;
static AJ_Time SignalArrivalTime;
static uint8_t g_error = 0;
static uint8_t g_exit = FALSE;

static uint8_t g_server = TRUE;

#define ARRAY_SIZE 10000
static const uint8_t byte_array[ARRAY_SIZE];

static const uint32_t CONNECT_TIMEOUT = 1000 * 200;
static const uint32_t UNMARSHAL_TIMEOUT = 100 * 5;

uint16_t ServicePort = 545;

static const AJ_SessionOpts session_opts = {
        AJ_SESSION_TRAFFIC_MESSAGES,
        AJ_SESSION_PROXIMITY_ANY,
        AJ_TRANSPORT_ANY,
        TRUE
};

static uint32_t Random()
{
    uint32_t r;
    AJ_RandBytes((uint8_t*) &r, sizeof(r));
    return r;
}


static void AppDoWork()
{
    static uint32_t count = 1;
    static uint32_t count_infinite_ttl = 1;
    AJ_Time now;
    AJ_Message msg;
    AJ_Status status;
    uint32_t ttimeToLive = g_timeToLive;

    uint32_t array_size = 0;
    uint32_t i;
    uint32_t r = Random();
    uint32_t pad = 0;

    // wait for a session id
    // and only if we're a server
    if (!g_SessionId) {
        return;
    }

    AJ_InitTimer(&now);

    if (AJ_GetTimeDifference(&now, &StartTime) > g_sleepTime) {
        printf("Time  %u exceeds  %u specified. program exits  \n", AJ_GetTimeDifference(&now, &StartTime), g_sleepTime);
        g_exit = TRUE;
        return;
    }

    if ((g_random_ttl) && (r % 2 == 0)) {
        ttimeToLive = 0;
    }

    status = AJ_MarshalSignal(&g_bus, &msg, APP_SLS_SIGNAL, NULL, g_SessionId, 0, ttimeToLive);

    // "!sls_signal >u >t >q >ay >u >u",
    status = AJ_MarshalArgs(&msg, "utq", count, now.seconds, now.milliseconds);

    if (g_random) {
        // range: [50, 100)
        array_size = 50 + (r % g_payload);
    } else {
        array_size = g_payload;
    }

    AJ_Printf("\tDEBUG: Size of array (in signal payload) is %u\n", array_size);

    if (array_size < ((array_size + 3) & 0xFFFFFFFC)) {
        pad = ((array_size + 3) & 0xFFFFFFFC) - array_size;
    }
    // array_size + pad + 1u for size + 2u for remaining parameters
    status = AJ_DeliverMsgPartial(&msg, 3 * sizeof(uint32_t) + (array_size) + pad);
    if (AJ_OK != status) {
        AJ_Printf("ERROR: DeliverMsgPartial returned: %s.\n", AJ_StatusText(status));
        goto MessageError;
    }

    status = AJ_MarshalRaw(&msg, &array_size, sizeof(uint32_t));
    if (AJ_OK != status) {
        AJ_Printf("ERROR: AJ_MarshalRaw of array_size returned %s.\n", AJ_StatusText(status));
        goto MessageError;
    }

    for (i = 0; i < (array_size) / ARRAY_SIZE; ++i) {
        status = AJ_MarshalRaw(&msg, byte_array, ARRAY_SIZE);
        if (AJ_OK != status) {
            AJ_Printf("ERROR: 1 Marshaling element (index: %d) failed. Got status: %s.\n", i, AJ_StatusText(status));
            goto MessageError;
        }
    }

    if (0 != (array_size) % ARRAY_SIZE) {
        uint32_t remaining = (array_size) % ARRAY_SIZE;
        status = AJ_MarshalRaw(&msg, byte_array, remaining);
        if (AJ_OK != status) {
            AJ_Printf("ERROR: 2 Marshaling element (index: %d) failed. Got status: %s.\n", i, AJ_StatusText(status));
            goto MessageError;
        }
    }

    if (pad != 0) {
        status = AJ_MarshalRaw(&msg, byte_array, pad);
        if (AJ_OK != status) {
            AJ_Printf("ERROR: Marshaling msg pad failed: %s.\n", AJ_StatusText(status));
            goto MessageError;
        }
    }

    status = AJ_MarshalRaw(&msg, &ttimeToLive, sizeof(ttimeToLive));
    if (AJ_OK != status) {
        AJ_Printf("ERROR: Marshaling ttl failed: %s.\n", AJ_StatusText(status));
        goto MessageError;
    }

    status = AJ_MarshalRaw(&msg, &count_infinite_ttl, sizeof(count_infinite_ttl));
    if (AJ_OK != status) {
        AJ_Printf("ERROR: Marshaling infinite ttl count failed: %s.\n", AJ_StatusText(status));
        goto MessageError;
    }

    printf("Sec is %u, ms is %u \n", now.seconds, now.milliseconds);
    printf("SendSignal #: %u %x\n", count, count);

   if (AJ_OK == status) {
        status = AJ_DeliverMsg(&msg);
        if (AJ_OK == status) {
            printf("Sec is %u, ms is %u \n", now.seconds, now.milliseconds);
            printf("SendSignal #: %u %x\n", count, count);
            AJ_Printf("Signal sent successfully.\n");
        } else {
            goto MessageError;
        }
    } else {
        AJ_Printf("ERROR: %s. Failed to send signal # %u\n", AJ_StatusText(status), count);
        goto MessageError;
    }

    count++;
    if (ttimeToLive == 0) {
        count_infinite_ttl++;
    }

    return;

MessageError:
    AJ_CloseMsg(&msg);
}

static void SignalHandler(AJ_Message* msg)
{
    static uint32_t expected_infinite_ttl_count = 1;
    uint32_t count = 0;
    uint64_t receivedSeconds = 0;
    uint16_t receivedMseconds = 0;

    uint32_t ttl = 0;
    uint32_t received_infinite_ttl_count = 0;

    uint32_t length = 0;
    size_t sz;
    void* raw = NULL;
    int32_t time_diff;
    uint32_t diff;
    AJ_Status status;

    AJ_InitTimer(&SignalArrivalTime);

    status = AJ_UnmarshalArgs(msg, "utq", &count, &receivedSeconds, &receivedMseconds);
    if (AJ_OK != status) {
        AJ_Printf("AJ_UnmarshalArgs(utq): %s\n", AJ_StatusText(status));
        return;
    }


    status = AJ_UnmarshalRaw(msg, (const void**) &raw, sizeof(uint32_t), &sz);
    if (AJ_OK != status) {
        AJ_Printf("ERROR: UnmarshalRaw 1st call status is %s \n", AJ_StatusText(status));
        return;
    } else {
        length = *((uint32_t*) raw);
        // need to align to the nearest WORD because there are two aligned uint32_t values after the array
        length += 3;
        length &= 0xFFFFFFFC;
    }

    AJ_Printf("============> Received sls_signal # %u, length %u\n", count, length);
    AJ_ASSERT(length < 0xFFFF);

    // read the array
    if (AJ_OK == status) {
        uint32_t bytesToBeFetched = length;

        while (0 != bytesToBeFetched) {
            raw = NULL;
            sz = 0;
            status = AJ_UnmarshalRaw(msg, (const void**) &raw, bytesToBeFetched, &sz);
            if (AJ_OK == status) {
                bytesToBeFetched -= sz;
                //AJ_Printf("Fetched %u bytes; %u remaining\n", sz, bytesToBeFetched);
            } else {
                AJ_Printf("UnmarshalRaw status is %s \n", AJ_StatusText(status));
                AJ_Printf("Bytes to be fetched: %u, actual bytes fetched: %u \n", bytesToBeFetched, (uint32_t) sz);
                return;
            }
        }
    }


    status = AJ_UnmarshalRaw(msg, (const void**) &raw, sizeof(uint32_t), &sz);
    if (AJ_OK != status) {
        AJ_Printf("ERROR: AJ_UnmarshalArgs(ttl): %s \n", AJ_StatusText(status));
        return;
    } else {
        AJ_ASSERT(sz == sizeof(uint32_t));
        ttl = *((uint32_t*) raw);
    }

    status = AJ_UnmarshalRaw(msg, (const void**) &raw, sizeof(uint32_t), &sz);
    if (AJ_OK != status) {
        AJ_Printf("ERROR: AJ_UnmarshalArgs(received_infinite_ttl_count): %s \n", AJ_StatusText(status));
        return;
    } else {
        AJ_ASSERT(sz == sizeof(uint32_t));
        received_infinite_ttl_count = *((uint32_t*) raw);
    }

    if (ttl == 0) {
        if (expected_infinite_ttl_count != received_infinite_ttl_count) {
            AJ_Printf("Missed infinite ttl signal. Expected %u, received %u \n", expected_infinite_ttl_count, received_infinite_ttl_count);
            assert(FALSE);
        }
        expected_infinite_ttl_count++;
    }

    diff = (SignalArrivalTime.seconds - receivedSeconds);
    AJ_Printf("Receiver- CTS: %lu, RTS: %lu  \n", SignalArrivalTime.seconds, receivedSeconds);
    AJ_Printf("Receiver- CTmS: %u, RTmS: %u  \n", SignalArrivalTime.milliseconds, receivedMseconds);

    time_diff = AJ_GetTimeDifference(&SignalArrivalTime, &StartTime);

    AJ_Printf("[%d] RxSignal:me: %s, ttl=%u ms, length=%u from: %s - %u %x in %u ms\n",
            time_diff, msg->bus->uniqueName, ttl, length,  msg->sender, count, count,  diff * 1000 + (SignalArrivalTime.milliseconds - receivedMseconds));
}

static void AJ_Main(void)
{
    AJ_Status status = AJ_OK;
    uint8_t connected = FALSE;
    /*
     * Buffer to hold the full service name. The buffer size must be AJ_MAX_SERVICE_NAME_SIZE.
     */
    char fullServiceName[AJ_MAX_SERVICE_NAME_SIZE];

    AJ_Initialize();


    // both a local and a proxy object
    AJ_RegisterObjects(ProxyObjects, ProxyObjects);

    AJ_PrintXML(ProxyObjects);

    AJ_InitTimer(&StartTime);

    while (TRUE) {
        AJ_Message msg;

        if (!connected) {
            if (!g_server) {
                status = AJ_StartClientByName(&g_bus, DaemonName, CONNECT_TIMEOUT, 0, ServiceName, ServicePort, &g_SessionId, &session_opts, fullServiceName);
            } else {
                status = AJ_StartService(&g_bus, DaemonName, CONNECT_TIMEOUT, 0, ServicePort, ServiceName, 0, &session_opts);
            }

            if (AJ_OK == status) {
                AJ_Printf("Start{Client,Service} returned %s, sessionId=%u\n", AJ_StatusText(status), g_SessionId);
                AJ_Printf("Connected to Daemon: %s\n", AJ_GetUniqueName(&g_bus));
                connected = TRUE;
            } else {
                AJ_Printf("Start{Client,Service} returned %s\n", AJ_StatusText(status));
                break;
            }
        }

        status = AJ_UnmarshalMsg(&g_bus, &msg, UNMARSHAL_TIMEOUT);
        if ((AJ_ERR_TIMEOUT != status) && (AJ_OK != status)) {
            AJ_Printf("ERROR: UnmarshalMsg returned %s \n", AJ_StatusText(status));
        } else {
            AppDoWork();
        }

        if (AJ_OK == status) {
            switch (msg.msgId) {

            case APP_SLS_SIGNAL:
            case PRX_SLS_SIGNAL:
                SignalHandler(&msg);
                status = AJ_OK;
                break;

                // if the server, wait for a client
            case AJ_SIGNAL_SESSION_JOINED:
            {
                uint16_t port;
                char* joiner;
                status = AJ_UnmarshalArgs(&msg, "qus", &port, &g_SessionId, &joiner);

                AJ_InitTimer(&StartTime);
                AJ_Printf("Client Joined with session %u\n", g_SessionId);
                break;
            }

            case AJ_METHOD_ACCEPT_SESSION:
            {
                AJ_Printf("Got Accept Session\n");
                AJ_BusReplyAcceptSession(&msg, TRUE);
                break;
            }

            case AJ_SIGNAL_SESSION_LOST_WITH_REASON:
            case AJ_SIGNAL_SESSION_LOST:
                AJ_Printf("Session Lost\n");
                g_SessionId = 0;
                status = AJ_ERR_READ;
                break;

            default:
                AJ_Printf("Default: msg id is %u\n", msg.msgId);
                status = AJ_BusHandleBusMessage(&msg);
                break;
            }
        }
        /*
         * Messages must be closed to free resources
         */
        if (status == AJ_OK) {
            status = AJ_CloseMsg(&msg);
            if (status != AJ_OK) {
                AJ_Printf("Close message failed \n");
                AJ_Disconnect(&g_bus);
                connected = FALSE;
                break;
            }
        }

        if ((AJ_ERR_READ == status) || g_error) {
            AJ_Printf("AllJoyn disconnect %s  \n", AJ_StatusText(status));
            AJ_Printf("Disconnected from Daemon:%s\n", AJ_GetUniqueName(&g_bus));
            AJ_Disconnect(&g_bus);
            connected = FALSE;
            break;
        }

        if (g_exit) {
            AJ_Printf("AllJoyn exiting\n");
            AJ_Disconnect(&g_bus);
            connected = FALSE;
            status = AJ_OK;
            break;
        }
    }
    AJ_Printf("sigtest exiting with status: %s\n", AJ_StatusText(status));
}

#ifdef AJ_MAIN
int main(void)
{
    /* We are not expecting AJ_Main to return */
    AJ_Main();

    return 0;
}
#endif




