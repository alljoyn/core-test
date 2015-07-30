/**
 * @file
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
#include <ajtcl/aj_security.h>

static const char* routingNodeName = "org.alljoyn.BusNode";

static const uint16_t CONNECT_TIMEOUT = 60000;
static const uint16_t UNMARSHAL_TIMEOUT = 5000;
static const uint32_t suites[] = { AUTH_SUITE_ECDHE_ECDSA, AUTH_SUITE_ECDHE_PSK, AUTH_SUITE_ECDHE_NULL };
//static const uint32_t suites[] = { AUTH_SUITE_ECDHE_NULL };

static AJ_Status AuthListenerCallback(uint32_t authmechanism, uint32_t command, AJ_Credential* cred)
{
    AJ_Status status = AJ_ERR_INVALID;

    AJ_AlwaysPrintf(("AuthListenerCallback authmechanism %d command %d\n", authmechanism, command));

    switch (authmechanism) {
    case AUTH_SUITE_ECDHE_NULL:
        cred->expiration = 0xFFFFFFFF;
        status = AJ_OK;
        break;

    default:
        break;
    }
    return status;
}

void AJ_Main(void)
{
    AJ_Status status = AJ_OK;
    AJ_BusAttachment bus;
    AJ_Message msg;

    AJ_Initialize();
    //AJ_SetSelectionTimeout(2000);

    status = AJ_StartService(&bus, routingNodeName, CONNECT_TIMEOUT, FALSE, 5, "innocent.app", AJ_NAME_REQ_DO_NOT_QUEUE, NULL);
    if (AJ_OK == status) {
        AJ_Printf("Connected to routing node (protocol version = %u). Got unique name - %s\n", AJ_GetRoutingProtoVersion(), AJ_GetUniqueName(&bus));
    } else {
        AJ_Printf("!!!Unexpected!!! failure when connecting to routing node: %s (code: %u)\n", AJ_StatusText(status), status);
    }

    //status = AJ_SecurityInit(&bus);
    AJ_SecuritySetClaimConfig(&bus, APP_STATE_CLAIMABLE, CLAIM_CAPABILITY_ECDHE_NULL, 0);
    AJ_BusEnableSecurity(&bus, suites, ArraySize(suites));
    AJ_BusSetAuthListenerCallback(&bus, AuthListenerCallback);
    while (TRUE) {

        status = AJ_UnmarshalMsg(&bus, &msg, UNMARSHAL_TIMEOUT);
        if (status == AJ_ERR_TIMEOUT) {
            printf("Nothing to do.. \n");
            continue;
        } else if (status == AJ_OK)   {
            switch (msg.msgId) {
            default:
                status = AJ_BusHandleBusMessage(&msg);
                break;
            }
        }

        AJ_CloseMsg(&msg);
    }
}

#ifdef AJ_MAIN
int main(void)
{
    /* AJ_Main is not expected to return */
    AJ_Main();

    return 0;
}
#endif
