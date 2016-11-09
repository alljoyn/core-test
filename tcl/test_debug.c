/**
 * @file
 */
/******************************************************************************
 *  *    Copyright (c) Open Connectivity Foundation (OCF) and AllJoyn Open
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
#define AJ_MODULE TEST

#include "alljoyn.h"
#include "aj_debug.h"
/**
 * 5 means AJ_DEBUG_ALL
 * However, if AJ_DbgLevel in aj_debug.c is set to AJ_DEBUG_ERROR,
 * only error messages are printed.
 * To print info messages, AJ_DbgLevel need to be AJ_DEBUG_INFO/AJ_DEBUG_ALL and
 * AJ_DEBUG_RESTRICT needs to be AJ_DEBUG_INFO/AJ_DEBUG_ALL
 */
uint8_t dbgTEST = 5;

int AJ_Main()
{
    AJ_Status status = AJ_OK;
    AJ_ErrPrintf(("Got error status %s\n", AJ_StatusText(status)));
    AJ_ErrPrintf(("Error print\n"));
    AJ_WarnPrintf(("Got warn status %s\n", AJ_StatusText(status)));
    AJ_WarnPrintf(("Warn print\n"));
    AJ_InfoPrintf(("Got info status %s\n", AJ_StatusText(status)));
    AJ_InfoPrintf(("Info print\n"));

    return 0;
}

#ifdef AJ_MAIN
int main()
{
    return AJ_Main();
}
#endif