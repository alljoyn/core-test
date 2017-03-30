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

#include <alljoyn/BusAttachment.h>
#include <alljoyn/Status.h>
#include <alljoyn/AllJoynStd.h>
#include <alljoyn/version.h>

// Based on guidelines at http://www.freebsd.org/cgi/man.cgi?query=sysexits
enum retval_t {
    EXIT_OK = 0,
    EXIT_SOFTWARE = 70
};

int main(const int argc, const char* argv[])
{
    std::cout << "AllJoyn Library version: " << ajn::GetVersion() <<
        std::endl << "AllJoyn Library build info: " << ajn::GetBuildInfo() <<
        std::endl;

    ajn::BusAttachment bus("max-unique-address", false, 1);

    if (ER_OK != bus.Start()) {
        std::cout << "Failed to start bus attachment." << std::endl;
        return EXIT_SOFTWARE;
    }

    for (uint64_t i = 0; i < UINT32_MAX; i++) {
        if (ER_OK != bus.Connect()) {
            // Lets give it another good ol college try
            continue;
        }

        const qcc::String uniqueNameObtained = bus.GetUniqueName();

        bus.Disconnect();

        if (0 == i % UINT16_MAX) {
            std::cout << "The unique address (iter: " << i << ") is " << uniqueNameObtained.c_str() << std::endl;
        }
    }

    bus.Stop();

    return EXIT_OK;
}