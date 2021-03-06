/******************************************************************************
 *
 *
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
#ifndef AJTESTCOMMON_H
#define AJTESTCOMMON_H

#include <qcc/String.h>
#include <alljoyn/BusAttachment.h>
#include "BusEndpoint.h"
/*
 * this header file contains a functions that can be used to replace common
 * actions in the test code.
 */
namespace ajn {

/**
 * Obtain the default connection arg for the OS the test is run on.
 * If running on on windows this should be "tcp:addr=127.0.0.1,port=9955"
 * If running on a unix variant this should be "unix:abstract=alljoyn"
 *
 * The environment variable BUS_ADDRESS is specified it will be used in place
 * of the default address
 *
 * @return a qcc::String containing the default connection arg
 */
qcc::String getConnectArg(const char* envvar = "BUS_ADDRESS");

/**
 * Generate a globally unique name for use in advertising.
 *
 * Advertised names should be unique to avoid multiple running instances
 * of the test suite from interferring with each other.
 */
qcc::String genUniqueName(const BusAttachment& bus);

/**
 * Get the prefix of the uniqueNames used in advertising
 *
 * Advertised names should be unique to avoid multiple running instances
 * of the test suite from interferring with each other.
 */
qcc::String getUniqueNamePrefix(const BusAttachment& bus);

}

/*
 * gtest printers
 */
void PrintTo(const QStatus& status, ::std::ostream* os);
::std::ostream& operator<<(::std::ostream& os, const QStatus& status);

namespace qcc {
void PrintTo(const String& s, ::std::ostream* os);
}

namespace ajn {
::std::ostream& operator<<(::std::ostream& os, const BusEndpoint& ep);
::std::ostream& operator<<(::std::ostream& os, const AllJoynMessageType& type);
}
#endif //AJTESTCOMMON_H