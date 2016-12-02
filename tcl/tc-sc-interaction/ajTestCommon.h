/******************************************************************************
 *
 *
 *  * 
 *    Copyright (c) 2016 Open Connectivity Foundation and AllJoyn Open
 *    Source Project Contributors and others.
 *    
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0

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