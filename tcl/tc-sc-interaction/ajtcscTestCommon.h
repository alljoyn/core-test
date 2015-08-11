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

#include <gtest/gtest.h>

extern "C" {
#include <ajtcl/alljoyn.h>
#include <ajtcl/aj_crypto.h>
/* Undefine a TC deprecated flag that causes conflicts with SC headers */
#ifdef ALLJOYN_FLAG_SESSIONLESS
#undef ALLJOYN_FLAG_SESSIONLESS
#endif

/* Undefine all SC conflicting macros defined by Thin Library */

#ifdef min
#undef min
#endif

#ifdef max
#undef max
#endif

#ifdef KEYLEN
#undef KEYLEN
#endif

#ifdef OUTLEN
#undef OUTLEN
#endif

#ifdef SEEDLEN
#undef SEEDLEN
#endif

#ifdef SIGNAL
#undef SIGNAL
#endif

#ifdef PROPERTY
#undef PROPERTY
#endif
}

#include <qcc/Util.h>
#include <qcc/StringUtil.h>
#include <qcc/Thread.h>

#include <alljoyn/AllJoynStd.h>
#include <alljoyn/DBusStd.h>

#include <alljoyn/Message.h>
#include <alljoyn/TransportMask.h>

#include <alljoyn/BusAttachment.h>
#include <alljoyn/Init.h>

#include <alljoyn/BusObject.h>
#include <alljoyn/ProxyBusObject.h>
#include <alljoyn/InterfaceDescription.h>

#include <alljoyn/AboutData.h>
#include <alljoyn/AboutObjectDescription.h>
#include <alljoyn/AboutProxy.h>
#include <alljoyn/AboutListener.h>

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

// The parameter passed to AJ_FindBusAndConnect API (value in milliseconds)
const uint16_t TC_LEAFNODE_CONNECT_TIMEOUT = 1500;

// The parameter passed to AJ_UnmarshalMsg API (value in milliseconds)
const uint16_t TC_UNMARSHAL_TIMEOUT = 100;

// The duration for which the test waits for an event before delcaring a failure
const uint16_t WAIT_TIME = 3000;
