/**
 * @file
 * test program that will register and unregister bus objects with the bus.
 * The bus objects are created after connecting to the bus.
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
#include <qcc/platform.h>

#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <vector>

#include <qcc/Debug.h>
#include <qcc/Environ.h>
#include <qcc/Mutex.h>
#include <qcc/String.h>
#include <qcc/Thread.h>
#include <qcc/time.h>
#include <qcc/Util.h>

#include <alljoyn/BusAttachment.h>
#include <alljoyn/BusObject.h>
#include <alljoyn/DBusStd.h>
#include <alljoyn/AllJoynStd.h>
#include <alljoyn/MsgArg.h>
#include <alljoyn/version.h>

#include <alljoyn/Status.h>


#define QCC_MODULE "ALLJOYN"
#define NO_OF_BUS_OBJECTS 20000

using namespace std;
using namespace qcc;
using namespace ajn;


/* Static top level globals */
static BusAttachment* g_msgBus = NULL;

static volatile sig_atomic_t g_interrupt = false;
static Mutex lock;
static bool startDeregistering = false;
static bool startFreeing = false;

static void SigIntHandler(int sig)
{
    g_interrupt = true;
}

class LocalTestObject : public BusObject {

  public:

    LocalTestObject(BusAttachment& bus, const char* path) :
        BusObject(path), objPath(path)
    { }

    void ObjectRegistered(void)
    {
        static int count = 0;
        lock.Lock();
        count++;
        printf("Object[%d] registered  path is %s \n", count, objPath.c_str());
        if (count == NO_OF_BUS_OBJECTS) { startDeregistering = true; }
        lock.Unlock();
    }

    void ObjectUnregistered(void)
    {
        static int count = NO_OF_BUS_OBJECTS;
        lock.Lock();
        printf("Object[%d] unregistered path is %s \n", count, objPath.c_str());
        count--;
        if (count == 0) { startFreeing = true; }
        lock.Unlock();
    }

    String objPath;
};

static void usage(void)
{
    printf("Usage: slsreceiver [-n <name>] [-i #] \n\n");
    printf("Options:\n");
    printf("   -h                    = Print this help message\n");
    printf("   -?                    = Print this help message\n");
}

/** Main entry point */
int main(int argc, char** argv)
{
    QStatus status = ER_OK;

    printf("AllJoyn Library version: %s\n", ajn::GetVersion());
    printf("AllJoyn Library build info: %s\n", ajn::GetBuildInfo());

    /* Install SIGINT handler */
    signal(SIGINT, SigIntHandler);

    /* Parse command line args */
    for (int i = 1; i < argc; ++i) {
        if (0 == strcmp("-h", argv[i]) || 0 == strcmp("-?", argv[i])) {
            usage();
            exit(0);
        } else {
            status = ER_FAIL;
            printf("Unknown option %s\n", argv[i]);
            usage();
            exit(1);
        }
    }

    /* Get env vars */
    Environ* env = Environ::GetAppEnviron();
    qcc::String clientArgs = env->Find("BUS_ADDRESS");

    /* Create message bus */
    g_msgBus = new BusAttachment("registerbusobjects", true);

    /* Start the msg bus */
    if (ER_OK == status) {
        status = g_msgBus->Start();
    } else {
        QCC_LogError(status, ("BusAttachment::Start failed"));
        exit(1);
    }

    /* Connect to the daemon */
    if (clientArgs.empty()) {
        status = g_msgBus->Connect();
    } else {
        status = g_msgBus->Connect(clientArgs.c_str());
    }
    if (ER_OK != status) {
        QCC_LogError(status, ("Failed to connect to \"%s\"", clientArgs.c_str()));
        exit(-1);
    }

    /* Register local objects and connect to the daemon */
    LocalTestObject*testObj[NO_OF_BUS_OBJECTS];
    for (int i = 0; i < NO_OF_BUS_OBJECTS; i++) {
        char obj_path[200];
        sprintf(obj_path, "/com/cool%d", i);
        testObj[i] = new LocalTestObject(*g_msgBus, obj_path);
        g_msgBus->RegisterBusObject(*testObj[i]);
    }

    while (!startDeregistering && !g_interrupt)
        qcc::Sleep(100);

    for (int i = NO_OF_BUS_OBJECTS - 1; i >= 0; i--) {
        g_msgBus->UnregisterBusObject(*testObj[i]);
    }

    while (!startFreeing && !g_interrupt)
        qcc::Sleep(100);

    for (int i = 0; i < NO_OF_BUS_OBJECTS; i++)
        delete testObj[i];


    /* Clean up msg bus */
    delete g_msgBus;

    printf("%s exiting with status %d (%s)\n", argv[0], status, QCC_StatusText(status));

    return (int) status;
}
