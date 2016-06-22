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
var testname = "Test bbclient launch"

var target = UIATarget.localTarget();
var app = target.frontMostApp();
var window = app.mainWindow();
var wkName = "gov.t";
var inputTxt = window.textFields()[0];
var startBtn = window.buttons()[0];

var discovered = "Discovered advertised name";
var joined = "Successfully joined session";
var received = "Received ping string [Ping String 1]";

UIALogger.logStart(testname);

inputTxt.setValue(wkName);
target.delay(1);
startBtn.tap();

// TCP and udp discovery + join may take 60 seconds
target.delay(60);

var outputTxt = window.textViews()[0].value();

//Make sure discovery, joinSession and ping successful

if (outputTxt.indexOf(discovered) == -1)
{
   UIALogger.logFail("Discovery fail!");
}
else if (outputTxt.indexOf(joined) == -1)
{
   UIALogger.logFail("JoinSession fail!");
}
else if (outputTxt.indexOf(received) == -1)
{
   UIALogger.logFail("Received ping string fail!");
}
else
{   
   UIALogger.logPass("Client completed OK");
}