/******************************************************************************
 *  * 
 *    Copyright (c) 2016 Open Connectivity Foundation and AllJoyn Open
 *    Source Project Contributors and others.
 *    
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0

 ******************************************************************************/
var testname = "Test bbservice launch"

var target = UIATarget.localTarget();
var app = target.frontMostApp();
var window = app.mainWindow();
var wkName = "gov.s";
var inputTxt = window.textFields()[0];
var startBtn = window.buttons()[0];

var registered = "Bus object registered successfully";
var connected = "Bus connected successfully";
var requested = "Request for service name succeeded";
var binded = "Session to port binding successfully";

UIALogger.logStart(testname);

inputTxt.setValue(wkName);
target.delay(2);
startBtn.tap();

// android tcp or udp client discover + join at most takes 60 seconds 
target.delay(60);

var outputTxt = window.textViews()[0].value();

//Make sure register, connect, request, advertise, bind successful

if (outputTxt.indexOf(registered) == -1)
{
   UIALogger.logFail("Bus object register fail!");
}
else if (outputTxt.indexOf(connected) == -1)
{
   UIALogger.logFail("Bus connect fail!" + outputTxt);
}
else if (outputTxt.indexOf(requested) == -1)
{
   UIALogger.logFail("Request for service name fail!");
}
else if (outputTxt.indexOf(binded) == -1)
{
   UIALogger.logFail("Session to port binding fail!");
}
else
{   
   UIALogger.logPass("Service started OK");
}