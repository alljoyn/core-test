/******************************************************************************
 * Copyright (c) 2016 Open Connectivity Foundation (OCF) and AllJoyn Open
 *    Source Project (AJOSP) Contributors and others.
 *
 *    SPDX-License-Identifier: Apache-2.0
 *
 *    All rights reserved. This program and the accompanying materials are
 *    made available under the terms of the Apache License, Version 2.0
 *    which accompanies this distribution, and is available at
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Copyright 2016 Open Connectivity Foundation and Contributors to
 *    AllSeen Alliance. All rights reserved.
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
package org.alljoyn.bus.samples.simpleclient.test;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

import org.alljoyn.bus.samples.simpleclient.*;

import android.test.ActivityInstrumentationTestCase2;
import android.util.Log;

import com.robotium.solo.Solo;

public class JniSimpleClientSolo extends ActivityInstrumentationTestCase2<Client>
{
	private static final String TAG = "JniSimpleClientTest";
	
	private Solo solo;
	
	//8 seconds for client to discover
	private static final Integer CLIENT_DISCOVERY_IN_MS = 8000;
	
	// 8 seconds for client join session
	private static final Integer CLIENT_JOIN_IN_MS = 8000;
	
	private static final String CONNECT = "Connect";
	private static final String CONNECT_BUTTON_MISSING = "Connect button missing for discovery failure!";
	private static final String CONNECT_BUTTON_ENABLED = "Connect button enabled!";
	private static final String CONNECT_BUTTON_DISABLED = "Connect button disabled!";
	
	private static final String DISCONNECT = "Disconnect";
	private static final String DISCONNECT_BUTTON_MISSING = "Disconnect button missing for join failure!";
	private static final String DISCONNECT_BUTTON_ENABLED = "Disconnect button enabled!";
	private static final String DISCONNECT_BUTTON_DISABLED = "Disconnect button missing for join failure!";
	
	private static final String PING = "Ping";
	private static final String PING_BUTTON_MISSING = "Ping button missing!";
	private static final String PING_BUTTON_ENABLED = "Ping button enabled!";
	private static final String PING_BUTTON_DISABLED = "Ping button disabled!";
	
	private static final String DEFAULT_WELL_NAME = "simple.service";
	private static final String DEFAULT_CLIENT_MSG = "jni client message";
	
	// android setting file path
	private static final String SETTING_PATH = "/data/local/tmp";
	private static final String SETTING_FILE = "/alljoyn.setting";
	
	private static final String NAME_KEY = "WELL_KNOWN_NAME";
	private String mNameValue = DEFAULT_WELL_NAME;
	
	private static final String CLIENT_MESSAGE_KEY = "CLIENT_MSG";
	private String mClientMsgValue = DEFAULT_CLIENT_MSG;
	
	public JniSimpleClientSolo() {
		super(Client.class);

	}

	@Override
	public void setUp() throws Exception {
		//This is where the solo object is created.
		solo = new Solo(getInstrumentation(), getActivity());
		
		getSettingsFromFile();
		
	}

	@Override
	public void tearDown() throws Exception {
		//finishOpenedActivities() will finish all the activities that have been opened during the test execution.
		solo.finishOpenedActivities();
	}

	// Read setting from file system
	private boolean getSettingsFromFile()
	{
		boolean readOK = false;
		String name = null;
		String value = null;
		
		
		try
		{
			FileReader input = new FileReader(SETTING_PATH + SETTING_FILE);
			BufferedReader bufRead = new BufferedReader(input);
			String myLine = null;

			while ( (myLine = bufRead.readLine()) != null)
			{    
				String[] nameValuePairs = myLine.split("=");
				// check to make sure you have valid data
				name = nameValuePairs[0];
				value = nameValuePairs[1];
				Log.d(TAG, "Name/value from file : " + name + "/" + value);
				
				if (name.equalsIgnoreCase(NAME_KEY) && value != null)
				{
					mNameValue = value;
					// If well known name is set, the file is ok
					readOK = true;
				}
				else if (name.equalsIgnoreCase(CLIENT_MESSAGE_KEY) && value != null)
				{
					mClientMsgValue = value;
				}
			}
			
			bufRead = null;
			input = null;
			
		} catch (FileNotFoundException e)
		{
			Log.w(TAG, "Setting file not found : " + SETTING_PATH + SETTING_FILE);
			
		} catch (IOException e) {
			Log.e(TAG, "Read from setting file failed!");
		}
		
		return readOK;
	}
	
	private void discover() throws Exception
	{

		// make sure discovery complete
		try {
			Thread.sleep(CLIENT_DISCOVERY_IN_MS);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		// Well known name discovered
		assertTrue("Discovery failed!", solo.searchText(mNameValue));
		
		// Make sure connect button displayed and enabled
		assertTrue(CONNECT_BUTTON_MISSING, solo.searchButton(CONNECT));
		
		assertTrue(CONNECT_BUTTON_DISABLED, solo.getButton(CONNECT).isEnabled());
			
	}
	
	private void joinSession() throws Exception
	{
		solo.clickOnButton(CONNECT);
		
		// make sure dialog is displayed
		try {
			Thread.sleep(CLIENT_JOIN_IN_MS);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// Make sure connect button displayed and enabled
		assertTrue(DISCONNECT_BUTTON_MISSING, solo.searchButton(DISCONNECT));
		
		assertTrue(DISCONNECT_BUTTON_DISABLED, solo.getButton(DISCONNECT).isEnabled());
			
	}
	private void quitMenu() throws Exception
	{
		// wait for advertise to complete to join
		try {
			Thread.sleep(100);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		solo.clickOnMenuItem("Quit");
	}
	
	public void testSend() throws Exception
	{
		discover();
		
		joinSession();
	
		// type text
		Log.d(TAG, "Sending: " + mClientMsgValue);
		
		solo.typeText(0, mClientMsgValue);
		
		// Ping button should be enabled
		assertTrue(PING_BUTTON_DISABLED, solo.getButton(PING).isEnabled());
		
		// Click Ping button
		solo.clickOnButton(PING);
		
		// Wait 2 seconds to reach service
		try {
			Thread.sleep(2000);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		quitMenu();
	}	
}