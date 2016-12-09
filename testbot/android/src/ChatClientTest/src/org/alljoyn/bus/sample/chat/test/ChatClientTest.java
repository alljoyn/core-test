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
package org.alljoyn.bus.sample.chat.test;
import org.alljoyn.bus.sample.chat.*;
import org.alljoyn.bus.sample.chat.R;

import android.app.Instrumentation;
import android.test.ActivityInstrumentationTestCase2;
import android.view.KeyEvent;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TabHost;
import android.widget.TextView;

public class ChatClientTest extends ActivityInstrumentationTestCase2<TabWidget>
{
	/* ice and bt takes long to discover 
	 * Both discovery time should be less than SERVICE_WAIT_MAX
	 */
	private final long WIFI_DISCOVERY_TIMEOUT = 60 * 1000;
	
	/* Client should wait after calling service bus method. 
	 * CLIENT_WAIT_MAX + BT_DISCOVERY_TIMEOUT should be greater than
	 * SERVICE_WAIT_MAX defined in RawServiceTest
	 */
	private final long JOIN_SESSION_TIMEOUT = 20 * 1000;
	private final long SERVICE_MESSAGE_TIMEOUT = 40 * 1000;
	
	private final String clientString = "C L I E N T";
	private final String serviceString = "service";
	
	/* Channel name is AllChatz, same as ios chat to interop */
	private final String ChannelName = "AllChatz";
	private final String JoinedStatus = "Joined";
	
	//private Solo tabActivity;
	private TabWidget tabActivity;
	private TabHost tabHost;
	private View useView = null;
	
	private Button joinChannelBtn = null;
	private EditText chatEditor = null;
	private TextView channelName = null;
	private TextView channelStatus = null;
	private ListView chatList = null;
	
	private boolean onUIThread = true;
	
	public ChatClientTest() 
	{
		super("org.alljoyn.bus.sample.chat", TabWidget.class);
	}

	public void setUp() throws Exception 
	{
		tabActivity = this.getActivity();
		tabHost = tabActivity.getTabHost();
	}
	
	@Override
	public  void tearDown() throws Exception 
	{
	 	super.tearDown();
	}
			
	/* Make Join Channel button the input focus */
	private void focusJoinChannelBtn()
	{
		
		tabActivity.runOnUiThread(
			      new Runnable() {
			        public void run() 
			        {
			          tabHost.requestFocus();
			          tabHost.setCurrentTab(0);
			          
				  		/* Wait 200ms till tab content is ready */
				  	   	try {
				  			Thread.sleep(200);
				  		} catch (InterruptedException e) {
				  			assertTrue("sleep timeout!", false);
				  		}
				  		
				  		useView = tabHost.getCurrentView();
				  		assertTrue("Current view empty!", useView!=null);
				  		
				  		joinChannelBtn = (Button)useView.findViewById(R.id.useJoin);
				  		assertTrue("Join button is Null!", joinChannelBtn!=null);
				  			  		
				  		chatList = (ListView)useView.findViewById(R.id.useHistoryList);
				  		assertTrue("Chat list is Null!", chatList!=null);
				  		
				  		joinChannelBtn.requestFocus();
				  		
				  		onUIThread = false;
			        }
			      }
			     );
	}
	
	/* Make chat editor the input focus */
	private void focusChatEditor()
	{
		
		tabActivity.runOnUiThread(
			      new Runnable() {
			        public void run() 
			        {
	
				  		channelName = (TextView)useView.findViewById(R.id.useChannelName);
				  		assertTrue("Name is null!", channelName!=null);
				  		
				  		channelStatus = (TextView)useView.findViewById(R.id.useChannelStatus);
				  		assertTrue("Status is null!", channelStatus!=null);
				  		
				  		chatEditor = (EditText)useView.findViewById(R.id.useMessage);
				  		assertTrue("Chat editbox is Null!", chatEditor!=null);
				  		
			        	chatEditor.requestFocus();
			        	
			        	onUIThread = false;
			        }
			      }
			     );
	}
	
	private void waitDiscoveryComplete()
	{
  		/* Wait 20 second for discovery complete */
  	   	try {
  			Thread.sleep(WIFI_DISCOVERY_TIMEOUT);
  		} catch (InterruptedException e) {
  			assertTrue("sleep timeout!", false);
  		}		
	}
	
	private void waitJoinSessionComplete()
	{
  		/* Wait 20 second for joinSession complete */
  	   	try {
  			Thread.sleep(JOIN_SESSION_TIMEOUT);
  		} catch (InterruptedException e) {
  			assertTrue("sleep timeout!", false);
  		}		
	}
	
	private void checkJoinStatus()
	{
		
  		/* Channel name and status should be set after joinSession successful */
  		assertEquals("Channel Name not " + ChannelName, ChannelName, channelName.getText().toString());
		assertEquals("Channel status not joined!", JoinedStatus, channelStatus.getText().toString());
		
		// Join button should be disabled after joinSession successful
  	   	assertFalse("Join Channel fail!", joinChannelBtn.isEnabled());
  	   	
	}
	
	private void waitServiceMessage()
	{
  		/* Wait 40 second for service send message after getting client message */
  	   	try {
  			Thread.sleep(SERVICE_MESSAGE_TIMEOUT);
  		} catch (InterruptedException e) {
  			assertTrue("sleep timeout!", false);
  		}		
	}
	
	/* Test client functions - join channel and chat */
	public void testClient()
	{
		waitDiscoveryComplete();
		
  		onUIThread = true;
  		
		focusJoinChannelBtn();
		
  		while (onUIThread)
  		{
  			try {
				Thread.sleep(200);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
  			
  		}
		/* Join channel */
		this.sendKeys(KeyEvent.KEYCODE_DPAD_CENTER);
		
  		/* Wait 1 second till channel name is ready in dialog */
  	   	try {
  			Thread.sleep(1000);
  		} catch (InterruptedException e) {
  			assertTrue("sleep timeout!", false);
  		}
  		
		this.sendKeys(KeyEvent.KEYCODE_ENTER);
		
		waitJoinSessionComplete();	
  	   	
  		onUIThread = true;
  		
  		focusChatEditor();
  		
  		while (onUIThread)
  		{
  			try {
				Thread.sleep(200);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
  			
  		}

  		checkJoinStatus();
  		
		/* Enter client from editor */	
		this.sendKeys(clientString);
		this.sendKeys(KeyEvent.KEYCODE_ENTER);
		
		waitServiceMessage();
  	   	
		/* Check list has 2nd message from service */
		assertTrue("Miss service message!", chatList.getCount() == 2);
			
		assertTrue("Miss service message!", chatList.getItemAtPosition(1).toString().endsWith(serviceString));
	}
}