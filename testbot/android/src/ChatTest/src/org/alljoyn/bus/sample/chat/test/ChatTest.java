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


public class ChatTest extends ActivityInstrumentationTestCase2<TabWidget> 
{
	/* Wifi discovery should take less than BT 
	 * Both discovery time should be less than SERVICE_WAIT_MAX
	 */
	private final long WIFI_DISCOVERY_TIMEOUT = 30 * 1000;
	private final long BT_DISCOVERY_TIMEOUT = 90 * 1000;
	
	/* Client should wait after calling service bus method. 
	 * CLIENT_WAIT_MAX + BT_DISCOVERY_TIMEOUT should be greater than
	 * SERVICE_WAIT_MAX defined in RawServiceTest
	 */
	private final long CLIENT_WAIT_MAX = 90 * 1000;
	
	private final String clientString = "client";
	private final String serviceString = "S E R V I C E";
	
	/* Channel name is AllChatz, shared by IOS and Android */
	private final String iosAndroidName = "AllChatz";
	
	private Instrumentation instrumentation;
	private TabWidget tabActivity;
	private TabHost tabHost;
	private View hostView = null;
	private View useView = null;
	
	private Button setChannelBtn = null;
	private Button startChannelBtn = null;
	private Button joinChannelBtn = null;
	private ListView chatList = null;
	private TextView channelName = null;
	private TextView channelStatus = null;
	private EditText chatEditor = null;
	
	private boolean onUIThread = true;
	
	public ChatTest() 
	{
		super("org.alljoyn.bus.sample.chat", TabWidget.class);
	}

	public void setUp() throws Exception 
	{
		instrumentation = getInstrumentation();

		//tabActivity = new Solo(instrumentation, getActivity());
		tabActivity = this.getActivity();
		tabHost = tabActivity.getTabHost();
		
		//setChannelBtn = (Button)tabHost.findViewById(R.id.hostSetName);	
	    
	}
	
	@Override
	public  void tearDown() throws Exception {

	 	super.tearDown();
	}
	
	/* Make Set Channel Name button the input focus */
	private void focusSetChannelBtn()
	{
		
		tabActivity.runOnUiThread(
			      new Runnable() {
			        public void run() {
			          tabHost.requestFocus();
			          tabHost.setCurrentTab(1);
			          
			  		/* Wait 200ms till tab content is ready */
			  	   	try {
			  			Thread.sleep(200);
			  		} catch (InterruptedException e) {
			  			assertTrue("sleep timeout!", false);
			  		}
			  		
			  		hostView = tabHost.getCurrentView();
			  		assertTrue("Current view empty!", hostView!=null);
			  		
			  		setChannelBtn = (Button)hostView.findViewById(R.id.hostSetName);
			  		assertTrue("Set button is Null!", setChannelBtn!=null);
			  		
					startChannelBtn = (Button)hostView.findViewById(R.id.hostStart);
			  		assertTrue("Start button is Null!", startChannelBtn!=null);
			  		
					setChannelBtn.requestFocus();		        

					onUIThread = false;
					
			        } // end of run() method definition
			      } // end of anonymous Runnable object instantiation
			    ); // end of invocation of runOnUiThread
		
	}
	
	/* Make Start Channel button the input focus */
	private void focusStartChannelBtn()
	{
		assertTrue("Set button is Null!", startChannelBtn!=null);
		
		tabActivity.runOnUiThread(
			      new Runnable() {
			        public void run() 
			        {
			        	startChannelBtn.requestFocus();
			        	onUIThread = false;
			        }
			      }
			     );
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
			          
				  		/* Wait 1 second till tab content is ready */
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
	
	private void checkAdvertisement()
	{
 	   	// Start channel button is disabled after advertisement
  	   	assertFalse("Start channel fail!", startChannelBtn.isEnabled());
	}
	
	private void checkClientMsg()
	{
		/* Check list has 1st message from client */
		assertTrue("Client chat miss!", chatList.getCount() == 1);
		
		assertTrue("No client message!", chatList.getItemAtPosition(0).toString().endsWith(clientString));
	}
	
	/* Test service functions - set/start channel */
	public void testService()
	{
		onUIThread = true;
		
		focusSetChannelBtn();
		
		while (onUIThread)
  		{
  			try {
				Thread.sleep(200);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
  			
  		}
		/* Enter host channel name */
		this.sendKeys(KeyEvent.KEYCODE_DPAD_CENTER);
		
		// this.sendKeys(ChannelSequence);
		
		instrumentation.sendStringSync(iosAndroidName);
		
 		/* Wait 3 seconds */
  	   	try {
  			Thread.sleep(3000);
  		} catch (InterruptedException e) {
  			assertTrue("sleep timeout!", false);
  		}
  		
		this.sendKeys(KeyEvent.KEYCODE_ENTER);
		
		onUIThread = true;
		
		/* Start channel just entered */
		focusStartChannelBtn();
		while (onUIThread)
  		{
  			try {
				Thread.sleep(200);
			} catch (InterruptedException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
  			
  		}
		
		this.sendKeys(KeyEvent.KEYCODE_DPAD_CENTER);
 		
		/* Wait 1 second */
  	   	try {
  			Thread.sleep(1000);
  		} catch (InterruptedException e) {
  			assertTrue("sleep timeout!", false);
  		}
  		
  	   	
		this.sendKeys(KeyEvent.KEYCODE_ENTER);
		
  		/* Wait 3 second till advertisement complete */
  	   	try {
  			Thread.sleep(3000);
  		} catch (InterruptedException e) {
  			assertTrue("sleep timeout!", false);
  		}
  		
  	   	checkAdvertisement();
  	   	
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
		
  		/* Wait 1 second till channel name is ready */
  	   	try {
  			Thread.sleep(1000);
  		} catch (InterruptedException e) {
  			assertTrue("sleep timeout!", false);
  		}
  		
		this.sendKeys(KeyEvent.KEYCODE_ENTER);
		
		/* Wait chat client to join and send 1st message
		 * Ideally, chat app should provide a public method to
		 * notify that if a client has joined and send message
		 */
	   	try {
			Thread.sleep(90000);
		} catch (InterruptedException e) {
			assertFalse("Sleep fail for discovery!", true);
		}
		
	   	checkClientMsg();
		
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
		/* Enter service from editor */	
		this.sendKeys(serviceString);
		this.sendKeys(KeyEvent.KEYCODE_ENTER);
		
		/* Wait 30 seconds to send message */
  	   	try {
  			Thread.sleep(30000);
  		} catch (InterruptedException e) {
  			assertTrue("sleep timeout!", false);
  		}
	}

}