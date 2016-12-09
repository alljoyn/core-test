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


import org.alljoyn.bus.samples.simpleclient.*;

import android.test.ActivityInstrumentationTestCase2;
import android.view.KeyEvent;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.ListView;

public class TestSimpleClient extends ActivityInstrumentationTestCase2<Client> 
{
	private Client clientActivity;
	private ListView listOfMessages;
	private ArrayAdapter<String> listAdapter;
	private EditText textEditor;
	
	private final String pingMsg1 = "C L I E N T";
	private final String replyMsg1 = "Reply:  client";
	private final String pingMsg2 = "S U P E R L O N G M E S S A G E";
	private final String replyMsg2 = "Reply:  superlongmessage";
	
	public TestSimpleClient() 
	{
		super("org.alljoyn.bus.samples.simpleclient", Client.class);
	}

	public void setUp() throws Exception 
	{
		super.setUp();
		
		clientActivity = this.getActivity();
		
		listOfMessages = (ListView)clientActivity.findViewById(org.alljoyn.bus.samples.simpleclient.R.id.ListView);
		listAdapter = (ArrayAdapter<String>) listOfMessages.getAdapter();
		textEditor = (EditText)clientActivity.findViewById(org.alljoyn.bus.samples.simpleclient.R.id.EditText);
	}
	
	@Override
	public  void tearDown() throws Exception 
	{
	 	super.tearDown();
	}
	
	private void waitDiscoveryComplete()
	{
  		/* Wait 30 second for discovery complete */
  	   	try {
  			Thread.sleep(30000);
  		} catch (InterruptedException e) {
  			assertTrue("sleep timeout!", false);
  		}		
	}
	
	private void waitReplyBack()
	{
  		/* Wait 10 second for reply back */
  	   	try {
  			Thread.sleep(10000);
  		} catch (InterruptedException e) {
  			assertTrue("sleep timeout!", false);
  		}		
	}

	private void checkListView()
	{
		int msgCount = listAdapter.getCount();
			
		assertEquals("Reply not received!", 4, msgCount);
		
		assertEquals("1st reply missing!", replyMsg1, listAdapter.getItem(1));
		
		assertEquals("2nd reply missing!", replyMsg2, listAdapter.getItem(3));
	}
	
	public void testClientPing()
	{
		waitDiscoveryComplete();
		
		// text editor should focus after discovery and joinSession complete
		assertTrue("Discovery or joinSession fail!", textEditor.isInputMethodTarget());
		
		this.sendKeys(pingMsg1);
		
  		/* Wait 100ms for discovery complete */
  	   	try {
  			Thread.sleep(100);
  		} catch (InterruptedException e) {
  			assertTrue("sleep timeout!", false);
  		}		
  	   	
		this.sendKeys(KeyEvent.KEYCODE_ENTER);
		
		// Wait till reply back from service
		waitReplyBack();
		
		this.sendKeys(pingMsg2);
		
  		/* Wait 100ms for discovery complete */
  	   	try {
  			Thread.sleep(100);
  		} catch (InterruptedException e) {
  			assertTrue("sleep timeout!", false);
  		}		
  	   	
		this.sendKeys(KeyEvent.KEYCODE_ENTER);
		
		// Wait till reply back from service
		waitReplyBack();
		
		// Check reply from service
		checkListView();
	}

}