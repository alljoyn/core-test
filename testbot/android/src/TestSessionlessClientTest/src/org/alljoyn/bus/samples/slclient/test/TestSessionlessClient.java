/******************************************************************************
 * Copyright (c) Open Connectivity Foundation (OCF) and AllJoyn Open
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
package org.alljoyn.bus.samples.slclient.test;

import org.alljoyn.bus.samples.slclient.Client;

import android.test.ActivityInstrumentationTestCase2;
import android.view.KeyEvent;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.ListView;

public class TestSessionlessClient extends ActivityInstrumentationTestCase2<Client>
{
	private Client slClientActivity;
	
	private ListView listOfMessages;
	private ArrayAdapter<String> listAdapter;
	private EditText textEditor;
	
	private final String pingMsg1 = "S L C L I E N T";
	private final String pingMsg2 = "S U P E R L O N G M E S S A G E";
	
	public TestSessionlessClient()
	{
		super("org.alljoyn.bus.samples.slclient.Client", Client.class);
	}
	
	public void setUp() throws Exception 
	{
		super.setUp();
		
			
		slClientActivity = this.getActivity();
			
		listOfMessages = (ListView)slClientActivity.findViewById(org.alljoyn.bus.samples.slclient.R.id.ListView);
		listAdapter = (ArrayAdapter<String>) listOfMessages.getAdapter();
		textEditor = (EditText)slClientActivity.findViewById(org.alljoyn.bus.samples.slclient.R.id.EditText);
	}
		
	@Override
	public  void tearDown() throws Exception 
	{
	 	super.tearDown();
	} 
		
	private void waitSignalArrive()
	{
  		/* Wait 30 seconds for signal to reach service */
  	   	try {
  			Thread.sleep(30000);
  		} catch (InterruptedException e) {
  			assertTrue("sleep timeout!", false);
  		}		
	}
	
	public void testClientPing()
	{
		// text editor should focus
		assertTrue("Not able to enter text", textEditor.isInputMethodTarget());
		
		this.sendKeys(pingMsg1);
		
  		// Wait 100ms 
  	   	try {
  			Thread.sleep(100);
  		} catch (InterruptedException e) {
  			assertTrue("sleep timeout!", false);
  		}		
  	   	
		this.sendKeys(KeyEvent.KEYCODE_ENTER);
		
  		// Wait 100ms 
  	   	try {
  			Thread.sleep(100);
  		} catch (InterruptedException e) {
  			assertTrue("sleep timeout!", false);
  		}
		
		waitSignalArrive();
		
		this.sendKeys(pingMsg2);
		
  		// Wait 100ms 
  	   	try {
  			Thread.sleep(100);
  		} catch (InterruptedException e) {
  			assertTrue("sleep timeout!", false);
  		}		
  	   	
		this.sendKeys(KeyEvent.KEYCODE_ENTER);
		
		waitSignalArrive();
	}
}