/******************************************************************************
 *    Copyright (c) Open Connectivity Foundation (OCF) and AllJoyn Open
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
package org.alljoyn.bus.samples.slservice.test;

import org.alljoyn.bus.samples.slservice.Service;

import android.test.ActivityInstrumentationTestCase2;
import android.widget.ArrayAdapter;
import android.widget.ListView;

public class TestSessionlessService extends ActivityInstrumentationTestCase2<Service>
{
	private Service slServiceActivity;
	
	private ListView listOfMessages;
	private ArrayAdapter<String> listAdapter;
	
	private final String pingMsg1 = "Ping:  slclient";
	private final String pingMsg2 = "Ping:  slclientsuperlongmessage";
	
	public TestSessionlessService() 
	{
		super("org.alljoyn.bus.samples.slservice.Service", Service.class);
	}

	public void setUp() throws Exception 
	{
		super.setUp();
		
			
		slServiceActivity = this.getActivity();
			
		listOfMessages = (ListView)slServiceActivity.findViewById(org.alljoyn.bus.samples.slservice.R.id.ListView);
		listAdapter = (ArrayAdapter<String>) listOfMessages.getAdapter();
	}
		
	@Override
	public  void tearDown() throws Exception 
	{
	 	super.tearDown();
	} 
		
	private void waitSignalsArrived()
	{
  		/* Wait 60 seconds for 2 signals to reach service */
  	   	try {
  			Thread.sleep(60000);
  		} catch (InterruptedException e) {
  			assertTrue("sleep timeout!", false);
  		}		
	}
	

	private void checkListView()
	{
		int msgCount = listAdapter.getCount();
			
		assertEquals("Pings not received!", 2, msgCount);
		
		assertEquals("1st ping missing!", pingMsg1, listAdapter.getItem(0));
		
		assertEquals("2nd ping missing!", pingMsg2, listAdapter.getItem(1));
	}
	
	public void testSignalFromClient()
	{
		waitSignalsArrived();
  	   	
		checkListView();
		
	}
}