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