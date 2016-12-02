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
package org.alljoyn.bus.samples.chat.test;

import com.robotium.solo.Solo;
import org.alljoyn.bus.samples.chat.Chat;
import android.test.ActivityInstrumentationTestCase2;


public class JniChatServiceSolo extends ActivityInstrumentationTestCase2<Chat>
{
	private Solo solo;
	private static final String CREATE_SESSION = "Create your chat session"; 
	
	private static final String ADVERTISE_DIALOG_TITLE = "Name to be advertised:";
	private static final String DIALOG_MISSING = "Advertise dialog missing!";
	
	private static final String JOIN_DIALOG_TITLE = "Name of session you want to join:";
	private static final String JOIN_DIALOG_MISSING = "Join dialog missing!";
	
	private static final String WELL_KNOWN_NAME = "jniChat";
	private static final String CHAT_SESSION_NAME_MISSING = "chat session name missing!";
	
	private static final String SERVICE_MESSAGE = "service message";
	private static final String SERVICE_MESSAGE_MISSING = "service message missing!";
	
	private static final String CLIENT_MESSAGE = "client message";
	private static final String CLIENT_MESSAGE_MISSING = "client message missing!";
	
	//8 seconds for client to discover and join
	private static final Integer CLIENT_JOIN_IN_MS = 8000;
	
	//15 seconds for service to wait for client
	private static final Integer SERVICE_WAIT_CLIENT_IN_MS = 15000;
	
	// 20 seconds to exchange message
	private static final Integer MESSAGE_EXCHANGE_IN_MS = 20000;
	
	private static final String QUIT_MENU = "Quit";
	
	public JniChatServiceSolo() {
		super(Chat.class);

	}

	@Override
	public void setUp() throws Exception {
		//This is where the solo object is created.
		solo = new Solo(getInstrumentation(), getActivity());
		
	}

	@Override
	public void tearDown() throws Exception {
		//finishOpenedActivities() will finish all the activities that have been opened during the test execution.
		solo.finishOpenedActivities();
		

	}
	
	private void advertise() throws Exception
	{
		// Click radio button - Create your chat session
		solo.clickOnRadioButton(0);
		
		// make sure dialog is displayed
		try {
			Thread.sleep(10);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// Make sure advertise dialog displayed
		assertTrue(DIALOG_MISSING, solo.searchText(ADVERTISE_DIALOG_TITLE));
		
		// Enter well known name in textbot
		solo.enterText(0, WELL_KNOWN_NAME);
		
		// Click ok button
		solo.clickOnButton("OK");
		
		// wait for client to join
		try {
			Thread.sleep(SERVICE_WAIT_CLIENT_IN_MS);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// Make sure well known name are displayed
		assertTrue(CHAT_SESSION_NAME_MISSING, solo.searchText(WELL_KNOWN_NAME));
		
		
	}
	
	private void joinChat() throws Exception
	{
		// Click radio button - Join a chat session
		solo.clickOnRadioButton(1);
		
		// make sure join dialog is displayed
		try {
			Thread.sleep(100);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// Make sure join dialog displayed
		assertTrue(JOIN_DIALOG_MISSING, solo.searchText(JOIN_DIALOG_TITLE));
		
		// Enter well known name in textbot
		solo.enterText(0, WELL_KNOWN_NAME);
		
		// Click ok button
		solo.clickOnButton("OK");
		
		// discover and join
		try {
			Thread.sleep(CLIENT_JOIN_IN_MS);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// Make sure well known name are displayed
		assertTrue(CHAT_SESSION_NAME_MISSING, solo.searchText(WELL_KNOWN_NAME));
		
		
	}
	
	private void serviceWaitClientMessage() throws Exception
	{
		// make sure dialog is displayed
		try {
			Thread.sleep(MESSAGE_EXCHANGE_IN_MS);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// Make sure service message are displayed 
		assertTrue(CLIENT_MESSAGE_MISSING, solo.searchText(CLIENT_MESSAGE));
	}
	
	private void clientWaitServiceMessage() throws Exception
	{
		// make sure dialog is displayed
		try {
			Thread.sleep(MESSAGE_EXCHANGE_IN_MS);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// Make sure service message are displayed 
		assertTrue(SERVICE_MESSAGE_MISSING, solo.searchText(SERVICE_MESSAGE));
	}
	
	private void quitTest() throws Exception
	{
		// make sure dialog is displayed
		try {
			Thread.sleep(10);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	
		solo.clickOnMenuItem(QUIT_MENU);
	}
	public void testServerMessage() throws Exception
	{
		advertise();
		
		// Enter 1st message
		solo.typeText(0, SERVICE_MESSAGE);
		
		try {
			Thread.sleep(100);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		solo.sendKey(Solo.ENTER);
		
		// make sure dialog is displayed
		try {
			Thread.sleep(100);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// Make sure service message are displayed 
		assertTrue(SERVICE_MESSAGE_MISSING, solo.searchText(SERVICE_MESSAGE));
		
		// Wait for client message to arrive
		serviceWaitClientMessage();
		
		quitTest();
	}
	
	public void testClientMessage() throws Exception
	{
		joinChat();
		
		// Enter 1st message
		solo.typeText(0, CLIENT_MESSAGE);
		
		// make sure dialog is displayed
		try {
			Thread.sleep(100);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		solo.sendKey(Solo.ENTER);
		
		// make sure dialog is displayed
		try {
			Thread.sleep(100);
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		// Make sure service message are displayed 
		assertTrue(CLIENT_MESSAGE_MISSING, solo.searchText(CLIENT_MESSAGE));
		
		// Wait for service message to arrive
		clientWaitServiceMessage();
		
		quitTest();
	}
}