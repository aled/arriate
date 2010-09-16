package com.wibblr.arriate.auth;

import java.util.UUID;

import org.junit.Test;

public class OpenStreetMapTests {
	
	@Test
	public void getRequestToken() throws Exception {
		OAuth10 oa = new OAuth10("api06.dev.openstreetmap.org");
		oa.getRequestToken(Long.toString(System.currentTimeMillis()/1000), UUID.randomUUID().toString());
		
		OAuth10 oa2 = new OAuth10("term.ie");		
		oa2.getRequestToken("1284667200", "12345");
	}
}
