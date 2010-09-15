package com.wibblr.arriate.auth;

import java.io.IOException;

import org.junit.Test;

public class OpenStreetMapTests {
	
	@Test
	public void getRequestToken() throws Exception {
		//OAuth10 oa = new OAuth10("api06.dev.openstreetmap.org");
		OAuth10 oa = new OAuth10("term.ie");
		
		oa.getRequestToken();
	}
}
