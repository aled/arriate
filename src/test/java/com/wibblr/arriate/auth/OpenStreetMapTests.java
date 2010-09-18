package com.wibblr.arriate.auth;

import static org.junit.Assert.assertEquals;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import org.junit.Test;

public class OpenStreetMapTests {
	
	@Test
	public void getUserDetails() throws Exception {
		String scheme = "http";
		
		String host = "api06.dev.openstreetmap.org";
		String path = "/api/0.6/user/details";
		
		//String host = "term.ie";
		//String path = "/oauth/example/echo_api.php?a=b&c=d";
		
		HttpURLConnection con = (HttpURLConnection) new URL(scheme + "://" + host + path).openConnection();		
		con.setRequestMethod("GET");
		
		// Expect 'unauthorised' response at this point
		//assertEquals(401, con.getResponseCode());
		
		// Now try again using OAuth
		//con.disconnect();
		OAuth10 oauth = new OAuth10(host);
		oauth.authenticate();
		oauth.signRequest(con);
		assertEquals(200, con.getResponseCode());
		
		System.out.println(con.getContentLength());
		
		BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()));
		String line;
		while ((line = br.readLine()) != null) {
			System.out.println(line);
		}
	}
	
	//@Test
	public void getRequestToken() throws Exception {
		
		
		
		OAuth10 oa = new OAuth10("api06.dev.openstreetmap.org");
		oa.authenticate();
		
		
		
		//OAuth10 oa2 = new OAuth10("term.ie");		
		//oa2.authenticate();
	}
}
