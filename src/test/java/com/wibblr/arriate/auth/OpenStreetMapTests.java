package com.wibblr.arriate.auth;

import static org.junit.Assert.assertEquals;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import org.junit.Test;

public class OpenStreetMapTests {
	private String host = "api06.dev.openstreetmap.org";
	
	private void callApiMethod(String path) throws Exception {
		String scheme = "http";
		String pathPrefix = "/api/0.6";
		
		HttpURLConnection con = (HttpURLConnection) new URL(scheme + "://" + host + pathPrefix + path).openConnection();		
		con.setRequestMethod("GET");
		
		OAuth10 oauth = new OAuth10(host);
		oauth.authenticate();
		oauth.signRequest(con);
		assertEquals(200, con.getResponseCode());
		
		System.out.println("ContentLength = " + con.getContentLength());
		
		BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()));
		String line;
		while ((line = br.readLine()) != null) {
			System.out.println(line);
		}
	}
	
	@Test
	public void getUserDetails() throws Exception {
		
		callApiMethod("/user/details");
		
		//String host = "term.ie";
		//String path = "/oauth/example/echo_api.php?a=b&c=d";
		
		
		// Expect 'unauthorised' response at this point
		//assertEquals(401, con.getResponseCode());
		
		// Now try again using OAuth
		//con.disconnect();
		
		
	}
	
	@Test
	public void getGpxFiles() throws Exception {
		callApiMethod("/user/gpx_files");
	}
	
	//@Test
	public void getRequestToken() throws Exception {	
		OAuth10 oa = new OAuth10("api06.dev.openstreetmap.org");
		oa.authenticate();
		
		//OAuth10 oa2 = new OAuth10("term.ie");		
		//oa2.authenticate();
	}
}
