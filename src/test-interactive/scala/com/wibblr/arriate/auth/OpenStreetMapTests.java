package com.wibblr.arriate.auth;

import static org.junit.Assert.assertEquals;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

import org.junit.Test;

import com.wibblr.arriate.osm.api06.Api06;

public class OpenStreetMapTests {
	private String provider = "api06.dev.openstreetmap.org";
		
	private void sentHttpPost() {
		
	}
	
	private void sendHttpGet(String path) throws Exception {
		String scheme = "http";
		String pathPrefix = "/api/0.6";
		
		HttpURLConnection con = (HttpURLConnection) new URL(scheme + "://" + provider + pathPrefix + path).openConnection();		
		con.setRequestMethod("GET");
		
		OAuth10 oauth = new OAuth10(provider, new TokenStorage(provider), new ManualAuthorizer());
		
		if (!oauth.isAuthorized()) {
			oauth.authorize();
		}
		
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
		//sendHttpGet("/user/details");
		Api06 api = new Api06(provider, new OAuth10(provider, new TokenStorage(provider), new ManualAuthorizer()));
		
		api.getUserDetails();
	}
	
	@Test
	public void getGpxFiles() throws Exception {
		sendHttpGet("/user/gpx_files");
	}
}
