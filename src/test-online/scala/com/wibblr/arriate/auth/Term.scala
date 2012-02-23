package com.wibblr.arriate.auth;import java.io.ByteArrayInputStream;import java.io.BufferedReader;import java.io.InputStreamReader;
import java.net.URL;import java.net.HttpURLConnection;import org.junit._;

import org.junit.Test;

class Term {
	val scheme = "http";
	val provider = "term.ie"
	val pathPrefix = "/oauth/example"
	
	def callGetMethod(path: String): Array[Byte] = {
		val url = new URL(scheme + "://" + provider + pathPrefix + path)
		val con = url.openConnection().asInstanceOf[HttpURLConnection]
		con.setRequestMethod("GET")
		
		val oauth: OAuth10 = new OAuth10(provider, new TokenStorage(provider), new NullAuthorizer())
		
		if (!oauth.isAuthorized()) {
			oauth.authorize();
		}
		
		oauth.signRequest(con);				Assert.assertEquals(200, con.getResponseCode());		Assert.assertEquals(7, con.getContentLength());				val buf = new Array[Byte](con.getContentLength());				Assert.assertEquals(7, con.getInputStream().read(buf));				return buf;
	}
	
	@Test
	def echo() {
		Assert.assertArrayEquals("a=b&c=d".getBytes, callGetMethod("/echo_api.php?a=b&c=d"));
	}
}