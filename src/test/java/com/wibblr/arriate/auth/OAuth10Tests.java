package com.wibblr.arriate;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

import com.wibblr.arriate.OAuth;

public class OAuth10Tests  {

	@Test
	public void parameterEncoding() {
		// These test cases from http://wiki.oauth.net/TestCases
		assertEquals(OAuth.encodeParameter("abcABC123"), "abcABC123");
		assertEquals(OAuth.encodeParameter("-._~"), "-._~");
		assertEquals(OAuth.encodeParameter("%"), "%25");
		assertEquals(OAuth.encodeParameter("+"), "%2B");
		assertEquals(OAuth.encodeParameter("&=*"), "%26%3D%2A");
		assertEquals(OAuth.encodeParameter("/n"), "%0A");
		assertEquals(OAuth.encodeParameter("\u0020"), "%20");
		assertEquals(OAuth.encodeParameter("\u007F"), "%7F");
		assertEquals(OAuth.encodeParameter("\u0080"), "%C2%80");
		assertEquals(OAuth.encodeParameter("\u3001"), "%E3%80%81");
		assertEquals(OAuth.encodeParameter("\u0080"), "%C2%80");
	}
}
