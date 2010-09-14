package com.wibblr.arriate.auth;

import static org.junit.Assert.assertEquals;

import org.junit.Test;

public class OAuth10Tests  {

	@Test
	public void parameterEncoding() {
		// These test cases from http://wiki.oauth.net/TestCases
		assertEquals("abcABC123", OAuth10.encodeParameter("abcABC123"));
		assertEquals("-._~", OAuth10.encodeParameter("-._~"));
		assertEquals("%25", OAuth10.encodeParameter("%"));
		assertEquals("%2B", OAuth10.encodeParameter("+"));
		assertEquals("%26%3D%2A", OAuth10.encodeParameter("&=*"));
		assertEquals("%0A", OAuth10.encodeParameter("\n"));
		assertEquals("%20", OAuth10.encodeParameter("\u0020"));
		assertEquals("%7F", OAuth10.encodeParameter("\u007F"));
		assertEquals("%C2%80", OAuth10.encodeParameter("\u0080"));
		assertEquals("%E3%80%81", OAuth10.encodeParameter("\u3001"));
		assertEquals("%C2%80", OAuth10.encodeParameter("\u0080"));
	}
}
