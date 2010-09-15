package com.wibblr.arriate.auth;

import static org.junit.Assert.assertEquals;

import org.apache.commons.codec.DecoderException;
import org.junit.Test;

public class OAuth10Tests  {

	@Test
	public void encodeParameter() {
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
	
	@Test
	public void decodeParameter() throws DecoderException {
		assertEquals("abcABC123", OAuth10.decodeParameter("abcABC123"));
		assertEquals("-._~", OAuth10.decodeParameter("-._~"));
		assertEquals("%", OAuth10.decodeParameter("%25"));
		assertEquals("+", OAuth10.decodeParameter("%2B"));
		assertEquals("&=*", OAuth10.decodeParameter("%26%3D%2A"));
		assertEquals("\n", OAuth10.decodeParameter("%0A"));
		assertEquals("\u0020", OAuth10.decodeParameter("%20"));
		assertEquals("\u007F", OAuth10.decodeParameter("%7F"));
		assertEquals("\u0080", OAuth10.decodeParameter("%C2%80"));
		assertEquals("\u3001", OAuth10.decodeParameter("%E3%80%81"));
		assertEquals("\u0080", OAuth10.decodeParameter("%C2%80"));
	}
	
	@Test
	public void parameterNormalization() {
		assertEquals("name", OAuth10.normalizeParameters("name"));
		assertEquals("a=b", OAuth10.normalizeParameters("a=b"));
		assertEquals("a=b&c=d", OAuth10.normalizeParameters("a=b&c=d"));
		assertEquals("a=x!y&a=x+y", OAuth10.normalizeParameters("a=x%20y&a=x%21y"));
		assertEquals("x!y=a&x=a", OAuth10.normalizeParameters("x=a&x%21y=a"));
	}
}
