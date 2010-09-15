package com.wibblr.arriate.auth;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.HashMap;

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
	public void parseResponseParameters() throws IOException, DecoderException {
		HashMap<String, String> parameters = OAuth10.parseParameters(new ByteArrayInputStream(
				"oauth_token=ab3cd9j4ks73hf7g&oauth_token_secret=xyz4992k83j47x0b".getBytes("UTF-8")));
		assertEquals(2, parameters.size());
		assertEquals("ab3cd9j4ks73hf7g", parameters.get("oauth_token"));
		assertEquals("xyz4992k83j47x0b", parameters.get("oauth_token_secret"));
	}
	
	@Test
	public void getSignature() throws Exception {
		assertEquals("tR3+Ty81lMeYAr/Fid0kMTYa/WM=", OAuth10.hmacsha1(
				"GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal", 
				"kd94hf93k423kf44&pfkkdhi9sl3r4s00"));
	}
	
	@Test
	public void parameterNormalization() {
		//assertEquals("name", OAuth10.normalizeParameters("name"));
		//assertEquals("a=b", OAuth10.normalizeParameters("a=b"));
		//assertEquals("a=b&c=d", OAuth10.normalizeParameters("a=b&c=d"));
		//assertEquals("a=x!y&a=x+y", OAuth10.normalizeParameters("a=x%20y&a=x%21y"));
		//assertEquals("x!y=a&x=a", OAuth10.normalizeParameters("x=a&x%21y=a"));
	}
}
