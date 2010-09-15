package com.wibblr.arriate.auth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLConnection;
import java.util.HashMap;
import java.util.Properties;
import java.util.UUID;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class OAuth10 {
	// As far as I can tell, all the available OAuth libraries seem to only work with 
	// v1.0a of the standard.
	// Therefore let's just write the stupid thing in longhand - how hard can it be...?
	
	private String consumerKey = null;
	private String consumerSecret = null;
	private String requestTokenUrl = null;
	private String accessTokenUrl = null;
	private String authoriseUrl = null;
	
	public OAuth10(String url) throws IOException {
		Properties p = new Properties();
		p.load(getClass().getResourceAsStream("/oauth/" + url + "/oauth-consumer.properties"));
		
		consumerKey = p.getProperty("CONSUMER_KEY");
		consumerSecret = p.getProperty("CONSUMER_SECRET");
		
		p.clear();
		p.load(getClass().getResourceAsStream("/oauth/" + url + "/oauth-provider.properties"));
	
		requestTokenUrl = p.getProperty("REQUEST_TOKEN_URL");
		accessTokenUrl = p.getProperty("ACCESS_TOKEN_URL");
		authoriseUrl = p.getProperty("AUTHORISE_URL");
	}

	public static void main(String[] args) {
		try {
			new OAuth10("www.openstreetmap.org").authenticate();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	private void authenticate() {
		try {
			getRequestToken();
		} catch (Exception e) {		
			System.out.println(e.getMessage());
		}	
	}
	
	private void getRequestToken() {
		HashMap<String, String> authFields = new HashMap<String, String>();
		authFields.put("oauth_consumer_key", consumerKey);
		authFields.put("oauth_signature_method", "HMAC_SHA1");
		authFields.put("oauth_signature", "");
		authFields.put("oauth_timestamp", Long.toString(System.currentTimeMillis() / 1000));
		authFields.put("oauth_nonce", UUID.randomUUID().toString());
		authFields.put("oauth_version", "1.0");
		authFields.put("oauth_callback", "");
	
		HashMap<String, String> requestHeaders = new HashMap<String, String>();
		requestHeaders.put("Authorization", getAuthorizationHeader(authFields));
		getResponse(requestTokenUrl, requestHeaders);
	}
	
	private String getAuthorizationHeader(HashMap<String, String> authFields) {
		StringBuilder sb = new StringBuilder();
		
		for (String k : authFields.keySet()) {
			if (sb.length() == 0) {
				sb.append("OAuth ");		
			} else {
				sb.append(",");
			}
			sb.append(encodeParameter(k));
			sb.append("=\"");
			sb.append(encodeParameter(authFields.get(k)));
			sb.append("\"");
		}		
		return sb.toString();
	}
	
	static String normalizeParameters(String s) {
		return null;
	}
	
	static String decodeParameter(String s) throws DecoderException {
		StringBuffer sb = new StringBuffer();
		
		char[] hexBuf = new char[2];
		ByteArrayOutputStream buf = new ByteArrayOutputStream();
		
		try {
			for (int i = 0; i < s.length(); i++) {
				char c = s.charAt(i);
				
				if (c != '%') {
					if (buf.size() > 0) {						
						sb.append(buf.toString("UTF-8"));
						buf.reset();
					}
					sb.append(c);
				}			
				else if (c == '%') {			
					hexBuf[0] = s.charAt(++i);
					hexBuf[1] = s.charAt(++i);
					buf.write(Hex.decodeHex(hexBuf)[0]);
				}
			}
			if (buf.size() > 0) {
				sb.append(buf.toString("UTF-8"));
			}
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		return sb.toString();
	}
	
	static String encodeParameter(String s) {
		StringBuffer sb = new StringBuffer();
		
		for (int i = 0; i < s.length(); i++) {
			char c = s.charAt(i);
			if (Character.isLetterOrDigit(c)
				|| c == '_'
				|| c == '-'
				|| c == '.'
				|| c == '~') {
				sb.append(c);
			}
			else {
				
				try {
					byte[] utf8Char = new String(new char[]{c}).getBytes("UTF-8");					
					
					for (byte b : utf8Char) {
						sb.append("%");
						sb.append(Hex.encodeHexString(new byte[]{b}).toUpperCase());
					}
				} catch (UnsupportedEncodingException e) {
					e.printStackTrace();
				}
			}				
		}
		return sb.toString();
	}
	
	private void getResponse(String url,  HashMap<String, String> requestHeaders) {
		try {
			URLConnection con = new URL(url).openConnection();
			
			for (String k : requestHeaders.keySet()) {
				con.setRequestProperty(k, requestHeaders.get(k));
			}
			
			HashMap<String, String> encodedParameters = new HashMap<String, String>();
			//ByteArrayOutputStream bais = new ByteArrayOutputStream( (null, con.getContentLength(), 0);
			
		}
		catch (Exception e) {
			e.printStackTrace();
		}
	}
}
