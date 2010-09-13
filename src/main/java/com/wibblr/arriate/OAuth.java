package com.wibblr.arriate;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URL;
import java.net.URLConnection;
import java.util.HashMap;
import java.util.UUID;

public class OAuth {
	// As far as I can tell, all the available OAuth libraries seem to only work with 
	// v1.0a of the standard.
	// Therefore let's just write the stupid thing in longhand - how hard can it be...?
	
	private static String CONSUMER_KEY = "";
	private static String CONSUMER_SECRET = "";
	
	private static String REQUEST_TOKEN_URL = "http://www.openstreetmap.org/oauth/request_token";
	private static String ACCESS_TOKEN_URL = "http://www.openstreetmap.org/oauth/access_token";
	private static String AUTHORISE_URL = "http://www.openstreetmap.org/oauth/authorize";
	
	public static void main(String[] args) {
		new OAuth().authenticate();
	}
	
	private void authenticate() {
		try {
			getRequestToken();
			
//			Map<String, List<String>> headerFields = con.getHeaderFields();
//			
//			for (String k : headerFields.keySet()) {
//				System.out.println(k);
//				for (String v : headerFields.get(k)) {
//					System.out.println("  " + v);
//				}
//			}
		} catch (Exception e) {		
			System.out.println(e.getMessage());
		}
		
	}
	
	private void getRequestToken() {
		HashMap<String, String> authFields = new HashMap<String, String>();
		authFields.put("oauth_consumer_key", CONSUMER_KEY);
		authFields.put("oauth_signature_method", "HMAC_SHA1");
		authFields.put("oauth_signature", "");
		authFields.put("oauth_timestamp", Long.toString(System.currentTimeMillis() / 1000));
		authFields.put("oauth_nonce", UUID.randomUUID().toString());
		authFields.put("oauth_version", "1.0");
		authFields.put("oauth_callback", "");
	
		HashMap<String, String> requestHeaders = new HashMap<String, String>();
		requestHeaders.put("Authorization", getAuthorizationHeader(authFields));
		getResponse(REQUEST_TOKEN_URL, requestHeaders);
	}
	
	private String getAuthorizationHeader(HashMap<String, String> authFields) {
		StringBuilder sb = new StringBuilder();
		
		for (String k : authFields.keySet()) {
			if (sb.length() == 0) {
				sb.append("OAuth ");		
			} else {
				sb.append(",");
			}
			sb.append(parameterEncode(k));
			sb.append("=\"");
			sb.append(parameterEncode(authFields.get(k)));
			sb.append("\"");
		}		
		return sb.toString();
	}
	
	private String parameterEncode(String s) {
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
				sb.append("%");
				
				try {
					byte[] utf8Char = new String(new char[] {c}).getBytes("UTF-8");
				} catch (UnsupportedEncodingException e) {
					e.printStackTrace();
					
					// output as hex
				}
			}
						
		}
	}
	
	private void getResponse(String url,  HashMap<String, String> requestHeaders) {
		try {
			URLConnection con = new URL(url).openConnection();
			
			for (String k : requestHeaders.keySet()) {
				con.setRequestProperty(k, requestHeaders.get(k));
			}
		}
		catch (Exception e) {}
	}
}
