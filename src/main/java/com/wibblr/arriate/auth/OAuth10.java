package com.wibblr.arriate.auth;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.Properties;
import java.util.UUID;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

public class OAuth10 {
	// As far as I can tell, all the available OAuth libraries seem to only work with 
	// v1.0a of the standard.
	// Therefore let's just write the stupid thing in longhand - how hard can it be...?
	
	private String consumerKey = null;
	private String consumerSecret = null;
	private String requestTokenUrl = null;
	private String accessTokenUrl = null;
	private String authorizeUrl = null;
	
	public OAuth10(String url) throws IOException {
		Properties p = new Properties();
		p.load(getClass().getResourceAsStream("/oauth/" + url + "/oauth-consumer.properties"));
		
		consumerKey = p.getProperty("CONSUMER_KEY");
		consumerSecret = p.getProperty("CONSUMER_SECRET");
		
		p.clear();
		p.load(getClass().getResourceAsStream("/oauth/" + url + "/oauth-provider.properties"));
	
		requestTokenUrl = p.getProperty("REQUEST_TOKEN_URL");
		accessTokenUrl = p.getProperty("ACCESS_TOKEN_URL");
		authorizeUrl = p.getProperty("AUTHORIZE_URL");
	}

	private void authenticate() {
		try {
			getRequestToken(Long.toString(System.currentTimeMillis() / 1000), UUID.randomUUID().toString());
		} catch (Exception e) {		
			System.out.println(e.getMessage());
		}	
	}
	
	void getRequestToken(String timestamp, String nonce) throws Exception {
		HashMap<String, String> authFields = new HashMap<String, String>();
		authFields.put("oauth_consumer_key", consumerKey);
		authFields.put("oauth_signature_method", "HMAC-SHA1");
		authFields.put("oauth_token", "");
		authFields.put("oauth_timestamp", timestamp);
		authFields.put("oauth_nonce", nonce);
		authFields.put("oauth_version", "1.0");
		authFields.put("oauth_callback", "");
		
		HashMap<String, String> requestProperties = new HashMap<String, String>();
		
		String httpRequestMethod = "POST";
		String requestUrl = requestTokenUrl;
		String normalizedParameters = normalizeParameters(authFields);
		
		String signatureBaseString = getSignatureBaseString(httpRequestMethod, requestUrl, normalizedParameters);
		
		authFields.put("oauth_signature",  getSignature(signatureBaseString, consumerSecret, ""));
		requestProperties.put("Authorization", getAuthorizationHeader(authFields));
		
		try {
			HttpURLConnection con = (HttpURLConnection) new URL(requestTokenUrl).openConnection();
			con.setRequestMethod(httpRequestMethod);
			
			System.out.println("Request properties:");
			for (String key : requestProperties.keySet()) {
				con.setRequestProperty(key, requestProperties.get(key));
				System.out.println(key + " = " + requestProperties.get(key));
			}
			
			System.out.println("Response headers:");
			for (String key : con.getHeaderFields().keySet()) {
				System.out.println(key + " = " + con.getHeaderField(key));
			}
			
			if (con.getResponseCode() != 200) {
				BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()));
				String line;
				while ((line = br.readLine()) != null) {
					System.out.println(line);
				}
				return;
			}
			
			HashMap<String, String> responseParameters = parseParameters(con.getInputStream());
			
			System.out.println("Response parameters:");
			for (String key : responseParameters.keySet()) {
				System.out.println(key + " = " + responseParameters.get(key));
			}			
		}
		catch (Exception e) {
			e.printStackTrace();
		}
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
	
	public static HashMap<String, String> parseParameters(InputStream is) throws IOException, DecoderException {
		HashMap<String, String> parameters = new HashMap<String, String>();
		DelimitedStringReader rdr = new DelimitedStringReader(new InputStreamReader(is));
		
		while (rdr.ready()) {
			parameters.put(decodeParameter(rdr.next('=')), decodeParameter(rdr.next('&')));
		}	
		return parameters;
	}
	
	static String getSignature(String signatureBaseString, String consumerSecret, String tokenSecret) throws Exception {
		return hmacsha1(signatureBaseString, encodeParameter(consumerSecret) + "&" + encodeParameter(tokenSecret));
	}
	
	static String hmacsha1(String text, String key) throws Exception {
		SecretKeySpec keySpec = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA1");
		Mac mac = Mac.getInstance("HmacSHA1");
		mac.init(keySpec);
		byte[] bytes = mac.doFinal(text.getBytes("UTF-8"));
		return new String(Base64.encodeBase64(bytes));
	}
	
	static String getSignatureBaseString(String httpRequestMethod, String requestUrl, String normalizedParameters) {
		return encodeParameter(httpRequestMethod) 
			+ "&" + encodeParameter(requestUrl) 
			+ "&" + encodeParameter(normalizedParameters);
	}
	
	static String normalizeUrl(String scheme, String host, int port, String path) {
		StringBuffer sb = new StringBuffer();
		sb.append(scheme);
		sb.append("://");
		sb.append(host);
		if (("http".equals(scheme) && port != 80) || ("https".equals(scheme) && port != 443)) {
			sb.append(":");
			sb.append(Integer.toString(port));
		}
		sb.append(path);
		return sb.toString();
	}
	
	static String normalizeParameters(HashMap<String, String> parameterMap) {
		ArrayList<String[]> parameterArray = new ArrayList<String[]>();
		
		for(String key : parameterMap.keySet()) {
			if (key.equals("oauth_signature")) continue;
			if (key.equals("realm")) continue;
			
			parameterArray.add(new String[] { encodeParameter(key), encodeParameter(parameterMap.get(key)) });
		}
		
		Collections.sort(parameterArray, new Comparator<String[]>() {
			public int compare(String[] s1, String[] s2) {
				int ret = s1[0].compareTo(s2[0]);
				if (ret == 0) {
					ret = s1[1].compareTo(s2[1]);
				}
				return ret;
			}
		});
		
		StringBuffer sb = new StringBuffer();
		for (String[] s : parameterArray) {
			if (sb.length() > 0) sb.append("&");
			sb.append(s[0]);
			sb.append('=');
			sb.append(s[1]);
		}
		return sb.toString();
	}
	
	static int decodeHex(char c) throws IllegalArgumentException {
		if (c >= '0' && c <= '9') {
			return c - '0';
		}
		else if (c >= 'A' && c <= 'Z') {
			return c - 'A' + 10;
		}
		throw new IllegalArgumentException();
	}
	
	// converts two hex characters into a byte (which is returned as a character)
	// e.g. converts ('6', '5') into 'A'
	static char decodeHex(char c1, char c2) throws IllegalArgumentException {
		return (char) (decodeHex(c1) << 4 | decodeHex(c2));
	}
	
	static String decodeParameter(String s) throws DecoderException {
		StringBuffer sb = new StringBuffer();
		
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
					buf.write(decodeHex(s.charAt(++i), s.charAt(++i)));
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
}
