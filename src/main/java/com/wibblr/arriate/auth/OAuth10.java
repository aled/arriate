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
import java.util.Random;

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
	
	private String token = "";
	private String tokenSecret = "";
	
	private Random random = new Random(System.currentTimeMillis());
	
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

	void authenticate() {
		try {
			HashMap<String, String> requestTokenMap = getRequestToken();
		
			token = requestTokenMap.get("oauth_token");
			tokenSecret = requestTokenMap.get("oauth_token_secret");
			
			// Note that there is an optional callback parameter that can be passed to the authorizeUrl
			System.out.println("Please go to the following URL to authenticate: " + authorizeUrl + "?" + "oauth_token=" + token);
			System.in.read();
			
			HashMap<String, String> accessTokenMap = getAccessToken();
			
			token = accessTokenMap.get("oauth_token");
			tokenSecret = accessTokenMap.get("oauth_token_secret");
			
		} catch (Exception e) {		
			System.out.println(e.getMessage());
		}	
	}
	
	String getOauthTime() {
		return Long.toString(System.currentTimeMillis() / 1000);
	}
	
	String getNonce() {
		return Long.toString(random.nextLong());
	}
	
	// @return A Map containing the response parameters.
	HashMap<String, String> getRequestToken() throws Exception {
		return getToken(requestTokenUrl);
	}
	
	// @return A Map containing the response parameters.
	HashMap<String, String> getAccessToken() throws Exception {
		return getToken(accessTokenUrl);
	}
	
	HashMap<String, String> getToken(String requestUrl) throws Exception {
		return getToken(requestUrl, getOauthTime(), getNonce());
	}
	
	HashMap<String, String> getToken(String requestUrl, String timestamp, String nonce) throws Exception {		
		HttpURLConnection con = (HttpURLConnection) new URL(requestUrl).openConnection();
		con.setRequestMethod("POST");
		
		// Need content-length header to fix the following failure:
		//    HTTP/1.0 411 Length Required
		//    X-Squid-Error = ERR_INVALID_REQ 0
		con.setRequestProperty("Content-Length", "0");
		
		signRequest(con, timestamp, nonce);
		
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
			throw new IOException();
		}
		
		return parseParameters(con.getInputStream());
	}
	
	void signRequest(HttpURLConnection con) throws Exception {
		signRequest(con, getOauthTime(), getNonce());
	}
	
	void signRequest(HttpURLConnection con, String timestamp, String nonce) throws Exception {
		System.out.println("Signing request: " + con.getURL());
		
		HashMap<String, String> authFields = new HashMap<String, String>();
		authFields.put("oauth_consumer_key", consumerKey);
		authFields.put("oauth_signature_method", "HMAC-SHA1");
		authFields.put("oauth_token", token);
		authFields.put("oauth_timestamp", timestamp);
		authFields.put("oauth_nonce", nonce);
		authFields.put("oauth_version", "1.0");
		//authFields.put("oauth_callback", "");
			
		URL url = con.getURL();
		HashMap<String, String> urlParameters = new HashMap<String, String>();
		if (url.getQuery() != null) {
			String[] keyvalues = url.getQuery().split("&");
			for (String keyvalue : keyvalues) {
				String[] p = keyvalue.split("=");
				urlParameters.put(p[0], p[1]);
			}
		}
		
		String method = con.getRequestMethod();
		String normalizedUrl = getNormalizedUrl(url.getProtocol(), url.getHost(), url.getPort(), url.getPath());
		String normalizedParameters = getNormalizedParameters(authFields, urlParameters);		
		String signatureBaseString = getSignatureBaseString(method, normalizedUrl, normalizedParameters);
		
		authFields.put("oauth_signature",  getSignature(signatureBaseString, consumerSecret, tokenSecret));
		con.setRequestProperty("Authorization", getAuthorizationHeader(authFields));
		//System.out.println("Request properties:");
		
		System.out.println("Added Authorization header: " + getAuthorizationHeader(authFields));
		//for (String key : con.getRequestProperties().keySet()) {
		//	System.out.println(key + " = " + con.getRequestProperties().get(key));
		//}		
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

	public static HashMap<String, String> parseParameters() throws IOException, DecoderException {
		return parseParameters();		
	}
	
	public static HashMap<String, String> parseParameters(InputStream is) throws IOException, DecoderException {
		HashMap<String, String> parameters = new HashMap<String, String>();
		DelimitedStringReader rdr = new DelimitedStringReader(new InputStreamReader(is));
		
		String key, value;
		do {
			key = rdr.next('=');
			value = rdr.next('&');
			
			if (key != null && value != null) {
				parameters.put(decodeParameter(key), decodeParameter(value));
			}
		} while (key != null && value != null);
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
	
	static String getNormalizedUrl(String protocol, String host, int port, String path) {
		StringBuffer sb = new StringBuffer();
		sb.append(protocol);
		sb.append("://");
		sb.append(host);
		if (port > 0 && (("http".equals(protocol) && port != 80) || ("https".equals(protocol) && port != 443))) {
			sb.append(":");
			sb.append(Integer.toString(port));
		}
		sb.append(path);
		return sb.toString();
	}
	
	static String getNormalizedParameters(HashMap<String, String> authFields, HashMap<String, String> parameters) {
		ArrayList<String[]> parameterArray = new ArrayList<String[]>();
		
		for(String key : authFields.keySet()) {
			if (key.equals("oauth_signature")) continue;
			if (key.equals("realm")) continue;
			
			parameterArray.add(new String[] { encodeParameter(key), encodeParameter(authFields.get(key)) });
		}
		
		if (parameters != null) {
			for(String key : parameters.keySet()) {
				if (key.equals("oauth_signature")) continue;
				if (key.equals("realm")) continue;
				
				parameterArray.add(new String[] { encodeParameter(key), encodeParameter(parameters.get(key)) });
			}
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
