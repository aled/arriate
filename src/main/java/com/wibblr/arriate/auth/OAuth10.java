package com.wibblr.arriate.auth;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
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
			getRequestToken();
		} catch (Exception e) {		
			System.out.println(e.getMessage());
		}	
	}
	
	void getRequestToken() throws Exception {
		HashMap<String, String> authFields = new HashMap<String, String>();
		authFields.put("oauth_consumer_key", consumerKey);
		authFields.put("oauth_signature_method", "HMAC-SHA1");
		authFields.put("oauth_timestamp", Long.toString(System.currentTimeMillis() / 1000));
		authFields.put("oauth_nonce", UUID.randomUUID().toString());
		authFields.put("oauth_version", "1.0");
		authFields.put("oauth_callback", "");
		
		HashMap<String, String> requestProperties = new HashMap<String, String>();
		
		String httpRequestMethod = "POST";
		String requestUrl = requestTokenUrl;
		String normalizedParameters = normalizeParameters(authFields);
		
		String signatureBaseString = getSignatureBaseString(httpRequestMethod, requestUrl, normalizedParameters);
		
		authFields.put("oauth_signature",  encodeParameter(getSignature(signatureBaseString, consumerSecret, "")));
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
			
			if (con.getResponseCode() == 401) {
				throw new Exception("401 returned");
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
	
	static String normalizeParameters(HashMap<String, String> parameterMap) {
		ArrayList<String> parameterList = new ArrayList<String>();
		for(String key : parameterMap.keySet()) {
			if (key.equals("oauth_signature")) continue;
			if (key.equals("realm")) continue;
			
			parameterList.add(encodeParameter(key) + "=" + encodeParameter(parameterMap.get(key)));
		}
		
		Collections.sort(parameterList);
		
		StringBuffer sb = new StringBuffer();
		for (String s : parameterList) {
			if (sb.length() > 0) sb.append("&");
			sb.append(s);
		}
		return sb.toString();
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
	
	private void getResponse(String url,  HashMap<String, String> requestProperties) {
		
	}
}
