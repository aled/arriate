package com.wibblr.arriate.auth;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
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
  private ConnectionProperties properties = null;
  
  private TokenStorage tokenStorage = null;
  private ExternalAuthorizer authorizer = null;
  
  private Random random = new Random(System.currentTimeMillis());
  
  /**
   * Constructor
   * 
   * @param provider: The name of a (predefined) provider, used to look up the consumer key, consumer secret, and all the URLs
   *           involved in the authorization process. Currently the provider must be one of:
   *           <ul>
   *           <li>www.openstreetmap.org</li>
   *           <li>api06.dev.openstreetmap.org</li>
   *           <li>term.ie</li>
   *           </ul>
   *         
   * @param tokenStorage: An object used to save the access token and secret in persistant storage
   * 
   * @param authorizer: An object used to perform authorization against the provider.
   */
   public OAuth10(String provider, TokenStorage tokenStorage, ExternalAuthorizer authorizer) throws IOException {
      this.tokenStorage = tokenStorage;
      this.authorizer = authorizer;
      
      Properties consumerProperties = new Properties();
      consumerProperties.load(getClass().getResourceAsStream("/oauth/" + provider + "/oauth-consumer.properties"));
        
      Properties providerProperties = new Properties();
      providerProperties.load(getClass().getResourceAsStream("/oauth/" + provider + "/oauth-provider.properties"));
    
      this.properties = new ConnectionProperties(
        consumerProperties.getProperty("CONSUMER_KEY"),
        consumerProperties.getProperty("CONSUMER_SECRET"),
        providerProperties.getProperty("REQUEST_TOKEN_URL"),
        providerProperties.getProperty("ACCESS_TOKEN_URL"),
        providerProperties.getProperty("AUTHORIZE_URL")
      );
  }
   
  public OAuth10(ConnectionProperties properties, TokenStorage tokenStorage, ExternalAuthorizer authorizer) {
      this.properties = properties;
      this.tokenStorage = tokenStorage;
      this.authorizer = authorizer;
   }

  public boolean isAuthorized() {
    return (tokenStorage.getToken().length() > 0 && tokenStorage.getTokenSecret().length() > 0);
  }
   
  /**
   * Deletes all access tokens and secrets for this provider from memory (and persistent storage, if any)
   */
  public void deauthorize() {
    tokenStorage.set(null, null);
  }
  
  /**
   * Sets up everything so that requests can be signed. Will call back to the ExternalAuthorizer passed
   * to the constructor, which is responsible for authorizing the user to the external site.
   */
  public void authorize() throws IOException, SignatureCalculationException {
    String accessToken = null, accessTokenSecret = null;
    
    try {    
      HashMap<String, String> requestTokenMap = getRequestToken();
      
      String requestToken = requestTokenMap.get("oauth_token");
      String requestTokenSecret = requestTokenMap.get("oauth_token_secret");
      
      String verifier = authorizer.authorize(properties.authorizeUrl() + "?" + "oauth_token=" + requestToken);
  
      HashMap<String, String> accessTokenMap = getAccessToken(requestToken, requestTokenSecret, verifier);  
      accessToken = accessTokenMap.get("oauth_token");
      accessTokenSecret = accessTokenMap.get("oauth_token_secret");  
    } finally {
      tokenStorage.set(accessToken, accessTokenSecret);
    }   
  }
 
  public void signRequest(HttpURLConnection con) throws SignatureCalculationException {
    Properties oauthProperties = getOauthProperties(tokenStorage.getToken());
    String tokenSecret = tokenStorage.getTokenSecret();
    
    signRequest(con, oauthProperties, tokenSecret);
  }
  
  private String getOauthTime() {
    return Long.toString(System.currentTimeMillis() / 1000);
  }
  
  private String getNonce() {
    return Long.toString(random.nextLong());
  }
  
  private Properties getOauthProperties(String token) {
    return getOauthProperties(token, getOauthTime(), getNonce());
  }
  
  /**
   * 
   * @param token
   * @param timestamp
   * @param nonce
   * @return Properties object containing the common oauth properties that are required for
   * all requests
   */
  private Properties getOauthProperties(String token, String timestamp, String nonce) {
    Properties oauthProperties = new Properties();
    
    oauthProperties.put("oauth_consumer_key", properties.consumerKey());
    oauthProperties.put("oauth_signature_method", "HMAC-SHA1");
    oauthProperties.put("oauth_token", token);
    oauthProperties.put("oauth_timestamp", timestamp);
    oauthProperties.put("oauth_nonce", nonce);
    oauthProperties.put("oauth_version", "1.0");
    
    return oauthProperties;
  }
  
  // @return A Map containing the response parameters.
  private HashMap<String, String> getRequestToken() throws IOException, SignatureCalculationException {
    Properties oauthProperties = getOauthProperties("");
    oauthProperties.setProperty("oauth_callback", "oob");
    
    return getToken(properties.requestTokenUrl(), oauthProperties, null);
  }
  
  // @return A Map containing the response parameters.
  HashMap<String, String> getAccessToken(String requestToken, String requestTokenSecret, String verifier) throws IOException, SignatureCalculationException {
    Properties oauthProperties = getOauthProperties(requestToken);
    oauthProperties.setProperty("oauth_callback", "oob");
    oauthProperties.setProperty("oauth_verifier", verifier);
    
    return getToken(properties.accessTokenUrl(), oauthProperties, requestTokenSecret);
  }
  
  HashMap<String, String> getToken(String requestUrl, Properties oauthProperties, String tokenSecret) throws IOException, SignatureCalculationException {    
    HttpURLConnection con = (HttpURLConnection) new URL(requestUrl).openConnection();
    con.setRequestMethod("POST");
    
    // Need content-length header to fix the following failure:
    //    HTTP/1.0 411 Length Required
    //    X-Squid-Error = ERR_INVALID_REQ 0
    con.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
    con.setRequestProperty("Content-Length", "0");
    con.setFixedLengthStreamingMode(0);
    con.setDoOutput(true);
    
    signRequest(con, oauthProperties, tokenSecret);
    
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
    
    HashMap<String, String> parameters = new HashMap<String, String>();
    try {
      parameters = parseParameters(con.getInputStream());
    }
    catch (ParseException pe) {
      throw new IOException(pe);
    }
    
    return parameters;
  }  
    
  private void signRequest(HttpURLConnection con, Properties oauthProperties, String tokenSecret) throws SignatureCalculationException {
    System.out.println("Signing request: " + con.getURL());
    
    if (tokenSecret == null) tokenSecret = "";
      
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
    String normalizedParameters = getNormalizedParameters(oauthProperties, urlParameters);    
    String signatureBaseString = getSignatureBaseString(method, normalizedUrl, normalizedParameters);
    
    oauthProperties.setProperty("oauth_signature",  getSignature(signatureBaseString, properties.consumerSecret(), tokenSecret));
    con.setRequestProperty("Authorization", getAuthorizationHeader(oauthProperties));
    //System.out.println("Request properties:");
    
    System.out.println("Added Authorization header: " + getAuthorizationHeader(oauthProperties));
    //for (String key : con.getRequestProperties().keySet()) {
    //  System.out.println(key + " = " + con.getRequestProperties().get(key));
    //}    
  }
  
  private String getAuthorizationHeader(Properties oauthProperties) {
    StringBuilder sb = new StringBuilder();
    
    for (Object o : oauthProperties.keySet()) {
      String k = (String) o;
      if (sb.length() == 0) {
        sb.append("OAuth ");    
      } else {
        sb.append(",");
      }
      sb.append(encodeParameter(k));
      sb.append("=\"");
      sb.append(encodeParameter(oauthProperties.getProperty(k)));
      sb.append("\"");
    }    
    return sb.toString();
  }
  
  public static HashMap<String, String> parseParameters(InputStream is) throws ParseException {
    HashMap<String, String> parameters = new HashMap<String, String>();
    DelimitedStringReader rdr = new DelimitedStringReader(new InputStreamReader(is));
    
    try {
      String key, value;
      do {
        key = rdr.next('=');
        value = rdr.next('&');
        
        if (key != null && value != null) {
          parameters.put(decodeParameter(key), decodeParameter(value));
        }
      } while (key != null && value != null);
    } catch (IOException ioe) {
      throw new ParseException(ioe.getLocalizedMessage(), rdr.bytesRead());
    } catch (DecoderException de) {
      throw new ParseException(de.getLocalizedMessage(), rdr.bytesRead());
    }
    return parameters;
  }
  
  static String getSignature(String signatureBaseString, String consumerSecret, String tokenSecret) throws SignatureCalculationException {
    return hmacsha1(signatureBaseString, encodeParameter(consumerSecret) + "&" + encodeParameter(tokenSecret));
  }
  
  static String hmacsha1(String text, String key) throws SignatureCalculationException {
    try {
      SecretKeySpec keySpec = new SecretKeySpec(key.getBytes("UTF-8"), "HmacSHA1");
      Mac mac = Mac.getInstance("HmacSHA1");
      mac.init(keySpec);
      byte[] bytes = mac.doFinal(text.getBytes("UTF-8"));
      return new String(Base64.encodeBase64(bytes));
    } catch (NoSuchAlgorithmException nsae) {
      throw new SignatureCalculationException();
    } catch (UnsupportedEncodingException uee) {
      throw new SignatureCalculationException();
    } catch (InvalidKeyException ike) {
      throw new SignatureCalculationException();
    }
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
  
  static String getNormalizedParameters(Properties oauthProperties, HashMap<String, String> parameters) {
    ArrayList<String[]> parameterArray = new ArrayList<String[]>();
    
    for(Object o : oauthProperties.keySet()) {
      String key = (String) o;
      if (key.equals("oauth_signature")) continue;
      if (key.equals("realm")) continue;
      
      String value = oauthProperties.getProperty(key);
      if (value == null) {
        value = "";
      }
      
      parameterArray.add(new String[] { encodeParameter(key), encodeParameter(value) });
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
