package com.wibblr.arriate.osm.api06;import java.io.InputStream;
import java.net.URL;import java.net.HttpURLConnection;import com.wibblr.arriate.osm.OsmApiException;import com.wibblr.arriate.auth.OAuth10;
class Api06(provider: String, oauth: OAuth10) {		val scheme = "http"
	val pathPrefix = "/api/0.6"
	
	def callGetMethod(path: String): InputStream = {
		val url = new URL(scheme + "://" + provider + pathPrefix + path)
		val con = url.openConnection().asInstanceOf[HttpURLConnection]
		con.setRequestMethod("GET")
		
		if (!oauth.isAuthorized()) {
			oauth.authorize()
		}
		
		oauth.signRequest(con);		var responseCode = con.getResponseCode();				if (responseCode != 200) {			throw new OsmApiException();		};					return con.getInputStream();
	}
		def getUserDetails(): UserDetails = {
		UserDetails.deserialize(callGetMethod("/user/details"));  
	}

}