package com.wibblr.arriate.auth

import java.io.File;
import java.io.FileInputStream;import java.io.FileOutputStream;
import java.util.Properties;

// Simple class for storing access token in ~/.arriate/access_token
class TokenStorage() {
	val tokenStorageDirectory: File = new File(System.getProperty("user.home"), ".arriate")
	val tokenStorageFile: File = new File(tokenStorageDirectory, "access_token")
	
	var token: String = null
	var tokenSecret: String = null
		
	try {
		val p = new Properties()
		p.load(new FileInputStream(tokenStorageFile));
		token = p.getProperty("token")
		tokenSecret = p.getProperty("token_secret")
	}
	catch {
		case e: Exception => Unit;
	}

	
	def getToken(): String = token
	def getTokenSecret(): String = tokenSecret
	
	def set(token: String, tokenSecret: String) = {
		this.token = token
		this.tokenSecret = tokenSecret
		
		if (this.token == null) this.token = "";
		if (this.tokenSecret == null) this.tokenSecret = "";
		
		if (tokenStorageFile.exists) {
			tokenStorageFile.delete()
		}
		if (!tokenStorageDirectory.exists()) {
			tokenStorageDirectory.mkdir()
		}
		tokenStorageFile.createNewFile()
		
		val p = new Properties
		p.setProperty("token", this.token)
		p.setProperty("token_secret", this.tokenSecret)
		p.store(new FileOutputStream(tokenStorageFile), "OAuth access tokens")
	}
}