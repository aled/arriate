package com.wibblr.arriate.auth

import java.io.File;
import java.io.FileInputStream;import java.io.FileOutputStream;
import java.util.Properties;

// Simple class for storing access token in ~/.arriate/access_tokens/providername
class TokenStorage(provider: String) {
	val tokenStorageDirectory: File = new File(System.getProperty("user.home"), ".arriate")
	val tokenStorageFile: File = new File(tokenStorageDirectory, provider)
	
	var token: String = ""
	var tokenSecret: String = ""
		
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
			tokenStorageDirectory.mkdirs()
		}
		tokenStorageFile.createNewFile()
		
		val p = new Properties
		p.setProperty("token", this.token)
		p.setProperty("token_secret", this.tokenSecret)
		p.store(new FileOutputStream(tokenStorageFile), "OAuth access tokens")
	}
}