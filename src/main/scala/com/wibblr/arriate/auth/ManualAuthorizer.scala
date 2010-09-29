package com.wibblr.arriate.auth
import java.io.BufferedReader;
import java.io.InputStreamReader;

class ManualAuthorizer extends ExternalAuthorizer {
	def authorize(url: String): String = {
		System.out.println("Authorization required: please visit the following URL, then enter the verification code to continue (or an empty line to cancel).");
		System.out.println(url);
		
		return new BufferedReader(new InputStreamReader(System.in)).readLine();
	}		
}