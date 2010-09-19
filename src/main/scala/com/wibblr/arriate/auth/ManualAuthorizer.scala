package com.wibblr.arriate.auth

class ManualAuthorizer extends ExternalAuthorizer {
	def authorize(url: String): Boolean = {
		System.out.println("Authorization required: please visit the following URL, then press any key to continue (or ctrl-c to cancel).");
		System.out.println(url);
		
		val i = System.in.read();
		System.out.println(i);
		
		return true;
	}		
}