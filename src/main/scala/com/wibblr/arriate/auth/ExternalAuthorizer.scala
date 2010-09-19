package com.wibblr.arriate.auth

trait ExternalAuthorizer {
	def authorize(url: String): Boolean;
}