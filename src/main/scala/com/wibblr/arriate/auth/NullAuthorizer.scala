package com.wibblr.arriate.auth

/**
 * Authoriser class that does nothing. Use for providers
 * that give out pre-authorized tokens (for testing only) *
 */
class NullAuthorizer extends ExternalAuthorizer {
	def authorize(url: String): String = "[no verification code]"
}