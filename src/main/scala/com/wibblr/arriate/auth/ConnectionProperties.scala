package com.wibblr.arriate.auth

case class ConnectionProperties(
  consumerKey: String,
  consumerSecret: String,
  requestTokenUrl: String,
  accessTokenUrl: String,
  authorizeUrl: String
)