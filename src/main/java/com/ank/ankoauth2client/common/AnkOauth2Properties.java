package com.ank.ankoauth2client.common;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Data;

@Data
@ConfigurationProperties(prefix="ank.oauth2")
public class AnkOauth2Properties {

	/**
	 * JWT token generation related properties
	 */
	private Jwt jwt;

	/**
	 * Client web application's base URL. Used in the verification link mailed
	 * to the users, etc.
	 * can be configured in application.properties
	 */
	private String applicationUrl = "http://localhost:6001/";

	/**
	 * The default URL to redirect to after a user logs in using
	 * OAuth2/OpenIDConnect
	 * can be configured in application.properties
	 */
	private String oauth2AuthenticationSuccessUrl = "http://localhost:6001/social-login-success?token=";
	
	public static final String dummyVal = "DummyString";

	@Data
	public static class Jwt {

		/**
		 * Secret for signing JWT
		 */
		private String secret;

		/**
		 * Default expiration milliseconds
		 */
		private long expirationMillis = 864000000L; // 10 days

		/**
		 * Expiration milliseconds for short-lived tokens and cookies
		 */
		private int shortLivedMillis = 120000; // Two minutes
	}
}
