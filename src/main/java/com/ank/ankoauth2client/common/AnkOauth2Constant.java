package com.ank.ankoauth2client.common;

public class AnkOauth2Constant {

	public static final String TOKEN_PREFIX = "Bearer ";
	public static final int TOKEN_PREFIX_LENGTH = 7;
	public static final String TOKEN_RESPONSE_HEADER = "Ank-Oauth2-Authorization";

	/**
	 * JWT Service related constants
	 */
	public static final String ANK_OAUTH2_IAT = "ank-oauth2-iat";
	public static final String AUTH_AUDIENCE = "auth";
	public static final String USER_CLAIM = "user";

	/**
	 * Social Login Providers registration Id
	 */
	public static final String REGISTRATION_GOOGLE = "google";
	public static final String REGISTRATION_GITHUB = "github";
	public static final String REGISTRATION_FACEBOOK = "facebook";
	public static final String REGISTRATION_TWITTER = "twitter";
	public static final String REGISTRATION_LINKEDIN = "linkedin";

}
