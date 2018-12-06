package com.ank.ankoauth2client.security;

import java.util.Map;

import org.springframework.security.core.CredentialsContainer;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import lombok.Data;

@Data
public abstract class AnkOauth2User implements CredentialsContainer, OidcUser, OAuth2User {

	private Map<String, Object> attributes;
	private Map<String, Object> claims;

	private OidcUserInfo userInfo;
	private OidcIdToken idToken;

//	private String name;

	@Override
	public void eraseCredentials() {

		attributes = null;
		claims = null;
		userInfo = null;
		idToken = null;
	}
}
