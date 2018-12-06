package com.ank.ankoauth2client.security;

import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;

public class AnkOidcUserService extends OidcUserService {

	private AnkOAuth2UserService ankOAuth2UserService;

	public AnkOidcUserService(AnkOAuth2UserService ankOAuth2UserService) {
		this.ankOAuth2UserService = ankOAuth2UserService;
	}

	@Override
	public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {

		OidcUser oidcUser = super.loadUser(userRequest);
		UserDetailsPrincipal userDetailsPrincipal = ankOAuth2UserService.buildUserDetailPrincipal(oidcUser,
				userRequest.getClientRegistration().getRegistrationId());
		userDetailsPrincipal.setClaims(oidcUser.getClaims());
		userDetailsPrincipal.setIdToken(oidcUser.getIdToken());
		userDetailsPrincipal.setUserInfo(oidcUser.getUserInfo());
		return userDetailsPrincipal;
	}
}
