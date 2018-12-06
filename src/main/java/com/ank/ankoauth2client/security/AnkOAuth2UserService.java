package com.ank.ankoauth2client.security;

import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;

import com.ank.ankoauth2client.resource.UserDto;
import com.ank.ankoauth2client.service.AnkOauth2Service;

public abstract class AnkOAuth2UserService extends DefaultOAuth2UserService {

	@Autowired
	AnkOauth2Service ankOauth2Service;

	@Override
	public UserDetailsPrincipal loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
		OAuth2User oAuth2User = super.loadUser(userRequest);
		UserDetailsPrincipal userDetailPrincipal = buildUserDetailPrincipal(oAuth2User,
				userRequest.getClientRegistration().getRegistrationId());

		return userDetailPrincipal;
	}

	public UserDetailsPrincipal buildUserDetailPrincipal(OAuth2User oath2User, String registrationId) {
		UserDetailsPrincipal userDetailsPrincipal = null;

		Map<String, Object> attributes = oath2User.getAttributes();
		String email = ankOauth2Service.getOAuth2Email(attributes);
		try {
			userDetailsPrincipal = loadUserByEmail(email);
		} catch (UsernameNotFoundException unfe) {
			System.out.println("Username does not exist in the database");
			System.out.println("Creating a new one.");
		}

		if (userDetailsPrincipal == null) {
			UserDto userDto = new UserDto();
			ankOauth2Service.fillAdditionalFields(userDto, attributes, registrationId);

			userDto = registerNewOAuth2User(userDto);
			userDetailsPrincipal = new UserDetailsPrincipal(userDto);
			userDetailsPrincipal.setAttributes(attributes);

			// check for below validity
			userDetailsPrincipal.setName(oath2User.getName());
		}

		return userDetailsPrincipal;
	}

	/**
	 * Registering a new user in case does not exist. To be implemented in the
	 * child. The logic to register a new user and returned and registered UserDto
	 * object.
	 */
	public abstract UserDto registerNewOAuth2User(UserDto userDto);

	/**
	 * Load existing user by Email. The method will return a valid
	 * userDetailsPrincipal if the user has signed in before with the same social
	 * sign in provider. If the user is visiting for the first time it will return
	 * null.
	 */
	public abstract UserDetailsPrincipal loadUserByEmail(String email);

}
