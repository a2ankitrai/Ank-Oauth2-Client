package com.ank.ankoauth2client.service;

import static com.ank.ankoauth2client.common.AnkOauth2Constant.REGISTRATION_GITHUB;
import static com.ank.ankoauth2client.common.AnkOauth2Constant.REGISTRATION_GOOGLE;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

import com.ank.ankoauth2client.common.AnkOauth2Constant;
import com.ank.ankoauth2client.common.AnkOauth2Properties;
import com.ank.ankoauth2client.common.GithubAttributes;
import com.ank.ankoauth2client.resource.AuthType;
import com.ank.ankoauth2client.resource.UserDto;
import com.ank.ankoauth2client.util.AnkOauth2Util;

public class AnkOauth2Service {

	@Autowired
	private AnkOauth2Properties properties;

	@Autowired
	private JwtService jwtService;

	@Autowired
	public void createNsService(AnkOauth2Properties properties, JwtService jwtService) {
		this.properties = properties;
		this.jwtService = jwtService;
	}

	public void fillAdditionalFields(UserDto user, Map<String, Object> attributes, String registrationId) {

		switch (registrationId) {

		case REGISTRATION_GOOGLE:
			user.setName((String) attributes.get(StandardClaimNames.NAME));
			user.setProfilePicture((String) attributes.get(StandardClaimNames.PICTURE));
			user.setFirstName((String) attributes.get(StandardClaimNames.GIVEN_NAME));
			user.setLastName((String) attributes.get(StandardClaimNames.FAMILY_NAME));
			user.setEmail((String) attributes.get(StandardClaimNames.EMAIL));
			user.setUserName((String) attributes.get(StandardClaimNames.EMAIL));
			user.setAuthType(AuthType.GOOGLE);
			break;

		case REGISTRATION_GITHUB:
			user.setUserName((String) attributes.get(GithubAttributes.LOGIN));
			user.setName((String) attributes.get(GithubAttributes.NAME));
			user.setProfilePicture((String) attributes.get(GithubAttributes.AVATAR_URL));
			user.setEmail((String) attributes.get(GithubAttributes.EMAIL));
			user.setAuthType(AuthType.GITHUB);
			break;

		default:
			throw new UnsupportedOperationException("Fetching name from " + registrationId + " login not supported");
		}

		user.setProviderName(registrationId);

	}

	/**
	 * Extracts the email id from user attributes received from OAuth2 provider,
	 * e.g. Google
	 * 
	 */
	public String getOAuth2Email(Map<String, Object> attributes) {

		return (String) attributes.get(StandardClaimNames.EMAIL);
	}

	public Map<String, Object> getContext(Optional<Long> expirationMillis, HttpServletResponse response) {

		UserDto currentUser = AnkOauth2Util.currentUser();
		if (currentUser != null) {
			addAuthHeader(response, currentUser.getUserName(),
					expirationMillis.orElse(properties.getJwt().getExpirationMillis()));
		}

		Map<String, Object> contextMap = new HashMap<>();
		contextMap.put("user", currentUser);

		return contextMap;
	}

	public UserDto getCurrentUser(HttpServletResponse response) {
		UserDto currentUser = AnkOauth2Util.currentUser();
		if (currentUser != null) {
			addAuthHeader(response, currentUser.getUserName(), properties.getJwt().getExpirationMillis());
		}
		return currentUser;
	}

	public void addAuthHeader(HttpServletResponse response, String username, Long expirationMillis) {
		response.addHeader(AnkOauth2Constant.TOKEN_RESPONSE_HEADER, AnkOauth2Constant.TOKEN_PREFIX
				+ jwtService.createToken(AnkOauth2Constant.AUTH_AUDIENCE, username, expirationMillis));
	}

}
