package com.ank.ankoauth2client.util;

import java.io.Serializable;
import java.util.Base64;
import java.util.Optional;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.util.SerializationUtils;

import com.ank.ankoauth2client.common.AnkOauth2Constant;
import com.ank.ankoauth2client.resource.UserDto;
import com.ank.ankoauth2client.security.UserDetailsPrincipal;
import com.nimbusds.jwt.JWTClaimsSet;

public class AnkOauth2Util {

	public static final Logger logger = LoggerFactory.getLogger(AnkOauth2Util.class);

	/**
	 * Fetches a cookie from the request
	 */
	public static Optional<Cookie> fetchCookie(HttpServletRequest request, String name) {

		Cookie[] cookies = request.getCookies();

		if (cookies != null && cookies.length > 0)
			for (int i = 0; i < cookies.length; i++)
				if (cookies[i].getName().equals(name))
					return Optional.of(cookies[i]);

		return Optional.empty();
	}

	/**
	 * Utility for deleting related cookies
	 */
	public static void deleteCookies(HttpServletRequest request, HttpServletResponse response, String name) {

		Cookie[] cookies = request.getCookies();

		if (cookies != null && cookies.length > 0)
			for (int i = 0; i < cookies.length; i++)
				if (cookies[i].getName().equals(name)) {

					cookies[i].setValue("");
					cookies[i].setPath("/");
					cookies[i].setMaxAge(0);
					response.addCookie(cookies[i]);
				}
	}

	/**
	 * Serializes an object
	 */
	public static String serialize(Serializable obj) {

		return Base64.getUrlEncoder().encodeToString(SerializationUtils.serialize(obj));
	}

	/**
	 * Deserializes an object
	 */
	@SuppressWarnings("unchecked")
	public static <T> T deserialize(String serializedObj) {

		return (T) SerializationUtils.deserialize(Base64.getUrlDecoder().decode(serializedObj));
	}

	/**
	 * Gets the current-user
	 */
	public static UserDto currentUser() {

		Optional<Authentication> authentication = Optional
				.ofNullable(SecurityContextHolder.getContext().getAuthentication());
		UserDto userDto = null;

		userDto = authentication.map(auth -> {
			Object principal = auth.getPrincipal();
			if (principal instanceof UserDetailsPrincipal) {
				return ((UserDetailsPrincipal) principal).getUserDto();
			} else {
				OAuth2User user = ((OAuth2AuthenticationToken) auth).getPrincipal();
				logger.debug("" + user);
				// Create a userDto from OAuth2User. Check if this is required..
				return null;
			}
		}).orElse(null);

		return userDto;
	}

	public static UserDto getUserDtoFromClaims(JWTClaimsSet claims) {

		Object userClaim = claims.getClaim(AnkOauth2Constant.USER_CLAIM);

		if (userClaim == null)
			return null;

		return deserialize((String) userClaim);
	}

	/**
	 * Throws BadCredentialsException if not valid
	 * 
	 * @param valid
	 * @param messageKey
	 */
//	public static void ensureCredentials(boolean valid, String messageKey) {
//
//		if (!valid)
//			throw new BadCredentialsException(messageKey);
////			throw new BadCredentialsException(LexUtils.getMessage(messageKey));
//	}
}
