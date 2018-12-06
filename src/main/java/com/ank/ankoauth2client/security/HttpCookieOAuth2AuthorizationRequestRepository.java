package com.ank.ankoauth2client.security;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.util.Assert;

import com.ank.ankoauth2client.common.AnkOauth2Properties;
import com.ank.ankoauth2client.util.AnkOauth2Util;

public class HttpCookieOAuth2AuthorizationRequestRepository
		implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

	private static final String AUTHORIZATION_REQUEST_COOKIE_NAME = "ank_oauth2_authorization_request";
	public static final String ANK_OAUTH2_REDIRECT_URI_COOKIE_PARAM_NAME = "ank_oauth2_redirect_uri";
	public static final String DUMMY_STRING = AnkOauth2Properties.dummyVal;

	private int cookieExpirySecs;

	public HttpCookieOAuth2AuthorizationRequestRepository(AnkOauth2Properties ankOauth2Properties) {
		cookieExpirySecs = ankOauth2Properties.getJwt().getShortLivedMillis() / 1000;
	}

	@Override
	public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
		Assert.notNull(request, "request cannot be null");

		return AnkOauth2Util.fetchCookie(request, AUTHORIZATION_REQUEST_COOKIE_NAME).map(this::deserialize)
				.orElse(null);
	}

	@Override
	public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request,
			HttpServletResponse response) {
		Assert.notNull(request, "request cannot be null");
		Assert.notNull(response, "response cannot be null");

		if (authorizationRequest == null) {

			deleteCookies(request, response);
			return;
		}

		Cookie cookie = new Cookie(AUTHORIZATION_REQUEST_COOKIE_NAME, AnkOauth2Util.serialize(authorizationRequest));
		cookie.setPath("/");
		cookie.setHttpOnly(true);
		cookie.setMaxAge(cookieExpirySecs);
		response.addCookie(cookie);

		String ankOauth2RedirectUri = request.getParameter(ANK_OAUTH2_REDIRECT_URI_COOKIE_PARAM_NAME);
		if (StringUtils.isNotBlank(ankOauth2RedirectUri)) {

			cookie = new Cookie(ANK_OAUTH2_REDIRECT_URI_COOKIE_PARAM_NAME, ankOauth2RedirectUri);
			cookie.setPath("/");
			cookie.setHttpOnly(true);
			cookie.setMaxAge(cookieExpirySecs);
			response.addCookie(cookie);
		}
	}

	@Override
	public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request) {
		OAuth2AuthorizationRequest oauthRequest = loadAuthorizationRequest(request);
		return oauthRequest;
	}

	private OAuth2AuthorizationRequest deserialize(Cookie cookie) {
		return AnkOauth2Util.deserialize(cookie.getValue());
	}

	public static void deleteCookies(HttpServletRequest request, HttpServletResponse response) {
		AnkOauth2Util.deleteCookies(request, response, AUTHORIZATION_REQUEST_COOKIE_NAME);
		AnkOauth2Util.deleteCookies(request, response, ANK_OAUTH2_REDIRECT_URI_COOKIE_PARAM_NAME);
	}

}
