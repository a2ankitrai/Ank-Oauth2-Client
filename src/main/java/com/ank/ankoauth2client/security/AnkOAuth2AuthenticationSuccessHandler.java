package com.ank.ankoauth2client.security;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import com.ank.ankoauth2client.common.AnkOauth2Constant;
import com.ank.ankoauth2client.common.AnkOauth2Properties;
import com.ank.ankoauth2client.resource.UserDto;
import com.ank.ankoauth2client.service.JwtService;
import com.ank.ankoauth2client.util.AnkOauth2Util;

public class AnkOAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

	@Autowired
	private AnkOauth2Properties properties;

	@Autowired
	private JwtService jwtService;

	@Override
	protected String determineTargetUrl(HttpServletRequest request, HttpServletResponse response) {

		UserDto currentUser = AnkOauth2Util.currentUser();

		String shortLivedAuthToken = jwtService.createToken(AnkOauth2Constant.AUTH_AUDIENCE, currentUser.getUserName(),
				(long) properties.getJwt().getShortLivedMillis());

		String targetUrl = AnkOauth2Util
				.fetchCookie(request,
						HttpCookieOAuth2AuthorizationRequestRepository.ANK_OAUTH2_REDIRECT_URI_COOKIE_PARAM_NAME)
				.map(Cookie::getValue).orElse(properties.getOauth2AuthenticationSuccessUrl());

		HttpCookieOAuth2AuthorizationRequestRepository.deleteCookies(request, response);

		return targetUrl + shortLivedAuthToken;
	}

}
