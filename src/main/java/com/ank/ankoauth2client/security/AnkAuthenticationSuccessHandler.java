package com.ank.ankoauth2client.security;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import com.ank.ankoauth2client.common.AnkOauth2Properties;
import com.ank.ankoauth2client.resource.UserDto;
import com.ank.ankoauth2client.service.AnkOauth2Service;
import com.ank.ankoauth2client.util.AnkOauth2Util;
import com.fasterxml.jackson.databind.ObjectMapper;

public class AnkAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

	private ObjectMapper objectMapper;
	private AnkOauth2Service ankOauth2Service;
	private long defaultExpirationMillis;

	public AnkAuthenticationSuccessHandler(ObjectMapper objectMapper, AnkOauth2Service ankOauth2Service,
			AnkOauth2Properties properties) {

		this.objectMapper = objectMapper;
		this.ankOauth2Service = ankOauth2Service;
		this.defaultExpirationMillis = properties.getJwt().getExpirationMillis();
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

		response.setStatus(HttpServletResponse.SC_OK);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);

		String expirationMillisStr = request.getParameter("expirationMillis");
		long expirationMillis = expirationMillisStr == null ? defaultExpirationMillis
				: Long.valueOf(expirationMillisStr);

		UserDto currentUser = AnkOauth2Util.currentUser();
		ankOauth2Service.addAuthHeader(response, currentUser.getUserName(), expirationMillis);

		// write current-user data to the response
		response.getOutputStream().print(objectMapper.writeValueAsString(currentUser));

		// as done in the base class
		clearAuthenticationAttributes(request);

	}

}
