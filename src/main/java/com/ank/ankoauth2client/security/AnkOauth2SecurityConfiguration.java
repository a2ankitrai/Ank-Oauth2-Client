package com.ank.ankoauth2client.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.ank.ankoauth2client.common.AnkOauth2Properties;
import com.ank.ankoauth2client.filter.AnkOauth2WebTokenAuthenticationFilter;

public class AnkOauth2SecurityConfiguration {

	@Autowired
	private AnkOauth2Properties properties;
	@Autowired
	private AnkAuthenticationSuccessHandler authenticationSuccessHandler;
	@Autowired
	private AuthenticationFailureHandler authenticationFailureHandler;
	@Autowired
	private AnkOAuth2AuthenticationSuccessHandler oauth2AuthenticationSuccessHandler;
	@Autowired
	private AnkOAuth2AuthenticationFailureHandler oauth2AuthenticationFailureHandler;

	private AnkOAuth2UserService oauth2UserService;

	private AnkOidcUserService oidcUserService;

	public void configure(HttpSecurity http, AnkOauth2WebTokenAuthenticationFilter webTokenAuthenticationFilter,
			AnkOAuth2UserService oauth2UserService) throws Exception {

		this.oauth2UserService = oauth2UserService;
		this.oidcUserService = new AnkOidcUserService(oauth2UserService);

		exceptionHandling(http); // exception handling

		tokenAuthentication(http, webTokenAuthenticationFilter); // configure token authentication filter

		login(http);

		oauth2Client(http);
	}

	/**
	 * Configures exception-handling: To prevent redirection to the login page when
	 * someone tries to access a restricted page
	 */
	protected void exceptionHandling(HttpSecurity http) throws Exception {

		http.exceptionHandling().authenticationEntryPoint(new Http403ForbiddenEntryPoint());
	}

	/**
	 * Configuring token authentication filter
	 */
	protected void tokenAuthentication(HttpSecurity http,
			AnkOauth2WebTokenAuthenticationFilter webTokenAuthenticationFilter) throws Exception {

		http.addFilterBefore(webTokenAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
	}

	/**
	 * Configuring authentication.
	 */
	protected void login(HttpSecurity http) throws Exception {

		http.formLogin() // form login

				// login page commented
				// .loginPage(loginPage())

				// .defaultSuccessUrl("/", true)

				/******************************************
				 * Setting a successUrl would redirect the user there. Instead, let's send 200
				 * and the userDto along with an Authorization token.
				 *****************************************/
				.successHandler(authenticationSuccessHandler)

				/*******************************************
				 * Setting the failureUrl will redirect the user to that url if login fails.
				 * Instead, we need to send 401. So, let's set failureHandler instead.
				 *******************************************/
				.failureHandler(authenticationFailureHandler);
	}

	protected void oauth2Client(HttpSecurity http) throws Exception {

		System.out.println("properties inside AnkOauth2SecurityConfiguration: oauth2Client" + properties);

		http.oauth2Login().authorizationEndpoint()
				.authorizationRequestRepository(new HttpCookieOAuth2AuthorizationRequestRepository(properties)).and()
				.successHandler(oauth2AuthenticationSuccessHandler).failureHandler(oauth2AuthenticationFailureHandler)
				.userInfoEndpoint().oidcUserService(oidcUserService).userService(oauth2UserService);
	}

}
