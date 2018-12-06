package com.ank.ankoauth2client.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import com.ank.ankoauth2client.common.AnkOauth2Properties;
import com.ank.ankoauth2client.security.AnkAuthenticationSuccessHandler;
import com.ank.ankoauth2client.security.AnkOAuth2AuthenticationFailureHandler;
import com.ank.ankoauth2client.security.AnkOAuth2AuthenticationSuccessHandler;
import com.ank.ankoauth2client.security.AnkOauth2CorsConfig;
import com.ank.ankoauth2client.security.AnkOauth2SecurityConfiguration;
import com.ank.ankoauth2client.service.AnkOauth2Service;
import com.ank.ankoauth2client.service.JwtService;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.KeyLengthException;

@Configuration
public class AnkOauth2BeansConfiguration {

	@Bean
	public AnkOauth2Properties ankOauth2Properties() {
		return new AnkOauth2Properties();
	}

	@Bean
	@ConditionalOnMissingBean(JwtService.class)
	public JwtService jwtService(AnkOauth2Properties properties) throws KeyLengthException {
		return new JwtService(properties.getJwt().getSecret());
	}

	@Bean
	@ConditionalOnMissingBean(AnkOauth2Service.class)
	public AnkOauth2Service ankOauth2Service() {
		return new AnkOauth2Service();
	}

	@Bean
	@ConditionalOnMissingBean(AnkAuthenticationSuccessHandler.class)
	public AnkAuthenticationSuccessHandler authenticationSuccessHandler(ObjectMapper objectMapper,
			AnkOauth2Service ankOauth2Service, AnkOauth2Properties properties) {
		return new AnkAuthenticationSuccessHandler(objectMapper, ankOauth2Service, properties);
	}

	@Bean
	@ConditionalOnMissingBean(AuthenticationFailureHandler.class)
	public AuthenticationFailureHandler authenticationFailureHandler() {
		return new SimpleUrlAuthenticationFailureHandler();
	}

	@Bean
	@ConditionalOnMissingBean(AnkOAuth2AuthenticationSuccessHandler.class)
	public AnkOAuth2AuthenticationSuccessHandler oauth2AuthenticationSuccessHandler() {
		return new AnkOAuth2AuthenticationSuccessHandler();
	}

	@Bean
	@ConditionalOnMissingBean(AnkOAuth2AuthenticationFailureHandler.class)
	public AnkOAuth2AuthenticationFailureHandler oauth2AuthenticationFailureHandler() {
		return new AnkOAuth2AuthenticationFailureHandler();
	}

	@Bean
	@ConditionalOnMissingBean(AnkOauth2CorsConfig.class)
	public AnkOauth2CorsConfig ankOauth2CorsConfig() {
		return new AnkOauth2CorsConfig();
	}

	@Bean
	public AnkOauth2SecurityConfiguration ankOauth2SecurityConfiguration() {
		return new AnkOauth2SecurityConfiguration();
	}

}
