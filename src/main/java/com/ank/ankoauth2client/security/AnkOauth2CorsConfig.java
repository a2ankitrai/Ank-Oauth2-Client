package com.ank.ankoauth2client.security;

import org.springframework.http.HttpHeaders;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import com.ank.ankoauth2client.common.AnkOauth2Constant;

import lombok.Data;

public class AnkOauth2CorsConfig implements WebMvcConfigurer {

	private Cors cors = new Cors();

	@Override
	public void addCorsMappings(CorsRegistry registry) {

		registry.addMapping("/**").allowedOrigins(cors.getAllowedOrigins()).allowedMethods(cors.getAllowedMethods())
				.allowedHeaders(cors.getAllowedHeaders()).exposedHeaders(cors.getExposedHeaders())
				.allowCredentials(true).maxAge(cors.getMaxAge());
	}

	@Data
	public static class Cors {

		/**
		 * Comma separated white-listed URLs for CORS. Should contain the applicationURL
		 * at the minimum. Not providing this property would disable CORS configuration.
		 */
		private String[] allowedOrigins = { "*" };

		/**
		 * Methods to be allowed, e.g. GET,POST,...
		 */
		private String[] allowedMethods = { "GET", "HEAD", "POST", "PUT", "DELETE", "TRACE", "OPTIONS", "PATCH" };

		/**
		 * Request headers to be allowed, e.g.
		 * content-type,accept,origin,x-requested-with,...
		 */
		private String[] allowedHeaders = { HttpHeaders.ACCEPT, HttpHeaders.ACCEPT_ENCODING,
				HttpHeaders.ACCEPT_LANGUAGE, HttpHeaders.CACHE_CONTROL, HttpHeaders.CONNECTION,
				HttpHeaders.CONTENT_LENGTH, HttpHeaders.CONTENT_TYPE, HttpHeaders.COOKIE, HttpHeaders.HOST,
				HttpHeaders.ORIGIN, HttpHeaders.PRAGMA, HttpHeaders.REFERER, HttpHeaders.USER_AGENT,
				HttpHeaders.AUTHORIZATION, "x-requested-with" };

		/**
		 * Response headers that you want to expose to the client JavaScript program.
		 * 
		 * <br>
		 * See <a href=
		 * "http://stackoverflow.com/questions/25673089/why-is-access-control-expose-headers-needed#answer-25673446">
		 * here</a> to know why this could be needed.
		 */
		private String[] exposedHeaders = { HttpHeaders.CACHE_CONTROL, HttpHeaders.CONNECTION, HttpHeaders.CONTENT_TYPE,
				HttpHeaders.DATE, HttpHeaders.EXPIRES, HttpHeaders.PRAGMA, HttpHeaders.SERVER, HttpHeaders.SET_COOKIE,
				AnkOauth2Constant.TOKEN_RESPONSE_HEADER, HttpHeaders.TRANSFER_ENCODING, "X-Content-Type-Options",
				"X-XSS-Protection", "X-Frame-Options", "X-Application-Context" };

		/**
		 * CORS <code>maxAge</code> long property
		 */
		private long maxAge = 3600L;

	}
}
