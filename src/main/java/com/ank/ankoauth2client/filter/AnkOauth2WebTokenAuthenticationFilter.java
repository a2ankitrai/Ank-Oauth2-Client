package com.ank.ankoauth2client.filter;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.ank.ankoauth2client.common.AnkOauth2Constant;
import com.ank.ankoauth2client.resource.UserDto;
import com.ank.ankoauth2client.security.UserDetailsPrincipal;
import com.ank.ankoauth2client.service.JwtService;
import com.ank.ankoauth2client.util.AnkOauth2Util;
import com.nimbusds.jwt.JWTClaimsSet;

@Component
public abstract class AnkOauth2WebTokenAuthenticationFilter extends OncePerRequestFilter {

	public static final Logger logger = LoggerFactory.getLogger(AnkOauth2WebTokenAuthenticationFilter.class);

	@Autowired
	private JwtService jwtService;

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String header = request.getHeader(HttpHeaders.AUTHORIZATION);

		if (header != null && header.startsWith(AnkOauth2Constant.TOKEN_PREFIX)) {

			String token = header.substring(7);
			try {
				Authentication auth = createAuthToken(token);

				try {
					System.out.println(SecurityContextHolder.getContext().getAuthentication().getPrincipal());
				} catch (Exception e) {
					logger.error("principal not exist - " + e.getMessage());
				}

				SecurityContextHolder.getContext().setAuthentication(auth);
				logger.debug("Token authentication successful");

			} catch (Exception e) {
				logger.error("Token authentication failed -" + e.getMessage());
				response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Authentication Failed: " + e.getMessage());

				return;
			}
		} else {
			logger.debug("Token authentication skipped");
		}
		filterChain.doFilter(request, response);
	}

	protected Authentication createAuthToken(String token) {
		JWTClaimsSet claims = jwtService.parseToken(token, AnkOauth2Constant.AUTH_AUDIENCE);

		UserDto userDto = AnkOauth2Util.getUserDtoFromClaims(claims);

		userDto = userDto == null ? fetchUserDto(claims.getSubject()) : userDto;

		UserDetailsPrincipal userDetailsPrincipal = new UserDetailsPrincipal(userDto);

		return new UsernamePasswordAuthenticationToken(userDetailsPrincipal, token,
				userDetailsPrincipal.getAuthorities());
	}

	protected abstract UserDto fetchUserDto(String userName);

}
