package com.ank.ankoauth2client.service;

import java.text.ParseException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.stereotype.Component;

import com.ank.ankoauth2client.common.AnkOauth2Constant;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.KeyLengthException;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.DirectEncrypter;
import com.nimbusds.jose.jwk.source.ImmutableSecret;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.BadJOSEException;
import com.nimbusds.jose.proc.JWEDecryptionKeySelector;
import com.nimbusds.jose.proc.JWEKeySelector;
import com.nimbusds.jose.proc.SimpleSecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

/**
 * Service class for performing JSON Web Token related operations. <br>
 * JwtService is primarily used to create a short lived token once we receive
 * success response from SAS provider.
 */
@Component
public class JwtService {

	public static final Logger logger = LoggerFactory.getLogger(JwtService.class);

	private DirectEncrypter encrypter;
	private JWEHeader header = new JWEHeader(JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256);
	private ConfigurableJWTProcessor<SimpleSecurityContext> jwtProcessor;

	public JwtService(String secret) throws KeyLengthException {
		byte[] secretKey = secret.getBytes();
		encrypter = new DirectEncrypter(secretKey);
		jwtProcessor = new DefaultJWTProcessor<SimpleSecurityContext>();

		JWKSource<SimpleSecurityContext> jweKeySource = new ImmutableSecret<SimpleSecurityContext>(secretKey);

		/**
		 * Configure a key selector to handle the decryption phase
		 */
		JWEKeySelector<SimpleSecurityContext> jweKeySelector = new JWEDecryptionKeySelector<SimpleSecurityContext>(
				JWEAlgorithm.DIR, EncryptionMethod.A128CBC_HS256, jweKeySource);

		jwtProcessor.setJWEKeySelector(jweKeySelector);
	}

	public String createToken(String aud, String subject, Long expirationMillis, Map<String, Object> claimMap) {

		JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder();

		builder.expirationTime(new Date(System.currentTimeMillis() + expirationMillis)).audience(aud).subject(subject)
				.claim(AnkOauth2Constant.ANK_OAUTH2_IAT, System.currentTimeMillis());

		claimMap.forEach(builder::claim);
		JWTClaimsSet claims = builder.build();
		Payload payload = new Payload(claims.toJSONObject());
		JWEObject jweObject = new JWEObject(header, payload);
		try {
			jweObject.encrypt(encrypter);
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
		return jweObject.serialize();
	}

	public String createToken(String audience, String subject, Long expirationMillis) {
		return createToken(audience, subject, expirationMillis, new HashMap<>());
	}

	public JWTClaimsSet parseToken(String token, String audience) {
		JWTClaimsSet claims = parseToken(token);

		// validate claim for audience. follow below approach.
		// create message.properties file for the same
		// LecUtils.ensureCredentials(audience != null &&
		// claims.getAudience().contains(audience),
		// "com.ank.spring.wrong.audience");

		long expirationTime = claims.getExpirationTime().getTime();
		long currentTime = System.currentTimeMillis();

		logger.debug("Parsing JWT. Expiration time = " + expirationTime + ". Current time = " + currentTime);

		// validate credentials. follow same as in lemon
		// LecUtils.ensureCredentials(expirationTime >= currentTime,
		// "com.naturalprogrammer.spring.expiredToken");

		return claims;
	}

	/**
	 * Parses a token
	 */
	public JWTClaimsSet parseToken(String token) {
		try {
			return jwtProcessor.process(token, null);
		} catch (ParseException | BadJOSEException | JOSEException e) {
			throw new BadCredentialsException(e.getMessage());
		}
	}
}
