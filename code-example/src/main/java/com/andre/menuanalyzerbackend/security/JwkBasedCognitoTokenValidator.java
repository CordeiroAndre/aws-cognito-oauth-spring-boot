package com.andre.awscognitoauth.security;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.jwk.source.RemoteJWKSet;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import jakarta.annotation.PostConstruct;
import java.net.MalformedURLException;
import java.net.URL;
import java.text.ParseException;

@Slf4j
@Component
public class JwkBasedCognitoTokenValidator {

    @Value("${aws.cognito.region}")
    private String region;

    @Value("${aws.cognito.userPoolId}")
    private String userPoolId;

    @Value("${aws.cognito.clientId}")
    private String clientId;

    private ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    @PostConstruct
    public void initializeJwtProcessor() throws MalformedURLException {
        String jwkUrl = String.format(
                "https://cognito-idp.%s.amazonaws.com/%s/.well-known/jwks.json",
                region,
                userPoolId
        );

        log.info("Initializing JWT processor with JWK URL: {}", jwkUrl);

        try {
            // Create the RemoteJWKSet with the URL
            JWKSource<SecurityContext> keySource = new RemoteJWKSet<>(new URL(jwkUrl));
            JWSAlgorithm expectedJWSAlg = JWSAlgorithm.RS256;
            JWSKeySelector<SecurityContext> keySelector = new JWSVerificationKeySelector<>(expectedJWSAlg, keySource);
            jwtProcessor = new DefaultJWTProcessor<>();
            jwtProcessor.setJWSKeySelector(keySelector);
        } catch (Exception e) {
            log.error("Failed to initialize JWT processor with URL: {}", jwkUrl, e);
            throw new RuntimeException("Failed to initialize JWT processor", e);
        }
    }

    public JWTClaimsSet validateToken(String token) throws ParseException {
        try {
            SecurityContext securityContext = null;
            JWTClaimsSet jwtClaimsSet = jwtProcessor.process(token, securityContext);

            // Validate audience for access tokens or token_use for ID tokens
            if (!validateAudienceOrClientId(jwtClaimsSet)) {
                throw new IllegalArgumentException("Invalid audience or client ID in token");
            }

            // Validate token issuer
            if (!validateIssuer(jwtClaimsSet)) {
                throw new IllegalArgumentException("Invalid issuer in token");
            }

            log.debug("Token validated successfully for subject: {}", jwtClaimsSet.getSubject());
            return jwtClaimsSet;
        } catch (Exception e) {
            log.error("Token validation failed", e);
            throw new IllegalArgumentException("Invalid token", e);
        }
    }

    private boolean validateAudienceOrClientId(JWTClaimsSet claimsSet) {
        String clientIdClaim = (String) claimsSet.getClaim("client_id");
        if (clientIdClaim != null) {
            return clientId.equals(clientIdClaim);
        }
        Object audience = claimsSet.getAudience().get(0);
        return clientId.equals(audience);
    }

    private boolean validateIssuer(JWTClaimsSet claimsSet) {
        String issuer = claimsSet.getIssuer();
        String expectedIssuer = String.format("https://cognito-idp.%s.amazonaws.com/%s", region, userPoolId);
        return expectedIssuer.equals(issuer);
    }
}