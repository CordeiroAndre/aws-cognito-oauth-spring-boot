package com.andre.awscognitoauth.auth.service;

import com.andre.awscognitoauth.auth.dto.SignInResultDTO;
import com.andre.awscognitoauth.auth.dto.SignInResultSuccessDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import jakarta.annotation.PostConstruct;
import java.util.Map;

@Service
public class AuthService {

    @Value("${aws.accesskeyid}")
    private String accessKeyId;

    @Value("${aws.accesskeysecret}")
    private String accessKeySecret;

    @Value("${aws.cognito.region}")
    private Region region;

    @Value("${aws.cognito.clientId}")
    private String appClient;

    private CognitoIdentityProviderClient cognitoClient;
    private final Logger logger = LoggerFactory.getLogger(AuthService.class);

    @PostConstruct
    public void init() {
        if (accessKeyId == null || accessKeySecret == null || region == null || appClient == null) {
            throw new IllegalStateException("AWS configuration properties not properly loaded. Please check your application.properties/application.yml file.");
        }

        cognitoClient = CognitoIdentityProviderClient.builder()
                .region(region)
                .credentialsProvider(() -> AwsBasicCredentials.create(accessKeyId, accessKeySecret))
                .build();
    }

    public SignUpResponse signUp(String email, String password) {
        logger.info("Initiating sign up for email: {}", email);
        try {
            AttributeType emailAttribute = AttributeType.builder()
                    .name("email")
                    .value(email)
                    .build();

            SignUpRequest signUpRequest = SignUpRequest.builder()
                    .clientId(appClient)
                    .username(email)
                    .password(password)
                    .userAttributes(emailAttribute)
                    .build();

            SignUpResponse response = cognitoClient.signUp(signUpRequest);
            logger.info("Successfully initiated sign up for email: {}", email);
            return response;
        } catch (Exception e) {
            logger.error("Error during sign up for email: {}", email, e);
            throw e;
        }
    }

    public void confirmSignUp(String code, String username){
        logger.info("Initiating sign up confirmation for user: {}", username);
        try {
            ConfirmSignUpRequest confirmSignUpRequest = ConfirmSignUpRequest.builder()
                    .clientId(appClient)
                    .username(username)
                    .confirmationCode(code)
                    .build();

            cognitoClient.confirmSignUp(confirmSignUpRequest);
            logger.info("Successfully confirmed sign up for user: {}", username);
        } catch (Exception e) {
            logger.error("Error confirming sign up for user: {}", username, e);
            throw e;
        }
    }

    public void resendConfirmationCode(String email){
        logger.info("Initiating resend confirmation code for email: {}", email);
        try {
            ResendConfirmationCodeRequest resendConfirmationCodeRequest = ResendConfirmationCodeRequest.builder()
                    .clientId(appClient)
                    .username(email)
                    .build();

            cognitoClient.resendConfirmationCode(resendConfirmationCodeRequest);
            logger.info("Successfully resent confirmation code for email: {}", email);
        } catch (Exception e) {
            logger.error("Error resending confirmation code for email: {}", email, e);
            throw e;
        }
    }

    public SignInResultDTO signIn(String email, String password){
        logger.info("Initiating sign in for email: {}", email);
        try {
            InitiateAuthRequest initiateAuthRequest = InitiateAuthRequest.builder()
                    .clientId(appClient)
                    .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
                    .authParameters(Map.of("USERNAME", email, "PASSWORD", password))
                    .build();
            var authResult =  new SignInResultSuccessDTO(cognitoClient.initiateAuth(initiateAuthRequest).authenticationResult());
            logger.info("Successfully initiated sign in for email: {}", email);
            return authResult;
        } catch (Exception e) {
            logger.error("Error during sign in for email: {}", email, e);
            throw e;
        }
    }
}
