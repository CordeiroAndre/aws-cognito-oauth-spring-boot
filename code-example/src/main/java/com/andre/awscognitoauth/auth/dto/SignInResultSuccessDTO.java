package com.andre.awscognitoauth.auth.dto;

import lombok.Getter;
import software.amazon.awssdk.services.cognitoidentityprovider.model.AuthenticationResultType;

@Getter
public class SignInResultSuccessDTO extends SignInResultDTO {

    private final String accessToken;
    private final Integer expiresIn;
    private final String tokenType;
    private final String refreshToken;
    private final String idToken;

    public SignInResultSuccessDTO(String accessToken, Integer expiresIn, String tokenType, String refreshToken, String idToken) {
        super("SignIn.SuccessMessage");
        this.accessToken = accessToken;
        this.expiresIn = expiresIn;
        this.tokenType = tokenType;
        this.refreshToken = refreshToken;
        this.idToken = idToken;
    }

    public SignInResultSuccessDTO(AuthenticationResultType authenticationResult) {
        super("SignIn.SuccessMessage");
        accessToken = authenticationResult.accessToken();
        expiresIn = authenticationResult.expiresIn();
        tokenType = authenticationResult.tokenType();
        refreshToken = authenticationResult.refreshToken();
        idToken = authenticationResult.idToken();
    }
}
