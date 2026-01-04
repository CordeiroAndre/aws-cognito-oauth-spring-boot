package com.andre.awscognitoauth.auth.dto;

import lombok.Getter;

@Getter
public class SignInResultFailureDTO extends SignInResultDTO {

    private final String errorMessage;

    public SignInResultFailureDTO(String errorMessage) {
        super("SignIn.FailureMessage");
        this.errorMessage = errorMessage;
    }
}
