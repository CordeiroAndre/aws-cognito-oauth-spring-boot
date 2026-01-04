package com.andre.awscognitoauth.auth.dto;

import lombok.Getter;

@Getter
public class SignInResultDTO {

    private final String message;

    public SignInResultDTO(String message) {
        this.message = message;
    }
}
