package com.andre.awscognitoauth.dummytests.controllers;

import com.andre.awscognitoauth.security.UserPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class TestController {

    @GetMapping("/user/profile")
    public String getUserProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated() && 
            !(authentication.getPrincipal() instanceof String && "anonymousUser".equals(authentication.getPrincipal()))) {
            UserPrincipal userPrincipal = (UserPrincipal) authentication.getPrincipal();
            return "User profile for: " + userPrincipal.getUsername() + 
                   " (Email: " + userPrincipal.getEmail() + ")";
        }
        return "No authenticated user";
    }

    @GetMapping("/protected/test")
    public String protectedTest() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        return "This is a protected endpoint. Authenticated user: " + 
               authentication.getName();
    }
    
    @GetMapping("/")
    public String home() {
        return "Welcome to AWS Cognito OAuth Spring Boot! Authentication is now enabled.";
    }
}