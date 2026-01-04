package com.andre.awscognitoauth.auth.controllers;

import com.andre.awscognitoauth.auth.service.AuthService;
import com.andre.awscognitoauth.auth.dto.SignInResultDTO;
import com.andre.awscognitoauth.auth.dto.SignInResultFailureDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class AuthController {

    private final Logger logger;
    final AuthService authService;

    public AuthController(AuthService authService) {
        logger = LoggerFactory.getLogger(AuthController.class);
        this.authService = authService;
    }

    @PostMapping("/public/signUp")
    public ResponseEntity<String> signUp(@RequestParam String email, @RequestParam String password) {
        logger.info("Sign up request received for email: {}", email);
        try {
            authService.signUp(email, password);
            logger.info("Successfully created new user for email: {}", email);
            return ResponseEntity.ok().body("Successfully created new user!");
        } catch (Exception e) {
            logger.error("Error during sign up for email: {}", email, e);
            return ResponseEntity.badRequest().body("Error creating user: " + e.getMessage());
        }
    }

    @PutMapping("/public/confirmSignup")
    public ResponseEntity<String> confirmSignup(@RequestParam String email, @RequestParam String code) {
        logger.info("Confirm sign up request received for email: {}", email);
        try {
            authService.confirmSignUp(code, email);
            logger.info("Successfully confirmed sign up code for email: {}", email);
            return ResponseEntity.ok().body("Successfully confirmed sign up code for user");
        } catch (Exception e) {
            logger.error("Error confirming sign up for email: {}", email, e);
            return ResponseEntity.badRequest().body("Error confirming signup for email: " + email);
        }
    }

    @PutMapping("/public/resendConfirmationCode")
    public ResponseEntity<String> resendConfirmationCode(@RequestParam String email)
    {
        logger.info("Resend confirmation code request received for email: {}", email);
        try {
            authService.resendConfirmationCode(email);
            logger.info("Successfully resent sign up code for email: {}", email);
            return ResponseEntity.ok().body("Successfully resent sign up code for user");
        } catch (Exception e) {
            logger.error("Error resending confirmation code for email: {}", email, e);
            return ResponseEntity.badRequest().body("Error resending signup code for email: " + email);
        }
    }

    @PostMapping("/public/signIn")
    public ResponseEntity<SignInResultDTO> signIn(@RequestParam String email, @RequestParam String password) {
        logger.info("Sign in request received for email: {}", email);
        try {
            var authResult = authService.signIn(email, password);
            logger.info("Successfully signed in user: {}", email);
            return ResponseEntity.ok().body(authResult);
        } catch (Exception e) {
            logger.error("Error signing user in: email={}", email, e);
            SignInResultFailureDTO signInResultFailureDTO = new SignInResultFailureDTO(e.getMessage());
            return ResponseEntity.badRequest().body(signInResultFailureDTO);
        }
    }


}
