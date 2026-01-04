# AWS Cognito + OAuth + Spring Boot

This project is a study of OAuth + AWS Cognito + Spring Boot.

## Introduction

### Why user authentication?

Applications need to log users in:

1. **User login is a complex subsystem of the application:**
   - Security
   - Store, retrieve and validate credentials
   - 2FA (Two-Factor Authentication)
   - Password recovery
   - Other functionalities

2. **We have two alternatives:**
   - Implement everything manually
   - Delegate to a third party

3. **OAuth** is a protocol that enables a third-party application to obtain limited access to an HTTP service.

---

## Security Concepts

### What is Security?

- **Authentication:** Who are you?
- **Authorization:** What are you allowed to do?

---

## OAuth - Roles

- **Resource Owner:** Owner of the resource
- **Resource Server:** Where the resource is located
- **Authorization Server:** Grants access to the resource
- **Client:** Requests access to the resource

---

## Token Types

### Access Token

- Grant access to protected resources
- Understood by the resource server

### Refresh Token

- Access tokens expire
- Obtain new tokens without needing to log in again
- Usually opaque
- Sent to the authorization server

---

## JWT (JSON Web Token)

- JSON Web Token
- Content can be read

### Opaque Token

- Only the issuer can read it

---

## Scopes

Roles, permissions, associated with the Access Token.

**Examples:**
- Read email
- Create calendar event
- Access contacts


