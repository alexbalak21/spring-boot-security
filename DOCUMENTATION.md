# Spring Boot Security with JWT Authentication

## Table of Contents
1. [Project Overview](#project-overview)
2. [Authentication Flow](#authentication-flow)
3. [Security Configuration](#security-configuration)
4. [JWT Implementation](#jwt-implementation)
5. [API Endpoints](#api-endpoints)
6. [Database Schema](#database-schema)
7. [Error Handling](#error-handling)
8. [Configuration](#configuration)
9. [Testing](#testing)
10. [Deployment](#deployment)

## Project Overview
This project implements a secure RESTful API using Spring Boot 3.5.0 and Spring Security 6. It features JWT (JSON Web Token) based authentication with access and refresh tokens. The application provides user registration and login functionality with role-based access control.

## Authentication Flow
1. **Registration**:
   - User provides username, password, and role
   - Password is encoded using BCrypt
   - User is saved to the database

2. **Login**:
   - User provides username and password
   - Credentials are validated
   - JWT access token and refresh token are generated and returned
   - Access token has a short expiration time
   - Refresh token has a longer expiration time

3. **Accessing Protected Resources**:
   - Client includes the access token in the Authorization header
   - Server validates the token and grants access if valid
   - If token is expired, client can request a new one using the refresh token

## Security Configuration
The security is configured in `SecurityConfig` class with the following features:
- CSRF protection disabled (suitable for stateless REST APIs)
- Public endpoints for registration and login
- Role-based authorization for protected endpoints
- JWT authentication filter
- Password encoding using BCrypt
- Session management set to stateless

## JWT Implementation
- Uses `jjwt` library for JWT operations
- Supports both access and refresh tokens
- Token validation and parsing
- Custom claims for additional user information
- Token expiration handling

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register a new user
  ```json
  {
    "username": "user@example.com",
    "password": "password123",
    "fullName": "John Doe",
    "role": "ROLE_USER"
  }
  ```

- `POST /api/auth/login` - Authenticate and get tokens
  ```json
  {
    "username": "user@example.com",
    "password": "password123"
  }
  ```
  Response:
  ```json
  {
    "accessToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
  }
  ```

## Database Schema
The application uses the following database schema:

### users Table
- `id` - Primary key, auto-increment
- `username` - Unique username/email
- `password` - Encrypted password
- `full_name` - User's full name
- `role` - User role (ROLE_USER, ROLE_ADMIN)

## Error Handling
The application provides meaningful error messages for various scenarios:
- Invalid credentials
- Expired tokens
- Missing or invalid tokens
- Access denied
- User already exists
- Validation errors

## Configuration
Application properties can be configured in `application.yml` or `application.properties`:

```yaml
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/your_database
    username: your_username
    password: your_password
  jpa:
    hibernate:
      ddl-auto: update
    show-sql: true

app:
  jwt:
    authSecret: your-512-bit-secret-key-here
    refreshSecret: your-512-bit-refresh-secret-key-here
    authExpiration: 900000 # 15 minutes in milliseconds
    refreshExpiration: 604800000 # 7 days in milliseconds
```

## Testing
Run the application and test the endpoints using tools like Postman or cURL:

1. Register a new user
2. Login to get tokens
3. Access protected endpoints with the access token
4. Test token expiration and refresh flow

## Deployment
1. Build the application:
   ```bash
   mvn clean package
   ```
2. Run the JAR file:
   ```bash
   java -jar target/spring-boot-security-0.0.1-SNAPSHOT.jar
   ```
3. The application will be available at `http://localhost:8080`

## Dependencies
- Spring Boot 3.5.0
- Spring Security 6
- Spring Data JPA
- MySQL Connector/J
- JJWT for JWT operations
- Lombok for reducing boilerplate code
- Spring Boot Validation

## Contributing
1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request
