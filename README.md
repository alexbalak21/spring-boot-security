# Spring Boot Security with JWT Authentication

[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.5.0-brightgreen)](https://spring.io/projects/spring-boot)
[![Java](https://img.shields.io/badge/Java-24-blue)](https://www.oracle.com/java/technologies/javase/jdk24-archive-downloads.html)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A secure RESTful API implementation using Spring Boot 3.5.0 and Spring Security 6 with JWT (JSON Web Token) authentication. This project demonstrates best practices for implementing authentication and authorization in a Spring Boot application.

## ✨ Features

- 🔒 JWT-based authentication with access and refresh tokens
- 👥 Role-based access control (RBAC)
- 🔄 Token refresh mechanism
- 🔐 Password encryption with BCrypt
- 🛡️ Secure API endpoints
- ✅ Input validation
- 📝 Detailed API documentation
- 🧪 Comprehensive test coverage

## 🚀 Quick Start

### Prerequisites

- Java 24
- Maven 3.9+
- MySQL 8.0+

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/spring-boot-security.git
   cd spring-boot-security
   ```

2. Configure the database:
   - Create a MySQL database
   - Update `application.properties` with your database credentials

3. Build the application:
   ```bash
   mvn clean install
   ```

4. Run the application:
   ```bash
   mvn spring-boot:run
   ```

The application will be available at `http://localhost:8080`

## 📚 API Documentation

For detailed API documentation, please refer to the [API Documentation](DOCUMENTATION.md).

## 🔧 Configuration

Application configuration can be modified in `application.properties`:

```properties
# Database Configuration
spring.datasource.url=jdbc:mysql://localhost:3306/your_database
spring.datasource.username=your_username
spring.datasource.password=your_password
spring.jpa.hibernate.ddl-auto=update

# JWT Configuration
app.jwt.authSecret=your-512-bit-secret-key-here
app.jwt.refreshSecret=your-512-bit-refresh-secret-key-here
app.jwt.AuthExpiration=900000
app.jwt.refreshExpiration=604800000
```

## 🧪 Testing

Run the tests using:

```bash
mvn test
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

Distributed under the MIT License. See `LICENSE` for more information.

## 📫 Contact

Your Name - [@yourtwitter](https://twitter.com/yourtwitter) - email@example.com

Project Link: [https://github.com/yourusername/spring-boot-security](https://github.com/yourusername/spring-boot-security)

## 🙏 Acknowledgments

- [Spring Boot](https://spring.io/projects/spring-boot)
- [Spring Security](https://spring.io/projects/spring-security)
- [JJWT](https://github.com/jwtk/jjwt)
- [Lombok](https://projectlombok.org/)
