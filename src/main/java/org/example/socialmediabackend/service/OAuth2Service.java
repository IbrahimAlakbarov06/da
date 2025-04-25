package org.example.socialmediabackend.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.example.socialmediabackend.model.User;
import org.example.socialmediabackend.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.IOException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Optional;
import java.util.UUID;

@Service
public class OAuth2Service {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final WebClient webClient;
    private final ObjectMapper objectMapper;

    public OAuth2Service(
            UserRepository userRepository,
            PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.webClient = WebClient.create();
        this.objectMapper = new ObjectMapper();
    }

    public User processGoogleToken(String idToken) {
        try {
            // Verify the token with Google
            String googleResponse = webClient.get()
                    .uri("https://oauth2.googleapis.com/tokeninfo?id_token=" + idToken)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            JsonNode userInfo = objectMapper.readTree(googleResponse);
            String email = userInfo.get("email").asText();
            String name = userInfo.get("name").asText();

            return findOrCreateUser(email, name);
        } catch (Exception e) {
            throw new RuntimeException("Failed to process Google token: " + e.getMessage());
        }
    }

    public User processFacebookToken(String accessToken) {
        try {
            // Verify the token with Facebook
            String facebookResponse = webClient.get()
                    .uri("https://graph.facebook.com/me?fields=name,email&access_token=" + accessToken)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            JsonNode userInfo = objectMapper.readTree(facebookResponse);
            String email = userInfo.get("email").asText();
            String name = userInfo.get("name").asText();

            return findOrCreateUser(email, name);
        } catch (Exception e) {
            throw new RuntimeException("Failed to process Facebook token: " + e.getMessage());
        }
    }

    public User processAppleToken(String identityToken) {
        try {
            // For Apple, the validation is more complex, involving JWT verification
            // This is a simplified version that extracts the email from the token
            String[] parts = identityToken.split("\\.");
            String payload = new String(Base64.getUrlDecoder().decode(parts[1]));

            JsonNode tokenData = objectMapper.readTree(payload);
            String email = tokenData.get("email").asText();
            String name = email.split("@")[0]; // Use part of email as name if not provided

            return findOrCreateUser(email, name);
        } catch (Exception e) {
            throw new RuntimeException("Failed to process Apple token: " + e.getMessage());
        }
    }

    private User findOrCreateUser(String email, String name) throws IOException {
        Optional<User> existingUser = userRepository.findByEmail(email);

        if (existingUser.isPresent()) {
            return existingUser.get();
        } else {
            // Create a new user
            User newUser = new User();
            newUser.setEmail(email);

            String username = generateUsername(name);
            newUser.setUsername(username);

            // Generate a strong random password
            String randomPassword = generateSecurePassword();
            newUser.setPassword(passwordEncoder.encode(randomPassword));

            // Social login users are pre-verified
            newUser.setEnabled(true);

            return userRepository.save(newUser);
        }
    }

    private String generateUsername(String name) {
        // Convert name to lowercase, remove spaces and special chars
        String baseName = name.toLowerCase().replaceAll("[^a-z0-9]", "");

        // Check if the username already exists, if so add random numbers
        String username = baseName;
        int attempt = 0;

        while (userRepository.findByUsername(username).isPresent()) {
            attempt++;
            username = baseName + attempt;
        }

        return username;
    }

    private String generateSecurePassword() {
        // Generate a secure random password
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[24];
        random.nextBytes(bytes);
        return Base64.getEncoder().encodeToString(bytes);
    }
}