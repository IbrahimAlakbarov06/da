package org.example.socialmediabackend.service;

import org.example.socialmediabackend.model.User;
import org.example.socialmediabackend.repository.UserRepository;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

import java.util.Optional;
import java.util.Random;

@Service
public class OAuth2UserService extends DefaultOAuth2UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public OAuth2UserService(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);

        try {
            return processOAuth2User(oAuth2UserRequest, oAuth2User);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception ex) {
            throw new InternalAuthenticationServiceException(ex.getMessage(), ex.getCause());
        }
    }

    private OAuth2User processOAuth2User(OAuth2UserRequest oAuth2UserRequest, OAuth2User oAuth2User) {
        String provider = oAuth2UserRequest.getClientRegistration().getRegistrationId();
        String email = extractEmail(provider, oAuth2User);

        if (!StringUtils.hasText(email)) {
            throw new OAuth2AuthenticationException("Email not found from OAuth2 provider");
        }

        Optional<User> userOptional = userRepository.findByEmail(email);
        User user;

        if (userOptional.isPresent()) {
            user = userOptional.get();
            // Update existing user with any new info from OAuth provider if needed
        } else {
            user = registerNewUser(provider, oAuth2User);
        }

        return new OAuth2UserPrincipal(user, oAuth2User.getAttributes());
    }

    private String extractEmail(String provider, OAuth2User oAuth2User) {
        switch (provider) {
            case "google":
                return oAuth2User.getAttribute("email");
            case "facebook":
                return oAuth2User.getAttribute("email");
            case "apple":
                return oAuth2User.getAttribute("email");
            default:
                return null;
        }
    }

    private User registerNewUser(String provider, OAuth2User oAuth2User) {
        String email = extractEmail(provider, oAuth2User);
        String name = extractName(provider, oAuth2User);
        String username = generateUsername(name);

        // Generate a random secure password for OAuth users
        String password = generateRandomPassword();

        User user = new User();
        user.setUsername(username);
        user.setEmail(email);
        user.setPassword(passwordEncoder.encode(password));
        user.setEnabled(true); // OAuth users are pre-verified

        return userRepository.save(user);
    }

    private String extractName(String provider, OAuth2User oAuth2User) {
        switch (provider) {
            case "google":
                return oAuth2User.getAttribute("name");
            case "facebook":
                return oAuth2User.getAttribute("name");
            case "apple":
                String firstName = oAuth2User.getAttribute("firstName");
                String lastName = oAuth2User.getAttribute("lastName");
                if (firstName != null && lastName != null) {
                    return firstName + " " + lastName;
                }
                return "Apple User";
            default:
                return "User";
        }
    }

    private String generateUsername(String name) {
        String baseUsername = name.toLowerCase().replaceAll("\\s+", "") + new Random().nextInt(1000);
        String username = baseUsername;
        int count = 0;

        // Make sure username is unique
        while (userRepository.findByUsername(username).isPresent()) {
            username = baseUsername + (++count);
        }

        return username;
    }

    private String generateRandomPassword() {
        // Generate a secure random password
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()";
        StringBuilder sb = new StringBuilder();
        Random random = new Random();
        for (int i = 0; i < 16; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }
}