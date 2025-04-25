package org.example.socialmediabackend.config;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.example.socialmediabackend.model.User;
import org.example.socialmediabackend.service.JwtService;
import org.example.socialmediabackend.service.OAuth2UserPrincipal;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

@Component
public class OAuth2AuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final JwtService jwtService;
    private final String redirectUri = "http://localhost:3000/oauth2/redirect";

    public OAuth2AuthenticationSuccessHandler(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication)
            throws IOException, ServletException {
        if (response.isCommitted()) {
            return;
        }

        OAuth2UserPrincipal oAuth2UserPrincipal = (OAuth2UserPrincipal) authentication.getPrincipal();
        User user = oAuth2UserPrincipal.getUser();

        String token = jwtService.generateToken(user);
        String targetUrl = UriComponentsBuilder.fromUriString(redirectUri)
                .queryParam("token", token)
                .queryParam("expiresIn", jwtService.getExpirationTime())
                .build().toUriString();

        getRedirectStrategy().sendRedirect(request, response, targetUrl);
    }
}