package org.example.socialmediabackend.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class SocialLoginDto {
    private String token;
    private String email;
    private String name;
    private String pictureUrl;
}