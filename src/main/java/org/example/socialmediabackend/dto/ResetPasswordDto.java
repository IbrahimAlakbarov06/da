package org.example.socialmediabackend.dto;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class ResetPasswordDto {
    private String email;
    private String resetCode;
    private String newPassword;
}