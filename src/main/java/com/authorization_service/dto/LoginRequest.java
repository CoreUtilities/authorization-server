package com.authorization_service.dto;

import lombok.Data;

@Data
public class LoginRequest {
    private String username;
    private String password;
    // Getters & Setters
}

