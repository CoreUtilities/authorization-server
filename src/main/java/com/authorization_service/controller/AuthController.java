package com.authorization_service.controller;

import com.authorization_service.dto.LoginRequest;
import com.authorization_service.dto.RegisterRequest;
import com.authorization_service.service.JwtService;
import com.authorization_service.service.RefreshTokenService;

import jakarta.servlet.http.HttpServletResponse;

import com.authorization_service.entity.RefreshToken;
import com.authorization_service.entity.User;
import com.authorization_service.repository.UserRepository;

import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserRepository userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final RefreshTokenService refreshTokenService;

    public AuthController(UserRepository userRepo, PasswordEncoder passwordEncoder, JwtService jwtService, RefreshTokenService refreshTokenService) {
        this.userRepo = userRepo;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.refreshTokenService = refreshTokenService;
    }

    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterRequest request) {
        if (userRepo.findByUsername(request.getUsername()).isPresent()) {
            return ResponseEntity.badRequest().body("Username already exists.");
        }
        User user = new User();
        user.setUsername(request.getUsername());
        user.setPassword(passwordEncoder.encode(request.getPassword()));
        userRepo.save(user);
        return ResponseEntity.ok("User registered successfully.");
    }

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request, HttpServletResponse response) {
        User user = userRepo.findByUsername(request.getUsername()).orElse(null);
        if (user == null || !passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid credentials");
        }

        String accessToken = jwtService.generateToken(user.getUsername());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(user.getUsername());

        // Set refresh token as HTTPOnly cookie
        ResponseCookie cookie = ResponseCookie.from("refreshToken", refreshToken.getToken())
                .httpOnly(true)
                .secure(true) // 🔒 for HTTPS environments
                .path("/api/auth")
                .maxAge(7 * 24 * 60 * 60) // 7 days
                .sameSite("Strict")
                .build();

        response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());

        return ResponseEntity.ok(Map.of("accessToken", accessToken));
    }


    @PostMapping("/refresh-token")
    public ResponseEntity<?> refresh(@CookieValue("refreshToken") String refreshToken, HttpServletResponse response) {
        return refreshTokenService.findByToken(refreshToken)
            .map(refreshTokenService::verifyExpiration)
            .map(RefreshToken::getUser)
            .map(user -> {
                refreshTokenService.deleteByUserId(user.getId());
                RefreshToken newRefreshToken = refreshTokenService.createRefreshToken(user.getUsername());

                String newAccessToken = jwtService.generateToken(user.getUsername());

                // 🔄 Replace old cookie with new one
                ResponseCookie cookie = ResponseCookie.from("refreshToken", newRefreshToken.getToken())
                        .httpOnly(true)
                        .secure(true)
                        .path("/api/auth")
                        .maxAge(7 * 24 * 60 * 60)
                        .sameSite("Strict")
                        .build();
                response.setHeader(HttpHeaders.SET_COOKIE, cookie.toString());

                return ResponseEntity.ok(Map.of("accessToken", newAccessToken));
            }).orElseThrow(() -> new RuntimeException("Invalid refresh token."));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestBody Map<String, String> request) {
        String refreshToken = request.get("refreshToken");
        
        return refreshTokenService.findByToken(refreshToken)
            .map(RefreshToken::getUser)
            .map(user -> {
                refreshTokenService.deleteByUserId(user.getId());
                return ResponseEntity.ok("Logged out successfully.");
            }).orElseThrow(() -> new RuntimeException("Invalid refresh token."));
    }

}

