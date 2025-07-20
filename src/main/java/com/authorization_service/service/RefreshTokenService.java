package com.authorization_service.service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.authorization_service.entity.RefreshToken;
import com.authorization_service.entity.User;
import com.authorization_service.repository.RefreshTokenRepository;
import com.authorization_service.repository.UserRepository;

@Service
public class RefreshTokenService {

    @Value("${app.jwt.refresh-expiration-ms}")
    private Long refreshTokenDurationMs;

    private final RefreshTokenRepository refreshTokenRepo;
    private final UserRepository userRepo;

    public RefreshTokenService(RefreshTokenRepository repo, UserRepository userRepo) {
        this.refreshTokenRepo = repo;
        this.userRepo = userRepo;
    }

    public RefreshToken createRefreshToken(String username) {
        User user = userRepo.findByUsername(username).orElseThrow();

        RefreshToken token = new RefreshToken();
        token.setUser(user);
        token.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
        token.setToken(UUID.randomUUID().toString());

        return refreshTokenRepo.save(token);
    }

    public RefreshToken verifyExpiration(RefreshToken token) {
        if (token.getExpiryDate().isBefore(Instant.now())) {
            refreshTokenRepo.delete(token);
            throw new RuntimeException("Refresh token expired. Login again.");
        }
        return token;
    }

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepo.findByToken(token);
    }

    public void deleteByUserId(Long userId) {
        User user = userRepo.findById(userId).orElseThrow();
        refreshTokenRepo.deleteByUser(user);
    }
}

