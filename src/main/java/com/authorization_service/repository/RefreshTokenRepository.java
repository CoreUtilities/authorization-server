package com.authorization_service.repository;

import java.util.Optional;
import org.springframework.data.jpa.repository.JpaRepository;
import com.authorization_service.entity.RefreshToken;
import com.authorization_service.entity.User;

public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);
    int deleteByUser(User user);
}

