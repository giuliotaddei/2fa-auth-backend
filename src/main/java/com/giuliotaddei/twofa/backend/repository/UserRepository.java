package com.giuliotaddei.twofa.backend.repository;

import com.giuliotaddei.twofa.backend.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.time.LocalDateTime;
import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByEmail(String email);

    boolean existsByEmail(String email);

    @Modifying
    @Query("UPDATE User u SET u.failedAttempts = 0, u.lockedUntil = null, u.lastLogin = :now WHERE u.id = :id")
    void resetFailedAttemptsAndUpdateLogin(Long id, LocalDateTime now);

    @Modifying
    @Query("UPDATE User u SET u.failedAttempts = u.failedAttempts + 1 WHERE u.id = :id")
    void incrementFailedAttempts(Long id);

    @Modifying
    @Query("UPDATE User u SET u.lockedUntil = :lockedUntil WHERE u.id = :id")
    void lockUser(Long id, LocalDateTime lockedUntil);
}
