package auth.app.api.repositories;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import auth.app.api.domain.User;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByEmail(String email);
}
