package auth.app.api.controllers;

import java.util.Optional;

import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import auth.app.api.domain.User;
import auth.app.api.dtos.LoginRequestDto;
import auth.app.api.dtos.RegisterRequestDto;
import auth.app.api.infra.security.TokenService;
import auth.app.api.repositories.UserRepository;
import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthController {
    private final UserRepository userRepository;
    private final TokenService tokenService;
    private final PasswordEncoder passwordEncoder;

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody LoginRequestDto body) {
        User user = userRepository.findByEmail(body.email()).orElseThrow(() -> new RuntimeException("User Not Found"));
        if (!passwordEncoder.matches(body.password(), user.getPassword())) {
            return ResponseEntity.badRequest().build();
        }
        String token = tokenService.generateToken(user);
        return ResponseEntity.ok(token);
    }

    @PostMapping("/register")
    public ResponseEntity<String> login(@RequestBody RegisterRequestDto body) {
        Optional<User> user = userRepository.findByEmail(body.email());

        if (user.isEmpty()) {
            User newUser = new User();
            newUser.setName(body.name());
            newUser.setEmail(body.email());
            newUser.setPassword(passwordEncoder.encode(body.password()));
            userRepository.save(newUser);

            String token = tokenService.generateToken(newUser);
            return ResponseEntity.ok(token);
        }

        return ResponseEntity.badRequest().build();
    }
}
