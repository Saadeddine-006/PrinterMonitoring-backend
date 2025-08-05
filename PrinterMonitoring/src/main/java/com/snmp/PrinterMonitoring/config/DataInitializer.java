package com.snmp.PrinterMonitoring.config;

import com.snmp.PrinterMonitoring.entities.User;
import com.snmp.PrinterMonitoring.enums.Role;
import com.snmp.PrinterMonitoring.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
@Slf4j
public class DataInitializer implements CommandLineRunner {

    private static final List<TestUser> DEFAULT_USERS = List.of(
            new TestUser("Admin User", "admin@test.com", "Admin@123", Role.ADMIN),
            new TestUser("Technician User", "tech@test.com", "Tech@123", Role.TECHNICIAN),
            new TestUser("Viewer User", "viewer@test.com", "Viewer@123", Role.VIEWER)
    );

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    @Override
    public void run(String... args) {
        try {
            DEFAULT_USERS.forEach(this::initializeUser);
            logInitializedUsers();
        } catch (Exception e) {
            log.error("Data initialization failed: {}", e.getMessage(), e);
            throw new IllegalStateException("Failed to initialize application data", e);
        }
    }

    private void initializeUser(TestUser testUser) {
        if (!userRepository.existsByEmail(testUser.email())) {
            User user = User.builder()
                    .fullName(testUser.fullName())
                    .email(testUser.email())
                    .password(passwordEncoder.encode(testUser.password()))
                    .role(testUser.role())
                    .active(true)
                    .build();
            userRepository.save(user);
        }
    }

    private void logInitializedUsers() {
        if (log.isInfoEnabled()) {
            log.info("Application users status:");
            DEFAULT_USERS.forEach(user -> {
                String status = userRepository.existsByEmail(user.email())
                        ? "EXISTS" : "MISSING";
                log.info("{} - {}: {}", user.role(), user.email(), status);
            });
        }
    }

    private record TestUser(
            String fullName,
            String email,
            String password,
            Role role
    ) {}
}