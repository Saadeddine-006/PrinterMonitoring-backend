package com.snmp.PrinterMonitoring.controllers;

import com.snmp.PrinterMonitoring.dtos.auth.AuthRequest;
import com.snmp.PrinterMonitoring.dtos.auth.AuthResponse;
import com.snmp.PrinterMonitoring.dtos.auth.RefreshTokenRequest;
import com.snmp.PrinterMonitoring.dtos.auth.UserProfileResponse;
import com.snmp.PrinterMonitoring.dtos.users.CreateUserRequest;
import com.snmp.PrinterMonitoring.dtos.users.UserDTO;
import com.snmp.PrinterMonitoring.services.AuthService;
import com.snmp.PrinterMonitoring.services.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Endpoints for user authentication and registration")
public class AuthController {

    private final AuthService authService;
    private final UserService userService;
    private final ModelMapper modelMapper;

    @PostMapping("/login")
    @Operation(summary = "User login", description = "Authenticate user and return JWT token")
    @SecurityRequirements() // Disable security requirement for this endpoint
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody AuthRequest request,
            HttpServletRequest httpRequest) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok()
                .header("X-Auth-Method", "JWT")
                .body(response);
    }

    // ✅ Version fixée pour la création automatique avec mot de passe généré
    @PostMapping("/register")
    @Operation(summary = "User registration", description = "Register a new user account")
    @SecurityRequirements()
    public ResponseEntity<AuthResponse> register(
            @Valid @RequestBody CreateUserRequest createUserRequest) {

        // Convert CreateUserRequest en UserDTO
        UserDTO userDTO = modelMapper.map(createUserRequest, UserDTO.class);

        // Appelle le service pour créer l'utilisateur et générer un mot de passe
        AuthResponse response = authService.register(userDTO);

        return ResponseEntity.status(HttpStatus.CREATED)
                .header("X-Auth-Method", "JWT")
                .body(response);
    }

    @PostMapping("/refresh")
    @Operation(summary = "Refresh token", description = "Get new access token using refresh token")
    public ResponseEntity<AuthResponse> refreshToken(
            @Valid @RequestBody RefreshTokenRequest refreshRequest) {
        AuthResponse response = authService.refreshToken(refreshRequest);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/me")
    @Operation(summary = "Current user info", description = "Get authenticated user's information")
    public ResponseEntity<UserProfileResponse> getCurrentUser() {
        UserProfileResponse profile = authService.getCurrentUserProfile();
        return ResponseEntity.ok(profile);
    }
}
