package com.snmp.PrinterMonitoring.controllers;

import com.snmp.PrinterMonitoring.dtos.auth.AuthRequest;
import com.snmp.PrinterMonitoring.dtos.auth.AuthResponse;
import com.snmp.PrinterMonitoring.dtos.users.UserDTO;
import com.snmp.PrinterMonitoring.services.AuthService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirements;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.snmp.PrinterMonitoring.dtos.auth.*;
import com.snmp.PrinterMonitoring.dtos.users.UserDTO;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
@Tag(name = "Authentication", description = "Endpoints for user authentication and registration")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/login")
    @Operation(summary = "User login", description = "Authenticate user and return JWT token")
    @SecurityRequirements() // Disables security requirement for this endpoint
    public ResponseEntity<AuthResponse> login(
            @Valid @RequestBody AuthRequest request,
            HttpServletRequest httpRequest) {
        AuthResponse response = authService.login(request);
        return ResponseEntity.ok()
                .header("X-Auth-Method", "JWT")
                .body(response);
    }

    @PostMapping("/register")
    @Operation(summary = "User registration", description = "Register a new user account")
    @SecurityRequirements()
    public ResponseEntity<AuthResponse> register(
            @Valid @RequestBody UserDTO userDTO) {
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