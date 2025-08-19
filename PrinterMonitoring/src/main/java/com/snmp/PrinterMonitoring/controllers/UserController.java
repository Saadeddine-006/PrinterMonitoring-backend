package com.snmp.PrinterMonitoring.controllers;

import com.snmp.PrinterMonitoring.dtos.users.ChangePasswordRequest;
import com.snmp.PrinterMonitoring.dtos.users.CreateUserRequest;
import com.snmp.PrinterMonitoring.dtos.users.UpdateUserRequest;
import com.snmp.PrinterMonitoring.dtos.users.UserDTO;
import com.snmp.PrinterMonitoring.dtos.users.UserResponseDTO;
import com.snmp.PrinterMonitoring.dtos.auth.UserProfileResponse;
import com.snmp.PrinterMonitoring.services.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/users")
@RequiredArgsConstructor
@Tag(name = "User Management", description = "Endpoints for managing user accounts")
@SecurityRequirement(name = "bearerAuth")
public class UserController {

    private final UserService userService;
    private final ModelMapper modelMapper;

    @PostMapping
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Create user", description = "Create a new user account (Admin only)")
    public ResponseEntity<UserResponseDTO> createUser(
            @Valid @RequestBody CreateUserRequest createUserRequest) {

        // Convert CreateUserRequest to UserDTO
        UserDTO userDTO = modelMapper.map(createUserRequest, UserDTO.class);

        // Call service to create user and get response DTO
        UserResponseDTO createdUser = userService.createUser(userDTO);

        return ResponseEntity.status(HttpStatus.CREATED).body(createdUser);
    }

    @GetMapping
    @PreAuthorize("hasAnyRole('ADMIN', 'TECHNICIAN')")
    @Operation(summary = "List users", description = "Get paginated list of all users")
    public ResponseEntity<Page<UserResponseDTO>> getAllUsers(
            @Parameter(hidden = true) Pageable pageable) {
        return ResponseEntity.ok(userService.getAllUsers(pageable));
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get user by ID", description = "Get user details by ID")
    public ResponseEntity<UserResponseDTO> getUserById(@PathVariable Long id) {
        return userService.getUserById(id)
                .map(user -> ResponseEntity.ok(modelMapper.map(user, UserResponseDTO.class)))
                .orElseGet(() -> ResponseEntity.notFound().build());
    }

    @PutMapping("/{id}")
    @Operation(summary = "Update user", description = "Update user information")
    @PreAuthorize("hasRole('ADMIN') or (#id == authentication.principal.id)") // Allow admin or self-update
    public ResponseEntity<UserResponseDTO> updateUser(
            @PathVariable Long id,
            @Valid @RequestBody UpdateUserRequest userDTO) {
        return ResponseEntity.ok(userService.updateUser(id, userDTO));
    }

    @DeleteMapping("/{id}")
    @PreAuthorize("hasRole('ADMIN')")
    @Operation(summary = "Delete user", description = "Delete a user account (Admin only)")
    public ResponseEntity<Void> deleteUser(@PathVariable Long id) {
        userService.deleteUser(id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/profile")
    @Operation(summary = "Current user profile", description = "Get authenticated user's profile")
    public ResponseEntity<UserProfileResponse> getCurrentUserProfile() {
        return ResponseEntity.ok(userService.getCurrentUserProfile());
    }

    @PutMapping("/{id}/password")
    @Operation(summary = "Change password", description = "Change user's password")
    @PreAuthorize("isAuthenticated() and #id == @userRepository.findByEmail(authentication.name).orElseThrow().getId()") // NEW: Allow authenticated user to change their own password
    public ResponseEntity<Void> changePassword(
            @PathVariable Long id,
            @Valid @RequestBody ChangePasswordRequest request) {
        userService.changePassword(id, request);
        return ResponseEntity.noContent().build();
    }
}
