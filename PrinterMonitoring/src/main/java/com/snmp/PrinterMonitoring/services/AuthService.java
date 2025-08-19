package com.snmp.PrinterMonitoring.services;

import com.snmp.PrinterMonitoring.dtos.auth.AuthRequest;
import com.snmp.PrinterMonitoring.dtos.auth.AuthResponse;
import com.snmp.PrinterMonitoring.dtos.auth.RefreshTokenRequest;
import com.snmp.PrinterMonitoring.dtos.auth.UserProfileResponse;
import com.snmp.PrinterMonitoring.dtos.users.UserDTO;
import com.snmp.PrinterMonitoring.dtos.users.UserResponseDTO; // Ensure this is imported
import com.snmp.PrinterMonitoring.entities.User;
import com.snmp.PrinterMonitoring.repositories.UserRepository;
import com.snmp.PrinterMonitoring.security.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional; // Keep @Transactional import

import java.util.Date;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final UserService userService; // Already injected for createUser
    private final JwtUtil jwtUtil;
    private final ModelMapper modelMapper;

    /**
     * Registers a new user and returns a JWT token along with user details.
     */
    @Transactional // Ensure transactional for user creation
    public AuthResponse register(UserDTO userDTO) {
        if (userRepository.existsByEmail(userDTO.getEmail())) {
            throw new IllegalArgumentException("Email already in use.");
        }

        // Call userService to create user (handles password generation and emailing)
        UserResponseDTO createdUserResponse = userService.createUser(userDTO);

        // Fetch the actual User entity needed by JwtUtil for claims
        User registeredUser = userRepository.findByEmail(createdUserResponse.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("Registered user not found after creation!"));

        String token = jwtUtil.generateToken(registeredUser);
        String refreshToken = jwtUtil.generateRefreshToken(registeredUser.getEmail());

        // MODIFIED: Populate the 'user' field in AuthResponse
        return new AuthResponse(token, refreshToken, "User registered successfully.", createdUserResponse);
    }

    /**
     * Authenticates user and returns a JWT token along with user details.
     */
    public AuthResponse login(AuthRequest authRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            authRequest.getEmail(),
                            authRequest.getPassword()
                    )
            );

            org.springframework.security.core.userdetails.User springUser =
                    (org.springframework.security.core.userdetails.User) authentication.getPrincipal();

            String email = springUser.getUsername();
            User authenticatedUser = userRepository.findByEmail(email)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));

            String token = jwtUtil.generateToken(authenticatedUser);
            String refreshToken = jwtUtil.generateRefreshToken(authenticatedUser.getEmail());

            // MODIFIED: Map authenticatedUser to UserResponseDTO and populate 'user' field in AuthResponse
            UserResponseDTO authenticatedUserDTO = modelMapper.map(authenticatedUser, UserResponseDTO.class);
            return new AuthResponse(token, refreshToken, "Login successful.", authenticatedUserDTO);
        } catch (BadCredentialsException e) {
            throw new IllegalArgumentException("Invalid email or password.");
        }
    }

    /**
     * Refreshes JWT token using a refresh token, returning new tokens and user details.
     * @param refreshRequest Contains the refresh token.
     * @return New AuthResponse with new access token, refresh token, and user details.
     * @throws IllegalArgumentException if refresh token is invalid or expired.
     */
    public AuthResponse refreshToken(RefreshTokenRequest refreshRequest) {
        String refreshToken = refreshRequest.getRefreshToken();
        if (refreshToken == null || refreshToken.isEmpty()) {
            throw new IllegalArgumentException("Refresh token is missing.");
        }

        try {
            String userEmail = jwtUtil.extractEmail(refreshToken);
            Date expiration = jwtUtil.extractExpiration(refreshToken);

            if (userEmail == null || expiration == null || expiration.before(new Date())) {
                throw new IllegalArgumentException("Invalid or expired refresh token.");
            }

            User userForNewToken = userRepository.findByEmail(userEmail)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found for refresh token: " + userEmail));

            String newAccessToken = jwtUtil.generateToken(userForNewToken);
            String newRefreshToken = jwtUtil.generateRefreshToken(userForNewToken.getEmail());

            // MODIFIED: Map userForNewToken to UserResponseDTO and populate 'user' field in AuthResponse
            UserResponseDTO refreshedUserDTO = modelMapper.map(userForNewToken, UserResponseDTO.class);
            return new AuthResponse(newAccessToken, newRefreshToken, "Token refreshed successfully.", refreshedUserDTO);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid or expired refresh token: " + e.getMessage());
        }
    }

    /**
     * Retrieves the profile of the currently authenticated user.
     * @return UserProfileResponse containing user details.
     * @throws UsernameNotFoundException if the authenticated user cannot be found.
     */
    public UserProfileResponse getCurrentUserProfile() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication == null || !authentication.isAuthenticated() || "anonymousUser".equals(authentication.getPrincipal())) {
            throw new IllegalStateException("User is not authenticated.");
        }

        String userEmail = ((org.springframework.security.core.userdetails.User) authentication.getPrincipal()).getUsername();

        User user = userRepository.findByEmail(userEmail)
                .orElseThrow(() -> new UsernameNotFoundException("Authenticated user not found in database: " + userEmail));

        return modelMapper.map(user, UserProfileResponse.class);
    }
}
