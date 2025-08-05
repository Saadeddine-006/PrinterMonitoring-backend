package com.snmp.PrinterMonitoring.services;

import com.snmp.PrinterMonitoring.dtos.auth.AuthRequest;
import com.snmp.PrinterMonitoring.dtos.auth.AuthResponse;
import com.snmp.PrinterMonitoring.dtos.auth.RefreshTokenRequest;
import com.snmp.PrinterMonitoring.dtos.auth.UserProfileResponse;
import com.snmp.PrinterMonitoring.dtos.users.UserDTO;
import com.snmp.PrinterMonitoring.dtos.users.UserResponseDTO;
import com.snmp.PrinterMonitoring.entities.User; // Ensure this is the correct User entity import
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

import java.util.Date;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final AuthenticationManager authenticationManager;
    private final UserRepository userRepository;
    private final UserService userService;
    private final JwtUtil jwtUtil;
    private final ModelMapper modelMapper;

    /**
     * Registers a new user and returns a JWT token
     */
    public AuthResponse register(UserDTO userDTO) {
        if (userRepository.existsByEmail(userDTO.getEmail())) {
            throw new IllegalArgumentException("Email already in use.");
        }

        UserResponseDTO createdUserResponse = userService.createUser(userDTO); // This returns a DTO
        // We need the actual User entity to pass to JwtUtil
        User registeredUser = userRepository.findByEmail(createdUserResponse.getEmail())
                .orElseThrow(() -> new UsernameNotFoundException("Registered user not found!"));

        String token = jwtUtil.generateToken(registeredUser); // MODIFIED: Pass User object
        String refreshToken = jwtUtil.generateRefreshToken(registeredUser.getEmail()); // Still uses email for refresh
        return new AuthResponse(token, refreshToken, "User registered successfully.");
    }

    /**
     * Authenticates user and returns a JWT token
     */
    public AuthResponse login(AuthRequest authRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            authRequest.getEmail(),
                            authRequest.getPassword()
                    )
            );

            // Get the principal, which is usually a Spring Security UserDetails object
            org.springframework.security.core.userdetails.User springUser =
                    (org.springframework.security.core.userdetails.User) authentication.getPrincipal();

            String email = springUser.getUsername();
            // Find the full User entity from the database to get its role
            User authenticatedUser = userRepository.findByEmail(email)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));

            String token = jwtUtil.generateToken(authenticatedUser); // MODIFIED: Pass User object
            String refreshToken = jwtUtil.generateRefreshToken(authenticatedUser.getEmail()); // Still uses email for refresh

            return new AuthResponse(token, refreshToken, "Login successful.");
        } catch (BadCredentialsException e) {
            throw new IllegalArgumentException("Invalid email or password.");
        }
    }

    /**
     * Refreshes JWT token using a refresh token.
     * @param refreshRequest Contains the refresh token.
     * @return New AuthResponse with new access token and refresh token.
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

            // For refresh token, we also need to get the User entity to generate the new access token with claims
            User userForNewToken = userRepository.findByEmail(userEmail)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found for refresh token: " + userEmail));

            String newAccessToken = jwtUtil.generateToken(userForNewToken); // MODIFIED: Pass User object
            String newRefreshToken = jwtUtil.generateRefreshToken(userForNewToken.getEmail());
            return new AuthResponse(newAccessToken, newRefreshToken, "Token refreshed successfully.");
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