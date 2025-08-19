package com.snmp.PrinterMonitoring.services;

import com.snmp.PrinterMonitoring.dtos.users.ChangePasswordRequest;
import com.snmp.PrinterMonitoring.dtos.users.UpdateUserRequest;
import com.snmp.PrinterMonitoring.dtos.users.UserDTO;
import com.snmp.PrinterMonitoring.dtos.users.UserResponseDTO;
import com.snmp.PrinterMonitoring.dtos.auth.UserProfileResponse;
import com.snmp.PrinterMonitoring.entities.User;
import com.snmp.PrinterMonitoring.enums.Role;
import com.snmp.PrinterMonitoring.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.modelmapper.ModelMapper;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final ModelMapper modelMapper;
    private final MailService mailService; // NEW: inject MailService

    @Transactional
    public UserResponseDTO createUser(UserDTO userDTO) {
        if (userRepository.existsByEmail(userDTO.getEmail())) {
            throw new IllegalArgumentException("Email already in use: " + userDTO.getEmail());
        }

        // ✅ Generate random password
        String rawPassword = UUID.randomUUID().toString().substring(0, 8);

        User user = modelMapper.map(userDTO, User.class);
        user.setPassword(passwordEncoder.encode(rawPassword)); // save encoded password
        user.setRole(userDTO.getRole() != null ? userDTO.getRole() : Role.VIEWER);
        user.setActive(true);

        User savedUser = userRepository.save(user);

        // ✅ Send welcome email
        mailService.sendWelcomeEmail(
                savedUser.getEmail(),
                savedUser.getFullName() != null ? savedUser.getFullName() : savedUser.getEmail()
                ,
                rawPassword
        );

        return modelMapper.map(savedUser, UserResponseDTO.class);
    }

    public Optional<User> getUserByEmail(String email) {
        return userRepository.findByEmail(email);
    }

    public Optional<User> getUserById(Long id) {
        return userRepository.findById(id);
    }

    public Page<UserResponseDTO> getAllUsers(Pageable pageable) {
        return userRepository.findAll(pageable)
                .map(user -> modelMapper.map(user, UserResponseDTO.class));
    }

    @Transactional
    public UserResponseDTO updateUser(Long id, UpdateUserRequest userDTO) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with ID: " + id));

        boolean updated = false;
        if (userDTO.getFullName() != null && !userDTO.getFullName().isBlank()) {
            user.setFullName(userDTO.getFullName());
            updated = true;
        }
        if (userDTO.getEmail() != null && !userDTO.getEmail().isBlank()) {
            if (!user.getEmail().equals(userDTO.getEmail()) && userRepository.existsByEmail(userDTO.getEmail())) {
                throw new IllegalArgumentException("New email is already in use by another user: " + userDTO.getEmail());
            }
            user.setEmail(userDTO.getEmail());
            updated = true;
        }

        if (!updated) {
            throw new IllegalArgumentException("No valid fields provided for user update.");
        }

        User updatedUser = userRepository.save(user);
        return modelMapper.map(updatedUser, UserResponseDTO.class);
    }

    @Transactional
    public void changePassword(Long id, ChangePasswordRequest request) {
        User user = userRepository.findById(id)
                .orElseThrow(() -> new UsernameNotFoundException("User not found with ID: " + id));

        if (!passwordEncoder.matches(request.getCurrentPassword(), user.getPassword())) {
            throw new IllegalArgumentException("Current password does not match.");
        }

        if (passwordEncoder.matches(request.getNewPassword(), user.getPassword())) {
            throw new IllegalArgumentException("New password cannot be the same as the current password.");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        userRepository.save(user);
    }

    public UserProfileResponse getCurrentUserProfile() {
        Object principal = SecurityContextHolder.getContext().getAuthentication().getPrincipal();

        if (principal instanceof org.springframework.security.core.userdetails.User) {
            String email = ((org.springframework.security.core.userdetails.User) principal).getUsername();
            User user = userRepository.findByEmail(email)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found with email: " + email));
            return modelMapper.map(user, UserProfileResponse.class);
        } else {
            throw new UsernameNotFoundException("No authenticated user found or unexpected principal type.");
        }
    }

    @Transactional
    public void deleteUser(Long userId) {
        if (!userRepository.existsById(userId)) {
            throw new UsernameNotFoundException("User not found with ID: " + userId);
        }
        userRepository.deleteById(userId);
    }
}
